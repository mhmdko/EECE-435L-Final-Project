"""
Threat Intelligence Service: 6 endpoints.

    POST   /threats           add a threat indicator
    GET    /threats           list all threat indicators
    GET    /threats/<id>      get one threat indicator
    GET    /threats/search    search by type, value, severity, source
    PUT    /threats/<id>      update description, severity, or source
    DELETE /threats/<id>      delete a threat indicator

When a High or Critical threat is added, every active Security Analyst gets a
Threat Alert notification (through the Notifications service).

Regular Employees have no access to this service.

Author: Anthony Feghali
"""
from flask import Blueprint, g, request

from app.common.auth import ADMIN, ANALYST, AUDITOR, roles_required
from app.common.errors import ApiError, success
from app.common.network_validation import hash_algorithm, require_domain, require_file_hash, require_ip
from app.common.validation import get_json_body, require_choice, require_text
from app.extensions import db
from app.services.logs.service import log_event
from app.services.notifications.service import create_notification
from app.services.threats.models import THREAT_SEVERITIES, THREAT_TYPES, Threat
from app.services.users.models import User

bp = Blueprint("threats", __name__, url_prefix="/threats")

SERVICE = "Threats"
SEARCH_FILTERS = ("type", "value", "severity", "source")
ALERT_SEVERITIES = ("High", "Critical")


# ---------- helpers ----------

def _normalize_value(threat_type, raw_value):
    """Check the value matches its type, and return it in a standard form."""
    if threat_type == "IP Address":
        return require_ip(raw_value, "threat_value")
    if threat_type == "Domain":
        return require_domain(raw_value)
    if threat_type == "File Hash":
        return require_file_hash(raw_value)
    return require_text(raw_value, "threat_value", 255)  # Malware Signature, Other


def _get_threat_or_404(threat_id):
    threat = db.session.get(Threat, threat_id)
    if threat is None:
        raise ApiError(f"Threat with id {threat_id} not found", 404)
    return threat


def _threat_dict(threat):
    data = threat.to_dict()
    if threat.threat_type == "File Hash":
        data["hash_algorithm"] = hash_algorithm(threat.threat_value)
    return data


def _alert_analysts(threat):
    """Send a Threat Alert to every active Security Analyst. Returns how many were alerted."""
    analysts = User.query.filter(User.role == ANALYST, User.account_status == "Active").all()
    for analyst in analysts:
        create_notification(
            user_id=analyst.user_id,
            title=f"New {threat.severity} threat indicator",
            message=f"{threat.threat_type} '{threat.threat_value}' was added to threat intelligence "
                    f"(threat id {threat.threat_id}, source: {threat.source}).",
            notification_type="Threat Alert",
            severity=threat.severity,
        )
    return len(analysts)


# ---------- 1. Add Threat Indicator ----------

@bp.post("")
@roles_required(ADMIN)
def add_threat():
    """
    Author: Anthony Feghali
    Add a threat indicator.
    Who can call it: Security Administrator.
    Body: threat_type, threat_value, description, severity, source
    """
    actor = g.current_user
    body = get_json_body(required=("threat_type", "threat_value", "description", "severity", "source"))
    threat_type = require_choice(body["threat_type"], "threat_type", THREAT_TYPES)
    threat_value = _normalize_value(threat_type, body["threat_value"])

    # Duplicates: checked here for a clear message, and also blocked by the
    # UNIQUE (threat_type, threat_value) constraint in the database.
    existing = Threat.query.filter_by(threat_type=threat_type, threat_value=threat_value).first()
    if existing:
        raise ApiError(
            f"This {threat_type} indicator already exists (threat id {existing.threat_id})", 409,
        )

    threat = Threat(
        threat_type=threat_type,
        threat_value=threat_value,
        description=require_text(body["description"], "description", 1000),
        severity=require_choice(body["severity"], "severity", THREAT_SEVERITIES),
        source=require_text(body["source"], "source", 100),
    )
    db.session.add(threat)
    db.session.commit()

    log_event(actor.user_id, "THREAT_ADDED",
              f"'{actor.username}' added {threat.severity} {threat.threat_type} threat "
              f"{threat.threat_id} '{threat.threat_value}'",
              "Warning" if threat.severity in ALERT_SEVERITIES else "Information", SERVICE)

    data = _threat_dict(threat)
    if threat.severity in ALERT_SEVERITIES:
        data["analysts_alerted"] = _alert_analysts(threat)
    return success("Threat indicator added successfully", data, 201)


# ---------- 2. Retrieve All Threat Indicators ----------

@bp.get("")
@roles_required(ADMIN, ANALYST, AUDITOR)
def get_all_threats():
    """
    Author: Anthony Feghali
    List every threat indicator, newest first.
    Who can call it: Security Administrator, Security Analyst, Auditor.
    """
    threats = Threat.query.order_by(Threat.date_added.desc(), Threat.threat_id.desc()).all()
    return success(f"{len(threats)} threat indicator(s) found", {
        "count": len(threats), "threats": [_threat_dict(threat) for threat in threats],
    })


# ---------- 3. Retrieve Specific Threat Indicator ----------

@bp.get("/<int:threat_id>")
@roles_required(ADMIN, ANALYST, AUDITOR)
def get_threat(threat_id):
    """
    Author: Anthony Feghali
    Get one threat indicator by id.
    Who can call it: Security Administrator, Security Analyst, Auditor.
    """
    return success("Threat indicator found", _threat_dict(_get_threat_or_404(threat_id)))


# ---------- 4. Search Threat Indicators ----------

@bp.get("/search")
@roles_required(ADMIN, ANALYST)
def search_threats():
    """
    Author: Anthony Feghali
    Search threat indicators. Filters can be combined; all must match.
    Who can call it: Security Administrator, Security Analyst.
    Query parameters:
        type      IP Address, Domain, File Hash, Malware Signature, Other
        value     part of the indicator value, any capitalization   e.g. ?value=185.220
        severity  Low, Medium, High, Critical
        source    part of the source name                           e.g. ?source=abuse
    """
    filters = {name: request.args.get(name, "").strip() for name in SEARCH_FILTERS}
    if not any(filters.values()):
        raise ApiError(f"Provide at least one search filter: {', '.join(SEARCH_FILTERS)}", 400)

    query = Threat.query
    if filters["type"]:
        query = query.filter(Threat.threat_type == require_choice(filters["type"], "threat type", THREAT_TYPES))
    if filters["value"]:
        query = query.filter(Threat.threat_value.ilike(f"%{filters['value']}%"))
    if filters["severity"]:
        query = query.filter(Threat.severity == require_choice(filters["severity"], "severity", THREAT_SEVERITIES))
    if filters["source"]:
        query = query.filter(Threat.source.ilike(f"%{filters['source']}%"))

    threats = query.order_by(Threat.date_added.desc(), Threat.threat_id.desc()).all()
    used_filters = {name: value for name, value in filters.items() if value}
    return success(f"{len(threats)} threat indicator(s) match the search", {
        "filters": used_filters, "count": len(threats), "threats": [_threat_dict(threat) for threat in threats],
    })


# ---------- 5. Update Threat Information ----------

@bp.put("/<int:threat_id>")
@roles_required(ADMIN)
def update_threat(threat_id):
    """
    Author: Anthony Feghali
    Update a threat's description, severity, or source.
    Who can call it: Security Administrator.
    The type and value identify the indicator, so they cannot be changed;
    delete the threat and add a new one instead.
    Body (at least one): description, severity, source
    """
    actor = g.current_user
    threat = _get_threat_or_404(threat_id)
    body = get_json_body(optional=("description", "severity", "source", "threat_type", "threat_value"))
    if "threat_type" in body or "threat_value" in body:
        raise ApiError(
            "Threat type and value cannot be changed. Delete this threat and add a new one instead", 400,
        )
    if not body:
        raise ApiError("Provide at least one field to update: description, severity, source", 400)

    changes = []
    if "description" in body:
        threat.description = require_text(body["description"], "description", 1000)
        changes.append("description")
    if "severity" in body:
        new_severity = require_choice(body["severity"], "severity", THREAT_SEVERITIES)
        if new_severity != threat.severity:
            changes.append(f"severity: {threat.severity} -> {new_severity}")
        threat.severity = new_severity
    if "source" in body:
        new_source = require_text(body["source"], "source", 100)
        if new_source != threat.source:
            changes.append(f"source: {threat.source} -> {new_source}")
        threat.source = new_source

    db.session.commit()
    db.session.refresh(threat)
    log_event(actor.user_id, "THREAT_UPDATED",
              f"'{actor.username}' updated threat {threat.threat_id}: {', '.join(changes) or 'no changes'}",
              "Information", SERVICE)
    return success("Threat indicator updated successfully", {"changes": changes, "threat": _threat_dict(threat)})


# ---------- 6. Delete Threat Indicator ----------

@bp.delete("/<int:threat_id>")
@roles_required(ADMIN)
def delete_threat(threat_id):
    """
    Author: Anthony Feghali
    Delete a threat indicator.
    Who can call it: Security Administrator only. Other roles get 403 and the attempt is logged.
    """
    actor = g.current_user
    threat = _get_threat_or_404(threat_id)
    summary = f"{threat.threat_type} threat {threat.threat_id} '{threat.threat_value}'"
    db.session.delete(threat)
    db.session.commit()

    log_event(actor.user_id, "THREAT_DELETED", f"'{actor.username}' deleted {summary}", "Warning", SERVICE)
    return success(f"Threat indicator {threat_id} deleted successfully")
