"""
Vulnerability Management Service: 6 endpoints.

    POST   /vulnerabilities           add a vulnerability
    GET    /vulnerabilities           list all vulnerabilities
    GET    /vulnerabilities/<id>      get one vulnerability
    PUT    /vulnerabilities/<id>      update description, severity, status, CVSS score, resolution date
    GET    /vulnerabilities/search    search by CVE, severity, asset, status
    DELETE /vulnerabilities/<id>      delete a vulnerability

When a High or Critical vulnerability is added, the affected asset's owner
gets a Vulnerability Alert notification (through the Notifications service).

Regular Employees have no access to this service.

Author: Anthony Feghali
"""
from datetime import datetime, time

from flask import Blueprint, g, request
from sqlalchemy.exc import IntegrityError

from app.common.auth import ADMIN, ANALYST, AUDITOR, roles_required
from app.common.errors import ApiError, success
from app.common.network_validation import require_cve, require_cvss, severity_for_cvss
from app.common.time_utils import utc_now
from app.common.validation import get_json_body, require_choice, require_date, require_int, require_text
from app.extensions import db
from app.services.assets.models import Asset
from app.services.logs.service import log_event
from app.services.notifications.service import create_notification
from app.services.vulnerabilities.models import (
    NEXT_STATUS, VULNERABILITY_SEVERITIES, VULNERABILITY_STATUSES, Vulnerability,
)

bp = Blueprint("vulnerabilities", __name__, url_prefix="/vulnerabilities")

SERVICE = "Vulnerabilities"
SEARCH_FILTERS = ("cve", "severity", "asset_id", "asset", "status")
ALERT_SEVERITIES = ("High", "Critical")


# ---------- helpers ----------

def _get_vulnerability_or_404(vulnerability_id):
    vulnerability = db.session.get(Vulnerability, vulnerability_id)
    if vulnerability is None:
        raise ApiError(f"Vulnerability with id {vulnerability_id} not found", 404)
    return vulnerability


def _check_severity_matches_score(severity, cvss_score):
    """The severity must agree with the official CVSS v3 band for the score."""
    expected = severity_for_cvss(cvss_score)
    if severity != expected:
        raise ApiError(
            f"Severity '{severity}' does not match CVSS score {cvss_score}, which is rated '{expected}' "
            "(Low 0.0-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0)", 400,
        )


def _vulnerability_list(vulnerabilities):
    return {
        "count": len(vulnerabilities),
        "vulnerabilities": [vulnerability.to_dict() for vulnerability in vulnerabilities],
    }


# ---------- 1. Add New Vulnerability ----------

@bp.post("")
@roles_required(ADMIN)
def add_vulnerability():
    """
    Author: Anthony Feghali
    Register a vulnerability found on an asset. New vulnerabilities start as Open.
    Who can call it: Security Administrator.
    Body: title, description, cve_id, cvss_score, severity, asset_id, discovery_source
    """
    actor = g.current_user
    body = get_json_body(required=(
        "title", "description", "cve_id", "cvss_score", "severity", "asset_id", "discovery_source",
    ))
    asset_id = require_int(body["asset_id"], "asset_id")
    asset = db.session.get(Asset, asset_id)
    if asset is None:
        raise ApiError(f"Affected asset with id {asset_id} not found", 404)

    cve_id = require_cve(body["cve_id"])
    cvss_score = require_cvss(body["cvss_score"])
    severity = require_choice(body["severity"], "severity", VULNERABILITY_SEVERITIES)
    _check_severity_matches_score(severity, cvss_score)

    if Vulnerability.query.filter_by(cve_id=cve_id, asset_id=asset_id).first():
        raise ApiError(f"{cve_id} is already registered for asset {asset_id}", 409)

    vulnerability = Vulnerability(
        title=require_text(body["title"], "title", 150),
        description=require_text(body["description"], "description", 2000),
        cve_id=cve_id,
        cvss_score=cvss_score,
        severity=severity,
        asset_id=asset_id,
        discovery_source=require_text(body["discovery_source"], "discovery_source", 100),
        status="Open",
    )
    db.session.add(vulnerability)
    db.session.commit()

    log_event(actor.user_id, "VULNERABILITY_ADDED",
              f"'{actor.username}' added {severity} vulnerability {vulnerability.vulnerability_id} "
              f"({cve_id}, CVSS {cvss_score}) on asset {asset_id} '{asset.asset_name}'",
              "Warning" if severity in ALERT_SEVERITIES else "Information", SERVICE)

    data = vulnerability.to_dict()
    if severity in ALERT_SEVERITIES:
        create_notification(
            user_id=asset.owner_id,
            title=f"{severity} vulnerability on {asset.asset_name}",
            message=f"{cve_id} (CVSS {cvss_score}) was found on your asset '{asset.asset_name}' "
                    f"({asset.ip_address}). Vulnerability id {vulnerability.vulnerability_id}.",
            notification_type="Vulnerability Alert",
            severity=severity,
        )
        data["owner_alerted"] = asset.owner_id
    return success("Vulnerability added successfully", data, 201)


# ---------- 2. Retrieve All Vulnerabilities ----------

@bp.get("")
@roles_required(ADMIN, ANALYST, AUDITOR)
def get_all_vulnerabilities():
    """
    Author: Anthony Feghali
    List every vulnerability with its severity, affected asset, and status.
    Who can call it: Security Administrator, Security Analyst, Auditor.
    """
    vulnerabilities = Vulnerability.query.order_by(Vulnerability.vulnerability_id).all()
    return success(f"{len(vulnerabilities)} vulnerability record(s) found", _vulnerability_list(vulnerabilities))


# ---------- 3. Retrieve Specific Vulnerability ----------

@bp.get("/<int:vulnerability_id>")
@roles_required(ADMIN, ANALYST, AUDITOR)
def get_vulnerability(vulnerability_id):
    """
    Author: Anthony Feghali
    Get one vulnerability by id, including the next allowed status.
    Who can call it: Security Administrator, Security Analyst, Auditor.
    """
    vulnerability = _get_vulnerability_or_404(vulnerability_id)
    data = vulnerability.to_dict()
    data["next_allowed_status"] = NEXT_STATUS[vulnerability.status]
    return success("Vulnerability found", data)


# ---------- 4. Update Vulnerability Information ----------

@bp.put("/<int:vulnerability_id>")
@roles_required(ADMIN, ANALYST)
def update_vulnerability(vulnerability_id):
    """
    Author: Anthony Feghali
    Update a vulnerability.
    Who can call it: Security Administrator, Security Analyst.
    Body (at least one): description, severity, status, cvss_score, resolution_date (YYYY-MM-DD)
    Rules:
      - status may only move one step forward:
        Open -> Under Investigation -> In Progress -> Resolved -> Closed
      - moving to Resolved fills resolution_date with today if none is given
      - severity must still match the CVSS score afterwards
      - resolution_date is only allowed once the status is Resolved or Closed
    """
    actor = g.current_user
    vulnerability = _get_vulnerability_or_404(vulnerability_id)
    body = get_json_body(optional=("description", "severity", "status", "cvss_score", "resolution_date"))
    if not body:
        raise ApiError(
            "Provide at least one field to update: description, severity, status, cvss_score, resolution_date",
            400,
        )

    changes = []
    old_status = vulnerability.status

    if "description" in body:
        vulnerability.description = require_text(body["description"], "description", 2000)
        changes.append("description")

    new_score = require_cvss(body["cvss_score"]) if "cvss_score" in body else vulnerability.cvss_score
    new_severity = (
        require_choice(body["severity"], "severity", VULNERABILITY_SEVERITIES)
        if "severity" in body else vulnerability.severity
    )
    if new_score != vulnerability.cvss_score or new_severity != vulnerability.severity:
        _check_severity_matches_score(new_severity, new_score)
        if new_score != vulnerability.cvss_score:
            changes.append(f"cvss_score: {vulnerability.cvss_score} -> {new_score}")
        if new_severity != vulnerability.severity:
            changes.append(f"severity: {vulnerability.severity} -> {new_severity}")
        vulnerability.cvss_score = new_score
        vulnerability.severity = new_severity

    if "status" in body:
        new_status = require_choice(body["status"], "status", VULNERABILITY_STATUSES)
        allowed_next = NEXT_STATUS[old_status]
        if new_status == old_status:
            raise ApiError(f"Vulnerability is already '{old_status}'", 400)
        if new_status != allowed_next:
            if allowed_next is None:
                message = f"Invalid status transition: '{old_status}' is final and cannot change"
            else:
                message = (
                    f"Invalid status transition from '{old_status}' to '{new_status}'. "
                    f"The next allowed status is '{allowed_next}'"
                )
            raise ApiError(message, 400)
        vulnerability.status = new_status
        changes.append(f"status: {old_status} -> {new_status}")
        if new_status == "Resolved" and "resolution_date" not in body:
            vulnerability.resolution_date = utc_now()

    if "resolution_date" in body:
        if vulnerability.status not in ("Resolved", "Closed"):
            raise ApiError("A resolution date can only be set once the status is Resolved or Closed", 400)
        resolution_day = require_date(body["resolution_date"], "resolution_date")
        if resolution_day < vulnerability.created_date.date():
            raise ApiError("The resolution date cannot be earlier than the date the vulnerability was added", 400)
        if resolution_day > utc_now().date():
            raise ApiError("The resolution date cannot be in the future", 400)
        vulnerability.resolution_date = datetime.combine(resolution_day, time())
        changes.append(f"resolution_date: {resolution_day.isoformat()}")

    db.session.commit()
    db.session.refresh(vulnerability)

    log_event(actor.user_id, "VULNERABILITY_UPDATED",
              f"'{actor.username}' updated vulnerability {vulnerability.vulnerability_id} "
              f"({vulnerability.cve_id}): {'; '.join(changes)}",
              "Information", SERVICE)

    data = vulnerability.to_dict()
    data["next_allowed_status"] = NEXT_STATUS[vulnerability.status]
    return success("Vulnerability updated successfully", {"changes": changes, "vulnerability": data})


# ---------- 5. Search Vulnerabilities ----------

@bp.get("/search")
@roles_required(ADMIN, ANALYST, AUDITOR)
def search_vulnerabilities():
    """
    Author: Anthony Feghali
    Search vulnerabilities. Filters can be combined; all must match.
    Who can call it: Security Administrator, Security Analyst, Auditor.
    Query parameters:
        cve       part of the CVE identifier          e.g. ?cve=2024
        severity  Low, Medium, High, Critical
        asset_id  exact affected asset id             e.g. ?asset_id=1
        asset     part of the affected asset's name   e.g. ?asset=payroll
        status    Open, Under Investigation, In Progress, Resolved, Closed
    """
    filters = {name: request.args.get(name, "").strip() for name in SEARCH_FILTERS}
    if not any(filters.values()):
        raise ApiError(f"Provide at least one search filter: {', '.join(SEARCH_FILTERS)}", 400)

    query = Vulnerability.query.join(Asset, Vulnerability.asset_id == Asset.asset_id)
    if filters["cve"]:
        query = query.filter(Vulnerability.cve_id.ilike(f"%{filters['cve']}%"))
    if filters["severity"]:
        query = query.filter(Vulnerability.severity == require_choice(
            filters["severity"], "severity", VULNERABILITY_SEVERITIES))
    if filters["asset_id"]:
        query = query.filter(Vulnerability.asset_id == require_int(filters["asset_id"], "asset_id"))
    if filters["asset"]:
        query = query.filter(Asset.asset_name.ilike(f"%{filters['asset']}%"))
    if filters["status"]:
        query = query.filter(Vulnerability.status == require_choice(
            filters["status"], "status", VULNERABILITY_STATUSES))

    vulnerabilities = query.order_by(Vulnerability.vulnerability_id).all()
    used_filters = {name: value for name, value in filters.items() if value}
    return success(f"{len(vulnerabilities)} vulnerability record(s) match the search", {
        "filters": used_filters, **_vulnerability_list(vulnerabilities),
    })


# ---------- 6. Delete Vulnerability ----------

@bp.delete("/<int:vulnerability_id>")
@roles_required(ADMIN)
def delete_vulnerability(vulnerability_id):
    """
    Author: Anthony Feghali
    Delete a vulnerability record.
    Who can call it: Security Administrator only. Other roles get 403 and the attempt is logged.
    """
    actor = g.current_user
    vulnerability = _get_vulnerability_or_404(vulnerability_id)
    summary = f"vulnerability {vulnerability.vulnerability_id} ({vulnerability.cve_id}) on asset {vulnerability.asset_id}"
    db.session.delete(vulnerability)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise ApiError("This vulnerability is still linked to other records", 409)

    log_event(actor.user_id, "VULNERABILITY_DELETED", f"'{actor.username}' deleted {summary}", "Warning", SERVICE)
    return success(f"Vulnerability {vulnerability_id} deleted successfully")
