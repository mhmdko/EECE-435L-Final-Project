"""
Security Reports Service: 6 endpoints.

    GET /reports/summary           overview of the whole system
    GET /reports/incidents         incident statistics
    GET /reports/assets            asset statistics
    GET /reports/threats           threat intelligence statistics
    GET /reports/vulnerabilities   vulnerability statistics
    GET /reports/activity          audit log activity statistics (optional ?days=N)

This service has no table of its own. Each report reads live data from the other
services' tables through their models (Users, Assets, Incidents, Threats,
Vulnerabilities, Logs, Playbooks), counts it with SQL GROUP BY queries, and
returns the totals. Every category is always listed, with 0 when empty, so
reports are easy to compare.

Who can call it: Security Administrator and Auditor only.

Author: Titia Saikali
"""
from datetime import timedelta

from flask import Blueprint, g, request
from sqlalchemy import func

from app.common.auth import ADMIN, AUDITOR, roles_required
from app.common.errors import ApiError, success
from app.common.time_utils import to_text, utc_now
from app.extensions import db
from app.services.assets.models import ASSET_CRITICALITIES, ASSET_STATUSES, ASSET_TYPES, Asset
from app.services.incidents.models import INCIDENT_CATEGORIES, INCIDENT_SEVERITIES, INCIDENT_STATUSES, Incident
from app.services.logs.models import LOG_SEVERITIES, Log
from app.services.logs.service import log_event
from app.services.playbooks.models import Playbook
from app.services.threats.models import THREAT_SEVERITIES, THREAT_TYPES, Threat
from app.services.users.models import User
from app.services.vulnerabilities.models import VULNERABILITY_SEVERITIES, VULNERABILITY_STATUSES, Vulnerability

bp = Blueprint("reports", __name__, url_prefix="/reports")

SERVICE = "Reports"
UNRESOLVED_INCIDENT_STATUSES = ("Open", "Under Investigation", "Mitigated")


# ---------- helpers ----------

def _count_by(column, all_values):
    """Count rows per value with GROUP BY, listing every allowed value (0 if none)."""
    counts = dict(db.session.query(column, func.count()).group_by(column).all())
    return {value: counts.get(value, 0) for value in all_values}


def _report(name, data):
    """Add who generated the report and when, log it, and return the response."""
    actor = g.current_user
    report = {
        "report": name,
        "generated_at": to_text(utc_now()),
        "generated_by": actor.username,
        **data,
    }
    log_event(actor.user_id, "REPORT_GENERATED", f"'{actor.username}' generated the {name} report",
              "Information", SERVICE)
    return success(f"{name.capitalize()} report generated", report)


# ---------- 1. Security Summary Report ----------

@bp.get("/summary")
@roles_required(ADMIN, AUDITOR)
def summary_report():
    """
    Author: Titia Saikali
    Overview of the current security status, gathered from every service.
    Who can call it: Security Administrator, Auditor.
    """
    return _report("security summary", {
        "users": User.query.count(),
        "active_users": User.query.filter_by(account_status="Active").count(),
        "assets": Asset.query.count(),
        "critical_assets": Asset.query.filter_by(criticality="Critical").count(),
        "incidents": Incident.query.count(),
        "open_incidents": Incident.query.filter(Incident.status.in_(UNRESOLVED_INCIDENT_STATUSES)).count(),
        "critical_open_incidents": Incident.query.filter(
            Incident.status.in_(UNRESOLVED_INCIDENT_STATUSES), Incident.severity == "Critical").count(),
        "unassigned_incidents": Incident.query.filter(
            Incident.status.in_(UNRESOLVED_INCIDENT_STATUSES), Incident.assigned_analyst_id.is_(None)).count(),
        "threats": Threat.query.count(),
        "critical_threats": Threat.query.filter_by(severity="Critical").count(),
        "open_vulnerabilities": Vulnerability.query.filter(
            Vulnerability.status.notin_(("Resolved", "Closed"))).count(),
        "playbooks": Playbook.query.count(),
        "security_events_last_24h": Log.query.filter(Log.timestamp >= utc_now() - timedelta(hours=24)).count(),
    })


# ---------- 2. Incident Report ----------

@bp.get("/incidents")
@roles_required(ADMIN, AUDITOR)
def incident_report():
    """
    Author: Titia Saikali
    Incident statistics from the Incident Management Service.
    Who can call it: Security Administrator, Auditor.
    """
    recent = Incident.query.order_by(Incident.created_date.desc(), Incident.incident_id.desc()).limit(5).all()
    return _report("incident", {
        "total_incidents": Incident.query.count(),
        "by_severity": _count_by(Incident.severity, INCIDENT_SEVERITIES),
        "by_status": _count_by(Incident.status, INCIDENT_STATUSES),
        "by_category": _count_by(Incident.category, INCIDENT_CATEGORIES),
        "unassigned_open_incidents": Incident.query.filter(
            Incident.status.in_(UNRESOLVED_INCIDENT_STATUSES), Incident.assigned_analyst_id.is_(None)).count(),
        "recent_incidents": [
            {"incident_id": incident.incident_id, "title": incident.title, "severity": incident.severity,
             "status": incident.status, "created_date": to_text(incident.created_date)}
            for incident in recent
        ],
    })


# ---------- 3. Asset Report ----------

@bp.get("/assets")
@roles_required(ADMIN, AUDITOR)
def asset_report():
    """
    Author: Titia Saikali
    Asset statistics from the Asset Management Service, plus which critical assets
    still have unresolved incidents or vulnerabilities.
    Who can call it: Security Administrator, Auditor.
    """
    critical_assets = Asset.query.filter_by(criticality="Critical").order_by(Asset.asset_id).all()
    critical_details = []
    for asset in critical_assets:
        critical_details.append({
            "asset_id": asset.asset_id,
            "asset_name": asset.asset_name,
            "status": asset.status,
            "open_incidents": Incident.query.filter(
                Incident.affected_asset_id == asset.asset_id,
                Incident.status.in_(UNRESOLVED_INCIDENT_STATUSES)).count(),
            "open_vulnerabilities": Vulnerability.query.filter(
                Vulnerability.asset_id == asset.asset_id,
                Vulnerability.status.notin_(("Resolved", "Closed"))).count(),
        })
    return _report("asset", {
        "total_assets": Asset.query.count(),
        "critical_assets": len(critical_assets),
        "by_type": _count_by(Asset.asset_type, ASSET_TYPES),
        "by_criticality": _count_by(Asset.criticality, ASSET_CRITICALITIES),
        "by_status": _count_by(Asset.status, ASSET_STATUSES),
        "critical_asset_details": critical_details,
    })


# ---------- 4. Threat Report ----------

@bp.get("/threats")
@roles_required(ADMIN, AUDITOR)
def threat_report():
    """
    Author: Titia Saikali
    Threat intelligence statistics from the Threat Intelligence Service.
    Who can call it: Security Administrator, Auditor.
    """
    recent = Threat.query.order_by(Threat.date_added.desc(), Threat.threat_id.desc()).limit(5).all()
    return _report("threat", {
        "total_threats": Threat.query.count(),
        "by_severity": _count_by(Threat.severity, THREAT_SEVERITIES),
        "by_type": _count_by(Threat.threat_type, THREAT_TYPES),
        "recent_threats": [
            {"threat_id": threat.threat_id, "threat_type": threat.threat_type, "threat_value": threat.threat_value,
             "severity": threat.severity, "date_added": to_text(threat.date_added)}
            for threat in recent
        ],
    })


# ---------- 5. Vulnerability Report ----------

@bp.get("/vulnerabilities")
@roles_required(ADMIN, AUDITOR)
def vulnerability_report():
    """
    Author: Titia Saikali
    Vulnerability statistics from the Vulnerability Management Service.
    Who can call it: Security Administrator, Auditor.
    """
    critical = (
        Vulnerability.query.filter_by(severity="Critical")
        .order_by(Vulnerability.cvss_score.desc(), Vulnerability.vulnerability_id).all()
    )
    average_score = db.session.query(func.avg(Vulnerability.cvss_score)).scalar()
    return _report("vulnerability", {
        "total_vulnerabilities": Vulnerability.query.count(),
        "by_severity": _count_by(Vulnerability.severity, VULNERABILITY_SEVERITIES),
        "by_status": _count_by(Vulnerability.status, VULNERABILITY_STATUSES),
        "average_cvss_score": round(average_score, 1) if average_score is not None else None,
        "critical_vulnerabilities": [
            {"vulnerability_id": vulnerability.vulnerability_id, "cve_id": vulnerability.cve_id,
             "title": vulnerability.title, "cvss_score": vulnerability.cvss_score, "status": vulnerability.status,
             "asset_name": vulnerability.asset.asset_name if vulnerability.asset else None}
            for vulnerability in critical
        ],
    })


# ---------- 6. Activity Report ----------

@bp.get("/activity")
@roles_required(ADMIN, AUDITOR)
def activity_report():
    """
    Author: Titia Saikali
    Security activity statistics, calculated from the audit logs.
    Who can call it: Security Administrator, Auditor.
    Optional query parameter: days (1 to 365) to only count the last N days, e.g. ?days=7
    """
    days_text = request.args.get("days", "").strip()
    query = Log.query
    period = "all time"
    if days_text:
        if not days_text.isdigit() or not 1 <= int(days_text) <= 365:
            raise ApiError("'days' must be a whole number from 1 to 365", 400)
        since = utc_now() - timedelta(days=int(days_text))
        query = query.filter(Log.timestamp >= since)
        period = f"last {int(days_text)} day(s)"

    filtered_logs = query.subquery()
    action_column = filtered_logs.c.action

    def count_action(action_name):
        return db.session.query(func.count()).select_from(filtered_logs).filter(action_column == action_name).scalar()

    top_actions = (
        db.session.query(action_column, func.count().label("total"))
        .group_by(action_column).order_by(func.count().desc(), action_column).limit(5).all()
    )
    top_users = (
        db.session.query(User.username, func.count().label("total"))
        .select_from(filtered_logs).join(User, User.user_id == filtered_logs.c.user_id)
        .group_by(User.username).order_by(func.count().desc(), User.username).limit(5).all()
    )
    successful_logins = count_action("LOGIN_SUCCESS")
    failed_logins = count_action("LOGIN_FAILED")

    return _report("activity", {
        "period": period,
        "total_activities": db.session.query(func.count()).select_from(filtered_logs).scalar(),
        "login_attempts": successful_logins + failed_logins,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "unauthorized_access_attempts": count_action("UNAUTHORIZED_ACCESS"),
        "by_severity": {
            severity: db.session.query(func.count()).select_from(filtered_logs)
            .filter(filtered_logs.c.severity == severity).scalar()
            for severity in LOG_SEVERITIES
        },
        "most_performed_actions": [{"action": action, "count": total} for action, total in top_actions],
        "most_active_users": [{"username": username, "count": total} for username, total in top_users],
    })
