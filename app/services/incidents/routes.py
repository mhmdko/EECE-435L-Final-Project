"""
Incident Management Service: 6 endpoints.

    POST /incidents                 report an incident
    GET  /incidents                 list all incidents
    GET  /incidents/<id>            get one incident with its notes and recommended playbook
    PUT  /incidents/<id>/assign     assign an incident to a Security Analyst
    PUT  /incidents/<id>/status     move an incident to its next status
    POST /incidents/<id>/notes      add an investigation note

How it works with other services:
- Users:          reporters and analysts are users; assignment checks the Security Analyst role
- Assets:         every incident names the affected asset, which must exist
- Notifications:  High/Critical incidents alert administrators; assignment alerts the analyst;
                  resolving an incident tells the reporter
- Audit Logging:  creation, assignment, status changes, and notes are all logged
- Playbooks:      GET /incidents/<id> suggests the playbook for the same category and severity

Author: Titia Saikali
"""
from flask import Blueprint, g

from app.common.auth import ADMIN, ANALYST, AUDITOR, EMPLOYEE, reject_forbidden, roles_required
from app.common.errors import ApiError, success
from app.common.time_utils import utc_now
from app.common.validation import get_json_body, require_choice, require_int, require_text
from app.extensions import db
from app.services.assets.models import Asset
from app.services.incidents.models import (
    INCIDENT_CATEGORIES, INCIDENT_SEVERITIES, INCIDENT_STATUSES, NEXT_STATUS, Incident, InvestigationNote,
)
from app.services.logs.service import log_event
from app.services.notifications.service import create_notification
from app.services.users.models import User

bp = Blueprint("incidents", __name__, url_prefix="/incidents")

SERVICE = "Incidents"
ALERT_SEVERITIES = ("High", "Critical")


# ---------- helpers ----------

def _get_incident_or_404(incident_id):
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        raise ApiError(f"Incident with id {incident_id} not found", 404)
    return incident


def _require_assigned_analyst(actor, incident, action):
    """Analysts may only work on incidents assigned to them. Administrators may work on any."""
    if actor.role == ANALYST and incident.assigned_analyst_id != actor.user_id:
        reject_forbidden(actor, f"You can only {action} incidents assigned to you")


def _recommended_playbook(incident):
    from app.services.playbooks.models import Playbook  # avoid a circular import

    playbook = Playbook.query.filter_by(incident_category=incident.category, severity=incident.severity).first()
    if playbook is None:
        return None
    return {"playbook_id": playbook.playbook_id, "name": playbook.name, "total_actions": len(playbook.actions)}


def _alert_administrators(incident):
    administrators = User.query.filter(User.role == ADMIN, User.account_status == "Active").all()
    for administrator in administrators:
        create_notification(
            user_id=administrator.user_id,
            title=f"New {incident.severity} incident reported",
            message=f"Incident {incident.incident_id} '{incident.title}' ({incident.category}) "
                    f"was reported by {incident.reporter.username} and needs an analyst.",
            notification_type="Security Alert",
            severity=incident.severity,
        )
    return len(administrators)


# ---------- 1. Create Incident ----------

@bp.post("")
@roles_required(ADMIN, EMPLOYEE)
def create_incident():
    """
    Author: Titia Saikali
    Report a cybersecurity incident. New incidents start as Open.
    Who can call it: Security Administrator, Regular Employee.
    The reporter is the logged-in user; an administrator may report on behalf of
    someone else by giving reporter_id.
    Body: title, description, category, severity, affected_asset_id (required); reporter_id (optional, admin only)
    """
    actor = g.current_user
    body = get_json_body(
        required=("title", "description", "category", "severity", "affected_asset_id"),
        optional=("reporter_id",),
    )

    reporter = actor
    if body.get("reporter_id") is not None:
        if actor.role != ADMIN:
            reject_forbidden(actor, "Only a Security Administrator can report an incident on behalf of another user")
        reporter_id = require_int(body["reporter_id"], "reporter_id")
        reporter = db.session.get(User, reporter_id)
        if reporter is None:
            raise ApiError(f"Reporter user with id {reporter_id} not found", 404)

    asset_id = require_int(body["affected_asset_id"], "affected_asset_id")
    if db.session.get(Asset, asset_id) is None:
        raise ApiError(f"Affected asset with id {asset_id} not found", 404)

    incident = Incident(
        title=require_text(body["title"], "title", 150),
        description=require_text(body["description"], "description", 2000),
        category=require_choice(body["category"], "category", INCIDENT_CATEGORIES),
        severity=require_choice(body["severity"], "severity", INCIDENT_SEVERITIES),
        reporter_id=reporter.user_id,
        affected_asset_id=asset_id,
        status="Open",
    )
    db.session.add(incident)
    db.session.commit()

    log_event(actor.user_id, "INCIDENT_CREATED",
              f"'{actor.username}' reported {incident.severity} {incident.category} incident "
              f"{incident.incident_id} '{incident.title}' on asset {asset_id}",
              "Warning" if incident.severity in ALERT_SEVERITIES else "Information", SERVICE)

    data = incident.to_dict()
    if incident.severity in ALERT_SEVERITIES:
        data["administrators_alerted"] = _alert_administrators(incident)
    return success("Incident reported successfully", data, 201)


# ---------- 2. Retrieve All Incidents ----------

@bp.get("")
@roles_required(ADMIN, AUDITOR)
def get_all_incidents():
    """
    Author: Titia Saikali
    List every incident with its current status and assigned analyst, newest first.
    Who can call it: Security Administrator, Auditor.
    """
    incidents = Incident.query.order_by(Incident.created_date.desc(), Incident.incident_id.desc()).all()
    return success(f"{len(incidents)} incident(s) found", {
        "count": len(incidents), "incidents": [incident.to_dict() for incident in incidents],
    })


# ---------- 3. Retrieve Specific Incident ----------

@bp.get("/<int:incident_id>")
@roles_required(ADMIN, ANALYST, EMPLOYEE, AUDITOR)
def get_incident(incident_id):
    """
    Author: Titia Saikali
    Get complete information about one incident: its investigation notes, the next
    allowed status, and the recommended response playbook.
    Who can call it: Security Administrator, Security Analyst, Auditor,
    Regular Employee (only incidents they reported).
    """
    actor = g.current_user
    incident = _get_incident_or_404(incident_id)
    if actor.role == EMPLOYEE and incident.reporter_id != actor.user_id:
        reject_forbidden(actor, "You can only view incidents you reported")

    data = incident.to_dict(include_notes=True)
    data["next_allowed_status"] = NEXT_STATUS[incident.status]
    data["recommended_playbook"] = _recommended_playbook(incident)
    return success("Incident found", data)


# ---------- 4. Assign Incident to Analyst ----------

@bp.put("/<int:incident_id>/assign")
@roles_required(ADMIN)
def assign_incident(incident_id):
    """
    Author: Titia Saikali
    Assign (or reassign) an incident to a Security Analyst.
    Who can call it: Security Administrator only.
    Checks: the incident exists and is not Resolved or Closed; the user exists, is Active,
    and has the Security Analyst role. The assignment is recorded in the audit log and
    the analyst receives an Incident Assignment notification.
    Body: analyst_id
    """
    actor = g.current_user
    incident = _get_incident_or_404(incident_id)
    body = get_json_body(required=("analyst_id",))
    analyst_id = require_int(body["analyst_id"], "analyst_id")

    if incident.status in ("Resolved", "Closed"):
        raise ApiError(f"Incident {incident_id} is {incident.status} and can no longer be assigned", 400)

    analyst = db.session.get(User, analyst_id)
    if analyst is None:
        raise ApiError(f"User with id {analyst_id} not found", 404)
    if analyst.role != ANALYST:
        raise ApiError(
            f"User '{analyst.username}' is a {analyst.role}. Incidents can only be assigned to a Security Analyst", 400,
        )
    if analyst.account_status != "Active":
        raise ApiError(f"Analyst '{analyst.username}' is {analyst.account_status} and cannot be assigned", 400)
    if incident.assigned_analyst_id == analyst.user_id:
        return success(f"Incident is already assigned to '{analyst.username}'", incident.to_dict())

    previous = incident.assigned_analyst.username if incident.assigned_analyst else None
    incident.assigned_analyst_id = analyst.user_id
    db.session.commit()
    db.session.refresh(incident)

    change = f"from '{previous}' to '{analyst.username}'" if previous else f"to '{analyst.username}'"
    log_event(actor.user_id, "INCIDENT_ASSIGNED",
              f"'{actor.username}' assigned incident {incident.incident_id} '{incident.title}' {change}",
              "Information", SERVICE)
    create_notification(
        user_id=analyst.user_id,
        title="Incident assigned to you",
        message=f"Incident {incident.incident_id} '{incident.title}' ({incident.severity}, {incident.category}) "
                f"was assigned to you by {actor.username}.",
        notification_type="Incident Assignment",
        severity=incident.severity,
    )
    data = incident.to_dict()
    data["analyst_notified"] = analyst.user_id
    return success(f"Incident assigned to '{analyst.username}'", data)


# ---------- 5. Update Incident Status ----------

@bp.put("/<int:incident_id>/status")
@roles_required(ADMIN, ANALYST)
def update_incident_status(incident_id):
    """
    Author: Titia Saikali
    Move an incident to its next status.
    Who can call it: Security Administrator (any incident), Security Analyst (incidents assigned to them).
    Rules:
      - Open -> Under Investigation -> Mitigated -> Resolved -> Closed, one step at a time
      - an incident needs an assigned analyst before investigation can start
      - moving to Resolved records the resolution date and notifies the reporter
    Body: status
    """
    actor = g.current_user
    incident = _get_incident_or_404(incident_id)
    _require_assigned_analyst(actor, incident, "update the status of")

    body = get_json_body(required=("status",))
    new_status = require_choice(body["status"], "status", INCIDENT_STATUSES)
    old_status = incident.status
    allowed_next = NEXT_STATUS[old_status]

    if new_status == old_status:
        raise ApiError(f"Incident is already '{old_status}'", 400)
    if new_status != allowed_next:
        if allowed_next is None:
            raise ApiError(f"Invalid status transition: '{old_status}' is final and cannot change", 400)
        raise ApiError(
            f"Invalid status transition from '{old_status}' to '{new_status}'. "
            f"The next allowed status is '{allowed_next}'", 400,
        )
    if new_status == "Under Investigation" and incident.assigned_analyst_id is None:
        raise ApiError("Assign a Security Analyst before starting the investigation", 400)

    incident.status = new_status
    if new_status == "Resolved":
        incident.resolution_date = utc_now()
    db.session.commit()
    db.session.refresh(incident)

    log_event(actor.user_id, "INCIDENT_STATUS_CHANGED",
              f"'{actor.username}' moved incident {incident.incident_id} from {old_status} to {new_status}",
              "Information", SERVICE)
    if new_status == "Resolved":
        create_notification(
            user_id=incident.reporter_id,
            title="Your incident was resolved",
            message=f"Incident {incident.incident_id} '{incident.title}' that you reported has been resolved.",
            notification_type="System Notification",
            severity="Low",
        )

    data = incident.to_dict()
    data["next_allowed_status"] = NEXT_STATUS[incident.status]
    return success(f"Incident status changed from '{old_status}' to '{new_status}'", data)


# ---------- 6. Add Investigation Notes ----------

@bp.post("/<int:incident_id>/notes")
@roles_required(ADMIN, ANALYST)
def add_investigation_note(incident_id):
    """
    Author: Titia Saikali
    Add an investigation note (analysis performed, evidence collected, actions taken).
    Who can call it: Security Administrator (any incident), Security Analyst (incidents assigned to them).
    Notes cannot be added to Closed incidents. Each note belongs to exactly one incident.
    Body: note_content
    """
    actor = g.current_user
    incident = _get_incident_or_404(incident_id)
    _require_assigned_analyst(actor, incident, "add notes to")
    if incident.status == "Closed":
        raise ApiError("Notes cannot be added to a Closed incident", 400)

    body = get_json_body(required=("note_content",))
    note = InvestigationNote(
        incident_id=incident.incident_id,
        analyst_id=actor.user_id,
        note_content=require_text(body["note_content"], "note_content", 4000),
    )
    db.session.add(note)
    db.session.commit()
    db.session.refresh(incident)

    log_event(actor.user_id, "INVESTIGATION_NOTE_ADDED",
              f"'{actor.username}' added note {note.note_id} to incident {incident.incident_id}",
              "Information", SERVICE)
    return success("Investigation note added successfully", {
        "note": note.to_dict(), "incident_id": incident.incident_id, "notes_count": len(incident.notes),
    }, 201)
