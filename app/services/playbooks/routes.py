"""
Security Playbook and Response Automation Service: 6 endpoints.

    POST   /playbooks                 create a response playbook
    GET    /playbooks                 list all playbooks (optional ?category= and ?severity=)
    GET    /playbooks/<id>            get one playbook with its ordered actions and their history
    POST   /playbooks/<id>/actions    add a response action (a numbered step)
    PUT    /actions/<id>/status       update an action's status, assigned user, or completion date
    DELETE /playbooks/<id>            delete a playbook (and its actions)

Regular Employees have no access to this service.

Author: Titia Saikali
"""
from datetime import datetime, time

from flask import Blueprint, g, request
from sqlalchemy import func

from app.common.auth import ADMIN, ANALYST, AUDITOR, reject_forbidden, roles_required
from app.common.errors import ApiError, success
from app.common.time_utils import utc_now
from app.common.validation import get_json_body, require_choice, require_date, require_int, require_text
from app.extensions import db
from app.services.incidents.models import INCIDENT_CATEGORIES
from app.services.logs.service import log_event
from app.services.notifications.service import create_notification
from app.services.playbooks.models import (
    ACTION_STATUSES, NEXT_ACTION_STATUS, PLAYBOOK_SEVERITIES, ActionHistory, Playbook, ResponseAction,
)
from app.services.users.models import User

# No url_prefix: this service owns both /playbooks/... and /actions/... routes.
bp = Blueprint("playbooks", __name__)

SERVICE = "Playbooks"
RESPONDER_ROLES = (ADMIN, ANALYST)


# ---------- helpers ----------

def _get_playbook_or_404(playbook_id):
    playbook = db.session.get(Playbook, playbook_id)
    if playbook is None:
        raise ApiError(f"Playbook with id {playbook_id} not found", 404)
    return playbook


def _get_action_or_404(action_id):
    action = db.session.get(ResponseAction, action_id)
    if action is None:
        raise ApiError(f"Response action with id {action_id} not found", 404)
    return action


def _require_responder(user_id_value):
    """Actions can only be assigned to an Active Security Analyst or Security Administrator."""
    user_id = require_int(user_id_value, "assigned_user_id")
    user = db.session.get(User, user_id)
    if user is None:
        raise ApiError(f"User with id {user_id} not found", 404)
    if user.role not in RESPONDER_ROLES:
        raise ApiError(
            f"User '{user.username}' is a {user.role}. Response actions can only be assigned "
            "to a Security Analyst or Security Administrator", 400,
        )
    if user.account_status != "Active":
        raise ApiError(f"User '{user.username}' is {user.account_status} and cannot be assigned", 400)
    return user


def _notify_assignee(user, action, actor):
    if user.user_id == actor.user_id:
        return
    create_notification(
        user_id=user.user_id,
        title="Response action assigned to you",
        message=f"Step {action.step_number} of playbook {action.playbook_id} "
                f"('{action.action_description}') was assigned to you by {actor.username}.",
        notification_type="System Notification",
        severity="Medium",
    )


# ---------- 1. Create Response Playbook ----------

@bp.post("/playbooks")
@roles_required(ADMIN)
def create_playbook():
    """
    Author: Titia Saikali
    Create a response playbook for one incident category and severity.
    Who can call it: Security Administrator.
    There can be only one playbook per (incident_category, severity) pair.
    Body: name, description, incident_category, severity
    """
    actor = g.current_user
    body = get_json_body(required=("name", "description", "incident_category", "severity"))
    category = require_choice(body["incident_category"], "incident_category", INCIDENT_CATEGORIES)
    severity = require_choice(body["severity"], "severity", PLAYBOOK_SEVERITIES)

    existing = Playbook.query.filter_by(incident_category=category, severity=severity).first()
    if existing:
        raise ApiError(
            f"A playbook for {category} incidents of {severity} severity already exists "
            f"(playbook id {existing.playbook_id})", 409,
        )

    playbook = Playbook(
        name=require_text(body["name"], "name", 150),
        description=require_text(body["description"], "description", 2000),
        incident_category=category,
        severity=severity,
        created_by=actor.user_id,
    )
    db.session.add(playbook)
    db.session.commit()

    log_event(actor.user_id, "PLAYBOOK_CREATED",
              f"'{actor.username}' created playbook {playbook.playbook_id} '{playbook.name}' "
              f"({category}, {severity})", "Information", SERVICE)
    return success("Playbook created successfully. Add its steps with POST /playbooks/{id}/actions",
                   playbook.to_dict(), 201)


# ---------- 2. Retrieve All Playbooks ----------

@bp.get("/playbooks")
@roles_required(ADMIN, ANALYST, AUDITOR)
def get_all_playbooks():
    """
    Author: Titia Saikali
    List every playbook with its category, severity, and progress (completed / total actions).
    Who can call it: Security Administrator, Security Analyst, Auditor.
    Optional query parameters: category, severity
    """
    query = Playbook.query
    category = request.args.get("category", "").strip()
    severity = request.args.get("severity", "").strip()
    if category:
        query = query.filter(Playbook.incident_category == require_choice(category, "category", INCIDENT_CATEGORIES))
    if severity:
        query = query.filter(Playbook.severity == require_choice(severity, "severity", PLAYBOOK_SEVERITIES))

    playbooks = query.order_by(Playbook.incident_category, Playbook.playbook_id).all()
    return success(f"{len(playbooks)} playbook(s) found", {
        "count": len(playbooks), "playbooks": [playbook.to_dict() for playbook in playbooks],
    })


# ---------- 3. Retrieve Specific Playbook ----------

@bp.get("/playbooks/<int:playbook_id>")
@roles_required(ADMIN, ANALYST, AUDITOR)
def get_playbook(playbook_id):
    """
    Author: Titia Saikali
    Get one playbook with all its response actions in step order, each with its status
    history.
    Who can call it: Security Administrator, Security Analyst, Auditor.
    """
    playbook = _get_playbook_or_404(playbook_id)
    return success("Playbook found", playbook.to_dict(include_actions=True))


# ---------- 4. Add Response Action ----------

@bp.post("/playbooks/<int:playbook_id>/actions")
@roles_required(ADMIN, ANALYST)
def add_response_action(playbook_id):
    """
    Author: Titia Saikali
    Add a numbered step to a playbook. New actions start as Pending.
    Who can call it: Security Administrator, Security Analyst.
    Ordering rules: step numbers start at 1, are unique within the playbook, and cannot
    skip numbers (the next step must be at most one more than the current highest).
    Body: action_description, step_number (required); assigned_user_id (optional)
    """
    actor = g.current_user
    playbook = _get_playbook_or_404(playbook_id)
    body = get_json_body(required=("action_description", "step_number"), optional=("assigned_user_id",))

    step_number = require_int(body["step_number"], "step_number")
    if step_number < 1:
        raise ApiError("'step_number' must be 1 or more", 400)
    if any(action.step_number == step_number for action in playbook.actions):
        raise ApiError(f"Step {step_number} already exists in playbook {playbook_id}", 409)
    highest_step = db.session.query(func.max(ResponseAction.step_number)).filter_by(playbook_id=playbook_id).scalar() or 0
    if step_number > highest_step + 1:
        raise ApiError(
            f"Steps cannot skip numbers. The next step for this playbook is {highest_step + 1}", 400,
        )

    assignee = None
    if body.get("assigned_user_id") is not None:
        assignee = _require_responder(body["assigned_user_id"])
        if actor.role == ANALYST and assignee.user_id != actor.user_id:
            reject_forbidden(actor, "Security Analysts can only assign actions to themselves")

    action = ResponseAction(
        playbook_id=playbook_id,
        action_description=require_text(body["action_description"], "action_description", 1000),
        step_number=step_number,
        status="Pending",
        assigned_user_id=assignee.user_id if assignee else None,
    )
    db.session.add(action)
    db.session.commit()

    log_event(actor.user_id, "RESPONSE_ACTION_ADDED",
              f"'{actor.username}' added step {step_number} (action {action.action_id}) to playbook {playbook_id}",
              "Information", SERVICE)
    if assignee:
        _notify_assignee(assignee, action, actor)
    return success(f"Step {step_number} added to playbook {playbook_id}", action.to_dict(), 201)


# ---------- 5. Update Response Action Status ----------

@bp.put("/actions/<int:action_id>/status")
@roles_required(ADMIN, ANALYST)
def update_action_status(action_id):
    """
    Author: Titia Saikali
    Update a response action's status, assigned user, or completion date.
    Who can call it: Security Administrator (any action), Security Analyst (actions assigned
    to them or not assigned yet; they can only assign actions to themselves).
    Rules:
      - Pending -> In Progress -> Completed, one step at a time
      - a step can only start when every earlier step is Completed (order is enforced)
      - starting an unassigned step assigns it to the person starting it
      - Completed fills completion_date with now, unless a date is given
      - completion_date is only allowed on a Completed action, never in the future
      - every status change is saved in the action's history
    Body (at least one): status, assigned_user_id, completion_date (YYYY-MM-DD)
    """
    actor = g.current_user
    action = _get_action_or_404(action_id)
    body = get_json_body(optional=("status", "assigned_user_id", "completion_date"))
    if not body:
        raise ApiError("Provide at least one field to update: status, assigned_user_id, completion_date", 400)

    if actor.role == ANALYST and action.assigned_user_id not in (None, actor.user_id):
        reject_forbidden(actor, "This action is assigned to another user")

    changes = []
    newly_assigned = None

    if "assigned_user_id" in body:
        assignee = _require_responder(body["assigned_user_id"])
        if actor.role == ANALYST and assignee.user_id != actor.user_id:
            reject_forbidden(actor, "Security Analysts can only assign actions to themselves")
        if assignee.user_id != action.assigned_user_id:
            action.assigned_user_id = assignee.user_id
            newly_assigned = assignee
            changes.append(f"assigned to '{assignee.username}'")

    old_status = action.status
    if "status" in body:
        new_status = require_choice(body["status"], "status", ACTION_STATUSES)
        allowed_next = NEXT_ACTION_STATUS[old_status]
        if new_status == old_status:
            raise ApiError(f"Action is already '{old_status}'", 400)
        if new_status != allowed_next:
            if allowed_next is None:
                raise ApiError("This action is already Completed and cannot change status", 400)
            raise ApiError(
                f"Invalid status transition from '{old_status}' to '{new_status}'. "
                f"The next allowed status is '{allowed_next}'", 400,
            )
        if new_status == "In Progress":
            unfinished_steps = [
                other.step_number for other in action.playbook.actions
                if other.step_number < action.step_number and other.status != "Completed"
            ]
            if unfinished_steps:
                raise ApiError(
                    f"Step {action.step_number} cannot start until earlier step(s) "
                    f"{', '.join(map(str, unfinished_steps))} are Completed", 400,
                )
            if action.assigned_user_id is None:
                action.assigned_user_id = actor.user_id
                changes.append(f"assigned to '{actor.username}' (started it)")
        action.status = new_status
        changes.append(f"status: {old_status} -> {new_status}")
        if new_status == "Completed" and "completion_date" not in body:
            action.completion_date = utc_now()
        db.session.add(ActionHistory(
            action_id=action.action_id, old_status=old_status, new_status=new_status, changed_by=actor.user_id,
        ))

    if "completion_date" in body:
        if action.status != "Completed":
            raise ApiError("A completion date can only be set on a Completed action", 400)
        completion_day = require_date(body["completion_date"], "completion_date")
        if completion_day > utc_now().date():
            raise ApiError("The completion date cannot be in the future", 400)
        if completion_day < action.created_date.date():
            raise ApiError("The completion date cannot be earlier than the date the action was added", 400)
        action.completion_date = datetime.combine(completion_day, time())
        changes.append(f"completion_date: {completion_day.isoformat()}")

    db.session.commit()
    db.session.refresh(action)

    log_event(actor.user_id, "RESPONSE_ACTION_UPDATED",
              f"'{actor.username}' updated action {action.action_id} (step {action.step_number} of playbook "
              f"{action.playbook_id}): {'; '.join(changes) or 'no changes'}", "Information", SERVICE)
    if newly_assigned:
        _notify_assignee(newly_assigned, action, actor)

    return success("Response action updated successfully", {
        "changes": changes, "action": action.to_dict(include_history=True),
    })


# ---------- 6. Delete Playbook ----------

@bp.delete("/playbooks/<int:playbook_id>")
@roles_required(ADMIN)
def delete_playbook(playbook_id):
    """
    Author: Titia Saikali
    Delete a playbook together with its response actions and their history.
    Who can call it: Security Administrator only. Other roles get 403 and the attempt is
    logged. The audit log keeps a record of the deletion.
    """
    actor = g.current_user
    playbook = _get_playbook_or_404(playbook_id)
    summary = f"playbook {playbook.playbook_id} '{playbook.name}' with {len(playbook.actions)} action(s)"
    db.session.delete(playbook)
    db.session.commit()

    log_event(actor.user_id, "PLAYBOOK_DELETED", f"'{actor.username}' deleted {summary}", "Warning", SERVICE)
    return success(f"Playbook {playbook_id} deleted successfully")
