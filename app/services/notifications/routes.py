"""
Notification and Alert Management Service: 6 endpoints.

    POST   /notifications                    create a notification
    GET    /notifications/user/<user_id>     list one user's notifications
    GET    /notifications/<id>               get one notification
    PUT    /notifications/<id>/read          mark a notification as read
    GET    /notifications/search             search by user, type, severity, status
    DELETE /notifications/<id>               delete a notification

Privacy rule: Security Analysts and Regular Employees can only see and update
their own notifications. Administrators and Auditors can see everyone's.

Author: Mohammad Kourani
"""
from flask import Blueprint, g, request

from app.common.auth import ADMIN, ALL_ROLES, ANALYST, AUDITOR, EMPLOYEE, reject_forbidden, roles_required
from app.common.errors import ApiError, success
from app.common.time_utils import utc_now
from app.common.validation import get_json_body, require_choice, require_int
from app.extensions import db
from app.services.logs.service import log_event
from app.services.notifications.models import (
    NOTIFICATION_SEVERITIES, NOTIFICATION_STATUSES, NOTIFICATION_TYPES, Notification,
)
from app.services.notifications.service import create_notification
from app.services.users.models import User

bp = Blueprint("notifications", __name__, url_prefix="/notifications")

SERVICE = "Notifications"
OWN_ONLY_ROLES = (ANALYST, EMPLOYEE)
SEARCH_FILTERS = ("user_id", "type", "severity", "status")


def _check_owner(actor, owner_user_id):
    """Analysts and employees may only access notifications addressed to them."""
    if actor.role in OWN_ONLY_ROLES and actor.user_id != owner_user_id:
        reject_forbidden(actor, "You can only access your own notifications")


def _get_notification_or_404(notification_id):
    notification = db.session.get(Notification, notification_id)
    if notification is None:
        raise ApiError(f"Notification with id {notification_id} not found", 404)
    return notification


def _notification_list(notifications):
    return {
        "count": len(notifications),
        "unread": sum(1 for item in notifications if item.status == "Unread"),
        "notifications": [item.to_dict() for item in notifications],
    }


# ---------- 1. Create Notification ----------

@bp.post("")
@roles_required(ADMIN)
def create_notification_route():
    """
    Author: Mohammad Kourani
    Send a notification to a user.
    Who can call it: Security Administrator. Other services create
    notifications internally with create_notification().
    Body: user_id, title, message, notification_type, severity
    """
    actor = g.current_user
    body = get_json_body(required=("user_id", "title", "message", "notification_type", "severity"))
    notification = create_notification(
        user_id=require_int(body["user_id"], "user_id"),
        title=body["title"],
        message=body["message"],
        notification_type=body["notification_type"],
        severity=body["severity"],
    )
    log_event(actor.user_id, "NOTIFICATION_CREATED",
              f"'{actor.username}' sent notification {notification.notification_id} "
              f"({notification.notification_type}) to user {notification.user_id}",
              "Information", SERVICE)
    return success("Notification created successfully", notification.to_dict(), 201)


# ---------- 2. Retrieve User Notifications ----------

@bp.get("/user/<int:user_id>")
@roles_required(*ALL_ROLES)
def get_user_notifications(user_id):
    """
    Author: Mohammad Kourani
    List all notifications for one user, newest first.
    Who can call it: all roles (analysts and employees only for themselves).
    """
    actor = g.current_user
    _check_owner(actor, user_id)
    user = db.session.get(User, user_id)
    if user is None:
        raise ApiError(f"User with id {user_id} not found", 404)

    notifications = (
        Notification.query.filter(Notification.user_id == user_id)
        .order_by(Notification.creation_date.desc(), Notification.notification_id.desc())
        .all()
    )
    message = (
        f"{len(notifications)} notification(s) found for user '{user.username}'"
        if notifications else f"No notifications found for user '{user.username}'"
    )
    return success(message, {"user_id": user_id, **_notification_list(notifications)})


# ---------- 3. Retrieve Specific Notification ----------

@bp.get("/<int:notification_id>")
@roles_required(*ALL_ROLES)
def get_notification(notification_id):
    """
    Author: Mohammad Kourani
    Get one notification by id.
    Who can call it: all roles (analysts and employees only their own).
    """
    notification = _get_notification_or_404(notification_id)
    _check_owner(g.current_user, notification.user_id)
    return success("Notification found", notification.to_dict())


# ---------- 4. Mark Notification as Read ----------

@bp.put("/<int:notification_id>/read")
@roles_required(ADMIN, ANALYST, EMPLOYEE)
def mark_notification_read(notification_id):
    """
    Author: Mohammad Kourani
    Change a notification's status from Unread to Read and record the read date.
    Who can call it: Security Administrator, Security Analyst and Regular Employee (own only).
    Marking an already-read notification changes nothing.
    """
    notification = _get_notification_or_404(notification_id)
    _check_owner(g.current_user, notification.user_id)

    if notification.status == "Read":
        return success("Notification was already marked as read", notification.to_dict())

    notification.status = "Read"
    notification.read_date = utc_now()
    db.session.commit()
    return success("Notification marked as read", notification.to_dict())


# ---------- 5. Search Notifications ----------

@bp.get("/search")
@roles_required(ADMIN, ANALYST, AUDITOR)
def search_notifications():
    """
    Author: Mohammad Kourani
    Search notifications. Filters can be combined; all must match.
    Who can call it: Security Administrator, Auditor, Security Analyst (own only).
    Query parameters:
        user_id    exact user id
        type       Incident Assignment, Security Alert, System Notification, Threat Alert, Vulnerability Alert
        severity   Low, Medium, High, Critical
        status     Unread, Read
    """
    actor = g.current_user
    filters = {name: request.args.get(name, "").strip() for name in SEARCH_FILTERS}
    if not any(filters.values()):
        raise ApiError(f"Provide at least one search filter: {', '.join(SEARCH_FILTERS)}", 400)

    query = Notification.query
    if filters["user_id"]:
        requested_user_id = require_int(filters["user_id"], "user_id")
        _check_owner(actor, requested_user_id)
        query = query.filter(Notification.user_id == requested_user_id)
    elif actor.role in OWN_ONLY_ROLES:
        query = query.filter(Notification.user_id == actor.user_id)
    if filters["type"]:
        query = query.filter(Notification.notification_type == require_choice(
            filters["type"], "notification type", NOTIFICATION_TYPES))
    if filters["severity"]:
        query = query.filter(Notification.severity == require_choice(
            filters["severity"], "severity", NOTIFICATION_SEVERITIES))
    if filters["status"]:
        query = query.filter(Notification.status == require_choice(
            filters["status"], "status", NOTIFICATION_STATUSES))

    notifications = query.order_by(Notification.creation_date.desc(), Notification.notification_id.desc()).all()
    used_filters = {name: value for name, value in filters.items() if value}
    return success(f"{len(notifications)} notification(s) match the search", {
        "filters": used_filters, **_notification_list(notifications),
    })


# ---------- 6. Delete Notification ----------

@bp.delete("/<int:notification_id>")
@roles_required(ADMIN)
def delete_notification(notification_id):
    """
    Author: Mohammad Kourani
    Delete one notification.
    Who can call it: Security Administrator only.
    """
    actor = g.current_user
    notification = _get_notification_or_404(notification_id)
    summary = f"notification {notification.notification_id} ('{notification.title}') of user {notification.user_id}"
    db.session.delete(notification)
    db.session.commit()

    log_event(actor.user_id, "NOTIFICATION_DELETED", f"'{actor.username}' deleted {summary}", "Information", SERVICE)
    return success(f"Notification {notification_id} deleted successfully")
