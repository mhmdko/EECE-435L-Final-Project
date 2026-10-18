"""
create_notification(): the function other services call to alert a user.

Example (from the Incidents service, when an incident is assigned):
    from app.services.notifications.service import create_notification

    create_notification(
        user_id=analyst.user_id,
        title="New incident assigned",
        message=f"Incident {incident.incident_id} '{incident.title}' was assigned to you",
        notification_type="Incident Assignment",
        severity=incident.severity,
    )

Author: Mohammad Kourani
"""
from app.common.errors import ApiError
from app.common.validation import require_choice, require_text
from app.extensions import db
from app.services.notifications.models import NOTIFICATION_SEVERITIES, NOTIFICATION_TYPES, Notification
from app.services.users.models import User


def create_notification(user_id, title, message, notification_type, severity):
    """Validate and save a new Unread notification. Raises ApiError on bad input."""
    if db.session.get(User, user_id) is None:
        raise ApiError(f"Recipient user with id {user_id} not found", 404)

    notification = Notification(
        user_id=user_id,
        title=require_text(title, "title", 150),
        message=require_text(message, "message", 1000),
        notification_type=require_choice(notification_type, "notification_type", NOTIFICATION_TYPES),
        severity=require_choice(severity, "severity", NOTIFICATION_SEVERITIES),
        status="Unread",
    )
    db.session.add(notification)
    db.session.commit()
    return notification
