"""
log_event(): the function every service calls to write an audit record.

Example (from the Incidents service):
    from app.services.logs.service import log_event

    log_event(
        user_id=g.current_user.user_id,
        action="INCIDENT_ASSIGNED",
        description=f"Incident {incident.incident_id} assigned to analyst {analyst.username}",
        severity="Information",
        related_service="Incidents",
    )

Author: Mohammad Kourani
"""
from flask import current_app

from app.extensions import db
from app.services.logs.models import LOG_SEVERITIES, Log


def log_event(user_id, action, description, severity="Information", related_service="System"):
    """Save one audit record. Returns the new Log, or None if saving failed."""
    if severity not in LOG_SEVERITIES:
        severity = "Information"
    log_record = Log(
        user_id=user_id,
        action=action,
        description=description,
        severity=severity,
        related_service=related_service,
    )
    try:
        db.session.add(log_record)
        db.session.commit()
        return log_record
    except Exception:
        # Logging must never crash the request that triggered it.
        db.session.rollback()
        current_app.logger.exception("Could not write audit log")
        return None
