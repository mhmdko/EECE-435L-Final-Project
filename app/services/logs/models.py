"""
Log model: one row of the `logs` table (an audit record).

Variables (columns):
    log_id           unique number for each log record (primary key)
    user_id          the user who performed the action (foreign key to users);
                     becomes empty if that user is later deleted, so the log survives
    action           short code for what happened, e.g. LOGIN_FAILED, USER_DELETED
    description      a readable sentence explaining the event
    timestamp        when it happened (UTC)
    severity         Information, Warning, Error, or Critical
    related_service  which service produced the log, e.g. Users, Incidents

Logs cannot be edited after creation: the API has no update endpoint, and a
database trigger rejects any UPDATE on this table.

Author: Mohammad Kourani
"""
from app.common.time_utils import to_text, utc_now
from app.extensions import db

LOG_SEVERITIES = ("Information", "Warning", "Error", "Critical")


class Log(db.Model):
    __tablename__ = "logs"

    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"))
    action = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, nullable=False, default=utc_now)
    severity = db.Column(db.String(20), nullable=False, default="Information")
    related_service = db.Column(db.String(50), nullable=False)

    def to_dict(self):
        return {
            "log_id": self.log_id,
            "user_id": self.user_id,
            "action": self.action,
            "description": self.description,
            "timestamp": to_text(self.timestamp),
            "severity": self.severity,
            "related_service": self.related_service,
        }
