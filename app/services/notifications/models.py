"""
Notification model: one row of the `notifications` table.

Variables (columns):
    notification_id    unique number for each notification (primary key)
    user_id            the user receiving it (foreign key to users)
    title              short heading
    message            full text of the alert
    notification_type  Incident Assignment, Security Alert, System Notification,
                       Threat Alert, or Vulnerability Alert
    severity           Low, Medium, High, or Critical
    status             Unread or Read
    creation_date      when it was created
    read_date          when the user marked it as read (empty while Unread)

Author: Mohammad Kourani
"""
from app.common.time_utils import to_text, utc_now
from app.extensions import db

NOTIFICATION_TYPES = (
    "Incident Assignment", "Security Alert", "System Notification", "Threat Alert", "Vulnerability Alert",
)
NOTIFICATION_SEVERITIES = ("Low", "Medium", "High", "Critical")
NOTIFICATION_STATUSES = ("Unread", "Read")


class Notification(db.Model):
    __tablename__ = "notifications"

    notification_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    message = db.Column(db.String(1000), nullable=False)
    notification_type = db.Column(db.String(30), nullable=False)
    severity = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(10), nullable=False, default="Unread")
    creation_date = db.Column(db.DateTime, nullable=False, default=utc_now)
    read_date = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "notification_id": self.notification_id,
            "user_id": self.user_id,
            "title": self.title,
            "message": self.message,
            "notification_type": self.notification_type,
            "severity": self.severity,
            "status": self.status,
            "creation_date": to_text(self.creation_date),
            "read_date": to_text(self.read_date),
        }
