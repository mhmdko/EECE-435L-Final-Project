"""
Playbook, ResponseAction, and ActionHistory models.

Playbook (one row of the `playbooks` table): a standard response procedure.
    playbook_id        unique number (primary key)
    name               e.g. "Phishing response, high severity"
    description        when and how to use it
    incident_category  which kind of incident it handles (same categories as incidents)
    severity           Low, Medium, High, or Critical
    created_by         the administrator who created it (foreign key to users)
    created_date       when it was created
    There is at most one playbook per (incident_category, severity) pair, so every
    incident has one clear standard procedure.

ResponseAction (one row of the `response_actions` table): one ordered step in a playbook.
    action_id          unique number (primary key)
    playbook_id        the playbook it belongs to (foreign key to playbooks)
    action_description what to do
    step_number        its position: 1, 2, 3, ... (unique within the playbook, no gaps)
    status             Pending, In Progress, or Completed
    assigned_user_id   who is responsible (foreign key to users, optional)
    completion_date    when it was completed (empty until then)

ActionHistory (one row of the `action_history` table): every status change of an action,
kept so the execution history is never lost.
    history_id, action_id, old_status, new_status, changed_by, changed_at

Author: Titia Saikali
"""
from app.common.time_utils import to_text, utc_now
from app.extensions import db

PLAYBOOK_SEVERITIES = ("Low", "Medium", "High", "Critical")
ACTION_STATUSES = ("Pending", "In Progress", "Completed")
NEXT_ACTION_STATUS = {"Pending": "In Progress", "In Progress": "Completed", "Completed": None}


def _user_summary(user):
    if user is None:
        return None
    return {"user_id": user.user_id, "username": user.username, "full_name": user.full_name}


class Playbook(db.Model):
    __tablename__ = "playbooks"
    __table_args__ = (db.UniqueConstraint("incident_category", "severity", name="uq_playbook_category_severity"),)

    playbook_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(2000), nullable=False)
    incident_category = db.Column(db.String(30), nullable=False)
    severity = db.Column(db.String(10), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    created_date = db.Column(db.DateTime, nullable=False, default=utc_now)

    creator = db.relationship("User", lazy="joined")
    actions = db.relationship(
        "ResponseAction", back_populates="playbook", order_by="ResponseAction.step_number",
        cascade="all, delete-orphan", passive_deletes=True,
    )

    def progress(self):
        completed = sum(1 for action in self.actions if action.status == "Completed")
        return {"total_actions": len(self.actions), "completed_actions": completed}

    def to_dict(self, include_actions=False):
        data = {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "incident_category": self.incident_category,
            "severity": self.severity,
            "created_by": _user_summary(self.creator),
            "created_date": to_text(self.created_date),
            **self.progress(),
        }
        if include_actions:
            data["actions"] = [action.to_dict(include_history=True) for action in self.actions]
        return data


class ResponseAction(db.Model):
    __tablename__ = "response_actions"
    __table_args__ = (db.UniqueConstraint("playbook_id", "step_number", name="uq_action_playbook_step"),)

    action_id = db.Column(db.Integer, primary_key=True)
    playbook_id = db.Column(db.Integer, db.ForeignKey("playbooks.playbook_id", ondelete="CASCADE"), nullable=False)
    action_description = db.Column(db.String(1000), nullable=False)
    step_number = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(15), nullable=False, default="Pending")
    assigned_user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"))
    completion_date = db.Column(db.DateTime)
    created_date = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_date = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)

    playbook = db.relationship("Playbook", back_populates="actions")
    assigned_user = db.relationship("User", lazy="joined")
    history = db.relationship(
        "ActionHistory", order_by="ActionHistory.history_id",
        cascade="all, delete-orphan", passive_deletes=True,
    )

    def to_dict(self, include_history=False):
        data = {
            "action_id": self.action_id,
            "playbook_id": self.playbook_id,
            "step_number": self.step_number,
            "action_description": self.action_description,
            "status": self.status,
            "assigned_user": _user_summary(self.assigned_user),
            "completion_date": to_text(self.completion_date),
            "next_allowed_status": NEXT_ACTION_STATUS[self.status],
        }
        if include_history:
            data["history"] = [entry.to_dict() for entry in self.history]
        return data


class ActionHistory(db.Model):
    __tablename__ = "action_history"

    history_id = db.Column(db.Integer, primary_key=True)
    action_id = db.Column(db.Integer, db.ForeignKey("response_actions.action_id", ondelete="CASCADE"), nullable=False)
    old_status = db.Column(db.String(15), nullable=False)
    new_status = db.Column(db.String(15), nullable=False)
    changed_by = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"))
    changed_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    changer = db.relationship("User", lazy="joined")

    def to_dict(self):
        return {
            "old_status": self.old_status,
            "new_status": self.new_status,
            "changed_by": self.changer.username if self.changer else None,
            "changed_at": to_text(self.changed_at),
        }
