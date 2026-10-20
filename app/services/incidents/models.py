"""
Incident and InvestigationNote models.

Incident (one row of the `incidents` table):
    incident_id          unique number for each incident (primary key)
    title                short summary, e.g. "Phishing email targeting payroll team"
    description          what happened
    category             Malware Infection, Unauthorized Access, Phishing Attack, Data Leakage,
                         Account Compromise, Denial of Service, or Other
    severity             Low, Medium, High, or Critical
    reporter_id          the user who reported it (foreign key to users)
    affected_asset_id    the asset involved (foreign key to assets)
    assigned_analyst_id  the Security Analyst investigating it (foreign key to users, empty until assigned)
    status               Open, Under Investigation, Mitigated, Resolved, Closed
    created_date         when it was reported
    resolution_date      when it was resolved (empty until then)
    updated_date         when it was last changed

InvestigationNote (one row of the `investigation_notes` table):
    note_id              unique number for each note (primary key)
    incident_id          the incident it belongs to (foreign key to incidents)
    analyst_id           who wrote it (foreign key to users)
    note_content         analysis performed, evidence collected, or actions taken
    created_timestamp    when it was written

Status lifecycle (each step must follow the previous one):
    Open -> Under Investigation -> Mitigated -> Resolved -> Closed

Author: Titia Saikali
"""
from app.common.time_utils import to_text, utc_now
from app.extensions import db

INCIDENT_CATEGORIES = (
    "Malware Infection", "Unauthorized Access", "Phishing Attack", "Data Leakage",
    "Account Compromise", "Denial of Service", "Other",
)
INCIDENT_SEVERITIES = ("Low", "Medium", "High", "Critical")
INCIDENT_STATUSES = ("Open", "Under Investigation", "Mitigated", "Resolved", "Closed")

# Each status can only move to the one listed next to it.
NEXT_STATUS = {
    "Open": "Under Investigation",
    "Under Investigation": "Mitigated",
    "Mitigated": "Resolved",
    "Resolved": "Closed",
    "Closed": None,
}


def _user_summary(user):
    if user is None:
        return None
    return {"user_id": user.user_id, "username": user.username, "full_name": user.full_name}


class Incident(db.Model):
    __tablename__ = "incidents"

    incident_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(2000), nullable=False)
    category = db.Column(db.String(30), nullable=False)
    severity = db.Column(db.String(10), nullable=False)
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    affected_asset_id = db.Column(db.Integer, db.ForeignKey("assets.asset_id"))
    assigned_analyst_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"))
    status = db.Column(db.String(25), nullable=False, default="Open")
    created_date = db.Column(db.DateTime, nullable=False, default=utc_now)
    resolution_date = db.Column(db.DateTime)
    updated_date = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)

    reporter = db.relationship("User", foreign_keys=[reporter_id], lazy="joined")
    assigned_analyst = db.relationship("User", foreign_keys=[assigned_analyst_id], lazy="joined")
    affected_asset = db.relationship("Asset", lazy="joined")
    notes = db.relationship(
        "InvestigationNote", back_populates="incident", order_by="InvestigationNote.note_id",
        cascade="all, delete-orphan", passive_deletes=True,
    )

    def to_dict(self, include_notes=False):
        data = {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "reporter": _user_summary(self.reporter),
            "affected_asset": (
                {"asset_id": self.affected_asset.asset_id, "asset_name": self.affected_asset.asset_name,
                 "criticality": self.affected_asset.criticality}
                if self.affected_asset else None
            ),
            "assigned_analyst": _user_summary(self.assigned_analyst),
            "created_date": to_text(self.created_date),
            "resolution_date": to_text(self.resolution_date),
            "updated_date": to_text(self.updated_date),
            "notes_count": len(self.notes),
        }
        if include_notes:
            data["investigation_notes"] = [note.to_dict() for note in self.notes]
        return data


class InvestigationNote(db.Model):
    __tablename__ = "investigation_notes"

    note_id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.incident_id", ondelete="CASCADE"), nullable=False)
    analyst_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    note_content = db.Column(db.String(4000), nullable=False)
    created_timestamp = db.Column(db.DateTime, nullable=False, default=utc_now)

    incident = db.relationship("Incident", back_populates="notes")
    analyst = db.relationship("User", lazy="joined")

    def to_dict(self):
        return {
            "note_id": self.note_id,
            "incident_id": self.incident_id,
            "analyst": _user_summary(self.analyst),
            "note_content": self.note_content,
            "created_timestamp": to_text(self.created_timestamp),
        }
