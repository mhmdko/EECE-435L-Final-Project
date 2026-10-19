"""
Vulnerability model: one row of the `vulnerabilities` table.

Variables (columns):
    vulnerability_id  unique number for each vulnerability (primary key)
    title             short name, e.g. "OpenSSH remote code execution"
    description       what the weakness is and its impact
    cve_id            public CVE identifier, e.g. CVE-2024-6387
    cvss_score        CVSS score from 0.0 to 10.0
    severity          Low, Medium, High, or Critical (must match the CVSS score's rating band)
    asset_id          the affected asset (foreign key to assets); every vulnerability has exactly one
    discovery_source  how it was found, e.g. "Nessus scan", "Penetration test"
    status            Open, Under Investigation, In Progress, Resolved, Closed
    created_date      when it was registered
    resolution_date   when it was resolved (empty until then)
    updated_date      when it was last changed

The same CVE cannot be registered twice for the same asset.

Status lifecycle (each step must follow the previous one):
    Open -> Under Investigation -> In Progress -> Resolved -> Closed

Author: Anthony Feghali
"""
from app.common.time_utils import to_text, utc_now
from app.extensions import db

VULNERABILITY_SEVERITIES = ("Low", "Medium", "High", "Critical")
VULNERABILITY_STATUSES = ("Open", "Under Investigation", "In Progress", "Resolved", "Closed")

# Each status can only move to the one listed next to it.
NEXT_STATUS = {
    "Open": "Under Investigation",
    "Under Investigation": "In Progress",
    "In Progress": "Resolved",
    "Resolved": "Closed",
    "Closed": None,
}


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"
    __table_args__ = (db.UniqueConstraint("cve_id", "asset_id", name="uq_vulnerability_cve_asset"),)

    vulnerability_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(2000), nullable=False)
    cve_id = db.Column(db.String(20), nullable=False)
    cvss_score = db.Column(db.Float, nullable=False)
    severity = db.Column(db.String(10), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.asset_id"), nullable=False)
    discovery_source = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(25), nullable=False, default="Open")
    created_date = db.Column(db.DateTime, nullable=False, default=utc_now)
    resolution_date = db.Column(db.DateTime)
    updated_date = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)

    asset = db.relationship("Asset", lazy="joined")

    def to_dict(self):
        return {
            "vulnerability_id": self.vulnerability_id,
            "title": self.title,
            "description": self.description,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "affected_asset": {
                "asset_id": self.asset_id,
                "asset_name": self.asset.asset_name if self.asset else None,
                "ip_address": self.asset.ip_address if self.asset else None,
            },
            "discovery_source": self.discovery_source,
            "status": self.status,
            "created_date": to_text(self.created_date),
            "resolution_date": to_text(self.resolution_date),
            "updated_date": to_text(self.updated_date),
        }
