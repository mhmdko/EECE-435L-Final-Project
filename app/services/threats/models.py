"""
Threat model: one row of the `threats` table (a threat indicator).

Variables (columns):
    threat_id     unique number for each threat (primary key)
    threat_type   IP Address, Domain, File Hash, Malware Signature, or Other
    threat_value  the indicator itself, e.g. 185.220.101.4, evil-login.com, or a SHA-256 hash
    description   what the threat is and why it matters
    severity      Low, Medium, High, or Critical
    source        where the intelligence came from, e.g. AbuseIPDB, internal SOC, VirusTotal
    date_added    when it was recorded
    updated_date  when it was last changed

The pair (threat_type, threat_value) is unique: the same indicator cannot be
stored twice. Values are normalized before saving (IPs in standard form,
domains and hashes in lowercase), so "EVIL.com" and "evil.com" count as the same.

Author: Anthony Feghali
"""
from app.common.time_utils import to_text, utc_now
from app.extensions import db

THREAT_TYPES = ("IP Address", "Domain", "File Hash", "Malware Signature", "Other")
THREAT_SEVERITIES = ("Low", "Medium", "High", "Critical")


class Threat(db.Model):
    __tablename__ = "threats"
    __table_args__ = (db.UniqueConstraint("threat_type", "threat_value", name="uq_threat_type_value"),)

    threat_id = db.Column(db.Integer, primary_key=True)
    threat_type = db.Column(db.String(30), nullable=False)
    threat_value = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(1000), nullable=False)
    severity = db.Column(db.String(10), nullable=False)
    source = db.Column(db.String(100), nullable=False)
    date_added = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_date = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)

    def to_dict(self):
        return {
            "threat_id": self.threat_id,
            "threat_type": self.threat_type,
            "threat_value": self.threat_value,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "date_added": to_text(self.date_added),
            "updated_date": to_text(self.updated_date),
        }
