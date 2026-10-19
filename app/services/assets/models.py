"""
Asset model: one row of the `assets` table.

Variables (columns):
    asset_id          unique number for each asset (primary key)
    asset_name        name of the asset, e.g. "Payroll Database Server"
    asset_type        Server, Workstation, Database, Application, Network Device, or Cloud Resource
    ip_address        IPv4 or IPv6 address, validated and stored in standard form
    operating_system  e.g. "Ubuntu 22.04" (optional, not every asset has one)
    department        department that uses the asset
    owner_id          the user responsible for the asset (foreign key to users)
    location          where the asset is, e.g. "Beirut HQ, Server Room 2" (optional)
    criticality       Low, Medium, High, or Critical: how important the asset is to the business
    status            Active, Inactive, or Under Maintenance
    created_date      when the asset was registered
    updated_date      when it was last changed

Relationships:
    owner             -> users (one user owns many assets)
    vulnerabilities   <- vulnerabilities.asset_id (one asset has many vulnerabilities)
    incidents         <- incidents.affected_asset_id (added by the Incidents service)

Author: Anthony Feghali
"""
from app.common.time_utils import to_text, utc_now
from app.extensions import db

ASSET_TYPES = ("Server", "Workstation", "Database", "Application", "Network Device", "Cloud Resource")
ASSET_CRITICALITIES = ("Low", "Medium", "High", "Critical")
ASSET_STATUSES = ("Active", "Inactive", "Under Maintenance")


class Asset(db.Model):
    __tablename__ = "assets"

    asset_id = db.Column(db.Integer, primary_key=True)
    asset_name = db.Column(db.String(100), nullable=False)
    asset_type = db.Column(db.String(30), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    operating_system = db.Column(db.String(100))
    department = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    location = db.Column(db.String(150))
    criticality = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="Active")
    created_date = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_date = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)

    owner = db.relationship("User", lazy="joined")

    def to_dict(self):
        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "asset_type": self.asset_type,
            "ip_address": self.ip_address,
            "operating_system": self.operating_system,
            "department": self.department,
            "owner": {
                "user_id": self.owner_id,
                "username": self.owner.username if self.owner else None,
                "full_name": self.owner.full_name if self.owner else None,
            },
            "location": self.location,
            "criticality": self.criticality,
            "status": self.status,
            "created_date": to_text(self.created_date),
            "updated_date": to_text(self.updated_date),
        }
