"""
Asset Management Service: 6 endpoints.

    POST   /assets           add a new asset
    PUT    /assets/<id>      update asset information
    DELETE /assets/<id>      delete an asset
    GET    /assets           list all assets
    GET    /assets/<id>      get one asset (with its vulnerabilities)
    GET    /assets/search    search by name, type, IP, department, criticality, status

Regular Employees have no access to this service.

Author: Anthony Feghali
"""
from flask import Blueprint, g, request
from sqlalchemy.exc import IntegrityError

from app.common.auth import ADMIN, ANALYST, AUDITOR, roles_required
from app.common.errors import ApiError, success
from app.common.network_validation import require_ip
from app.common.validation import get_json_body, require_choice, require_int, require_text
from app.extensions import db
from app.services.assets.models import ASSET_CRITICALITIES, ASSET_STATUSES, ASSET_TYPES, Asset
from app.services.logs.service import log_event
from app.services.users.models import User

bp = Blueprint("assets", __name__, url_prefix="/assets")

SERVICE = "Assets"
SEARCH_FILTERS = ("name", "type", "ip", "department", "criticality", "status")


# ---------- helpers ----------

def _get_asset_or_404(asset_id):
    asset = db.session.get(Asset, asset_id)
    if asset is None:
        raise ApiError(f"Asset with id {asset_id} not found", 404)
    return asset


def _require_owner(owner_id_value):
    owner_id = require_int(owner_id_value, "owner_id")
    owner = db.session.get(User, owner_id)
    if owner is None:
        raise ApiError(f"Owner user with id {owner_id} not found", 404)
    return owner


def _optional_text(value, field_name, max_length):
    """Optional fields may be left empty; if given, they must be valid text."""
    if value is None or value == "":
        return None
    return require_text(value, field_name, max_length)


def _asset_list(assets):
    return {"count": len(assets), "assets": [asset.to_dict() for asset in assets]}


# ---------- 1. Add New Asset ----------

@bp.post("")
@roles_required(ADMIN)
def add_asset():
    """
    Author: Anthony Feghali
    Register a new organizational asset.
    Who can call it: Security Administrator.
    Body: asset_name, asset_type, ip_address, department, owner_id, criticality (required);
          operating_system, location, status (optional, status defaults to Active)
    """
    actor = g.current_user
    body = get_json_body(
        required=("asset_name", "asset_type", "ip_address", "department", "owner_id", "criticality"),
        optional=("operating_system", "location", "status"),
    )
    owner = _require_owner(body["owner_id"])

    asset = Asset(
        asset_name=require_text(body["asset_name"], "asset_name", 100),
        asset_type=require_choice(body["asset_type"], "asset_type", ASSET_TYPES),
        ip_address=require_ip(body["ip_address"]),
        operating_system=_optional_text(body.get("operating_system"), "operating_system", 100),
        department=require_text(body["department"], "department", 100),
        owner_id=owner.user_id,
        location=_optional_text(body.get("location"), "location", 150),
        criticality=require_choice(body["criticality"], "criticality", ASSET_CRITICALITIES),
        status=require_choice(body.get("status") or "Active", "status", ASSET_STATUSES),
    )
    db.session.add(asset)
    db.session.commit()

    log_event(actor.user_id, "ASSET_CREATED",
              f"'{actor.username}' added asset {asset.asset_id} '{asset.asset_name}' "
              f"({asset.asset_type}, {asset.criticality} criticality, owner '{owner.username}')",
              "Information", SERVICE)
    return success("Asset created successfully", asset.to_dict(), 201)


# ---------- 2. Update Asset Information ----------

@bp.put("/<int:asset_id>")
@roles_required(ADMIN)
def update_asset(asset_id):
    """
    Author: Anthony Feghali
    Update an asset's name, owner, department, criticality, status, IP, OS, or location.
    Who can call it: Security Administrator.
    Body (at least one): asset_name, owner_id, department, criticality, status,
                         ip_address, operating_system, location
    """
    actor = g.current_user
    asset = _get_asset_or_404(asset_id)
    body = get_json_body(optional=(
        "asset_name", "owner_id", "department", "criticality", "status",
        "ip_address", "operating_system", "location",
    ))
    if not body:
        raise ApiError(
            "Provide at least one field to update: asset_name, owner_id, department, criticality, status, "
            "ip_address, operating_system, location", 400,
        )

    changes = []

    def record(field, old_value, new_value):
        if old_value != new_value:
            changes.append(f"{field}: {old_value} -> {new_value}")

    if "asset_name" in body:
        new_name = require_text(body["asset_name"], "asset_name", 100)
        record("asset_name", asset.asset_name, new_name)
        asset.asset_name = new_name
    if "owner_id" in body:
        owner = _require_owner(body["owner_id"])
        record("owner_id", asset.owner_id, owner.user_id)
        asset.owner_id = owner.user_id
    if "department" in body:
        new_department = require_text(body["department"], "department", 100)
        record("department", asset.department, new_department)
        asset.department = new_department
    if "criticality" in body:
        new_criticality = require_choice(body["criticality"], "criticality", ASSET_CRITICALITIES)
        record("criticality", asset.criticality, new_criticality)
        asset.criticality = new_criticality
    if "status" in body:
        new_status = require_choice(body["status"], "status", ASSET_STATUSES)
        record("status", asset.status, new_status)
        asset.status = new_status
    if "ip_address" in body:
        new_ip = require_ip(body["ip_address"])
        record("ip_address", asset.ip_address, new_ip)
        asset.ip_address = new_ip
    if "operating_system" in body:
        new_os = _optional_text(body["operating_system"], "operating_system", 100)
        record("operating_system", asset.operating_system, new_os)
        asset.operating_system = new_os
    if "location" in body:
        new_location = _optional_text(body["location"], "location", 150)
        record("location", asset.location, new_location)
        asset.location = new_location

    if not changes:
        return success("No changes: the asset already has these values", asset.to_dict())

    db.session.commit()
    db.session.refresh(asset)
    log_event(actor.user_id, "ASSET_UPDATED",
              f"'{actor.username}' updated asset {asset.asset_id} '{asset.asset_name}': {'; '.join(changes)}",
              "Information", SERVICE)
    return success("Asset updated successfully", {"changes": changes, "asset": asset.to_dict()})


# ---------- 3. Delete Asset ----------

@bp.delete("/<int:asset_id>")
@roles_required(ADMIN)
def delete_asset(asset_id):
    """
    Author: Anthony Feghali
    Remove an asset from the system.
    Who can call it: Security Administrator only. Other roles get 403 and the attempt is logged.
    An asset that still has vulnerabilities or incidents linked to it cannot be deleted (409).
    """
    actor = g.current_user
    asset = _get_asset_or_404(asset_id)
    summary = f"asset {asset.asset_id} '{asset.asset_name}' ({asset.asset_type})"

    db.session.delete(asset)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise ApiError(
            "This asset still has vulnerabilities or incidents linked to it. "
            "Delete or reassign them first", 409,
        )

    log_event(actor.user_id, "ASSET_DELETED", f"'{actor.username}' deleted {summary}", "Warning", SERVICE)
    return success(f"Asset {asset_id} deleted successfully")


# ---------- 4. Retrieve All Assets ----------

@bp.get("")
@roles_required(ADMIN, AUDITOR)
def get_all_assets():
    """
    Author: Anthony Feghali
    List every registered asset with its criticality and current status.
    Who can call it: Security Administrator, Auditor.
    """
    assets = Asset.query.order_by(Asset.asset_id).all()
    return success(f"{len(assets)} asset(s) found", _asset_list(assets))


# ---------- 5. Retrieve Specific Asset ----------

@bp.get("/<int:asset_id>")
@roles_required(ADMIN, ANALYST, AUDITOR)
def get_asset(asset_id):
    """
    Author: Anthony Feghali
    Get one asset, including the vulnerabilities found on it.
    Who can call it: Security Administrator, Security Analyst, Auditor.
    """
    from app.services.vulnerabilities.models import Vulnerability  # avoid a circular import

    asset = _get_asset_or_404(asset_id)
    related_vulnerabilities = (
        Vulnerability.query.filter(Vulnerability.asset_id == asset_id)
        .order_by(Vulnerability.vulnerability_id).all()
    )
    asset_data = asset.to_dict()
    asset_data["vulnerabilities"] = [
        {
            "vulnerability_id": vulnerability.vulnerability_id,
            "title": vulnerability.title,
            "cve_id": vulnerability.cve_id,
            "severity": vulnerability.severity,
            "status": vulnerability.status,
        }
        for vulnerability in related_vulnerabilities
    ]
    return success("Asset found", asset_data)


# ---------- 6. Search Assets ----------

@bp.get("/search")
@roles_required(ADMIN, ANALYST, AUDITOR)
def search_assets():
    """
    Author: Anthony Feghali
    Search assets. Filters can be combined; all must match.
    Who can call it: Security Administrator, Security Analyst, Auditor.
    Query parameters:
        name         part of the asset name, any capitalization   e.g. ?name=server
        type         exact asset type                            e.g. ?type=Database
        ip           exact IP address, or the start of one       e.g. ?ip=10.0.1.
        department   part of the department name                 e.g. ?department=finance
        criticality  Low, Medium, High, or Critical
        status       Active, Inactive, or Under Maintenance
    """
    filters = {name: request.args.get(name, "").strip() for name in SEARCH_FILTERS}
    if not any(filters.values()):
        raise ApiError(f"Provide at least one search filter: {', '.join(SEARCH_FILTERS)}", 400)

    query = Asset.query
    if filters["name"]:
        query = query.filter(Asset.asset_name.ilike(f"%{filters['name']}%"))
    if filters["type"]:
        query = query.filter(Asset.asset_type == require_choice(filters["type"], "asset type", ASSET_TYPES))
    if filters["ip"]:
        query = query.filter(Asset.ip_address.like(f"{filters['ip']}%"))
    if filters["department"]:
        query = query.filter(Asset.department.ilike(f"%{filters['department']}%"))
    if filters["criticality"]:
        query = query.filter(Asset.criticality == require_choice(
            filters["criticality"], "criticality", ASSET_CRITICALITIES))
    if filters["status"]:
        query = query.filter(Asset.status == require_choice(filters["status"], "status", ASSET_STATUSES))

    assets = query.order_by(Asset.asset_id).all()
    used_filters = {name: value for name, value in filters.items() if value}
    return success(f"{len(assets)} asset(s) match the search", {"filters": used_filters, **_asset_list(assets)})
