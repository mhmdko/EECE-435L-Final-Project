"""
Security Audit Logging Service: 6 endpoints.

    POST   /logs                   create a log record
    GET    /logs                   list all logs
    GET    /logs/<id>              get one log
    GET    /logs/search            search logs by user, date, action, severity, service
    DELETE /logs/<id>              delete a log
    GET    /logs/user/<user_id>    list one user's logs

Most logs are written automatically by log_event() (logins, user changes,
denied requests, ...). POST /logs lets an administrator add one manually.

Author: Mohammad Kourani
"""
from flask import Blueprint, g, request
from sqlalchemy import func

from app.common.auth import ADMIN, ANALYST, AUDITOR, roles_required
from app.common.errors import ApiError, success
from app.common.validation import (
    get_json_body, require_choice, require_date, require_int, require_text,
)
from app.extensions import db
from app.services.logs.models import LOG_SEVERITIES, Log
from app.services.logs.service import log_event
from app.services.users.models import User

bp = Blueprint("logs", __name__, url_prefix="/logs")

SERVICE = "Logs"
SEARCH_FILTERS = ("user_id", "date", "action", "severity", "service")


def _get_log_or_404(log_id):
    log_record = db.session.get(Log, log_id)
    if log_record is None:
        raise ApiError(f"Log with id {log_id} not found", 404)
    return log_record


def _log_list(log_records):
    return {"count": len(log_records), "logs": [record.to_dict() for record in log_records]}


# ---------- 1. Create Log Record ----------

@bp.post("")
@roles_required(ADMIN)
def create_log():
    """
    Author: Mohammad Kourani
    Add an audit record manually.
    Who can call it: Security Administrator.
    Body: user_id, action, description, severity, related_service
    """
    body = get_json_body(required=("user_id", "action", "description", "severity", "related_service"))
    user_id = require_int(body["user_id"], "user_id")
    if db.session.get(User, user_id) is None:
        raise ApiError(f"User with id {user_id} not found", 404)

    log_record = Log(
        user_id=user_id,
        action=require_text(body["action"], "action", 50).upper().replace(" ", "_"),
        description=require_text(body["description"], "description", 500),
        severity=require_choice(body["severity"], "severity", LOG_SEVERITIES),
        related_service=require_text(body["related_service"], "related_service", 50),
    )
    db.session.add(log_record)
    db.session.commit()
    return success("Log record created successfully", log_record.to_dict(), 201)


# ---------- 2. Retrieve All Logs ----------

@bp.get("")
@roles_required(ADMIN, AUDITOR)
def get_all_logs():
    """
    Author: Mohammad Kourani
    List every audit record, newest first.
    Who can call it: Security Administrator, Auditor.
    """
    log_records = Log.query.order_by(Log.timestamp.desc(), Log.log_id.desc()).all()
    return success(f"{len(log_records)} log(s) found", _log_list(log_records))


# ---------- 3. Retrieve Specific Log ----------

@bp.get("/<int:log_id>")
@roles_required(ADMIN, AUDITOR, ANALYST)
def get_log(log_id):
    """
    Author: Mohammad Kourani
    Get one audit record by id.
    Who can call it: Security Administrator, Auditor, Security Analyst.
    """
    return success("Log found", _get_log_or_404(log_id).to_dict())


# ---------- 4. Search Logs ----------

@bp.get("/search")
@roles_required(ADMIN, AUDITOR, ANALYST)
def search_logs():
    """
    Author: Mohammad Kourani
    Search audit records. Filters can be combined; all must match.
    Who can call it: Security Administrator, Auditor, Security Analyst.
    Query parameters:
        user_id   exact user id                     e.g. ?user_id=1
        date      day in YYYY-MM-DD                 e.g. ?date=2026-10-01
        action    part of the action code           e.g. ?action=login
        severity  Information/Warning/Error/Critical
        service   related service name              e.g. ?service=Users
    """
    filters = {name: request.args.get(name, "").strip() for name in SEARCH_FILTERS}
    if not any(filters.values()):
        raise ApiError(f"Provide at least one search filter: {', '.join(SEARCH_FILTERS)}", 400)

    query = Log.query
    if filters["user_id"]:
        query = query.filter(Log.user_id == require_int(filters["user_id"], "user_id"))
    if filters["date"]:
        day = require_date(filters["date"], "date")
        query = query.filter(func.date(Log.timestamp) == day.isoformat())
    if filters["action"]:
        query = query.filter(Log.action.ilike(f"%{filters['action']}%"))
    if filters["severity"]:
        query = query.filter(Log.severity == require_choice(filters["severity"], "severity", LOG_SEVERITIES))
    if filters["service"]:
        query = query.filter(func.lower(Log.related_service) == filters["service"].lower())

    log_records = query.order_by(Log.timestamp.desc(), Log.log_id.desc()).all()
    used_filters = {name: value for name, value in filters.items() if value}
    return success(f"{len(log_records)} log(s) match the search", {
        "filters": used_filters, **_log_list(log_records),
    })


# ---------- 5. Delete Logs ----------

@bp.delete("/<int:log_id>")
@roles_required(ADMIN)
def delete_log(log_id):
    """
    Author: Mohammad Kourani
    Delete one audit record. The deletion itself is logged as Critical.
    Who can call it: Security Administrator only.
    """
    actor = g.current_user
    log_record = _get_log_or_404(log_id)
    summary = f"log {log_record.log_id} ({log_record.action}, {log_record.timestamp:%Y-%m-%d %H:%M:%S})"
    db.session.delete(log_record)
    db.session.commit()

    log_event(actor.user_id, "LOG_DELETED", f"'{actor.username}' deleted {summary}", "Critical", SERVICE)
    return success(f"Log {log_id} deleted successfully")


# ---------- 6. Retrieve Logs By User ----------

@bp.get("/user/<int:user_id>")
@roles_required(ADMIN, AUDITOR)
def get_logs_by_user(user_id):
    """
    Author: Mohammad Kourani
    List every audit record created by one user, newest first.
    Who can call it: Security Administrator, Auditor.
    """
    user = db.session.get(User, user_id)
    if user is None:
        raise ApiError(f"User with id {user_id} not found", 404)

    log_records = (
        Log.query.filter(Log.user_id == user_id)
        .order_by(Log.timestamp.desc(), Log.log_id.desc())
        .all()
    )
    message = (
        f"{len(log_records)} log(s) found for user '{user.username}'"
        if log_records else f"No logs found for user '{user.username}'"
    )
    return success(message, {"user_id": user_id, "username": user.username, **_log_list(log_records)})
