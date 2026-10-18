"""
Authentication (who are you?) and authorization (are you allowed?).

How it works:
1. POST /users/login checks the password and returns a signed token (JWT).
2. The client sends that token on every request in the header:
       Authorization: Bearer <token>
3. @roles_required(...) on a route:
   - rejects requests with no token or an invalid/expired token (401)
   - rejects users whose account is no longer Active (403)
   - rejects users whose role is not in the allowed list (403)
   - records every rejection in the audit log
   - otherwise stores the logged-in user in g.current_user and runs the route

Usage in any service:
    from app.common.auth import roles_required, ADMIN, AUDITOR

    @bp.get("/assets")
    @roles_required(ADMIN, AUDITOR)
    def get_all_assets():
        current_user = g.current_user
        ...

Author: Mohammad Kourani
"""
from datetime import timedelta
from functools import wraps

import jwt
from flask import current_app, g, request

from app.common.errors import ApiError
from app.common.time_utils import utc_now
from app.extensions import db

# The four roles, spelled exactly as stored in the database.
ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"
ALL_ROLES = (ADMIN, ANALYST, EMPLOYEE, AUDITOR)

TOKEN_ALGORITHM = "HS256"


def create_token(user):
    """Create a signed login token that identifies the user and expires after a few hours."""
    issued_at = utc_now()
    payload = {
        "sub": str(user.user_id),
        "role": user.role,
        "iat": issued_at,
        "exp": issued_at + timedelta(hours=current_app.config["TOKEN_EXPIRY_HOURS"]),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm=TOKEN_ALGORITHM)


def _service_name():
    """Name of the service handling this request, used when writing audit logs."""
    return (request.blueprint or "system").capitalize()


def _reject(message, status_code, user_id=None, who=None):
    """Record the rejected request in the audit log, then stop with an error."""
    from app.services.logs.service import log_event  # imported here to avoid a circular import

    prefix = f"{who} was denied: " if who else ""
    log_event(
        user_id=user_id,
        action="UNAUTHORIZED_ACCESS",
        description=f"{prefix}{message} ({request.method} {request.path})",
        severity="Warning",
        related_service=_service_name(),
    )
    raise ApiError(message, status_code)


def _user_from_token(raise_if_missing=True):
    """Return the user identified by the request's token, or None if there is no token."""
    from app.services.users.models import User  # imported here to avoid a circular import

    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        if raise_if_missing:
            _reject("Missing authentication token. Log in and send 'Authorization: Bearer <token>'", 401)
        return None

    token = header[len("Bearer "):].strip()
    try:
        payload = jwt.decode(token, current_app.config["JWT_SECRET"], algorithms=[TOKEN_ALGORITHM])
    except jwt.ExpiredSignatureError:
        _reject("Token has expired. Please log in again", 401)
    except jwt.InvalidTokenError:
        _reject("Invalid authentication token", 401)

    user = db.session.get(User, int(payload["sub"]))
    if user is None:
        _reject("The user for this token no longer exists", 401)
    if user.account_status != "Active":
        _reject(
            f"Account is {user.account_status}. Contact an administrator",
            403, user.user_id, f"{user.username} ({user.role})",
        )
    return user


def get_optional_user():
    """For routes that work both logged in and logged out (like registration)."""
    return _user_from_token(raise_if_missing=False)


def reject_forbidden(user, message="User does not have permission to perform this operation"):
    """Use inside a route for ownership rules, e.g. an employee editing someone else's profile."""
    _reject(message, 403, user.user_id, f"{user.username} ({user.role})")


def roles_required(*allowed_roles):
    """Decorator: only users with one of these roles may call the route."""

    def decorator(route_function):
        @wraps(route_function)
        def wrapper(*args, **kwargs):
            user = _user_from_token()
            if user.role not in allowed_roles:
                reject_forbidden(user)
            g.current_user = user
            return route_function(*args, **kwargs)

        return wrapper

    return decorator
