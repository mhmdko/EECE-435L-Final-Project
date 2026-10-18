"""
Users and Identity Management Service: 6 endpoints.

    POST   /users/register      register a new user
    POST   /users/login         log in and receive a token
    PUT    /users/<id>          update user information
    DELETE /users/<id>          delete a user
    GET    /users               list all users
    GET    /users/<username>    get one user by username

Author: Mohammad Kourani
"""
import re

from flask import Blueprint, g
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app.common.auth import (
    ADMIN, ALL_ROLES, AUDITOR, EMPLOYEE,
    create_token, get_optional_user, reject_forbidden, roles_required,
)
from app.common.errors import ApiError, success
from app.common.time_utils import utc_now
from app.common.validation import get_json_body, require_choice, require_email, require_text
from app.extensions import db
from app.services.logs.service import log_event
from app.services.users.models import ACCOUNT_STATUSES, User

bp = Blueprint("users", __name__, url_prefix="/users")

SERVICE = "Users"
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._]{3,30}$")


# ---------- helpers ----------

def _validate_password(password):
    """At least 8 characters with a letter, a number, and a symbol."""
    if not isinstance(password, str):
        raise ApiError("'password' must be text", 400)
    if (
        len(password) < 8
        or not re.search(r"[A-Za-z]", password)
        or not re.search(r"\d", password)
        or not re.search(r"[^A-Za-z0-9]", password)
    ):
        raise ApiError(
            "Password must be at least 8 characters and include a letter, a number, and a symbol",
            400,
        )


def _find_by_username(username):
    return User.query.filter(func.lower(User.username) == username.lower()).first()


def _email_taken(email, ignore_user_id=None):
    query = User.query.filter(func.lower(User.email) == email.lower())
    if ignore_user_id is not None:
        query = query.filter(User.user_id != ignore_user_id)
    return query.first() is not None


def _get_user_or_404(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        raise ApiError(f"User with id {user_id} not found", 404)
    return user


# ---------- 1. User Registration ----------

@bp.post("/register")
def register_user():
    """
    Author: Mohammad Kourani
    Create a new user account.
    Who can call it: anyone can self-register as a Regular Employee;
    only a logged-in Security Administrator can create other roles.
    Body: full_name, username, email, password, department, role
    """
    actor = get_optional_user()  # None when the caller is not logged in
    if actor is not None and actor.role not in (ADMIN, EMPLOYEE):
        reject_forbidden(actor)

    body = get_json_body(required=("full_name", "username", "email", "password", "department", "role"))
    full_name = require_text(body["full_name"], "full_name", 100)
    username = require_text(body["username"], "username", 30)
    email = require_email(body["email"])
    password = body["password"]
    department = require_text(body["department"], "department", 100)
    role = require_choice(body["role"], "role", ALL_ROLES)

    if not USERNAME_PATTERN.match(username):
        raise ApiError("Username must be 3 to 30 characters: letters, numbers, dots, or underscores", 400)
    _validate_password(password)

    if role != EMPLOYEE and (actor is None or actor.role != ADMIN):
        message = "Only a Security Administrator can create accounts with this role"
        if actor is None:
            log_event(None, "UNAUTHORIZED_ACCESS",
                      f"Anonymous self-registration as '{role}' was denied", "Warning", SERVICE)
            raise ApiError(message, 403)
        reject_forbidden(actor, message)

    # Duplicate usernames: checked here for a clear message, and also blocked
    # by the UNIQUE constraint on users.username in the database.
    if _find_by_username(username):
        raise ApiError(f"Username '{username}' is already taken", 409)
    if _email_taken(email):
        raise ApiError(f"Email '{email}' is already registered", 409)

    new_user = User(
        full_name=full_name, username=username, email=email,
        department=department, role=role, account_status="Active",
    )
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    created_by = actor.username if actor else "self-registration"
    log_event(
        actor.user_id if actor else new_user.user_id, "USER_CREATED",
        f"User '{new_user.username}' ({new_user.role}) created by {created_by}",
        "Information", SERVICE,
    )
    return success("User registered successfully", new_user.to_dict(), 201)


# ---------- 2. User Login ----------

@bp.post("/login")
def login():
    """
    Author: Mohammad Kourani
    Check a username (or email) and password, and return a login token.
    Who can call it: anyone with an Active account.
    Body: username or email, password
    """
    body = get_json_body(required=("password",), optional=("username", "email"))
    identifier = body.get("username") or body.get("email")
    if not identifier or not isinstance(identifier, str):
        raise ApiError("Provide a username or email", 400)
    password = body["password"]
    if not isinstance(password, str):
        raise ApiError("'password' must be text", 400)

    user = User.query.filter(or_(
        func.lower(User.username) == identifier.lower(),
        func.lower(User.email) == identifier.lower(),
    )).first()

    # Same message whether the username or the password is wrong,
    # so attackers cannot tell which usernames exist.
    if user is None or not user.check_password(password):
        log_event(user.user_id if user else None, "LOGIN_FAILED",
                  f"Failed login attempt for '{identifier}'", "Warning", SERVICE)
        raise ApiError("Invalid username or password", 401)

    if user.account_status != "Active":
        log_event(user.user_id, "LOGIN_FAILED",
                  f"Login blocked for '{user.username}': account is {user.account_status}",
                  "Warning", SERVICE)
        raise ApiError(f"Account is {user.account_status}. Contact an administrator", 403)

    user.last_login_date = utc_now()
    db.session.commit()
    log_event(user.user_id, "LOGIN_SUCCESS", f"'{user.username}' logged in", "Information", SERVICE)

    return success("Login successful", {
        "token": create_token(user),
        "token_type": "Bearer",
        "user": user.to_dict(),
    })


# ---------- 3. Update User Information ----------

@bp.put("/<int:user_id>")
@roles_required(ADMIN, EMPLOYEE)
def update_user(user_id):
    """
    Author: Mohammad Kourani
    Update a user's name, email, or department.
    Who can call it: Security Administrator (any user), Regular Employee (own account only).
    Only an administrator may also change role or account_status.
    Body (at least one): full_name, email, department, role, account_status
    """
    actor = g.current_user
    target_user = _get_user_or_404(user_id)

    if actor.role == EMPLOYEE and actor.user_id != target_user.user_id:
        reject_forbidden(actor, "You can only update your own information")

    body = get_json_body(optional=("full_name", "email", "department", "role", "account_status"))
    if not body:
        raise ApiError("Provide at least one field to update: full_name, email, department", 400)

    admin_only_fields = [field for field in ("role", "account_status") if field in body]
    if admin_only_fields and actor.role != ADMIN:
        reject_forbidden(actor, "Only a Security Administrator can change roles or account status")

    changes = []
    if "full_name" in body:
        target_user.full_name = require_text(body["full_name"], "full_name", 100)
        changes.append("full_name")
    if "email" in body:
        new_email = require_email(body["email"])
        if _email_taken(new_email, ignore_user_id=target_user.user_id):
            raise ApiError(f"Email '{new_email}' is already registered", 409)
        target_user.email = new_email
        changes.append("email")
    if "department" in body:
        target_user.department = require_text(body["department"], "department", 100)
        changes.append("department")

    old_role = target_user.role
    if "role" in body:
        new_role = require_choice(body["role"], "role", ALL_ROLES)
        if target_user.user_id == actor.user_id and new_role != ADMIN:
            raise ApiError("You cannot remove your own administrator role", 400)
        target_user.role = new_role

    old_status = target_user.account_status
    if "account_status" in body:
        new_status = require_choice(body["account_status"], "account_status", ACCOUNT_STATUSES)
        if target_user.user_id == actor.user_id and new_status != "Active":
            raise ApiError("You cannot deactivate your own account", 400)
        target_user.account_status = new_status

    db.session.commit()

    if changes:
        log_event(actor.user_id, "USER_UPDATED",
                  f"'{actor.username}' updated {', '.join(changes)} of user '{target_user.username}'",
                  "Information", SERVICE)
    if target_user.role != old_role:
        log_event(actor.user_id, "ROLE_CHANGED",
                  f"Role of '{target_user.username}' changed from {old_role} to {target_user.role}",
                  "Warning", SERVICE)
    if target_user.account_status != old_status:
        log_event(actor.user_id, "ACCOUNT_STATUS_CHANGED",
                  f"Status of '{target_user.username}' changed from {old_status} to {target_user.account_status}",
                  "Warning", SERVICE)

    return success("User updated successfully", target_user.to_dict())


# ---------- 4. Delete User ----------

@bp.delete("/<int:user_id>")
@roles_required(ADMIN)
def delete_user(user_id):
    """
    Author: Mohammad Kourani
    Delete a user account.
    Who can call it: Security Administrator only.
    The user's notifications are deleted with them; their audit logs are kept.
    """
    actor = g.current_user
    target_user = _get_user_or_404(user_id)
    if target_user.user_id == actor.user_id:
        raise ApiError("You cannot delete your own account", 400)

    deleted_summary = f"'{target_user.username}' ({target_user.role})"
    db.session.delete(target_user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise ApiError(
            "This user is still linked to other records (for example assets or incidents). "
            "Reassign those records first", 409,
        )

    log_event(actor.user_id, "USER_DELETED", f"User {deleted_summary} deleted by '{actor.username}'",
              "Warning", SERVICE)
    return success(f"User {deleted_summary} deleted successfully")


# ---------- 5. Retrieve All Users ----------

@bp.get("")
@roles_required(ADMIN, AUDITOR)
def get_all_users():
    """
    Author: Mohammad Kourani
    List every registered user (without password hashes).
    Who can call it: Security Administrator, Auditor.
    """
    users = User.query.order_by(User.user_id).all()
    return success(f"{len(users)} user(s) found", {
        "count": len(users),
        "users": [user.to_dict() for user in users],
    })


# ---------- 6. Retrieve User By Username ----------

@bp.get("/<string:username>")
@roles_required(ADMIN, AUDITOR, EMPLOYEE)
def get_user_by_username(username):
    """
    Author: Mohammad Kourani
    Get one user's information by username.
    Who can call it: Security Administrator, Auditor, Regular Employee (own account only).
    """
    actor = g.current_user
    if actor.role == EMPLOYEE and actor.username.lower() != username.lower():
        reject_forbidden(actor, "You can only view your own information")

    user = _find_by_username(username)
    if user is None:
        raise ApiError(f"User '{username}' not found", 404)
    return success("User found", user.to_dict())
