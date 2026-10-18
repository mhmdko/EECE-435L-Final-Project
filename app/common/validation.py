"""
Input validation helpers shared by every service.

They reject bad input before it reaches the database: non-JSON bodies,
unexpected fields, missing fields, wrong types, and values outside the
allowed lists. Database queries go through SQLAlchemy, which uses
parameterized queries, so user input is never pasted into SQL text
(this blocks SQL injection).

Author: Mohammad Kourani
"""
import re
from datetime import datetime

from flask import request

from app.common.errors import ApiError

EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def get_json_body(required=(), optional=()):
    """
    Read the JSON request body and check its fields.

    required: fields that must be present and not empty
    optional: fields that may be present
    Any other field is rejected, so clients cannot sneak in extra data.
    Text values are returned with surrounding spaces removed.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ApiError("Request body must be a valid JSON object", 400)

    allowed_fields = set(required) | set(optional)
    unexpected_fields = sorted(set(body) - allowed_fields)
    if unexpected_fields:
        raise ApiError(f"Unexpected field(s): {', '.join(unexpected_fields)}", 400)

    cleaned_body = {
        field: value.strip() if isinstance(value, str) else value
        for field, value in body.items()
    }

    missing_fields = [
        field for field in required
        if cleaned_body.get(field) is None or cleaned_body.get(field) == ""
    ]
    if missing_fields:
        raise ApiError(f"Missing required field(s): {', '.join(missing_fields)}", 400)

    return cleaned_body


def require_text(value, field_name, max_length=255):
    """The value must be non-empty text no longer than max_length."""
    if not isinstance(value, str) or not value:
        raise ApiError(f"'{field_name}' must be non-empty text", 400)
    if len(value) > max_length:
        raise ApiError(f"'{field_name}' must be at most {max_length} characters", 400)
    return value


def require_choice(value, field_name, allowed_values):
    """The value must be one of the allowed values (exact spelling)."""
    if value not in allowed_values:
        raise ApiError(
            f"Invalid {field_name} '{value}'. Allowed values: {', '.join(allowed_values)}", 400
        )
    return value


def require_int(value, field_name):
    """The value must be a whole number (also accepts digits sent as text)."""
    if isinstance(value, bool):
        raise ApiError(f"'{field_name}' must be a whole number", 400)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    raise ApiError(f"'{field_name}' must be a whole number", 400)


def require_email(value):
    require_text(value, "email", 120)
    if not EMAIL_PATTERN.match(value):
        raise ApiError("Invalid email format", 400)
    return value.lower()


def require_date(value, field_name):
    """The value must be a date written as YYYY-MM-DD."""
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        raise ApiError(f"'{field_name}' must be a date in YYYY-MM-DD format", 400)
