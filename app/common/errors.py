"""
One response format for the whole API.

Success: {"status": "success", "message": "...", "data": ...}
Error:   {"status": "error",   "message": "..."}

Any code can `raise ApiError("message", status_code)` and the handler below
turns it into a clean JSON error response.

Author: Mohammad Kourani
"""
from flask import jsonify
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException

from app.extensions import db


class ApiError(Exception):
    """An expected error with a message that is safe to show the client."""

    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def success(message, data=None, status_code=200):
    body = {"status": "success", "message": message}
    if data is not None:
        body["data"] = data
    return jsonify(body), status_code


def error(message, status_code):
    return jsonify({"status": "error", "message": message}), status_code


def register_error_handlers(app):
    @app.errorhandler(ApiError)
    def handle_api_error(api_error):
        db.session.rollback()
        return error(api_error.message, api_error.status_code)

    @app.errorhandler(IntegrityError)
    def handle_integrity_error(integrity_error):
        # A database rule (unique value, foreign key, allowed values) was broken.
        db.session.rollback()
        return error("The request conflicts with existing data", 409)

    @app.errorhandler(404)
    def handle_not_found(_):
        return error("Endpoint not found", 404)

    @app.errorhandler(405)
    def handle_method_not_allowed(_):
        return error("This HTTP method is not allowed on this endpoint", 405)

    @app.errorhandler(HTTPException)
    def handle_http_exception(http_exception):
        return error(http_exception.description, http_exception.code)

    @app.errorhandler(Exception)
    def handle_unexpected_error(unexpected_error):
        db.session.rollback()
        app.logger.exception(unexpected_error)
        return error("Internal server error", 500)
