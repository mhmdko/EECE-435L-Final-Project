"""
Creates the Flask application.

Every folder in app/services/ that contains a routes.py with a Blueprint named
`bp` is registered automatically. Teammates add their service folder and it
appears in the API without anyone editing this file.

Author: Mohammad Kourani
"""
import importlib
import pkgutil

from flask import Flask

from app.common.errors import register_error_handlers, success
from app.config import Config
from app.extensions import db


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.json.sort_keys = False  # keep JSON fields in the order we write them

    config_class.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    register_error_handlers(app)

    registered_services = _register_service_blueprints(app)

    @app.get("/")
    def health_check():
        """Author: Mohammad Kourani. Confirms the API is running and lists loaded services."""
        return success(
            "Security Incident Response API is running",
            {"services": registered_services},
        )

    return app


def _register_service_blueprints(app):
    """Find app/services/<name>/routes.py files and register their `bp` blueprint."""
    from app import services

    service_names = []
    for module_info in pkgutil.iter_modules(services.__path__):
        if not module_info.ispkg:
            continue
        routes_module_name = f"app.services.{module_info.name}.routes"
        try:
            routes_module = importlib.import_module(routes_module_name)
        except ModuleNotFoundError as error:
            if error.name == routes_module_name:
                continue  # service folder exists but has no routes yet
            raise
        blueprint = getattr(routes_module, "bp", None)
        if blueprint is not None:
            app.register_blueprint(blueprint)
            service_names.append(module_info.name)
    return sorted(service_names)
