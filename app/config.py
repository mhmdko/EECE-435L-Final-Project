"""
Configuration loaded from the .env file.

Secrets (SECRET_KEY, JWT_SECRET) are never written in the code. They live in
.env, which Git ignores, so they cannot leak to GitHub.

Author: Mohammad Kourani
"""
import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_DIR / ".env")


def _require(name):
    """Read a required setting from the environment, or stop with a clear message."""
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Missing setting '{name}'. Copy .env.example to .env and fill it in."
        )
    return value


class Config:
    SECRET_KEY = _require("SECRET_KEY")
    JWT_SECRET = _require("JWT_SECRET")
    TOKEN_EXPIRY_HOURS = int(os.getenv("TOKEN_EXPIRY_HOURS", "8"))

    DATABASE_PATH = PROJECT_DIR / os.getenv("DATABASE_PATH", "instance/security.db")
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATABASE_PATH.as_posix()}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
