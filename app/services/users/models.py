"""
User model: one row of the `users` table.

Variables (columns):
    user_id          unique number for each user (primary key)
    full_name        the person's full name
    username         login name, unique, case-insensitive
    email            unique email address
    password_hash    the hashed password; the plain password is never stored
    department       the department the user works in
    role             Security Administrator, Security Analyst, Regular Employee, or Auditor
    account_status   Active, Inactive, or Suspended; only Active users can log in
    created_date     when the account was created
    last_login_date  when the user last logged in successfully (user activity)

Author: Mohammad Kourani
"""
from werkzeug.security import check_password_hash, generate_password_hash

from app.common.time_utils import to_text, utc_now
from app.extensions import db

ACCOUNT_STATUSES = ("Active", "Inactive", "Suspended")


class User(db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(30), nullable=False)
    account_status = db.Column(db.String(20), nullable=False, default="Active")
    created_date = db.Column(db.DateTime, nullable=False, default=utc_now)
    last_login_date = db.Column(db.DateTime)

    def set_password(self, plain_password):
        """Hash the password (salted scrypt) and keep only the hash."""
        self.password_hash = generate_password_hash(plain_password)

    def check_password(self, plain_password):
        """Hash the given password the same way and compare it with the stored hash."""
        return check_password_hash(self.password_hash, plain_password)

    def to_dict(self):
        """Data returned by the API. The password hash is deliberately left out."""
        return {
            "user_id": self.user_id,
            "full_name": self.full_name,
            "username": self.username,
            "email": self.email,
            "department": self.department,
            "role": self.role,
            "account_status": self.account_status,
            "created_date": to_text(self.created_date),
            "last_login_date": to_text(self.last_login_date),
        }
