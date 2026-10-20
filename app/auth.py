import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import request
from sqlalchemy import text

from .db import get_engine

COOKIE_NAME = "tv_session"
SESSION_HOURS = 8

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id) -> str:
    """Make a random token, store only its hash, return the raw token for the cookie."""
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    with get_engine().begin() as conn:
        conn.execute(
            text("INSERT INTO sessions (token_hash, user_id, expires_at) "
                 "VALUES (:h, :u, :e)"),
            {"h": _hash_token(token), "u": user_id, "e": expires},
        )
    return token


def get_current_user():
    """Look the user up in the database on EVERY request. Returns a dict or None."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    with get_engine().connect() as conn:
        row = conn.execute(
            text("SELECT u.id, u.email, u.name, u.role, u.is_active "
                 "FROM sessions s JOIN users u ON u.id = s.user_id "
                 "WHERE s.token_hash = :h AND s.expires_at > now() AND u.is_active"),
            {"h": _hash_token(token)},
        ).mappings().first()
    return dict(row) if row else None


def delete_session(token: str) -> None:
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM sessions WHERE token_hash = :h"),
                     {"h": _hash_token(token)})


def delete_all_sessions(user_id) -> None:
    """Used when disabling a user or changing a password: kills every session at once."""
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM sessions WHERE user_id = :u"), {"u": user_id})