import os
import uuid

import pytest
from sqlalchemy import text

os.environ.setdefault("SECRET_KEY", "test-only-secret")

from app import create_app
from app.auth import create_session, hash_password
from app.db import get_engine


@pytest.fixture(scope="session", autouse=True)
def only_run_on_a_test_database():
    """Safety net: these tests create and delete rows, so refuse to touch anything else."""
    name = get_engine().url.database or ""
    if not name.endswith("_test"):
        pytest.exit(f"Refusing to run: database '{name}' is not a *_test database.",
                    returncode=2)


@pytest.fixture
def app():
    return create_app({"TESTING": True, "WTF_CSRF_ENABLED": False,
                       "RATELIMIT_ENABLED": False})


def _make_user(role):
    with get_engine().begin() as conn:
        return conn.execute(
            text("INSERT INTO users (email, name, password_hash, role) "
                 "VALUES (:e, :n, :p, :r) RETURNING id"),
            {"e": f"{uuid.uuid4().hex}@test.example", "n": role,
             "p": hash_password("x" * 12), "r": role}).scalar()


@pytest.fixture
def people():
    ids = {name: _make_user(role) for name, role in
           [("owner", "owner"), ("reader", "viewer"),
            ("stranger", "viewer"), ("admin", "admin")]}
    yield ids
    with get_engine().begin() as conn:  # audit rows stay, by design
        conn.execute(text("DELETE FROM documents WHERE owner_id = ANY(:ids)"),
                     {"ids": list(ids.values())})
        conn.execute(text("DELETE FROM users WHERE id = ANY(:ids)"),
                     {"ids": list(ids.values())})


@pytest.fixture
def client_for(app):
    """client_for(user_id) gives a test client that is logged in as that user,
    or an anonymous one for None. It skips the login form, CSRF and rate limit."""
    def make(user_id):
        c = app.test_client()
        if user_id:
            c.set_cookie("tv_session", create_session(user_id))
        return c
    return make


@pytest.fixture
def doc(people):
    """A document owned by `owner`, readable by `reader`, inserted directly."""
    with get_engine().begin() as conn:
        d = conn.execute(
            text("INSERT INTO documents (owner_id, name, storage_key, mime_type, "
                 "size_bytes, sha256) VALUES (:o, 'secret.pdf', :k, "
                 "'application/pdf', 3, 'x') RETURNING id"),
            {"o": people["owner"], "k": uuid.uuid4().hex}).scalar()
        conn.execute(
            text("INSERT INTO grants (document_id, user_id, permission, granted_by) "
                 "VALUES (:d, :u, 'read', :o)"),
            {"d": d, "u": people["reader"], "o": people["owner"]})
    return d