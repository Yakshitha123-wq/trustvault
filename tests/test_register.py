import uuid

from sqlalchemy import text

from app.db import get_engine


def test_register_ignores_a_role_field(app):
    email = f"{uuid.uuid4().hex}@test.example"
    try:
        r = app.test_client().post(
            "/register",
            data={"name": "Mallory", "email": email, "password": "x" * 12, "role": "admin"})
        assert r.status_code == 302
        with get_engine().connect() as conn:
            role = conn.execute(text("SELECT role FROM users WHERE email = :e"),
                                {"e": email}).scalar()
        assert role == "viewer"
    finally:
        with get_engine().begin() as conn:
            conn.execute(text("DELETE FROM users WHERE email = :e"), {"e": email})