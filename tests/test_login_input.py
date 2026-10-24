import uuid

from sqlalchemy import text

from app.db import get_engine


def test_login_audit_row_never_stores_a_huge_email(app):
    marker = uuid.uuid4().hex
    huge = marker + "a" * 10000 + "@example.com"
    r = app.test_client().post("/login", data={"email": huge, "password": "x" * 12})
    assert r.status_code == 401
    with get_engine().connect() as conn:
        longest = conn.execute(
            text("SELECT max(length(detail->>'email')) FROM audit_log "
                 "WHERE action = 'login' AND detail->>'email' LIKE :m"),
            {"m": marker + "%"}).scalar()
    assert longest is not None, "no audit row was written"
    assert longest <= 254