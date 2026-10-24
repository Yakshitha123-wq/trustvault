from sqlalchemy import text

from app.db import get_engine


def _login_rows():
    with get_engine().connect() as conn:
        return conn.execute(text("SELECT count(*) FROM audit_log WHERE action = 'login'")).scalar()


def test_head_login_is_not_a_failed_login(client_for):
    before = _login_rows()
    r = client_for(None).head("/login")
    assert r.status_code == 200
    assert _login_rows() == before


def test_head_register_is_just_the_form(client_for):
    assert client_for(None).head("/register").status_code == 200