from sqlalchemy import text

from app.db import get_engine


def test_session_cookie_is_httponly_and_samesite(app, people):
    with get_engine().connect() as conn:
        email = conn.execute(text("SELECT email FROM users WHERE id = :u"),
                             {"u": people["owner"]}).scalar()
    r = app.test_client().post("/login", data={"email": email, "password": "x" * 12})
    assert r.status_code == 302
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
def test_csrf_cookie_is_samesite_lax(client_for):
    cookie = client_for(None).get("/login").headers.get("Set-Cookie", "")
    assert "SameSite=Lax" in cookie