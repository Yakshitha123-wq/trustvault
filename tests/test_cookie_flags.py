from app import create_app


def test_flask_session_cookie_is_secure_when_switched_on(monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "1")
    app = create_app({"TESTING": True, "RATELIMIT_ENABLED": False})
    r = app.test_client().get("/login", base_url="https://localhost")
    cookie = next(c for c in r.headers.getlist("Set-Cookie") if c.startswith("session="))
    assert "Secure" in cookie and "HttpOnly" in cookie