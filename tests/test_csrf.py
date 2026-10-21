import io

from app import create_app
from app.auth import create_session


def test_post_without_csrf_token_is_rejected(people):
    app = create_app({"TESTING": True, "RATELIMIT_ENABLED": False})  # CSRF stays ON
    c = app.test_client()
    c.set_cookie("tv_session", create_session(people["owner"]))
    r = c.post("/documents",
               data={"file": (io.BytesIO(b"%PDF-1.4\n"), "a.pdf")},
               content_type="multipart/form-data")
    assert r.status_code == 400