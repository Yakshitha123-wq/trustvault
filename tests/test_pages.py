import re
from pathlib import Path

import pytest
from sqlalchemy import text

from app import create_app
from app.auth import create_session
from app.db import get_engine

STATIC = Path(__file__).resolve().parent.parent / "app" / "static"


# ---------- who may open a page ----------

@pytest.mark.parametrize("path", ["/app", "/app/upload", "/app/admin"])
def test_anonymous_is_sent_to_login(client_for, path):
    r = client_for(None).get(path)
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_document_page_sends_anonymous_to_login(client_for, doc):
    r = client_for(None).get(f"/app/documents/{doc}")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_only_an_admin_opens_the_admin_page(client_for, people):
    for who in ("owner", "reader", "stranger", "other_owner"):
        assert client_for(people[who]).get("/app/admin").status_code == 404
    assert client_for(people["admin"]).get("/app/admin").status_code == 200


def test_malformed_document_id_is_404(client_for, people):
    assert client_for(people["owner"]).get("/app/documents/not-a-uuid").status_code == 404


def test_pages_carry_no_document_data(client_for, people, doc):
    for who in ("owner", "reader", "stranger", "admin"):
        c = client_for(people[who])
        for path in ("/app", f"/app/documents/{doc}"):
            assert "secret.pdf" not in c.get(path).get_data(as_text=True)


def test_login_lands_on_the_documents_page(app, people):
    with get_engine().connect() as conn:
        email = conn.execute(text("SELECT email FROM users WHERE id = :u"),
                             {"u": people["owner"]}).scalar()
    r = app.test_client().post("/login", data={"email": email, "password": "x" * 12})
    assert r.status_code == 302 and r.headers["Location"].endswith("/app")


# ---------- nothing inline, nothing built from data ----------

def test_pages_have_no_inline_script_or_style(client_for, people, doc):
    cases = [(None, "/login"), (None, "/register"),
             ("owner", "/app"), ("owner", "/app/upload"),
             ("owner", f"/app/documents/{doc}"), ("admin", "/app/admin")]
    for who, path in cases:
        html = client_for(people[who] if who else None).get(path).get_data(as_text=True)
        assert not re.search(r"<script(?![^>]*\ssrc=)", html), path
        assert "<style" not in html, path
        assert not re.search(r"\son[a-z]+\s*=", html, re.I), path
        assert not re.search(r"\sstyle\s*=", html, re.I), path


def test_javascript_never_builds_html_from_data():
    files = sorted(STATIC.glob("*.js"))
    assert len(files) >= 5, "expected app.js and four page scripts"
    for js in files:
        source = js.read_text(encoding="utf-8")
        for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                    "document.write", "eval(", "new Function"):
            assert bad not in source, f"{js.name} uses {bad}"


# ---------- headers ----------

def test_csp_allows_only_our_own_scripts(client_for):
    csp = client_for(None).get("/login").headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "object-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp and "base-uri 'none'" in csp


def test_security_headers_on_every_kind_of_response(client_for, people, doc):
    c = client_for(people["owner"])
    for path in ("/login", "/app", "/documents", f"/documents/{doc}", "/health", "/nothing-here"):
        h = c.get(path).headers
        assert h["X-Content-Type-Options"] == "nosniff", path
        assert h["X-Frame-Options"] == "DENY", path
        assert h["Referrer-Policy"] == "same-origin", path
        assert "Content-Security-Policy" in h, path


def test_dynamic_responses_are_not_cached(client_for, people, doc):
    c = client_for(people["owner"])
    for path in ("/app", "/documents", f"/documents/{doc}"):
        assert "no-store" in c.get(path).headers["Cache-Control"], path


def test_hsts_only_over_https(client_for):
    c = client_for(None)
    assert "Strict-Transport-Security" not in c.get("/health").headers
    assert "max-age" in c.get("/health", base_url="https://localhost").headers["Strict-Transport-Security"]


# ---------- the token the page carries really works ----------

def test_csrf_token_from_the_page_works_in_the_header(people, doc):
    app = create_app({"TESTING": True, "RATELIMIT_ENABLED": False})  # CSRF stays ON
    c = app.test_client()
    c.set_cookie("tv_session", create_session(people["owner"]))
    html = c.get("/app").get_data(as_text=True)
    token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
    r = c.post(f"/documents/{doc}/edit", data={"name": "renamed.pdf"},
               headers={"X-CSRFToken": token})
    assert r.status_code == 200
    assert c.post(f"/documents/{doc}/edit", data={"name": "again.pdf"}).status_code == 400