from pathlib import Path

from sqlalchemy import text

from app import create_app
from app.db import get_engine


def _logged_ip(doc):
    with get_engine().connect() as conn:
        return str(conn.execute(
            text("SELECT ip FROM audit_log WHERE action = 'document_access' "
                 "AND document_id = :d ORDER BY id DESC LIMIT 1"), {"d": doc}).scalar())


def _probe(doc, config, headers):
    app = create_app({"TESTING": True, "RATELIMIT_ENABLED": False, **config})
    r = app.test_client().get(f"/documents/{doc}", headers=headers,
                              environ_overrides={"REMOTE_ADDR": "10.9.9.9"})
    assert r.status_code == 401          # anonymous: refused and audited
    return _logged_ip(doc)


def test_header_is_ignored_unless_trusted(doc):
    assert _probe(doc, {}, {"CF-Connecting-IP": "203.0.113.7"}) == "10.9.9.9"


def test_trusted_header_gives_the_real_address(doc):
    assert _probe(doc, {"TRUST_CF_CONNECTING_IP": True},
                  {"CF-Connecting-IP": "203.0.113.7"}) == "203.0.113.7"


def test_garbage_in_the_trusted_header_falls_back(doc):
    assert _probe(doc, {"TRUST_CF_CONNECTING_IP": True},
                  {"CF-Connecting-IP": "not-an-ip"}) == "10.9.9.9"


def test_no_code_reads_remote_addr_directly():
    app_dir = Path(__file__).resolve().parent.parent / "app"
    for py in app_dir.rglob("*.py"):
        if py.name != "clientip.py":
            assert "request.remote_addr" not in py.read_text(encoding="utf-8"), py.name