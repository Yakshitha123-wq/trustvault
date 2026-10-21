import io
import uuid

import pytest
from sqlalchemy import text

from app.db import get_engine

PDF = b"%PDF-1.4\n% test file\n"


def _upload(client, content=PDF, filename="contract.pdf", category="contracts"):
    return client.post(
        "/documents",
        data={"file": (io.BytesIO(content), filename), "category": category},
        content_type="multipart/form-data")


def _audit_count(action, outcome, actor_id=None, document_id=None):
    sql = "SELECT count(*) FROM audit_log WHERE action = :a AND outcome = :o"
    params = {"a": action, "o": outcome}
    if actor_id is not None:
        sql += " AND actor_id = :u"
        params["u"] = actor_id
    if document_id is not None:
        sql += " AND document_id = :d"
        params["d"] = document_id
    with get_engine().connect() as conn:
        return conn.execute(text(sql), params).scalar()


# ---------- upload ----------

def test_owner_can_upload_and_download_the_same_bytes(client_for, people):
    c = client_for(people["owner"])
    r = _upload(c)
    assert r.status_code == 201
    d = c.get(f"/documents/{r.get_json()['id']}/download")
    assert d.status_code == 200
    assert d.data == PDF


def test_viewer_cannot_upload(client_for, people):
    assert _upload(client_for(people["reader"])).status_code == 403


def test_anonymous_cannot_upload(client_for):
    assert _upload(client_for(None)).status_code in (401, 302)


@pytest.mark.parametrize("filename,content", [
    ("evil.pdf", b"MZ\x90\x00 this is not a pdf"),
    ("page.html", b"<script>alert(1)</script>"),
    ("image.svg", b"<svg onload=alert(1)></svg>"),
    ("noextension", PDF),
    ("script.pdf.exe", PDF),
    ("fake.png", PDF),
])
def test_bad_uploads_are_rejected(client_for, people, filename, content):
    assert _upload(client_for(people["owner"]), content, filename).status_code == 400


def test_empty_file_is_rejected(client_for, people):
    assert _upload(client_for(people["owner"]), b"", "empty.pdf").status_code == 400


def test_oversized_upload_is_rejected(client_for, people):
    big = PDF + b"0" * (5 * 1024 * 1024 + 1)
    assert _upload(client_for(people["owner"]), big).status_code == 413


def test_filename_cannot_carry_a_path(client_for, people):
    c = client_for(people["owner"])
    r = _upload(c, filename="../../etc/passwd.pdf")
    assert r.status_code == 201
    name = c.get(f"/documents/{r.get_json()['id']}").get_json()["name"]
    assert "/" not in name and "\\" not in name and ".." not in name


def test_upload_response_does_not_leak_storage_key(client_for, people):
    assert "storage_key" not in _upload(client_for(people["owner"])).get_json()


def test_upload_is_audited(client_for, people):
    before = _audit_count("upload", "allowed", people["owner"])
    assert _upload(client_for(people["owner"])).status_code == 201
    assert _audit_count("upload", "allowed", people["owner"]) == before + 1


# ---------- download ----------

def test_download_is_sent_as_an_attachment_with_nosniff(client_for, people, doc):
    r = client_for(people["reader"]).get(f"/documents/{doc}/download")
    assert r.status_code == 200
    assert r.headers["Content-Disposition"].startswith("attachment")
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_stranger_cannot_download(client_for, people, doc):
    assert client_for(people["stranger"]).get(f"/documents/{doc}/download").status_code == 404


def test_anonymous_cannot_download(client_for, doc):
    assert client_for(None).get(f"/documents/{doc}/download").status_code in (401, 302)


def test_admin_cannot_download_contents(client_for, people, doc):
    assert client_for(people["admin"]).get(f"/documents/{doc}/download").status_code == 404


def test_revoked_download_is_immediate(client_for, people, doc):
    c = client_for(people["reader"])
    assert c.get(f"/documents/{doc}/download").status_code == 200
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM grants WHERE document_id = :d"), {"d": doc})
    assert c.get(f"/documents/{doc}/download").status_code == 404  # same cookie


def test_successful_download_is_audited(client_for, people, doc):
    before = _audit_count("download", "allowed", people["reader"], doc)
    assert client_for(people["reader"]).get(f"/documents/{doc}/download").status_code == 200
    assert _audit_count("download", "allowed", people["reader"], doc) == before + 1


def test_refused_download_is_audited(client_for, people, doc):
    before = _audit_count("document_access", "denied", people["stranger"], doc)
    client_for(people["stranger"]).get(f"/documents/{doc}/download")
    assert _audit_count("document_access", "denied", people["stranger"], doc) == before + 1
def test_admin_cannot_upload(client_for, people):
    assert _upload(client_for(people["admin"])).status_code == 403