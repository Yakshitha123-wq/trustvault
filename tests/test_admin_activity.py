import io
import json

import pytest
from sqlalchemy import text

from app.db import get_engine


def _email(user_id):
    with get_engine().connect() as conn:
        return conn.execute(text("SELECT email FROM users WHERE id = :u"),
                            {"u": user_id}).scalar()


def _audit_count(action, outcome, actor_id):
    with get_engine().connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM audit_log WHERE action = :a AND outcome = :o "
                 "AND actor_id = :u"),
            {"a": action, "o": outcome, "u": actor_id}).scalar()


def _get(client, params=None):
    return client.get("/admin/activity", query_string=params or {})


def _events(client, params=None):
    r = _get(client, params)
    assert r.status_code == 200
    return r.get_json()["events"]


def _make_history(client_for, people, doc):
    """Real actions through the real routes: an allowed download, a grant, a revoke,
    and a refused download. Audit rows stay forever, so tests filter by document_id."""
    assert client_for(people["reader"]).get(f"/documents/{doc}/download").status_code == 200
    owner = client_for(people["owner"])
    assert owner.post(f"/documents/{doc}/grants",
                      data={"email": _email(people["stranger"]),
                            "permission": "read"}).status_code == 200
    assert owner.post(f"/documents/{doc}/grants/{people['stranger']}/revoke").status_code == 200
    assert client_for(people["stranger"]).get(f"/documents/{doc}/download").status_code == 404


# ---------- who may look ----------

def test_anonymous_is_refused(client_for):
    assert _get(client_for(None)).status_code in (401, 302)
    assert client_for(None).get("/admin/audit/verify").status_code in (401, 302)


@pytest.mark.parametrize("who", ["owner", "reader", "stranger", "other_owner"])
def test_non_admins_get_404(client_for, people, who):
    c = client_for(people[who])
    assert _get(c).status_code == 404
    assert c.get("/admin/audit/verify").status_code == 404


def test_refused_admin_attempt_is_audited(client_for, people):
    before = _audit_count("admin_access", "denied", people["stranger"])
    _get(client_for(people["stranger"]))
    assert _audit_count("admin_access", "denied", people["stranger"]) == before + 1


# ---------- what the admin sees ----------

def test_admin_sees_the_history_of_a_document(client_for, people, doc):
    _make_history(client_for, people, doc)
    events = _events(client_for(people["admin"]), {"document_id": str(doc)})
    pairs = {(e["action"], e["outcome"]) for e in events}
    assert ("download", "allowed") in pairs
    assert ("grant", "allowed") in pairs
    assert ("revoke", "allowed") in pairs
    assert ("document_access", "denied") in pairs      # refused attempts are recorded
    assert all(e["document_id"] == str(doc) for e in events)


def test_permission_changes_name_who_did_it_and_to_whom(client_for, people, doc):
    _make_history(client_for, people, doc)
    events = _events(client_for(people["admin"]), {"document_id": str(doc), "action": "grant"})
    assert len(events) == 1
    assert events[0]["actor_id"] == str(people["owner"])
    assert events[0]["target_user_id"] == str(people["stranger"])


def test_newest_first(client_for, people, doc):
    _make_history(client_for, people, doc)
    ids = [e["id"] for e in _events(client_for(people["admin"]), {"document_id": str(doc)})]
    assert ids == sorted(ids, reverse=True) and len(ids) >= 4


# ---------- filters ----------

def test_filters(client_for, people, doc):
    _make_history(client_for, people, doc)
    admin = client_for(people["admin"])
    denied = _events(admin, {"document_id": str(doc), "outcome": "denied"})
    assert denied and all(e["outcome"] == "denied" for e in denied)
    by_owner = _events(admin, {"document_id": str(doc), "actor_id": str(people["owner"])})
    assert by_owner and all(e["actor_id"] == str(people["owner"]) for e in by_owner)
    only_grants = _events(admin, {"document_id": str(doc), "action": "grant"})
    assert only_grants and all(e["action"] == "grant" for e in only_grants)


def test_date_filters(client_for, people, doc):
    _make_history(client_for, people, doc)
    admin = client_for(people["admin"])
    assert _events(admin, {"document_id": str(doc), "from": "2000-01-01"})
    assert _events(admin, {"document_id": str(doc), "from": "2100-01-01"}) == []
    assert _events(admin, {"document_id": str(doc), "to": "2000-01-01"}) == []


@pytest.mark.parametrize("params", [
    {"document_id": "not-a-uuid"}, {"actor_id": "x"}, {"outcome": "maybe"},
    {"from": "not-a-date"}, {"to": "2020-13-45"}, {"limit": "abc"}, {"limit": "0"},
    {"before_id": "x"},
])
def test_bad_filters_are_400(client_for, people, params):
    r = _get(client_for(people["admin"]), params)
    assert r.status_code == 400
    assert "error" in r.get_json()


@pytest.mark.parametrize("field", ["action", "outcome_text"])
def test_odd_filter_text_is_harmless(client_for, people, doc, field):
    r = _get(client_for(people["admin"]),
             {"action": "' OR '1'='1" if field == "action" else "x'; DROP TABLE audit_log; --"})
    assert r.status_code in (200, 400)
    if r.status_code == 200:
        assert r.get_json()["events"] == []
    assert client_for(people["admin"]).get("/admin/audit/verify").status_code == 200  # table still there

def test_limit_is_respected_and_capped(client_for, people, doc, monkeypatch):
    _make_history(client_for, people, doc)
    monkeypatch.setattr("app.routes.admin.MAX_LIMIT", 3)
    admin = client_for(people["admin"])
    assert len(_events(admin, {"document_id": str(doc), "limit": "2"})) == 2
    assert len(_events(admin, {"document_id": str(doc), "limit": "100000"})) == 3

def test_paging_with_before_id(client_for, people, doc):
    _make_history(client_for, people, doc)
    admin = client_for(people["admin"])
    page1 = _get(admin, {"document_id": str(doc), "limit": "2"}).get_json()
    assert page1["next_before_id"] is not None
    page2 = _events(admin, {"document_id": str(doc), "limit": "2",
                            "before_id": str(page1["next_before_id"])})
    assert page2 and max(e["id"] for e in page2) < min(e["id"] for e in page1["events"])


# ---------- what the admin must not see ----------

def test_no_hashes_or_storage_keys(client_for, people):
    owner = client_for(people["owner"])
    r = owner.post("/documents", data={"file": (io.BytesIO(b"%PDF-1.4\n% x\n"), "u.pdf")},
                   content_type="multipart/form-data")
    assert r.status_code == 201
    new_id = r.get_json()["id"]
    events = _events(client_for(people["admin"]), {"document_id": new_id})
    assert any(e["action"] == "upload" for e in events)
    assert "sha256" not in json.dumps(events)
    assert "storage_key" not in json.dumps(events)
    assert "row_hash" not in json.dumps(events) and "prev_hash" not in json.dumps(events)
    with get_engine().begin() as conn:      # clean up the document made through the route
        conn.execute(text("DELETE FROM documents WHERE id = :d"), {"d": new_id})


# ---------- reading the trail is itself audited ----------

def test_viewing_the_activity_is_audited(client_for, people):
    before = _audit_count("audit_view", "allowed", people["admin"])
    _get(client_for(people["admin"]))
    assert _audit_count("audit_view", "allowed", people["admin"]) == before + 1


def test_verify_reports_an_intact_chain_and_is_audited(client_for, people):
    before = _audit_count("audit_verify", "allowed", people["admin"])
    r = client_for(people["admin"]).get("/admin/audit/verify")
    assert r.status_code == 200
    assert r.get_json() == {"intact": True, "first_bad_row": None}
    assert _audit_count("audit_verify", "allowed", people["admin"]) == before + 1