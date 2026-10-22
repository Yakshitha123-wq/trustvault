import pytest
from sqlalchemy import text

from app import create_app
from app.auth import create_session
from app.db import get_engine

NOT_OWNERS = ["reader", "stranger", "admin", "other_owner"]


def _email(user_id):
    with get_engine().connect() as conn:
        return conn.execute(text("SELECT email FROM users WHERE id = :u"),
                            {"u": user_id}).scalar()


def _permission(doc, user_id):
    with get_engine().connect() as conn:
        return conn.execute(
            text("SELECT permission FROM grants WHERE document_id = :d AND user_id = :u"),
            {"d": doc, "u": user_id}).scalar()


def _grant(client, doc, email, permission="read"):
    return client.post(f"/documents/{doc}/grants",
                       data={"email": email, "permission": permission})


def _revoke(client, doc, user_id):
    return client.post(f"/documents/{doc}/grants/{user_id}/revoke")


def _audit_count(action, outcome, actor_id, document_id):
    with get_engine().connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM audit_log WHERE action = :a AND outcome = :o "
                 "AND actor_id = :u AND document_id = :d"),
            {"a": action, "o": outcome, "u": actor_id, "d": document_id}).scalar()


# ---------- the owner can share and take back ----------

def test_owner_grant_takes_effect_immediately(client_for, people, doc):
    stranger = client_for(people["stranger"])
    assert stranger.get(f"/documents/{doc}/download").status_code == 404
    r = _grant(client_for(people["owner"]), doc, _email(people["stranger"]))
    assert r.status_code == 200
    assert _permission(doc, people["stranger"]) == "read"
    assert stranger.get(f"/documents/{doc}/download").status_code == 200  # same cookie


def test_owner_can_upgrade_a_grant_to_edit(client_for, people, doc):
    c = client_for(people["owner"])
    _grant(c, doc, _email(people["stranger"]), "read")
    assert _grant(c, doc, _email(people["stranger"]), "edit").status_code == 200
    assert _permission(doc, people["stranger"]) == "edit"


def test_owner_revoke_takes_effect_immediately(client_for, people, doc):
    reader = client_for(people["reader"])
    assert reader.get(f"/documents/{doc}/download").status_code == 200
    assert _revoke(client_for(people["owner"]), doc, people["reader"]).status_code == 200
    assert _permission(doc, people["reader"]) is None
    assert reader.get(f"/documents/{doc}/download").status_code == 404  # same cookie


def test_owner_can_list_grants(client_for, people, doc):
    r = client_for(people["owner"]).get(f"/documents/{doc}/grants")
    assert r.status_code == 200
    grants = r.get_json()["grants"]
    assert [g["permission"] for g in grants] == ["read"]
    assert grants[0]["email"] == _email(people["reader"])


# ---------- nobody else can change who has access ----------

@pytest.mark.parametrize("who", NOT_OWNERS)
def test_non_owner_cannot_grant(client_for, people, doc, who):
    r = _grant(client_for(people[who]), doc, _email(people["stranger"]), "edit")
    assert r.status_code == 404
    assert _permission(doc, people["stranger"]) is None


def test_reader_cannot_upgrade_their_own_grant(client_for, people, doc):
    r = _grant(client_for(people["reader"]), doc, _email(people["reader"]), "edit")
    assert r.status_code == 404
    assert _permission(doc, people["reader"]) == "read"


def test_anonymous_cannot_grant(client_for, people, doc):
    r = _grant(client_for(None), doc, _email(people["stranger"]))
    assert r.status_code in (401, 302)
    assert _permission(doc, people["stranger"]) is None


@pytest.mark.parametrize("who", NOT_OWNERS)
def test_non_owner_cannot_revoke(client_for, people, doc, who):
    r = _revoke(client_for(people[who]), doc, people["reader"])
    assert r.status_code == 404
    assert _permission(doc, people["reader"]) == "read"


def test_anonymous_cannot_revoke(client_for, people, doc):
    r = _revoke(client_for(None), doc, people["reader"])
    assert r.status_code in (401, 302)
    assert _permission(doc, people["reader"]) == "read"


@pytest.mark.parametrize("who", NOT_OWNERS)
def test_non_owner_cannot_list_grants(client_for, people, doc, who):
    assert client_for(people[who]).get(f"/documents/{doc}/grants").status_code == 404
def test_anonymous_cannot_list_grants(client_for, doc):
    r = client_for(None).get(f"/documents/{doc}/grants")
    assert r.status_code in (401, 302)


# ---------- input checks (all by the real owner) ----------

@pytest.mark.parametrize("permission", ["owner", "admin", "delete", "", "READ "])
def test_invalid_permission_is_rejected(client_for, people, doc, permission):
    r = _grant(client_for(people["owner"]), doc, _email(people["stranger"]), permission)
    assert r.status_code == 400
    assert _permission(doc, people["stranger"]) is None


def test_unknown_email_is_rejected(client_for, people, doc):
    r = _grant(client_for(people["owner"]), doc, "nobody@test.example")
    assert r.status_code == 404
    assert "error" in r.get_json()  # a JSON error from our code, not a missing route


def test_owner_cannot_grant_to_themselves(client_for, people, doc):
    assert _grant(client_for(people["owner"]), doc, _email(people["owner"])).status_code == 400


def test_revoking_a_missing_grant_is_404(client_for, people, doc):
    r = _revoke(client_for(people["owner"]), doc, people["stranger"])
    assert r.status_code == 404
    assert "error" in r.get_json()


# ---------- the audit trail ----------

def test_grant_is_audited(client_for, people, doc):
    before = _audit_count("grant", "allowed", people["owner"], doc)
    _grant(client_for(people["owner"]), doc, _email(people["stranger"]))
    assert _audit_count("grant", "allowed", people["owner"], doc) == before + 1


def test_grant_audit_row_names_the_person_and_level(client_for, people, doc):
    _grant(client_for(people["owner"]), doc, _email(people["stranger"]), "edit")
    with get_engine().connect() as conn:
        row = conn.execute(
            text("SELECT target_user_id, detail FROM audit_log "
                 "WHERE action = 'grant' AND document_id = :d ORDER BY id DESC LIMIT 1"),
            {"d": doc}).mappings().first()
    assert row["target_user_id"] == people["stranger"]
    assert row["detail"]["permission"] == "edit"


def test_revoke_is_audited(client_for, people, doc):
    before = _audit_count("revoke", "allowed", people["owner"], doc)
    _revoke(client_for(people["owner"]), doc, people["reader"])
    assert _audit_count("revoke", "allowed", people["owner"], doc) == before + 1


def test_refused_grant_attempt_is_audited(client_for, people, doc):
    before = _audit_count("document_access", "denied", people["stranger"], doc)
    _grant(client_for(people["stranger"]), doc, _email(people["stranger"]), "edit")
    assert _audit_count("document_access", "denied", people["stranger"], doc) == before + 1


# ---------- CSRF stays on for these routes ----------

def _csrf_on_client(owner_id):
    app = create_app({"TESTING": True, "RATELIMIT_ENABLED": False})  # CSRF left ON
    c = app.test_client()
    c.set_cookie("tv_session", create_session(owner_id))
    return c


def test_grant_without_csrf_token_is_rejected(people, doc):
    r = _grant(_csrf_on_client(people["owner"]), doc, _email(people["stranger"]))
    assert r.status_code == 400
    assert _permission(doc, people["stranger"]) is None


def test_revoke_without_csrf_token_is_rejected(people, doc):
    r = _revoke(_csrf_on_client(people["owner"]), doc, people["reader"])
    assert r.status_code == 400
    assert _permission(doc, people["reader"]) == "read"