from sqlalchemy import text

from app.db import get_engine
   

MISSING = "00000000-0000-0000-0000-000000000000"


def _denied_count(actor_id):
    with get_engine().connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM audit_log WHERE actor_id = :a "
                 "AND action = 'document_access' AND outcome = 'denied'"),
            {"a": actor_id}).scalar()


def test_stranger_gets_404(client_for, people, doc):
    assert client_for(people["stranger"]).get(f"/documents/{doc}").status_code == 404


def test_anonymous_is_refused(client_for, doc):
    assert client_for(None).get(f"/documents/{doc}").status_code in (401, 302)


def test_reader_can_see_metadata(client_for, people, doc):
    r = client_for(people["reader"]).get(f"/documents/{doc}")
    assert r.status_code == 200
    assert r.get_json()["name"] == "secret.pdf"


def test_owner_can_see_metadata(client_for, people, doc):
    assert client_for(people["owner"]).get(f"/documents/{doc}").status_code == 200


def test_admin_can_see_metadata_only(client_for, people, doc):
    r = client_for(people["admin"]).get(f"/documents/{doc}")
    assert r.status_code == 200
    assert "storage_key" not in r.get_json()


def test_missing_and_forbidden_look_identical(client_for, people, doc):
    c = client_for(people["stranger"])
    forbidden = c.get(f"/documents/{doc}")
    missing = c.get(f"/documents/{MISSING}")
    assert forbidden.status_code == missing.status_code == 404
    assert forbidden.data == missing.data

def test_not_a_uuid_is_404_not_500(client_for, people):
    assert client_for(people["owner"]).get("/documents/not-a-uuid").status_code == 404


def test_revocation_is_immediate(client_for, people, doc):
    c = client_for(people["reader"])
    assert c.get(f"/documents/{doc}").status_code == 200
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM grants WHERE document_id = :d"), {"d": doc})
    assert c.get(f"/documents/{doc}").status_code == 404  # same client, same cookie


def test_refused_attempt_is_audited(client_for, people, doc):
    before = _denied_count(people["stranger"])
    client_for(people["stranger"]).get(f"/documents/{doc}")
    assert _denied_count(people["stranger"]) == before + 1

def test_detail_says_what_the_caller_may_do(client_for, people, doc):
    def can(who):
        return client_for(people[who]).get(f"/documents/{doc}").get_json()["can"]
    assert can("owner") == {"read": True, "edit": True, "delete": True, "share": True}
    assert can("reader") == {"read": True, "edit": False, "delete": False, "share": False}
    assert can("admin") == {"read": False, "edit": False, "delete": False, "share": False}


def test_an_editor_may_read_and_edit_only(client_for, people, doc):
    with get_engine().begin() as conn:
        conn.execute(text("UPDATE grants SET permission = 'edit' "
                          "WHERE document_id = :d AND user_id = :u"),
                     {"d": doc, "u": people["reader"]})
    can = client_for(people["reader"]).get(f"/documents/{doc}").get_json()["can"]
    assert can == {"read": True, "edit": True, "delete": False, "share": False}