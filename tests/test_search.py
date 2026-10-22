import uuid

import pytest
from sqlalchemy import text

from app.authz import authorize
from app.db import get_engine


def _make_doc(owner_id, name, category="general", created_at=None, deleted=False):
    with get_engine().begin() as conn:
        return conn.execute(
            text("INSERT INTO documents (owner_id, name, category, storage_key, mime_type, "
                 "size_bytes, sha256, created_at, deleted_at) VALUES (:o, :n, :c, :k, "
                 "'application/pdf', 3, 'x', COALESCE(CAST(:t AS timestamptz), now()), "
                 "CASE WHEN CAST(:del AS boolean) THEN now() END) RETURNING id"),
            {"o": owner_id, "n": name, "c": category, "k": uuid.uuid4().hex,
             "t": created_at, "del": deleted}).scalar()


def _grant_direct(doc_id, user_id, permission="read"):
    with get_engine().begin() as conn:
        owner = conn.execute(text("SELECT owner_id FROM documents WHERE id = :d"),
                             {"d": doc_id}).scalar()
        conn.execute(
            text("INSERT INTO grants (document_id, user_id, permission, granted_by) "
                 "VALUES (:d, :u, :p, :g)"),
            {"d": doc_id, "u": user_id, "p": permission, "g": owner})


def _rename_user(user_id, name):
    with get_engine().begin() as conn:
        conn.execute(text("UPDATE users SET name = :n WHERE id = :u"),
                     {"n": name, "u": user_id})


def _get(client, params=None):
    return client.get("/documents", query_string=params or {})


def _items(client, params=None):
    r = _get(client, params)
    assert r.status_code == 200
    return r.get_json()["documents"]


def _names(client, params=None):
    return [d["name"] for d in _items(client, params)]


def _ids(client, params=None):
    return [d["id"] for d in _items(client, params)]


# ---------- who sees what ----------

def test_anonymous_is_refused(client_for):
    assert _get(client_for(None)).status_code in (401, 302)


def test_owner_sees_their_document(client_for, people, doc):
    assert _names(client_for(people["owner"])) == ["secret.pdf"]


def test_reader_sees_a_granted_document(client_for, people, doc):
    assert _names(client_for(people["reader"])) == ["secret.pdf"]


@pytest.mark.parametrize("who", ["stranger", "other_owner"])
def test_others_see_nothing(client_for, people, doc, who):
    assert _names(client_for(people[who])) == []


def test_admin_sees_metadata_of_other_peoples_documents(client_for, people, doc):
    items = _items(client_for(people["admin"]))
    mine = [d for d in items if d["id"] == str(doc)]
    assert len(mine) == 1
    assert mine[0]["my_permission"] == "metadata"
    assert "storage_key" not in mine[0] and "sha256" not in mine[0]


def test_admin_does_not_see_soft_deleted_documents(client_for, people):
    gone = _make_doc(people["owner"], "gone.pdf", deleted=True)
    assert str(gone) not in _ids(client_for(people["admin"]))


def test_admin_can_search_by_owner(client_for, people):
    _rename_user(people["owner"], "Alice Example")
    _rename_user(people["other_owner"], "Bob Example")
    a = _make_doc(people["owner"], "alice.pdf")
    b = _make_doc(people["other_owner"], "bob.pdf")
    ids = _ids(client_for(people["admin"]), {"owner": "alice"})
    assert str(a) in ids and str(b) not in ids


def test_response_has_no_storage_key_or_hash(client_for, people, doc):
    item = _items(client_for(people["owner"]))[0]
    assert "storage_key" not in item and "sha256" not in item
    assert item["my_permission"] == "owner"


def test_my_permission_for_a_reader(client_for, people, doc):
    assert _items(client_for(people["reader"]))[0]["my_permission"] == "read"


def test_grant_and_revoke_change_the_list_immediately(client_for, people, doc):
    stranger = client_for(people["stranger"])  # same cookie throughout
    assert _names(stranger) == []
    _grant_direct(doc, people["stranger"])
    assert _names(stranger) == ["secret.pdf"]
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM grants WHERE document_id = :d AND user_id = :u"),
                     {"d": doc, "u": people["stranger"]})
    assert _names(stranger) == []


def test_soft_deleted_documents_are_hidden(client_for, people, doc):
    with get_engine().begin() as conn:
        conn.execute(text("UPDATE documents SET deleted_at = now() WHERE id = :d"), {"d": doc})
    assert _names(client_for(people["owner"])) == []
    assert _names(client_for(people["reader"])) == []


def test_list_matches_authorize_for_everyone(client_for, people, doc):
    """Guards against the SQL rule and authorize() drifting apart."""
    other = _make_doc(people["other_owner"], "other.pdf")
    gone = _make_doc(people["owner"], "gone.pdf", deleted=True)
    _grant_direct(gone, people["reader"])
    mine = {str(doc), str(other), str(gone)}
    for name, user_id in people.items():
        with get_engine().connect() as conn:
            user = dict(conn.execute(
                text("SELECT id, role, is_active FROM users WHERE id = :u"),
                {"u": user_id}).mappings().first())
            expected = set()
            for doc_id in mine:
                d = dict(conn.execute(
                    text("SELECT id, owner_id, deleted_at FROM documents WHERE id = :d"),
                    {"d": uuid.UUID(doc_id)}).mappings().first())
                rows = conn.execute(
                    text("SELECT user_id, permission FROM grants WHERE document_id = :d"),
                    {"d": uuid.UUID(doc_id)}).mappings().all()
                grants = {str(r["user_id"]): r["permission"] for r in rows}
                if d["deleted_at"] is None and authorize(user, d, "view_meta", grants):
                    expected.add(doc_id)
        actual = set(_ids(client_for(user_id))) & mine
        assert actual == expected, f"list and authorize disagree for {name}"


# ---------- filters can never reach documents the user was not granted ----------

@pytest.mark.parametrize("who", ["stranger", "other_owner"])
@pytest.mark.parametrize("params", [
    {"q": "secret"}, {"q": "secret.pdf"}, {"category": "general"}, {"owner": "owner"},
    {"from": "2000-01-01"}, {"to": "2100-01-01"}, {},
])
def test_filters_never_reach_ungranted_documents(client_for, people, doc, who, params):
    assert _names(client_for(people[who]), params) == []


@pytest.mark.parametrize("payload", ["' OR '1'='1", "x' OR 1=1 --", "'; DROP TABLE documents; --", "%", "_"])
@pytest.mark.parametrize("field", ["q", "category", "owner"])
def test_odd_input_never_widens_the_list(client_for, people, doc, field, payload):
    r = _get(client_for(people["stranger"]), {field: payload})
    assert r.status_code == 200
    assert r.get_json()["documents"] == []
    assert _names(client_for(people["owner"])) == ["secret.pdf"]  # table still there


# ---------- the filters themselves (by the owner) ----------

def test_name_search_ignores_case(client_for, people, doc):
    assert _names(client_for(people["owner"]), {"q": "SECRET"}) == ["secret.pdf"]
    assert _names(client_for(people["owner"]), {"q": "nothing-like-this"}) == []


def test_name_wildcards_are_literal(client_for, people):
    _make_doc(people["owner"], "50%off.pdf")
    _make_doc(people["owner"], "50xxoff.pdf")
    c = client_for(people["owner"])
    assert _names(c, {"q": "50%off"}) == ["50%off.pdf"]
    assert _names(c, {"q": "%"}) == ["50%off.pdf"]
    assert _names(c, {"q": "_"}) == []


def test_category_filter_is_exact(client_for, people):
    _make_doc(people["owner"], "a.pdf", category="contracts")
    _make_doc(people["owner"], "b.pdf", category="invoices")
    c = client_for(people["owner"])
    assert _names(c, {"category": "contracts"}) == ["a.pdf"]
    assert _names(c, {"category": "contract"}) == []


def test_owner_filter_uses_the_owner_name(client_for, people):
    _rename_user(people["owner"], "Alice Example")
    _rename_user(people["other_owner"], "Bob Example")
    a = _make_doc(people["owner"], "alice.pdf")
    b = _make_doc(people["other_owner"], "bob.pdf")
    _grant_direct(a, people["reader"])
    _grant_direct(b, people["reader"])
    c = client_for(people["reader"])
    assert sorted(_names(c)) == ["alice.pdf", "bob.pdf"]
    assert _names(c, {"owner": "alice"}) == ["alice.pdf"]
    assert _names(c, {"owner": "BOB"}) == ["bob.pdf"]


def test_date_filters(client_for, people):
    _make_doc(people["owner"], "old.pdf", created_at="2020-01-15T12:00:00+00:00")
    c = client_for(people["owner"])
    assert _names(c, {"from": "2020-01-01", "to": "2020-01-31"}) == ["old.pdf"]
    assert _names(c, {"to": "2020-01-15"}) == ["old.pdf"]      # "to" includes that whole day
    assert _names(c, {"from": "2020-01-15"}) == ["old.pdf"]
    assert _names(c, {"from": "2020-01-16"}) == []
    assert _names(c, {"to": "2020-01-14"}) == []


@pytest.mark.parametrize("params", [{"from": "not-a-date"}, {"to": "2020-13-45"}])
def test_invalid_date_is_a_400(client_for, people, params):
    r = _get(client_for(people["owner"]), params)
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_newest_first(client_for, people):
    _make_doc(people["owner"], "older.pdf", created_at="2020-01-01T12:00:00+00:00")
    _make_doc(people["owner"], "newer.pdf", created_at="2021-01-01T12:00:00+00:00")
    assert _names(client_for(people["owner"])) == ["newer.pdf", "older.pdf"]