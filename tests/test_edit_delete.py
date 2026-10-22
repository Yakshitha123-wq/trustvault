import pytest
from sqlalchemy import text

from app.db import get_engine


def _row(doc):
    with get_engine().connect() as conn:
        return dict(conn.execute(
            text("SELECT name, category, owner_id, storage_key, deleted_at "
                 "FROM documents WHERE id = :d"), {"d": doc}).mappings().first())


def _blob_exists(doc):
    with get_engine().connect() as conn:
        return conn.execute(text("SELECT count(*) FROM document_blobs WHERE document_id = :d"),
                            {"d": doc}).scalar() == 1


def _grant_direct(doc_id, user_id, permission):
    with get_engine().begin() as conn:
        owner = conn.execute(text("SELECT owner_id FROM documents WHERE id = :d"),
                             {"d": doc_id}).scalar()
        conn.execute(
            text("INSERT INTO grants (document_id, user_id, permission, granted_by) "
                 "VALUES (:d, :u, :p, :g) "
                 "ON CONFLICT (document_id, user_id) DO UPDATE SET permission = :p"),
            {"d": doc_id, "u": user_id, "p": permission, "g": owner})


def _revoke_direct(doc_id, user_id):
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM grants WHERE document_id = :d AND user_id = :u"),
                     {"d": doc_id, "u": user_id})


def _audit_count(action, outcome, actor_id, document_id):
    with get_engine().connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM audit_log WHERE action = :a AND outcome = :o "
                 "AND actor_id = :u AND document_id = :d"),
            {"a": action, "o": outcome, "u": actor_id, "d": document_id}).scalar()


def _edit(client, doc, **fields):
    return client.post(f"/documents/{doc}/edit", data=fields)


def _delete(client, doc):
    return client.post(f"/documents/{doc}/delete")


# ---------- who can edit ----------

def test_owner_can_rename_and_recategorise(client_for, people, doc):
    r = _edit(client_for(people["owner"]), doc, name="renamed.pdf", category="contracts")
    assert r.status_code == 200
    row = _row(doc)
    assert row["name"] == "renamed.pdf" and row["category"] == "contracts"


def test_editor_can_edit_with_the_same_cookie(client_for, people, doc):
    c = client_for(people["stranger"])
    assert _edit(c, doc, name="x.pdf").status_code == 404      # no grant yet
    _grant_direct(doc, people["stranger"], "edit")
    assert _edit(c, doc, name="x.pdf").status_code == 200       # same cookie
    assert _row(doc)["name"] == "x.pdf"


def test_revoking_edit_takes_effect_immediately(client_for, people, doc):
    _grant_direct(doc, people["stranger"], "edit")
    c = client_for(people["stranger"])
    assert _edit(c, doc, name="first.pdf").status_code == 200
    _revoke_direct(doc, people["stranger"])
    assert _edit(c, doc, name="second.pdf").status_code == 404
    assert _row(doc)["name"] == "first.pdf"


@pytest.mark.parametrize("who", ["reader", "stranger", "admin", "other_owner"])
def test_non_editors_cannot_edit(client_for, people, doc, who):
    r = _edit(client_for(people[who]), doc, name="hacked.pdf", category="x")
    assert r.status_code == 404
    assert _row(doc)["name"] == "secret.pdf"


def test_anonymous_cannot_edit(client_for, people, doc):
    assert _edit(client_for(None), doc, name="hacked.pdf").status_code in (401, 302)
    assert _row(doc)["name"] == "secret.pdf"


def test_refusal_does_not_depend_on_the_input(client_for, people, doc):
    """Authorisation runs before validation: a stranger gets 404 even for bad input."""
    r = _edit(client_for(people["stranger"]), doc, name="../../etc/passwd")
    assert r.status_code == 404


# ---------- what an edit may change ----------

@pytest.mark.parametrize("name", ["", "   ", "../x.pdf", "a/b.pdf", "a\\b.pdf",
                                  "x.exe", "noextension", "a" * 120 + ".pdf"])
def test_bad_names_are_rejected(client_for, people, doc, name):
    r = _edit(client_for(people["owner"]), doc, name=name)
    assert r.status_code == 400
    assert _row(doc)["name"] == "secret.pdf"


def test_edit_with_no_fields_is_a_400(client_for, people, doc):
    assert _edit(client_for(people["owner"]), doc).status_code == 400


def test_edit_cannot_change_owner_or_storage_or_deletion(client_for, people, doc):
    before = _row(doc)
    r = _edit(client_for(people["owner"]), doc, name="ok.pdf",
              owner_id=str(people["stranger"]), storage_key="evil",
              deleted_at="2020-01-01")
    assert r.status_code == 200
    after = _row(doc)
    assert after["owner_id"] == before["owner_id"]
    assert after["storage_key"] == before["storage_key"]
    assert after["deleted_at"] is None


def test_editor_cannot_delete(client_for, people, doc):
    _grant_direct(doc, people["stranger"], "edit")
    assert _delete(client_for(people["stranger"]), doc).status_code == 404
    assert _row(doc)["deleted_at"] is None


# ---------- delete ----------

def test_owner_can_soft_delete(client_for, people, doc):
    assert _delete(client_for(people["owner"]), doc).status_code == 200
    assert _row(doc)["deleted_at"] is not None


def test_delete_takes_effect_immediately_for_everyone_else(client_for, people, doc):
    reader = client_for(people["reader"])
    assert reader.get(f"/documents/{doc}/download").status_code == 200
    _delete(client_for(people["owner"]), doc)
    assert reader.get(f"/documents/{doc}").status_code == 404           # same cookie
    assert reader.get(f"/documents/{doc}/download").status_code == 404
    assert client_for(people["admin"]).get(f"/documents/{doc}").status_code == 404
    names = [d["name"] for d in reader.get("/documents").get_json()["documents"]]
    assert "secret.pdf" not in names


def test_delete_keeps_the_stored_bytes(client_for, people, doc):
    _delete(client_for(people["owner"]), doc)
    assert _blob_exists(doc)


@pytest.mark.parametrize("who", ["reader", "stranger", "admin", "other_owner"])
def test_non_owners_cannot_delete(client_for, people, doc, who):
    assert _delete(client_for(people[who]), doc).status_code == 404
    assert _row(doc)["deleted_at"] is None


def test_anonymous_cannot_delete(client_for, people, doc):
    assert _delete(client_for(None), doc).status_code in (401, 302)
    assert _row(doc)["deleted_at"] is None


def test_deleting_twice_is_a_404(client_for, people, doc):
    owner = client_for(people["owner"])
    assert _delete(owner, doc).status_code == 200
    assert _delete(owner, doc).status_code == 404


def test_deleted_document_cannot_be_edited(client_for, people, doc):
    owner = client_for(people["owner"])
    _delete(owner, doc)
    assert _edit(owner, doc, name="back.pdf").status_code == 404
    assert _row(doc)["name"] == "secret.pdf"


# ---------- the audit trail ----------

def test_edit_is_audited(client_for, people, doc):
    before = _audit_count("edit", "allowed", people["owner"], doc)
    _edit(client_for(people["owner"]), doc, name="renamed.pdf")
    assert _audit_count("edit", "allowed", people["owner"], doc) == before + 1


def test_delete_is_audited(client_for, people, doc):
    before = _audit_count("delete", "allowed", people["owner"], doc)
    _delete(client_for(people["owner"]), doc)
    assert _audit_count("delete", "allowed", people["owner"], doc) == before + 1


def test_refused_edit_and_delete_are_audited(client_for, people, doc):
    before = _audit_count("document_access", "denied", people["stranger"], doc)
    s = client_for(people["stranger"])
    _edit(s, doc, name="x.pdf")
    _delete(s, doc)
    assert _audit_count("document_access", "denied", people["stranger"], doc) == before + 2