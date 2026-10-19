import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from app.audit import verify_chain, write_audit
from app.db import _normalise, get_engine

OWNER_URL = os.environ.get("TEST_OWNER_DATABASE_URL")
needs_owner = pytest.mark.skipif(
    not OWNER_URL, reason="TEST_OWNER_DATABASE_URL is not set"
)


def _write_rows(n=3):
    """Write n audit rows with the app role, return their ids (oldest first)."""
    engine = get_engine()
    with engine.begin() as conn:
        for i in range(n):
            write_audit(conn, actor_id=None, action="test",
                        outcome="allowed", detail={"n": i})
    with engine.connect() as conn:
        ids = conn.execute(
            text("SELECT id FROM audit_log ORDER BY id DESC LIMIT :n"), {"n": n}
        ).scalars().all()
    return sorted(ids)


def test_chain_verifies_after_several_writes():
    _write_rows(3)
    with get_engine().connect() as conn:
        ok, bad = verify_chain(conn)
    assert ok, f"chain broken at row {bad}"


def test_app_role_cannot_update_or_delete_audit_rows():
    ids = _write_rows(1)
    for sql in ("UPDATE audit_log SET action = 'x' WHERE id = :i",
                "DELETE FROM audit_log WHERE id = :i"):
        with pytest.raises(DBAPIError, match="permission denied"):
            with get_engine().begin() as conn:
                conn.execute(text(sql), {"i": ids[0]})


@needs_owner
def test_trigger_blocks_even_the_owner():
    ids = _write_rows(1)
    owner = create_engine(_normalise(OWNER_URL))
    with pytest.raises(DBAPIError, match="append-only"):
        with owner.begin() as conn:
            conn.execute(text("UPDATE audit_log SET action = 'x' WHERE id = :i"),
                         {"i": ids[0]})


@needs_owner
def test_tampering_with_a_row_is_detected():
    ids = _write_rows(3)
    target = ids[1]  # a row in the middle of the chain
    owner = create_engine(_normalise(OWNER_URL))

    with owner.connect() as conn:
        trans = conn.begin()
        try:
            # What a powerful attacker would do: switch the trigger off, edit a row.
            conn.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_immutable"))
            conn.execute(text("UPDATE audit_log SET action = 'tampered' WHERE id = :i"),
                         {"i": target})
            ok, bad = verify_chain(conn)
        finally:
            trans.rollback()  # undoes the disable AND the edit

    assert ok is False, "tampering was NOT detected"
    assert bad == target, f"detected at row {bad}, expected {target}"

    # The rollback must have left the real chain clean.
    with get_engine().connect() as conn:
        assert verify_chain(conn)[0]