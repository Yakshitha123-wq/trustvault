import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import text

GENESIS = "0" * 64


def _row_hash(prev_hash, ts, actor_id, action, outcome,
              document_id, target_user_id, detail_json):
    parts = [prev_hash, ts, str(actor_id), action, outcome,
             str(document_id), str(target_user_id), detail_json]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def write_audit(conn, *, actor_id, action, outcome,
                document_id=None, target_user_id=None, ip=None, detail=None):
    """Append one audit row.

    Call this with the SAME connection/transaction as the action it records,
    so both succeed or both fail. If this raises, the action must fail too.
    """
    # One writer at a time, so two requests can't read the same prev_hash
    # and fork the chain. The lock is released when the transaction ends.
    conn.execute(text("SELECT pg_advisory_xact_lock(1)"))

    prev = conn.execute(
        text("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    ).scalar() or GENESIS

    # Choose the timestamp in Python, hash it, and store the same value.
    ts = datetime.now(timezone.utc).isoformat()
    detail_json = json.dumps(detail or {}, sort_keys=True)
    row_hash = _row_hash(prev, ts, actor_id, action, outcome,
                         document_id, target_user_id, detail_json)

    conn.execute(
        text("INSERT INTO audit_log "
             "(ts, actor_id, action, outcome, document_id, target_user_id, ip, "
             " detail, prev_hash, row_hash) "
             "VALUES (:ts, :a, :ac, :o, :d, :t, :ip, CAST(:detail AS jsonb), :p, :h)"),
        {"ts": ts, "a": actor_id, "ac": action, "o": outcome, "d": document_id,
         "t": target_user_id, "ip": ip, "detail": detail_json, "p": prev, "h": row_hash},
    )


def verify_chain(conn):
    """Recompute every hash in order. Returns (True, None) if the chain is intact,
    or (False, id_of_first_bad_row)."""
    rows = conn.execute(
        text("SELECT id, ts, actor_id, action, outcome, document_id, "
             "target_user_id, detail, prev_hash, row_hash "
             "FROM audit_log ORDER BY id")
    ).mappings().all()

    expected_prev = GENESIS
    for r in rows:
        if r["prev_hash"] != expected_prev:
            return False, r["id"]
        # Rebuild ts exactly as written: isoformat of a UTC datetime.
        ts = r["ts"].astimezone(timezone.utc).isoformat()
        detail_json = json.dumps(r["detail"], sort_keys=True)
        h = _row_hash(r["prev_hash"], ts, r["actor_id"], r["action"], r["outcome"],
                      r["document_id"], r["target_user_id"], detail_json)
        if h != r["row_hash"]:
            return False, r["id"]
        expected_prev = r["row_hash"]
    return True, None