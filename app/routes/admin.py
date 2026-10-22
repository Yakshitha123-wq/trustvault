import datetime as dt
import uuid

from flask import Blueprint, abort, jsonify, request
from sqlalchemy import text

from ..audit import verify_chain, write_audit
from ..auth import get_current_user
from ..authz import authorize
from ..db import get_engine

bp = Blueprint("admin", __name__)

MAX_LIMIT = 500
DEFAULT_LIMIT = 100
OUTCOMES = {"allowed", "denied"}
FILTER_KEYS = ("document_id", "actor_id", "action", "outcome", "from", "to", "limit", "before_id")

# authorize() decides, as everywhere else. The audit view is not about one document,
# so it is checked against an empty stand-in: only an admin holds view_audit.
_NO_DOCUMENT = {"owner_id": None, "deleted_at": None}


def _require_admin():
    """Anonymous: 401. Anyone who may not view the audit trail: an audited refusal, then 404."""
    user = get_current_user()
    if user is None:
        abort(401)
    if not authorize(user, _NO_DOCUMENT, "view_audit", {}):
        # Committed before aborting, so the refusal is not rolled back.
        with get_engine().begin() as conn:
            write_audit(conn, actor_id=user["id"], action="admin_access",
                        outcome="denied", ip=request.remote_addr,
                        detail={"path": request.path})
        abort(404)
    return user


def _bad(message):
    return jsonify(error=message), 400


@bp.get("/admin/activity")
def activity():
    user = _require_admin()

    # Only fixed strings are joined into the SQL. Every user value is a bound parameter.
    where, params = [], {}

    for key in ("document_id", "actor_id"):
        raw = request.args.get(key, "").strip()
        if raw:
            try:
                params[key] = uuid.UUID(raw)
            except ValueError:
                return _bad(f"'{key}' must be a UUID.")
            where.append(f"a.{key} = :{key}")

    action = request.args.get("action", "").strip()
    if action:
        if len(action) > 50:
            return _bad("'action' is too long.")
        where.append("a.action = :action")
        params["action"] = action

    outcome = request.args.get("outcome", "").strip()
    if outcome:
        if outcome not in OUTCOMES:
            return _bad("'outcome' must be allowed or denied.")
        where.append("a.outcome = :outcome")
        params["outcome"] = outcome

    for key in ("from", "to"):
        raw = request.args.get(key, "").strip()
        if not raw:
            continue
        try:
            day = dt.date.fromisoformat(raw)
        except ValueError:
            return _bad(f"'{key}' must be a date such as 2026-10-22.")
        if key == "from":
            where.append("a.ts >= CAST(:date_from AS date)")
            params["date_from"] = day
        else:
            where.append("a.ts < CAST(:date_to AS date) + 1")
            params["date_to"] = day

    limit = DEFAULT_LIMIT
    raw = request.args.get("limit", "").strip()
    if raw:
        try:
            limit = int(raw)
        except ValueError:
            return _bad("'limit' must be a number.")
        if limit < 1:
            return _bad("'limit' must be at least 1.")
        limit = min(limit, MAX_LIMIT)

    raw = request.args.get("before_id", "").strip()
    if raw:
        try:
            params["before_id"] = int(raw)
        except ValueError:
            return _bad("'before_id' must be a number.")
        where.append("a.id < :before_id")

    sql = ("SELECT a.id, a.ts, a.actor_id, ua.name AS actor_name, a.action, a.outcome, "
           "a.document_id, a.target_user_id, ut.name AS target_name, a.ip, a.detail "
           "FROM audit_log a "
           "LEFT JOIN users ua ON ua.id = a.actor_id "
           "LEFT JOIN users ut ON ut.id = a.target_user_id "
           + ("WHERE " + " AND ".join(where) + " " if where else "")
           + "ORDER BY a.id DESC LIMIT :fetch")
    params["fetch"] = limit + 1          # one extra row tells us whether there is a next page

    # The read and its own audit row commit together: no record, no answer.
    with get_engine().begin() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        write_audit(conn, actor_id=user["id"], action="audit_view", outcome="allowed",
                    ip=request.remote_addr,
                    detail={"filters": {k: request.args[k][:100]
                                        for k in FILTER_KEYS if k in request.args}})

    page = rows[:limit]
    return jsonify(
        events=[{
            "id": r["id"],
            "ts": r["ts"].isoformat(),
            "actor_id": str(r["actor_id"]) if r["actor_id"] else None,
            "actor_name": r["actor_name"],
            "action": r["action"],
            "outcome": r["outcome"],
            "document_id": str(r["document_id"]) if r["document_id"] else None,
            "target_user_id": str(r["target_user_id"]) if r["target_user_id"] else None,
            "target_name": r["target_name"],
            "ip": str(r["ip"]) if r["ip"] else None,
            # The content hash is left out, as it is from the document list.
            "detail": {k: v for k, v in r["detail"].items() if k != "sha256"},
        } for r in page],
        next_before_id=page[-1]["id"] if len(rows) > limit else None)


@bp.get("/admin/audit/verify")
def verify():
    user = _require_admin()
    with get_engine().begin() as conn:
        intact, first_bad_row = verify_chain(conn)
        write_audit(conn, actor_id=user["id"], action="audit_verify", outcome="allowed",
                    ip=request.remote_addr,
                    detail={"intact": intact, "first_bad_row": first_bad_row})
    return jsonify(intact=intact, first_bad_row=first_bad_row)