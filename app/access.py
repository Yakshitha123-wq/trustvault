import uuid

from flask import abort, request
from sqlalchemy import text

from .audit import write_audit
from .auth import get_current_user
from .authz import authorize
from .db import get_engine


def get_document_or_404(doc_id, action):
    """Load a document and check `action` against grants read fresh from the DB.

    Returns (user, document). Aborts with the SAME 404 whether the document is
    missing or the user is not allowed, so existence is not revealed. Refusals
    are written to the audit log.
    """
    user = get_current_user()

    try:
        doc_id = uuid.UUID(str(doc_id))
    except ValueError:
        abort(404)

    doc, grants = None, {}
    with get_engine().connect() as conn:
        doc = conn.execute(
            text("SELECT id, owner_id, name, category, storage_key, mime_type, "
                 "size_bytes, created_at, deleted_at FROM documents WHERE id = :d"),
            {"d": doc_id}).mappings().first()
        if doc:
            rows = conn.execute(
                text("SELECT user_id, permission FROM grants WHERE document_id = :d"),
                {"d": doc_id}).mappings().all()
            grants = {str(r["user_id"]): r["permission"] for r in rows}

    if doc is not None and authorize(user, dict(doc), action, grants):
        return user, dict(doc)

    # Refused. Write the audit row in its own committed transaction, THEN abort.
    # Aborting inside the "with" block would roll the audit row back.
    with get_engine().begin() as conn:
        write_audit(conn, actor_id=user["id"] if user else None,
                    action="document_access", outcome="denied",
                    document_id=doc_id, ip=request.remote_addr,
                    detail={"action": action})
    abort(401 if user is None else 404)