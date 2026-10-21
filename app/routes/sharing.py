import uuid

from flask import Blueprint, jsonify, request
from sqlalchemy import text

from ..access import get_document_or_404
from ..audit import write_audit
from ..db import get_engine

bp = Blueprint("sharing", __name__)

LEVELS = ("read", "edit")


@bp.get("/documents/<doc_id>/grants")
def list_grants(doc_id):
    user, doc = get_document_or_404(doc_id, "share")
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("SELECT g.user_id, u.email, u.name, g.permission, g.created_at "
                 "FROM grants g JOIN users u ON u.id = g.user_id "
                 "WHERE g.document_id = :d ORDER BY g.created_at"),
            {"d": doc["id"]}).mappings().all()
    return jsonify(grants=[
        {"user_id": str(r["user_id"]), "email": r["email"], "name": r["name"],
         "permission": r["permission"], "created_at": r["created_at"].isoformat()}
        for r in rows])


@bp.post("/documents/<doc_id>/grants")
def grant(doc_id):
    # The decision comes first: only the owner may share. Input is checked after it.
    user, doc = get_document_or_404(doc_id, "share")

    permission = request.form.get("permission", "")  # exact match, no trimming
    if permission not in LEVELS:
        return jsonify(error="Permission must be 'read' or 'edit'."), 400
    email = request.form.get("email", "").strip()

    # The change and its audit row commit together or not at all.
    with get_engine().begin() as conn:
        target = conn.execute(
            text("SELECT id FROM users WHERE email = :e AND is_active"),
            {"e": email}).scalar()
        if target is None:
            return jsonify(error="No active user with that email."), 404
        if target == doc["owner_id"]:
            return jsonify(error="The owner already has full access."), 400
        previous = conn.execute(
            text("SELECT permission FROM grants WHERE document_id = :d AND user_id = :u"),
            {"d": doc["id"], "u": target}).scalar()
        conn.execute(
            text("INSERT INTO grants (document_id, user_id, permission, granted_by) "
                 "VALUES (:d, :u, :p, :g) "
                 "ON CONFLICT (document_id, user_id) DO UPDATE "
                 "SET permission = EXCLUDED.permission, granted_by = EXCLUDED.granted_by"),
            {"d": doc["id"], "u": target, "p": permission, "g": user["id"]})
        write_audit(conn, actor_id=user["id"], action="grant", outcome="allowed",
                    document_id=doc["id"], target_user_id=target,
                    ip=request.remote_addr,
                    detail={"permission": permission, "previous": previous})
    return jsonify(user_id=str(target), permission=permission)


@bp.post("/documents/<doc_id>/grants/<user_id>/revoke")
def revoke(doc_id, user_id):
    user, doc = get_document_or_404(doc_id, "share")
    try:
        target = uuid.UUID(user_id)
    except ValueError:
        return jsonify(error="No such grant."), 404

    with get_engine().begin() as conn:
        previous = conn.execute(
            text("DELETE FROM grants WHERE document_id = :d AND user_id = :u "
                 "RETURNING permission"),
            {"d": doc["id"], "u": target}).scalar()
        if previous is None:
            return jsonify(error="No such grant."), 404
        write_audit(conn, actor_id=user["id"], action="revoke", outcome="allowed",
                    document_id=doc["id"], target_user_id=target,
                    ip=request.remote_addr, detail={"permission": previous})
    return jsonify(user_id=str(target), revoked=True)