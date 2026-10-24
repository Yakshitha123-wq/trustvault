import hashlib
import io
import secrets
import datetime as dt

from flask import Blueprint, abort, jsonify, request, send_file
from sqlalchemy import text

from ..access import get_document_or_404
from ..audit import write_audit
from ..auth import get_current_user
from ..db import get_engine
from ..validation import MAX_BYTES, UploadError, validate_upload
from ..authz import authorize

bp = Blueprint("documents", __name__)


def _audit_refusal(user, action, detail, document_id=None):
    with get_engine().begin() as conn:
        write_audit(conn, actor_id=user["id"] if user else None, action=action,
                    outcome="denied", document_id=document_id,
                    ip=request.remote_addr, detail=detail)


@bp.post("/documents")
def upload():
    user = get_current_user()
    if user is None:
        abort(401)
    if user["role"] != "owner":
        _audit_refusal(user, "upload", {"reason": "role"})
        abort(403)

    f = request.files.get("file")
    if f is None:
        abort(400)
    data = f.read(MAX_BYTES + 1)
    try:
        name, mime = validate_upload(f.filename, data)
    except UploadError as e:
        _audit_refusal(user, "upload", {"reason": str(e)})
        return jsonify(error=str(e)), e.status

    category = (request.form.get("category") or "general").strip()[:50] or "general"
    digest = hashlib.sha256(data).hexdigest()

    # Document row, file bytes and audit row commit together or not at all.
    with get_engine().begin() as conn:
        doc_id = conn.execute(
            text("INSERT INTO documents (owner_id, name, category, storage_key, "
                 "mime_type, size_bytes, sha256) "
                 "VALUES (:o, :n, :c, :k, :m, :s, :h) RETURNING id"),
            {"o": user["id"], "n": name, "c": category,
             "k": secrets.token_hex(16), "m": mime, "s": len(data), "h": digest},
        ).scalar()
        conn.execute(
            text("INSERT INTO document_blobs (document_id, content) VALUES (:d, :c)"),
            {"d": doc_id, "c": data})
        write_audit(conn, actor_id=user["id"], action="upload", outcome="allowed",
                    document_id=doc_id, ip=request.remote_addr,
                    detail={"name": name, "size": len(data), "sha256": digest})
    return jsonify(id=str(doc_id), name=name), 201
def _like(value):
    """Match user text literally: escape the LIKE wildcards (! is the escape character)."""
    safe = value.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    return f"%{safe}%"


@bp.get("/documents")
def list_documents():
    user = get_current_user()
    if user is None:
        abort(401)

    # Only fixed strings are joined into the SQL. Every user value is a bound parameter.
    # Visible: my own documents, documents I hold a grant on, or (admins only) metadata
    # of any document. Soft-deleted documents are never listed.
    where = ["d.deleted_at IS NULL",
             "(d.owner_id = :me OR g.user_id IS NOT NULL OR CAST(:is_admin AS boolean))"]
    params = {"me": user["id"], "is_admin": user["role"] == "admin"}

    q = request.args.get("q", "").strip()[:100]
    if q:
        where.append("d.name ILIKE :q ESCAPE '!'")
        params["q"] = _like(q)
    owner = request.args.get("owner", "").strip()[:100]
    if owner:
        where.append("u.name ILIKE :owner ESCAPE '!'")
        params["owner"] = _like(owner)
    category = request.args.get("category", "").strip()[:50]
    if category:
        where.append("d.category = :category")
        params["category"] = category
    for key in ("from", "to"):
        raw = request.args.get(key, "").strip()
        if not raw:
            continue
        try:
            day = dt.date.fromisoformat(raw)
        except ValueError:
            return jsonify(error=f"'{key}' must be a date such as 2026-10-22."), 400
        if key == "from":
            where.append("d.created_at >= CAST(:date_from AS date)")
            params["date_from"] = day
        else:
            where.append("d.created_at < CAST(:date_to AS date) + 1")
            params["date_to"] = day

    sql = ("SELECT d.id, d.name, d.category, d.mime_type, d.size_bytes, d.created_at, "
           "u.name AS owner_name, "
           "CASE WHEN d.owner_id = :me THEN 'owner' "
           "WHEN g.permission IS NOT NULL THEN g.permission "
           "ELSE 'metadata' END AS my_permission "
           "FROM documents d "
           "JOIN users u ON u.id = d.owner_id "
           "LEFT JOIN grants g ON g.document_id = d.id AND g.user_id = :me "
           "WHERE " + " AND ".join(where) +
           " ORDER BY d.created_at DESC, d.id LIMIT 100")
    with get_engine().connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()

    return jsonify(documents=[
        {"id": str(r["id"]), "name": r["name"], "category": r["category"],
         "mime_type": r["mime_type"], "size_bytes": r["size_bytes"],
         "created_at": r["created_at"].isoformat(), "owner_name": r["owner_name"],
         "my_permission": r["my_permission"]} for r in rows])


@bp.get("/documents/<doc_id>")
def detail(doc_id):
    user, doc = get_document_or_404(doc_id, "view_meta")
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("SELECT user_id, permission FROM grants WHERE document_id = :d"),
            {"d": doc["id"]}).mappings().all()
    grants = {str(r["user_id"]): r["permission"] for r in rows}
    # The same function that guards every route decides what the page offers.
    can = {a: authorize(user, doc, a, grants) for a in ("read", "edit", "delete", "share")}
    return jsonify(id=str(doc["id"]), name=doc["name"], category=doc["category"],
                   mime_type=doc["mime_type"], size_bytes=doc["size_bytes"],
                   created_at=doc["created_at"].isoformat(), can=can)
def _clean_name(new_name, current_name):
    """Return the cleaned name, or None if it is not acceptable.
    The name must keep the document's current extension, so a .pdf cannot be
    renamed to look like another type."""
    new_name = new_name.strip()
    if not new_name or len(new_name) > 100:
        return None
    if "/" in new_name or "\\" in new_name or any(ord(ch) < 32 for ch in new_name):
        return None
    if "." not in new_name or "." not in current_name:
        return None
    stem, new_ext = new_name.rsplit(".", 1)
    old_ext = current_name.rsplit(".", 1)[1]
    if not stem or new_ext.lower() != old_ext.lower():
        return None
    return new_name


@bp.post("/documents/<doc_id>/edit")
def edit(doc_id):
    # Authorisation first, so a stranger gets the same 404 whatever they send.
    user, doc = get_document_or_404(doc_id, "edit")
    if doc["deleted_at"] is not None:   # the owner may open a deleted document, not change it
        abort(404)

    new_name = request.form.get("name")
    new_category = request.form.get("category")
    if new_name is None and new_category is None:
        return jsonify(error="Send a name and/or a category."), 400

    name, category = doc["name"], doc["category"]
    if new_name is not None:
        name = _clean_name(new_name, doc["name"])
        if name is None:
            return jsonify(error="Invalid name: up to 100 characters, no slashes, "
                                 "and the same file extension as before."), 400
    if new_category is not None:
        category = new_category.strip()
        if not category or len(category) > 50:
            return jsonify(error="Category must be 1 to 50 characters."), 400

    # Only name and category are ever updated. Nothing else is read from the form.
    with get_engine().begin() as conn:
        changed = conn.execute(
            text("UPDATE documents SET name = :n, category = :c "
                 "WHERE id = :d AND deleted_at IS NULL"),
            {"n": name, "c": category, "d": doc["id"]}).rowcount
        if changed != 1:
            abort(404)
        write_audit(conn, actor_id=user["id"], action="edit", outcome="allowed",
                    document_id=doc["id"], ip=request.remote_addr,
                    detail={"old_name": doc["name"], "name": name,
                            "old_category": doc["category"], "category": category})
    return jsonify(id=str(doc["id"]), name=name, category=category)


@bp.post("/documents/<doc_id>/delete")
def delete(doc_id):
    # "delete" is not in any grant level, so only the owner can reach this.
    user, doc = get_document_or_404(doc_id, "delete")
    if doc["deleted_at"] is not None:
        abort(404)

    # Soft delete: the row and the stored bytes stay, so recovery is possible.
    with get_engine().begin() as conn:
        changed = conn.execute(
            text("UPDATE documents SET deleted_at = now() "
                 "WHERE id = :d AND deleted_at IS NULL"),
            {"d": doc["id"]}).rowcount
        if changed != 1:
            abort(404)
        write_audit(conn, actor_id=user["id"], action="delete", outcome="allowed",
                    document_id=doc["id"], ip=request.remote_addr,
                    detail={"name": doc["name"]})
    return jsonify(id=str(doc["id"]), deleted=True)

@bp.get("/documents/<doc_id>/download")
def download(doc_id):
    # THE decision point for reading file contents: needs the "read" action.
    user, doc = get_document_or_404(doc_id, "read")

    with get_engine().begin() as conn:
        content = conn.execute(
            text("SELECT content FROM document_blobs WHERE document_id = :d"),
            {"d": doc["id"]}).scalar()
        if content is None:
            abort(404)
        # If this audit write fails, the exception stops the request and no bytes are sent.
        write_audit(conn, actor_id=user["id"], action="download", outcome="allowed",
                    document_id=doc["id"], ip=request.remote_addr,
                    detail={"name": doc["name"]})

    resp = send_file(io.BytesIO(bytes(content)), mimetype=doc["mime_type"],
                     as_attachment=True, download_name=doc["name"])
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp