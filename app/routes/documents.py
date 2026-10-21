import hashlib
import io
import secrets

from flask import Blueprint, abort, jsonify, request, send_file
from sqlalchemy import text

from ..access import get_document_or_404
from ..audit import write_audit
from ..auth import get_current_user
from ..db import get_engine
from ..validation import MAX_BYTES, UploadError, validate_upload

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


@bp.get("/documents/<doc_id>")
def detail(doc_id):
    user, doc = get_document_or_404(doc_id, "view_meta")
    return jsonify(id=str(doc["id"]), name=doc["name"], category=doc["category"],
                   mime_type=doc["mime_type"], size_bytes=doc["size_bytes"],
                   created_at=doc["created_at"].isoformat())


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