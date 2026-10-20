from flask import Blueprint, jsonify

from ..access import get_document_or_404

bp = Blueprint("documents", __name__)


@bp.get("/documents/<doc_id>")
def detail(doc_id):
    user, doc = get_document_or_404(doc_id, "view_meta")
    return jsonify(id=str(doc["id"]), name=doc["name"], category=doc["category"],
                   mime_type=doc["mime_type"], size_bytes=doc["size_bytes"],
                   created_at=doc["created_at"].isoformat())