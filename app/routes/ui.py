import uuid

from flask import Blueprint, abort, redirect, render_template, url_for

from ..auth import get_current_user
from ..authz import authorize
from .admin import _NO_DOCUMENT

bp = Blueprint("ui", __name__)


@bp.app_context_processor
def nav_flags():
    """Only decides which links the navigation shows. The JSON routes enforce access."""
    user = get_current_user()
    return {
        "user": user,
        "show_upload": bool(user and user["role"] == "owner"),
        "show_admin": bool(user and authorize(user, _NO_DOCUMENT, "view_audit", {})),
    }


def _to_login():
    return redirect(url_for("auth.login"))


@bp.get("/app")
def documents_page():
    if get_current_user() is None:
        return _to_login()
    return render_template("documents.html")


@bp.get("/app/upload")
def upload_page():
    if get_current_user() is None:
        return _to_login()
    return render_template("upload.html")


@bp.get("/app/documents/<doc_id>")
def document_page(doc_id):
    if get_current_user() is None:
        return _to_login()
    try:
        doc_id = str(uuid.UUID(doc_id))
    except ValueError:
        abort(404)
    return render_template("detail.html", doc_id=doc_id)  # the page loads data through the API


@bp.get("/app/admin")
def admin_page():
    user = get_current_user()
    if user is None:
        return _to_login()
    if not authorize(user, _NO_DOCUMENT, "view_audit", {}):
        abort(404)
    return render_template("admin.html")