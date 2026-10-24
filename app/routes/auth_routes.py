from flask import Blueprint, make_response, redirect, render_template, request, url_for
from sqlalchemy import text

from .. import limiter
from ..audit import write_audit
from ..auth import (COOKIE_NAME, SESSION_HOURS, create_session, delete_session,
                    get_current_user, hash_password, verify_password)
from ..db import get_engine

bp = Blueprint("auth", __name__)


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method != "POST":      # HEAD and GET only show the form
        return render_template("register.html", error=None)
    name = request.form.get("name", "").strip()[:100]
    email = request.form.get("email", "").strip()[:254]
    password = request.form.get("password", "")
    if not name or "@" not in email or len(password) < 10:
        return render_template("register.html",
                               error="Check your details (password 10+ characters)."), 400
    # Self-registration ALWAYS creates a viewer. The role is never taken from the request.
    with get_engine().begin() as conn:
        exists = conn.execute(text("SELECT 1 FROM users WHERE email = :e"), {"e": email}).first()
        if exists:
            return render_template("register.html",
                                   error="Could not register with those details."), 400
        conn.execute(
            text("INSERT INTO users (email, name, password_hash, role) "
                 "VALUES (:e, :n, :p, 'viewer')"),
            {"e": email, "n": name, "p": hash_password(password)})
    return redirect(url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method != "POST":      # HEAD and GET only show the form
        return render_template("login.html", error=None)
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    with get_engine().begin() as conn:
        user = conn.execute(
            text("SELECT id, password_hash, is_active FROM users WHERE email = :e"),
            {"e": email}).mappings().first()
        ok = bool(user and user["is_active"] and verify_password(user["password_hash"], password))
        write_audit(conn, actor_id=user["id"] if user else None,
                    action="login", outcome="allowed" if ok else "denied",
                    ip=request.remote_addr, detail={"email": email})
    if not ok:
        return render_template("login.html", error="Wrong email or password."), 401
    token = create_session(user["id"])
    resp = make_response(redirect(url_for("ui.documents_page")))   # ONE response, then the cookie
    resp.set_cookie(COOKIE_NAME, token, max_age=SESSION_HOURS * 3600,
                    httponly=True, secure=request.is_secure, samesite="Lax")
    return resp


@bp.post("/logout")
def logout():
    token = request.cookies.get(COOKIE_NAME)
    user = get_current_user()
    if token:
        delete_session(token)
    if user:
        with get_engine().begin() as conn:
            write_audit(conn, actor_id=user["id"], action="logout", outcome="allowed",
                        ip=request.remote_addr)
    resp = make_response(redirect(url_for("auth.login")))
    resp.delete_cookie(COOKIE_NAME)
    return resp