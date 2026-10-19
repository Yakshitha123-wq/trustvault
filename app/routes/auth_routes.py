from .. import limiter
from flask import Blueprint, abort, make_response, redirect, render_template_string, request, url_for
from sqlalchemy import text

from ..audit import write_audit
from ..auth import (COOKIE_NAME, SESSION_HOURS, create_session, delete_session,
                    get_current_user, hash_password, verify_password)
from ..db import get_engine

bp = Blueprint("auth", __name__)

# Placeholder page so we can test. We'll replace it with real templates later.
FORM = """
<h1>{{ title }}</h1>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  {% if title == 'Register' %}<input name="name" placeholder="Name" required>{% endif %}
  <input name="email" type="email" placeholder="Email" required>
  <input name="password" type="password" placeholder="Password" required minlength="10">
  <button>{{ title }}</button>
</form>
{% if error %}<p>{{ error }}</p>{% endif %}
"""


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template_string(FORM, title="Register", error=None)
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    if not name or "@" not in email or len(password) < 10:
        return render_template_string(FORM, title="Register",
                                      error="Check your details (password 10+ characters)."), 400
    # Self-registration ALWAYS creates a viewer. The role is never taken from the request.
    with get_engine().begin() as conn:
        exists = conn.execute(text("SELECT 1 FROM users WHERE email = :e"), {"e": email}).first()
        if exists:
            return render_template_string(FORM, title="Register",
                                          error="Could not register with those details."), 400
        conn.execute(
            text("INSERT INTO users (email, name, password_hash, role) VALUES (:e, :n, :p, 'viewer')"),
            {"e": email, "n": name, "p": hash_password(password)})
    return redirect(url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "GET":
        return render_template_string(FORM, title="Login", error=None)
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
        return render_template_string(FORM, title="Login", error="Wrong email or password."), 401
    token = create_session(user["id"])
    resp = make_response(redirect("/health"))
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