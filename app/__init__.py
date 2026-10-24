import os

from flask import Flask, redirect, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from sqlalchemy import text
from werkzeug.middleware.proxy_fix import ProxyFix

from .db import get_engine
from .validation import MAX_BYTES

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")


def create_app(test_config=None):
    app = Flask(__name__)
    # Trust exactly one proxy (Render), so client IP and https are read correctly.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]  # required, no default
    # Hard cap on the whole request; validate_upload enforces the exact 5 MB on the file.
    app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES + 1024 * 1024
    # Flask's own cookie (it carries the CSRF token): not sent on cross-site POSTs.
    # Assigned directly: Flask's default config already has this key, so setdefault would do nothing.
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config.update(test_config or {})
    csrf.init_app(app)
    limiter.init_app(app)

    from .routes.admin import bp as admin_bp
    from .routes.auth_routes import bp as auth_bp
    from .routes.documents import bp as documents_bp
    from .routes.sharing import bp as sharing_bp
    from .routes.ui import bp as ui_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(sharing_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(ui_bp)

    @app.get("/")
    def index():
        return redirect("/app")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/health/db")
    def health_db():
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"db": "ok"}

    @app.errorhandler(413)
    def too_large(e):
        return {"error": "File too large (limit 5 MB)."}, 413

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if request.endpoint != "static":
            resp.headers.setdefault("Cache-Control", "no-store")
        if request.is_secure:  # true on Render because of ProxyFix
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return resp

    return app