import os

from flask import Flask, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from sqlalchemy import text
from werkzeug.middleware.proxy_fix import ProxyFix

from .db import get_engine
from .validation import MAX_BYTES

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")


def create_app(test_config=None):
    app = Flask(__name__)
    # Trust exactly one proxy (Render), so client IP and https are read correctly.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]  # required, no default
    # Hard cap on the whole request; validate_upload enforces the exact 5 MB on the file.
    app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES + 1024 * 1024
    app.config.update(test_config or {})
    csrf.init_app(app)
    limiter.init_app(app)

    from .routes.auth_routes import bp as auth_bp
    from .routes.documents import bp as documents_bp
    from .routes.sharing import bp as sharing_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(sharing_bp)

    @app.get("/")
    def index():
        return redirect("/login")

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

    return app