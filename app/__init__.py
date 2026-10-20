import os

from flask import Flask, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from sqlalchemy import text
from werkzeug.middleware.proxy_fix import ProxyFix

from .db import get_engine

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")


def create_app():
    app = Flask(__name__)
    # Trust exactly one proxy (Render), so client IP and https are read correctly.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]  # required, no default
    csrf.init_app(app)
    limiter.init_app(app)

    from .routes.auth_routes import bp as auth_bp
    app.register_blueprint(auth_bp)

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

    return app