import os
from flask import Flask
from flask_wtf import CSRFProtect
from sqlalchemy import text

from .db import get_engine

csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]  # required, no default
    csrf.init_app(app)

    from .routes.auth_routes import bp as auth_bp
    app.register_blueprint(auth_bp)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/health/db")
    def health_db():
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"db": "ok"}

    return app