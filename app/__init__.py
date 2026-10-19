from flask import Flask
from sqlalchemy import text

from .db import get_engine


def create_app():
    app = Flask(__name__)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/health/db")
    def health_db():
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"db": "ok"}

    return app