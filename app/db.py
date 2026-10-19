import os
from sqlalchemy import create_engine

_engine = None


def _normalise(url: str) -> str:
    # Render gives postgres:// or postgresql://, but SQLAlchemy with psycopg
    # needs the postgresql+psycopg:// form.
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def get_engine():
    global _engine
    if _engine is None:
        url = os.environ.get("DATABASE_URL")
        if not url:
            raise RuntimeError("DATABASE_URL is not set")
        _engine = create_engine(_normalise(url), pool_pre_ping=True)
    return _engine