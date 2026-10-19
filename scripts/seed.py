import secrets

from sqlalchemy import text

from app.audit import write_audit
from app.auth import hash_password
from app.db import get_engine

USERS = [
    ("admin@trustvault.example", "Demo Admin", "admin"),
    ("owner@trustvault.example", "Demo Owner", "owner"),
    ("viewer@trustvault.example", "Demo Viewer", "viewer"),
]


def main():
    created = []
    with get_engine().begin() as conn:
        for email, name, role in USERS:
            if conn.execute(text("SELECT 1 FROM users WHERE email = :e"),
                            {"e": email}).first():
                print(f"exists, skipped: {email}")
                continue
            password = secrets.token_urlsafe(12)
            user_id = conn.execute(
                text("INSERT INTO users (email, name, password_hash, role) "
                     "VALUES (:e, :n, :p, :r) RETURNING id"),
                {"e": email, "n": name, "p": hash_password(password), "r": role},
            ).scalar()
            write_audit(conn, actor_id=None, action="user_seed", outcome="allowed",
                        target_user_id=user_id, detail={"role": role})
            created.append((email, role, password))
    for email, role, password in created:
        print(f"{role:7} {email}  password: {password}")


if __name__ == "__main__":
    main()