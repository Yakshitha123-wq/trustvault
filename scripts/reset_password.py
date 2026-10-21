import secrets
import sys

from sqlalchemy import text

from app.audit import write_audit
from app.auth import hash_password
from app.db import get_engine


def main(email):
    password = secrets.token_urlsafe(12)
    with get_engine().begin() as conn:
        row = conn.execute(text("SELECT id FROM users WHERE email = :e"),
                           {"e": email}).first()
        if row is None:
            sys.exit(f"No such user: {email}")
        conn.execute(text("UPDATE users SET password_hash = :p WHERE id = :u"),
                     {"p": hash_password(password), "u": row[0]})
        conn.execute(text("DELETE FROM sessions WHERE user_id = :u"), {"u": row[0]})
        write_audit(conn, actor_id=None, action="password_reset", outcome="allowed",
                    target_user_id=row[0], detail={"by": "operator script"})
    print(f"{email}  new password: {password}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m scripts.reset_password EMAIL")
    main(sys.argv[1])