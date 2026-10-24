from sqlalchemy import text

from app.db import get_engine


def _email(user_id):
    with get_engine().connect() as conn:
        return conn.execute(text("SELECT email FROM users WHERE id = :u"),
                            {"u": user_id}).scalar()


def test_old_cookie_is_dead_after_logout(app, people, doc):
    c = app.test_client()
    r = c.post("/login", data={"email": _email(people["owner"]), "password": "x" * 12})
    assert r.status_code == 302
    token = c.get_cookie("tv_session").value
    assert c.get(f"/documents/{doc}").status_code == 200
    assert c.post("/logout").status_code == 302

    replay = app.test_client()
    replay.set_cookie("tv_session", token)            # the pre-logout cookie, replayed
    assert replay.get(f"/documents/{doc}").status_code == 401
    assert replay.get("/documents").status_code == 401


def test_disabling_a_user_cuts_access_on_the_next_request(client_for, people, doc):
    c = client_for(people["reader"])                  # same cookie throughout
    assert c.get(f"/documents/{doc}").status_code == 200
    assert c.get("/documents").status_code == 200
    with get_engine().begin() as conn:
        conn.execute(text("UPDATE users SET is_active = false WHERE id = :u"),
                     {"u": people["reader"]})
    assert c.get(f"/documents/{doc}").status_code in (401, 404)
    assert c.get(f"/documents/{doc}/download").status_code in (401, 404)
    assert c.get("/documents").status_code == 401