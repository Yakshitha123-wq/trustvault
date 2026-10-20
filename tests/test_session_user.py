from app.auth import create_session, get_current_user


def test_get_current_user_returns_is_active(app, people):
    token = create_session(people["owner"])
    with app.test_request_context(headers={"Cookie": f"tv_session={token}"}):
        user = get_current_user()
    assert user is not None
    assert user["is_active"] is True
    assert str(user["id"]) == str(people["owner"])


def test_no_cookie_means_no_user(app):
    with app.test_request_context():
        assert get_current_user() is None