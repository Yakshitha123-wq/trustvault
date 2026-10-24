import uuid

from app import create_app


def _app():
    return create_app({"TESTING": True, "WTF_CSRF_ENABLED": False,
                       "RATELIMIT_ENABLED": True})

def _email():
    return f"{uuid.uuid4().hex}@test.example"   # unique, so counters never leak between tests


def _try(client, email, address="127.0.0.1"):
    return client.post("/login", data={"email": email, "password": "wrong-password"},
                       environ_overrides={"REMOTE_ADDR": address}).status_code


def test_sixth_wrong_login_for_one_account_is_refused():
    client, email = _app().test_client(), _email()
    assert [_try(client, email) for _ in range(5)] == [401] * 5
    assert _try(client, email) == 429


def test_changing_address_does_not_reset_an_accounts_counter():
    client, email = _app().test_client(), _email()
    for i in range(5):
        assert _try(client, email, f"10.1.0.{i}") == 401
    assert _try(client, email, "10.1.0.99") == 429


def test_one_accounts_attempts_do_not_lock_another():
    client = _app().test_client()
    victim, other = _email(), _email()
    for _ in range(6):
        _try(client, victim)
    assert _try(client, other) == 401


def test_email_case_and_spaces_do_not_start_a_new_counter():
    client, email = _app().test_client(), _email()
    for _ in range(5):
        _try(client, email)
    assert _try(client, " " + email.upper() + " ") == 429