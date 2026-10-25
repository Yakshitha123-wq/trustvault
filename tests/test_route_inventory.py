import re
import uuid
from pathlib import Path

PUBLIC = {"/", "/health", "/health/db", "/login", "/register", "/logout"}
SAMPLE = str(uuid.uuid4())
API_MD = Path(__file__).resolve().parent.parent / "API.md"


def test_every_route_outside_the_public_list_refuses_an_anonymous_caller(app):
    client = app.test_client()
    checked = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static" or rule.rule in PUBLIC:
            continue
        path = re.sub(r"<[^>]+>", SAMPLE, rule.rule)
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            status = client.open(path, method=method).status_code
            assert status in (401, 302), f"{method} {rule.rule} answered {status}"
            checked.append((method, rule.rule))
    assert len(checked) >= 12   # guards against the loop silently checking nothing


def test_api_md_mentions_every_route(app):
    text = API_MD.read_text(encoding="utf-8")
    for rule in app.url_map.iter_rules():
        if rule.endpoint != "static":
            assert rule.rule in text, f"API.md does not mention {rule.rule}"