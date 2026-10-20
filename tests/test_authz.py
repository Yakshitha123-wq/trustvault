import pytest

from app.authz import authorize

# ---- Fixed people (plain dicts, shaped like what get_current_user returns) ----
OWNER    = {"id": "u-owner",    "role": "owner",  "is_active": True}
EDITOR   = {"id": "u-editor",   "role": "viewer", "is_active": True}
READER   = {"id": "u-reader",   "role": "viewer", "is_active": True}
STRANGER = {"id": "u-stranger", "role": "viewer", "is_active": True}
REVOKED  = {"id": "u-revoked",  "role": "viewer", "is_active": True}  # grant removed
DISABLED = {"id": "u-disabled", "role": "viewer", "is_active": False}
ADMIN    = {"id": "u-admin",    "role": "admin",  "is_active": True}
ANON     = None

# ---- One document, with its current grants ----
DOC = {"id": "d1", "owner_id": "u-owner", "deleted_at": None}
GRANTS = {"u-editor": "edit", "u-reader": "read"}   # REVOKED is absent on purpose

ACTIONS = {"read", "edit", "delete", "share", "view_meta", "view_audit"}

# ---- The table: (who, action, expected) ----
CASES = [
    # owner: everything
    (OWNER, "read", True), (OWNER, "edit", True), (OWNER, "delete", True),
    (OWNER, "share", True), (OWNER, "view_meta", True), (OWNER, "view_audit", True),

    # editor: read, edit, see metadata
    (EDITOR, "read", True), (EDITOR, "edit", True), (EDITOR, "delete", False),
    (EDITOR, "share", False), (EDITOR, "view_meta", True), (EDITOR, "view_audit", False),

    # reader: read and see metadata
    (READER, "read", True), (READER, "edit", False), (READER, "delete", False),
    (READER, "share", False), (READER, "view_meta", True), (READER, "view_audit", False),

    # stranger: nothing
    (STRANGER, "read", False), (STRANGER, "edit", False), (STRANGER, "delete", False),
    (STRANGER, "share", False), (STRANGER, "view_meta", False), (STRANGER, "view_audit", False),

    # revoked: nothing (grant removed)
    (REVOKED, "read", False), (REVOKED, "edit", False), (REVOKED, "delete", False),
    (REVOKED, "share", False), (REVOKED, "view_meta", False), (REVOKED, "view_audit", False),

    # disabled: nothing
    (DISABLED, "read", False), (DISABLED, "edit", False), (DISABLED, "delete", False),
    (DISABLED, "share", False), (DISABLED, "view_meta", False), (DISABLED, "view_audit", False),

    # anonymous: nothing
    (ANON, "read", False), (ANON, "edit", False), (ANON, "delete", False),
    (ANON, "share", False), (ANON, "view_meta", False), (ANON, "view_audit", False),

    # admin: metadata and audit only, never contents
    (ADMIN, "read", False), (ADMIN, "edit", False), (ADMIN, "delete", False),
    (ADMIN, "share", False), (ADMIN, "view_meta", True), (ADMIN, "view_audit", True),
]


@pytest.mark.parametrize("user,action,expected", CASES)
def test_matrix(user, action, expected):
    assert authorize(user, DOC, action, GRANTS) is expected


def test_every_case_uses_a_real_action():
    assert {a for _, a, _ in CASES} == ACTIONS


def test_disabled_owner_is_refused():
    disabled_owner = {"id": "u-owner", "role": "owner", "is_active": False}
    for action in ACTIONS:
        assert authorize(disabled_owner, DOC, action, GRANTS) is False


def test_disabled_user_with_a_grant_is_refused():
    for action in ACTIONS:
        assert authorize(DISABLED, DOC, action, {"u-disabled": "edit"}) is False


def test_unknown_action_is_denied():
    assert authorize(OWNER, DOC, "banana", GRANTS) is False


def test_soft_deleted_document_is_owner_only():
    gone = {**DOC, "deleted_at": "2026-10-19T12:00:00+00:00"}
    for action in ACTIONS:
        assert authorize(OWNER, gone, action, GRANTS) is True
        for who in (EDITOR, READER, STRANGER, ADMIN):
            assert authorize(who, gone, action, GRANTS) is False