ACTIONS = {"read", "edit", "delete", "share", "view_meta", "view_audit"}

# What each grant level allows. Owners and admins are handled separately.
GRANT_ALLOWS = {
    "read": {"read", "view_meta"},
    "edit": {"read", "edit", "view_meta"},
}
ADMIN_ALLOWS = {"view_meta", "view_audit"}


def authorize(user, document, action, grants):
    """Return True only if `user` may do `action` on `document`.

    user:     dict from get_current_user(), or None
    document: dict with "owner_id" and "deleted_at"
    action:   one of ACTIONS
    grants:   {user_id: "read" | "edit"} for this document, read fresh from the DB
    Deny by default: every path that is not explicitly allowed returns False.
    """
    # 1. No user, or a disabled user: nothing.
    if not user or not user.get("is_active"):
        return False

    # 2. Unknown action: deny.
    if action not in ACTIONS:
        return False

    is_owner = str(user["id"]) == str(document["owner_id"])

    # 3. Soft-deleted: only the owner may do anything. Must come before grants.
    if document.get("deleted_at") is not None:
        return is_owner

    # 4. The owner can do everything on their own document.
    if is_owner:
        return True

    # 5. Everyone else: collect what they may do, then check the action.
    allowed = set()
    if user.get("role") == "admin":
        allowed |= ADMIN_ALLOWS  # metadata and audit only, never contents

    level = {str(k): v for k, v in grants.items()}.get(str(user["id"]))
    allowed |= GRANT_ALLOWS.get(level, set())

    return action in allowed