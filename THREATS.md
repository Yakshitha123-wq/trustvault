# THREATS.md
## T1: Someone alters or deletes audit records (2026-10-19)
**Attack:** a bug, SQL injection or a stolen app credential runs UPDATE or DELETE on audit_log; a privileged user edits a row.
**Defence:** three layers. (1) The app role `trustvault_app` has only SELECT and INSERT on audit_log. (2) A trigger blocks UPDATE, DELETE and TRUNCATE for every role. (3) Rows are hash-chained and `verify_chain` (app/audit.py) detects edits.
**Status:** TESTED in tests/test_audit.py:
- test_app_role_cannot_update_or_delete_audit_rows
- test_trigger_blocks_even_the_owner
- test_tampering_with_a_row_is_detected
**Mutation check (2026-10-19):** I commented out the hash comparison in verify_chain; test_tampering_with_a_row_is_detected failed with "tampering was NOT detected", then passed again after restoring.
**Accepted risk:** someone who controls the owner account can disable the trigger and rewrite the whole chain consistently, and no test covers that. The app never uses that account. Possible later mitigation: publish the latest chain hash outside the database.
## T2: Guessing or enumerating document IDs (2026-10-20)
**Attack:** a logged-in user who was not granted a document requests `/documents/<id>` with an ID they guessed, copied or enumerated. A second angle: telling "exists but forbidden" apart from "does not exist" and so learning which documents exist.
**Defence:** IDs are UUIDs. Every request goes through `get_document_or_404` (app/access.py), which calls `authorize()` and returns the same 404 whether the document is missing or the user is not allowed. The response bodies are identical. A malformed ID also returns 404, not a 500. The JSON for the metadata route does not include `storage_key`.
**Status:** TESTED for `GET /documents/<id>` only, in tests/test_documents_access.py:
- test_stranger_gets_404
- test_missing_and_forbidden_look_identical
- test_not_a_uuid_is_404_not_500
- test_admin_can_see_metadata_only (no `storage_key` in the response)
**Mutation checks (2026-10-20):**
- I removed the `authorize(...)` call from `get_document_or_404`. Five tests failed: stranger, anonymous, missing-vs-forbidden, revocation and the audit test.
- I added `storage_key` to the JSON in documents.py. Only test_admin_can_see_metadata_only failed.
Both passed again after `git restore`.
**Not covered yet:** download, edit, delete, share and search do not exist, so this entry says nothing about them. Each needs the same tests when built.
**Accepted detail:** an anonymous request gets 401, not 404. That shows a login is needed but not whether the document exists.

## T4: Access still works after it was revoked (2026-10-20)
**Attack:** a user who was granted access keeps using it after the owner removes the grant, for example with the same session cookie.
**Defence:** grants are not stored in the session. `get_document_or_404` reads the grants for the document from the database on every request, so a deleted grant has no effect on the next request. The cost is one extra query per document request.
**Status:** TESTED for `GET /documents/<id>` only: test_revocation_is_immediate gets a 200, deletes the grant, and then expects a 404 on the same client with the same cookie.
**Mutation check (2026-10-20):** I forced `grants = {}` before the authorize call. test_revocation_is_immediate and test_reader_can_see_metadata failed, and both passed again after restoring.
**Not covered yet:** a disabled user, a revoked download link and a download already in progress when access is revoked. Download does not exist yet. The `is_active` check is unit-tested in tests/test_authz.py, but there is no route-level test for a disabled user.
## T8: Brute-force login (2026-10-19)
**Attack:** guessing passwords by repeated POSTs to /login.
**Defence:** Flask-Limiter, 5 POSTs per minute per IP (app/routes/auth_routes.py).
**Status:** BUILT, observed manually (6th attempt returned 429). Automated test PLANNED.
**Known weaknesses:** per-IP, so shared networks share a counter; memory storage is
per process and resets on restart; 429 responses are not written to the audit log.
## T11: Credentials exposed during setup (2026-10-20)
**What happened:** while deploying, the Render database owner URL and the `trustvault_app` password were pasted into an AI chat.
**Response:** the first database was deleted and recreated under a new owner credential, the app role password was changed, and the app now connects as `trustvault_app`. That role cannot UPDATE or DELETE audit rows (`has_table_privilege('trustvault_app','audit_log','UPDATE')` returned `f`).
**Accepted risks:**
- The Render database accepts connections from any IP (`0.0.0.0/0`) and is protected by its password only.
- Whoever holds the Render owner credential can still disable the audit trigger and rewrite the hash chain.
- The free database expires on 19 November 2026.
**Status:** DONE (manual checks, no automated test).