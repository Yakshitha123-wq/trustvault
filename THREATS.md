# THREATS.md

## T1: Someone alters or deletes audit records (2026-10-19)
**Attack:** a bug, SQL injection or a stolen app credential runs UPDATE or DELETE on audit_log; a privileged user edits a row.
**Defence:** three layers. (1) The app role `trustvault_app` has only SELECT and INSERT on audit_log. (2) A trigger blocks UPDATE, DELETE and TRUNCATE for every role. (3) Rows are hash-chained and `verify_chain` (app/audit.py) detects edits.
**Status:** TESTED in tests/test_audit.py:
- test_app_role_cannot_update_or_delete_audit_rows
- test_trigger_blocks_even_the_owner
- test_tampering_with_a_row_is_detected
**Mutation check (2026-10-19):** I commented out the hash comparison in verify_chain; test_tampering_with_a_row_is_detected failed with "tampering was NOT detected", then passed again after restoring.
**Live check (2026-10-21):** on the deployed database, `has_table_privilege` for `trustvault_app` on audit_log returned SELECT t, INSERT t, UPDATE f, DELETE f.
**Accepted risk:** someone who controls the owner account can disable the trigger and rewrite the whole chain consistently, and no test covers that. The app never uses that account. Possible later mitigation: publish the latest chain hash outside the database.

## T2: Guessing or enumerating document IDs (2026-10-20, updated 2026-10-21)
**Attack:** a logged-in user who was not granted a document requests `/documents/<id>` or `/documents/<id>/download` with an ID they guessed, copied or enumerated. A second angle: telling "exists but forbidden" apart from "does not exist" and so learning which documents exist.
**Defence:** IDs are UUIDs. Every request goes through `get_document_or_404` (app/access.py), which calls `authorize()` and returns the same 404 whether the document is missing or the user is not allowed. The response bodies are identical. A malformed ID also returns 404, not a 500. The JSON for the metadata route does not include `storage_key`. Admins get 404 on download, because they may see metadata only.
**Status:** TESTED for `GET /documents/<id>` and `GET /documents/<id>/download`.
- tests/test_documents_access.py: test_stranger_gets_404, test_missing_and_forbidden_look_identical, test_not_a_uuid_is_404_not_500, test_admin_can_see_metadata_only (no `storage_key` in the response)
- tests/test_upload_download.py: test_stranger_cannot_download, test_anonymous_cannot_download, test_admin_cannot_download_contents, test_refused_download_is_audited
**Mutation checks (2026-10-20 and 2026-10-21):**
- I removed the `authorize(...)` call from `get_document_or_404`. On the metadata route five tests failed (stranger, anonymous, missing-vs-forbidden, revocation, audit). On the download route five failed (stranger, anonymous, admin, revoked download, refused-download audit).
- I added `storage_key` to the JSON in documents.py. Only test_admin_can_see_metadata_only failed.
- I changed the download action from "read" to "view_meta". Only test_admin_cannot_download_contents failed.
Each passed again after `git restore`.
**Accepted detail:** an anonymous request gets 401, not 404. That shows a login is needed but not whether the document exists.
**Accepted risks:**
- A refused request writes an audit row and a missing-document request also does, but the forbidden path does extra work (grants lookup), so response time may differ slightly. I have not tried to hide this timing difference.
- A malformed ID returns 404 without an audit row. Anonymous and stranger probes each write a row, so an attacker could grow the audit log. Rate limiting these routes is not built yet.
**Not covered yet:** edit, delete, share and search do not exist, so this entry says nothing about them (see T13 and T15). Each needs the same tests when built.

## T3: A non-owner uploads a document (2026-10-21)
**Attack:** a viewer, an admin or an anonymous caller sends `POST /documents` directly to put files into the system.
**Defence:** the upload route requires the owner role on the server. Anonymous callers get 401, other roles 403, and the refusal is audited.
**Status:** TESTED: test_viewer_cannot_upload, test_anonymous_cannot_upload, test_admin_cannot_upload.
**Mutation check (2026-10-21):** I removed the owner-role check. test_viewer_cannot_upload failed with 201 instead of 403. Restored, it passed.

## T4: Access still works after it was revoked (2026-10-20, updated 2026-10-21)
**Attack:** a user who was granted access keeps using it after the owner removes the grant, for example with the same session cookie.
**Defence:** grants are not stored in the session. `get_document_or_404` reads the grants for the document from the database on every request, so a deleted grant has no effect on the next request. The cost is one extra query per document request.
**Status:** TESTED for the metadata route and the download route: test_revocation_is_immediate (metadata) and test_revoked_download_is_immediate (download). Each gets a 200, deletes the grant, and then expects a 404 on the same client with the same cookie. These tests delete the grant row directly. The revoke route itself is not built yet (see T13).
**Mutation checks:** forcing `grants = {}` before the authorize call failed test_revocation_is_immediate and test_reader_can_see_metadata (2026-10-20). Removing the authorize call also failed test_revoked_download_is_immediate (2026-10-21). Each passed again after restoring.
**Accepted risk:** the access check and the file read are two separate transactions, so a revoke landing in the milliseconds between them still lets that one download through, and its audit row records it. Once the bytes are sent there is nothing to take back.
**Not covered yet:** a route-level test for a disabled user (the `is_active` check is unit-tested in tests/test_authz.py and through a real session in tests/test_session_user.py, but not through a document route).

## T5: Malicious or disguised upload (2026-10-21)
**Attack:** a file renamed to look harmless, such as an executable named evil.pdf or a PDF named fake.png, or a huge file to fill the database.
**Defence:** in app/validation.py. Allowed types are pdf, png, jpg, jpeg and txt. The first bytes must match the extension (PDF "%PDF-", the PNG signature, JPEG FF D8 FF; text must be valid UTF-8 with no NUL bytes). Maximum 5 MB, plus a 6 MB cap on the whole request in Flask. The MIME type is chosen by the server from the extension; the browser's Content-Type is ignored.
**Status:** TESTED: test_bad_uploads_are_rejected (evil.pdf, fake.png, noextension, script.pdf.exe, page.html and image.svg cases), test_empty_file_is_rejected and test_oversized_upload_is_rejected.
**Mutation checks (2026-10-21):** removing the byte check failed both bad-upload cases. Removing the size check failed the oversize test. Each passed again after restoring.
**Accepted risk:** only the start of the file is checked. A file with a valid header can still carry harmful content, and there is no antivirus scan. Requests over the 6 MB cap get a 413 before the route runs, so they are not audited.

## T6: Path tricks in filenames (2026-10-21)
**Attack:** a filename such as `../../etc/passwd.pdf`, aiming to write or read outside the intended place.
**Defence:** the name goes through `secure_filename`. File bytes are stored in Postgres (document_blobs), not on disk, so the filename never becomes a path.
**Status:** TESTED: test_filename_cannot_carry_a_path.
**Mutation check (2026-10-21):** I used the raw filename. The test failed because the stored name still contained "/". Restored, it passed.

## T7: An uploaded file runs in the browser when downloaded (2026-10-21)
**Attack:** an uploaded file served so the browser executes it, for example HTML or SVG with script.
**Defence:** downloads are sent as attachments with `X-Content-Type-Options: nosniff`. HTML and SVG are not on the upload allowlist (test_bad_uploads_are_rejected includes page.html and image.svg), and the stored MIME type is set by the server.
**Status:** TESTED: test_download_is_sent_as_an_attachment_with_nosniff.
**Mutation check (2026-10-21):** I removed the nosniff header. The test failed. Restored, it passed.

## T8: Brute-force login and account probing (2026-10-19, updated 2026-10-21)
**Attack:** guessing passwords by repeated POSTs to /login, or telling registered emails from unregistered ones.
**Defence:** Flask-Limiter, 5 POSTs per minute per IP (app/routes/auth_routes.py). An unknown email and a wrong password give the same message and the same status.
**Status:** BUILT, observed manually (6th attempt returned 429). Automated test PLANNED.
**Known weaknesses:**
- The limit is per IP, so shared networks share a counter, and memory storage is per process and resets on restart.
- 429 responses are not written to the audit log.
- A failed login stores the email that was typed. If someone types a password into the email box, it lands in the permanent audit log.
- An unknown email skips the password check, so its response is slightly faster than a wrong password for a real account. I have not tried to hide this timing difference.

## T9: Access leaves no record (2026-10-21)
**Attack:** someone uploads, downloads or probes a document and afterwards nobody can say who did it, or refused attempts leave no trace.
**Defence:** every upload and download writes an `allowed` audit row in the same transaction as the action, so if the audit write fails the action fails. Every refused document request writes a `denied` row (action `document_access`) before the 404 or 401 is returned. Rows are hash-chained (T1).
**Status:** TESTED for upload, download and refused access: test_upload_is_audited, test_successful_download_is_audited, test_refused_download_is_audited, test_refused_attempt_is_audited.
**Mutation checks:** removing the `write_audit` call from `get_document_or_404` failed only test_refused_attempt_is_audited (2026-10-20). Removing it from the download route failed test_successful_download_is_audited (2026-10-21). Each passed again after restoring.
**Not covered yet:** grant, revoke, edit and delete (see T13 and T15). Login success and failure are audited, but no automated test checks them. Rate-limited logins (429) and requests over the size cap (413) are not recorded.

## T10: Known demo credentials on the live site (2026-10-21)
**Attack:** anyone who reads the README logs in as a demo user and tries to do more than demo data allows.
**Defence:** the brief requires one account per role, so this cannot be removed. Passwords are random (scripts/seed.py, scripts/reset_password.py). The admin cannot read file contents without a grant, and the viewer sees only what is granted. Login is rate limited (T8).
**Status:** ACCEPTED (required by the brief). No automated test.
**Accepted risk:** anyone can act as these users, including uploading as the owner. The accounts should be deleted or have their passwords changed after judging.

## T11: Credentials exposed during setup (2026-10-20, updated 2026-10-21)
**What happened:** while deploying, the Render database owner URL and the `trustvault_app` password were pasted into an AI chat. A local `postgres` password was also typed into a command that was pasted there.
**Response:** the first database was deleted and recreated under a new owner credential, and the app role password was changed. The app connects as `trustvault_app`, which cannot UPDATE or DELETE audit rows (`has_table_privilege('trustvault_app','audit_log','UPDATE')` returned `f`, also on the live database, see T1).
**Related action (2026-10-21):** the seeded owner account on the live site needed a new password. scripts/reset_password.py sets a new argon2 hash, deletes that user's sessions and writes a `password_reset` audit row. I ran it with a database login typed at a hidden prompt, then closed the window so the variables were gone.
**Accepted risks:**
- The Render database accepts connections from any IP (`0.0.0.0/0`) and is protected by its password only.
- Whoever holds the Render owner credential can still disable the audit trigger and rewrite the hash chain.
- The free database expires on 19 November 2026.
**Status:** DONE (manual checks, no automated test).

## T12: Cross-site request forgery on state-changing routes (2026-10-21)
**Attack:** a malicious page makes a logged-in user's browser send a POST to TrustVault (upload now, grant and revoke later), using their session cookie.
**Defence:** `CSRFProtect` is enabled for the whole app (app/__init__.py). Every POST needs a valid token, and Flask-WTF also checks the Referer over HTTPS. The session cookie is HttpOnly and SameSite=Lax.
**Status:** TESTED for `POST /documents` only: tests/test_csrf.py::test_post_without_csrf_token_is_rejected builds an app with CSRF left on and expects 400. The cookie flags are tested in tests/test_session_cookie.py.
**Mutation checks (2026-10-21):** with `WTF_CSRF_ENABLED` set to False in the CSRF test, it failed (201 instead of 400). In the cookie test, `httponly=False` failed the HttpOnly assertion and `samesite="None"` failed the SameSite assertion. Each passed again after restoring.
**Live check (2026-10-21):** a curl upload to the deployed site with no CSRF token and no session cookie returned 400. Without CSRF an anonymous upload would have returned 401 from the route, so the CSRF check runs first. I did not repeat this while logged in.
**Not covered:** every other test runs with CSRF switched off in conftest.py. CSRF tests for grant and revoke are written (tests/test_grants.py) but fail until those routes exist (T13). The cookie test does not check the Secure flag, which is only set over HTTPS, and I have not checked it on the live site.

## T13: Someone who is not the owner changes who has access (2026-10-21)
**Attack:** a reader, an editor, an admin, another owner or an anonymous caller grants themselves or someone else access, upgrades their own grant from read to edit, revokes another person's access, or lists who has access. A forged cross-site POST does the same through the owner's browser.
**Defence (planned):** the grant, revoke and list routes call `get_document_or_404` with the `share` action, which only the owner has, so everyone else gets the same 404 as for a missing document. Authorisation runs before input is checked, so a bad value cannot be used to probe. Each change and its audit row commit in one transaction. CSRF protection is global (T12).
**Status:** PLANNED. The routes are not built. The tests were written first (tests/test_grants.py, 33 cases) and run before any route existed: 20 failed and 13 passed. The 13 passes are the non-owner refusals, which pass only because a missing route also returns 404, so they prove nothing until a mutation check shows they can fail.
**Known weaknesses I am accepting:** an `edit` grant is stored and checked, but no edit route exists yet, so it currently gives the same access as `read`. Granting by email tells an owner whether an address is registered.

## T14: Registering as a more powerful role (2026-10-21)
**Attack:** a request to `/register` carries `role=admin` or `role=owner`, hoping the server copies it into the new account (mass assignment).
**Defence:** the register route writes the role `viewer` in its SQL and never reads a role from the request (app/routes/auth_routes.py).
**Status:** TESTED: tests/test_register.py::test_register_ignores_a_role_field posts `role=admin` and checks the stored role is `viewer`.
**Mutation check (2026-10-21):** I changed the INSERT to take the role from the form; the test failed because the role was `admin`. After `git restore` it passed again.
**Known gaps:** registration is not rate limited and does not write an audit row, so someone can create accounts without leaving a record. I accept this for now. New accounts can only be viewers, and a viewer sees only what an owner grants.

## T15: Edit, delete, document list and search (2026-10-21)
**Attack:** a user edits or deletes a document they only hold a read grant for; a document list or search shows names, owners or categories of documents the user was never granted, or the owner's soft-deleted documents.
**Defence (planned):** edit needs the `edit` action and delete the owner only, both through `get_document_or_404`. The list and search filter by permission inside the SQL `WHERE` clause (owner, or a grant exists, not deleted), never by fetching everything and filtering in Python.
**Status:** PLANNED. None of these routes exist. Each gets its tests written first.