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

## T2: Guessing or enumerating document IDs (2026-10-20, updated 2026-10-22)
**Attack:** a logged-in user who was not granted a document requests `/documents/<id>` or `/documents/<id>/download` with an ID they guessed, copied or enumerated. A second angle: telling "exists but forbidden" apart from "does not exist" and so learning which documents exist.
**Defence:** IDs are UUIDs. Every request goes through `get_document_or_404` (app/access.py), which calls `authorize()` and returns the same 404 whether the document is missing or the user is not allowed. The response bodies are identical. A malformed ID also returns 404, not a 500. The JSON for the metadata route does not include `storage_key`. Admins get 404 on download, because they may see metadata only.
**Status:** TESTED for `GET /documents/<id>` and `GET /documents/<id>/download`. The grant routes use the same function (see T13).
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
**Also covered by:** the list and search (T15) and edit and delete (T16).

## T3: A non-owner uploads a document (2026-10-21)
**Attack:** a viewer, an admin or an anonymous caller sends `POST /documents` directly to put files into the system.
**Defence:** the upload route requires the owner role on the server. Anonymous callers get 401 (not audited); other roles get 403 and the refusal is written to the audit log.
**Status:** TESTED: test_viewer_cannot_upload, test_anonymous_cannot_upload, test_admin_cannot_upload.
**Mutation check (2026-10-21):** I removed the owner-role check. test_viewer_cannot_upload failed with 201 instead of 403. Restored, it passed.

## T4: Access still works after it was revoked (2026-10-20, updated 2026-10-22)
**Attack:** a user who was granted access keeps using it after the owner removes the grant, for example with the same session cookie.
**Defence:** grants are not stored in the session. `get_document_or_404` reads the grants for the document from the database on every request, so a deleted grant has no effect on the next request. The cost is one extra query per document request.
**Status:** TESTED for the metadata route and the download route: test_revocation_is_immediate (metadata) and test_revoked_download_is_immediate (download). Each gets a 200, deletes the grant row, and then expects a 404 on the same client with the same cookie. The revoke route is tested the same way in tests/test_grants.py (test_owner_revoke_takes_effect_immediately, see T13).
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
**Defence:** “5 attempts per minute per account (lower-cased email) and 60 per minute per address (app/routes/auth_routes.py). An unknown email and a wrong password give the same message and status.”
**Status:** “TESTED in tests/test_login_limit.py (4 tests), with mutation checks (see T18).”
**Known weaknesses:**
- The limit is per IP, so shared networks share a counter, and memory storage is per process and resets on restart.
- 429 responses are not written to the audit log.
- A failed login stores the email that was typed. If someone types a password into the email box, it lands in the permanent audit log.
- An unknown email skips the password check, so its response is slightly faster than a wrong password for a real account. I have not tried to hide this timing difference.

## T9: Access leaves no record (2026-10-21, updated 2026-10-22)
**Attack:** someone uploads, downloads, shares or probes a document and afterwards nobody can say who did it, or refused attempts leave no trace.
**Defence:** every upload, download, grant and revoke writes an `allowed` audit row in the same transaction as the action, so if the audit write fails the action fails. Grant and revoke rows name the person affected and the permission. Every refused document request writes a `denied` row (action `document_access`) before the 404 or 401 is returned. Rows are hash-chained (T1).
**Status:** TESTED for upload, download, grant, revoke and refused access: test_upload_is_audited, test_successful_download_is_audited, test_refused_download_is_audited, test_refused_attempt_is_audited, test_grant_is_audited, test_grant_audit_row_names_the_person_and_level, test_revoke_is_audited, test_refused_grant_attempt_is_audited.
**Mutation checks:** removing the `write_audit` call from `get_document_or_404` failed only test_refused_attempt_is_audited (2026-10-20). Removing it from the download route failed test_successful_download_is_audited, and removing it from grant and revoke failed their audit tests (2026-10-21). Each passed again after restoring.
**Also covered:** edit and delete are audited in the same transaction (test_edit_is_audited, test_delete_is_audited, test_refused_edit_and_delete_are_audited, see T16).Viewing the activity, running the chain check and refused attempts at the admin routes are audited too (T17).
**Not covered:** list and search are not audited. Login success and failure are audited, but no automated test checks them. Anonymous upload refusals, rate-limited logins (429), requests over the size cap (413) and account registration are not recorded.

## T10: Known demo credentials on the live site (2026-10-21)
**Attack:** anyone who reads the README logs in as a demo user and tries to do more than demo data allows.
**Defence:** the brief requires one account per role, so this cannot be removed. Passwords are random (scripts/seed.py, scripts/reset_password.py). A viewer sees only what is granted and an owner only their own documents. The admin cannot read file contents, but can see the name, owner and category of every non-deleted document (T15) and read the whole audit trail (T17). Login is rate limited (T8).
**Status:** ACCEPTED (required by the brief). No automated test.
**Accepted risk:** anyone can act as these users, including uploading as the owner and reading the audit trail as the admin. The accounts should be deleted or have their passwords changed after judging.

## T11: Credentials exposed during setup (2026-10-20, updated 2026-10-21)
**What happened:** while deploying, the Render database owner URL and the `trustvault_app` password were pasted into an AI chat. A local `postgres` password was also typed into a command that was pasted there.
**Response:** the first database was deleted and recreated under a new owner credential, and the app role password was changed. The app connects as `trustvault_app`, which cannot UPDATE or DELETE audit rows (`has_table_privilege('trustvault_app','audit_log','UPDATE')` returned `f`, also on the live database, see T1).
**Related action (2026-10-21):** the seeded owner account on the live site needed a new password. scripts/reset_password.py sets a new argon2 hash, deletes that user's sessions and writes a `password_reset` audit row. I ran it with a database login typed at a hidden prompt, then closed the window so the variables were gone.
**Accepted risks:**
- The Render database accepts connections from any IP (`0.0.0.0/0`) and is protected by its password only.
- Whoever holds the Render owner credential can still disable the audit trigger and rewrite the hash chain.
- The free database expires on 19 November 2026.
**Status:** DONE (manual checks, no automated test).

## T12: Cross-site request forgery on state-changing routes (2026-10-21, updated 2026-10-22)
**Attack:** a malicious page makes a logged-in user's browser send a POST to TrustVault (upload, grant or revoke), using their session cookie.
**Defence:** `CSRFProtect` is enabled for the whole app (app/__init__.py). Every POST needs a valid token, and Flask-WTF also checks the Referer over HTTPS. The session cookie is HttpOnly and SameSite=Lax.
**Status:** TESTED for upload, grant and revoke: tests/test_csrf.py::test_post_without_csrf_token_is_rejected, and test_grant_without_csrf_token_is_rejected and test_revoke_without_csrf_token_is_rejected in tests/test_grants.py. Each builds an app with CSRF left on and expects 400. The cookie flags are tested in tests/test_session_cookie.py.
**Mutation checks (2026-10-21):** with CSRF switched off in the test app, the upload test failed (201 instead of 400) and both grant and revoke tests failed (200 instead of 400). In the cookie test, `httponly=False` failed the HttpOnly assertion and `samesite="None"` failed the SameSite assertion. Each passed again after restoring.
**Live check (2026-10-21):** a curl upload to the deployed site with no CSRF token and no session cookie returned 400. Without CSRF an anonymous upload would have returned 401 from the route, so the CSRF check runs first. I did not repeat this while logged in.
**Not covered:** login and logout have no CSRF test of their own, and every other test runs with CSRF switched off in conftest.py. Edit and delete share the global protection but have no CSRF test of their own. The cookie test does not check the Secure flag, which is only set over HTTPS, and I have not checked it on the live site.

## T13: Someone who is not the owner changes who has access (2026-10-21, updated 2026-10-22)
**Attack:** a reader, an editor, an admin, another owner or an anonymous caller grants themselves or someone else access, upgrades their own grant from read to edit, revokes another person's access, or lists who has access. A forged cross-site POST does the same through the owner's browser.
**Defence:** the grant, revoke and list routes (app/routes/sharing.py) call `get_document_or_404` with the `share` action, which only the owner has. Everyone else gets the same 404 as for a missing document, and an anonymous caller gets 401. Authorisation runs before input is checked, so a bad value cannot be used to probe a document. Each change and its audit row commit in one transaction. A second layer: the `grants.permission` column has a CHECK constraint that allows only read or edit.
**Status:** TESTED in tests/test_grants.py (34 cases): grant and revoke take effect on the next request with the same cookie; reader, stranger, admin and other owner are refused for grant, revoke and list; anonymous callers are refused for all three; a reader cannot upgrade their own grant; invalid permissions, an unknown email, a grant to the owner and a missing grant are rejected; grant and revoke are audited, including who and what level; a refused attempt is audited; grant and revoke without a CSRF token return 400.
**Written tests-first:** the file was committed before the routes existed. On that first run 20 failed and 13 passed. The 13 were the non-owner refusals, which passed only because a missing route also returns 404. The mutation checks below show they can now fail.
**Mutation checks (2026-10-21), restoring after each:**
1. `share` changed to `read` in grant: test_non_owner_cannot_grant[reader] and test_reader_cannot_upgrade_their_own_grant failed.
2. Same change in revoke: test_non_owner_cannot_revoke[reader] failed.
3. Same change in list_grants: test_non_owner_cannot_list_grants[reader] failed.
4. Removed the `authorize` call from `get_document_or_404`: 18 failed, 15 passed (every non-owner case for all three routes, both owner-effect tests, anonymous grant and revoke, and the refused-attempt audit).
5. Removed `write_audit` from grant: the two grant audit tests failed.
6. Removed `write_audit` from revoke: test_revoke_is_audited failed.
7. Removed the permission check from the route: the five invalid-permission tests failed, because the database CHECK constraint rejected the insert (IntegrityError). So the constraint is a real second layer, but without the route's check a bad value would cause a server error instead of a 400.
8. Turned CSRF off in the test client: both CSRF tests failed with 200 instead of 400.
**Gap found by mutation 4 and closed:** with the `authorize` call removed, an anonymous request to list grants returned 200 and the grantees' emails, and no test failed, because only anonymous grant and revoke were tested. I added test_anonymous_cannot_list_grants. Repeating mutation 4, it failed with `assert 200 in (401, 302)` (19 failed, 15 passed), and it passed again after restoring.
**Not covered:** an edit grant allows the edit route (T16) but not delete or share. The code refuses a disabled user as the target of a grant, but no test says so. Granting by email tells an owner whether an address is registered, which I accept. There is no limit on the number of grants per document and no rate limit on these routes.

## T14: Registering as a more powerful role (2026-10-21)
**Attack:** a request to `/register` carries `role=admin` or `role=owner`, hoping the server copies it into the new account (mass assignment).
**Defence:** the register route writes the role `viewer` in its SQL and never reads a role from the request (app/routes/auth_routes.py).
**Status:** TESTED: tests/test_register.py::test_register_ignores_a_role_field posts `role=admin` and checks the stored role is `viewer`.
**Mutation check (2026-10-21):** I changed the INSERT to take the role from the form; the test failed with `assert 'admin' == 'viewer'`. After `git restore` it passed again.
**Known gaps:** registration is not rate limited and does not write an audit row, so someone can create accounts without leaving a record. I accept this for now. New accounts can only be viewers, and a viewer sees only what an owner grants.

## T15: Document list and search (2026-10-22)
**Attack:** the list or a search shows the name, owner or category of a document the user was never granted, or a soft-deleted document. Search text is used for SQL injection or LIKE wildcard tricks (`%`, `_`). A filter combined with the permission rule widens the result.
**Defence:** `GET /documents` (app/routes/documents.py) puts the permission rule inside the SQL `WHERE`: my own documents, or a document I hold a grant on, or (admins only) metadata of any document, and never a soft-deleted one. The grants join is limited to the caller's own grant, so a grant held by someone else cannot make a document visible. The role is read from the database on every request. Every filter value (`q`, `owner`, `category`, `from`, `to`) is a bound parameter, and `%` and `_` in search text are escaped so they match literally. Bad dates return 400. Responses leave out `storage_key` and the file hash.
**Status:** TESTED in tests/test_search.py (50 tests), including test_list_matches_authorize_for_everyone, which compares the list with `authorize()` for every kind of user so the SQL rule and the Python rule cannot drift apart.
**Mutation checks (2026-10-22), restoring with `git restore` after each:**
1. Permission clause deleted: 18 failed (stranger and other owner see documents, the 14 ungranted-filter cases, the grant-and-revoke list test, the authorize comparison).
2. `is_admin` forced to True: the same 18 failed.
3. `is_admin` forced to False: 3 failed (admin sees metadata, admin owner search, authorize comparison).
4. `AND g.user_id = :me` dropped from the join: 19 failed, including the admin permission label showing `read`. My first attempt at this mutation removed a space and produced a SQL syntax error, so it proved nothing. I redid it.
5. `deleted_at IS NULL` removed: 3 failed (deleted hidden, admin does not see deleted, authorize comparison).
6. LIKE escaping removed: test_name_wildcards_are_literal failed.
7. Login check removed: test_anonymous_is_refused failed (a TypeError, so the check has to stay first).
**Note:** the injection-payload tests (test_odd_input_never_widens_the_list) stayed green under mutation 1, because those payloads match no document name either way. They show that injection text is treated as plain text, and the filter tests are what guard the permission rule.
**Design decision:** an admin sees the name, owner and category of every document that is not soft-deleted, but never contents, and the download still returns 404. This matches `authorize()` and the detail route, so an admin cannot open a document by ID that the list hides. A document name can itself be sensitive, and I accept that.
**Accepted risks:**
- The list hides soft-deleted documents even from their owner, while `authorize()` lets the owner open them by ID. This is intentional (the comparison test excludes deleted documents for that reason).
- At most 100 results, with no paging.
- Date filters compare against midnight in the database's time zone, so a document uploaded just after midnight local time can fall on the previous day.
- Searches are not written to the audit log. The brief asks for uploads, downloads, changes, deletions and permission changes.
- No rate limit on the list route.

## T16: Editing or deleting a document you were not allowed to change (2026-10-22)
**Attack:** a reader, stranger, admin or another owner calls the edit or delete route directly. An editor tries to delete. A user submits extra form fields (`owner_id`, `storage_key`, `deleted_at`) to change what an edit must not touch. A name such as `../x.pdf` or `x.exe` is used to disguise a file. A deleted document is edited or deleted again.
**Defence:** both routes go through `get_document_or_404` first, so a refused user gets the same 404 whatever they send. Edit needs the `edit` action (owner or an edit grant). Delete needs the `delete` action, which no grant level contains, so only the owner passes. The edit route reads only `name` and `category` from the form. A new name must keep the document's extension, contain no slashes or control characters, and be at most 100 characters. Delete is a soft delete: the row and the stored bytes stay. Edit and delete each write an audit row in the same transaction as the change.
**Status:** TESTED in tests/test_edit_delete.py (33 tests). The first run before the routes existed was 21 failed and 12 passed; the 12 were refusals that pass only because a missing route also returns 404.
**Mutation checks (2026-10-22):**
1. Edit asks for `read` instead of `edit`: test_non_editors_cannot_edit[reader] failed.
2. Delete asks for `edit` instead of `delete`: test_editor_cannot_delete failed.
3. Both deleted-document checks removed from edit: test_deleted_document_cannot_be_edited failed.
4. Both deleted-document checks removed from delete: test_deleting_twice_is_a_404 failed.
5. `write_audit` removed from edit: test_edit_is_audited failed.
6. `write_audit` removed from delete: test_delete_is_audited failed.
7. Name validation removed: all 8 test_bad_names_are_rejected cases failed.
8. The "no fields" check removed: test_edit_with_no_fields_is_a_400 failed.
Each passed again after `git restore`.
**Deliberate redundancy:** a deleted document is refused twice, in the route and in the SQL `WHERE deleted_at IS NULL`. Removing only one of the two changes nothing visible, so mutations 3 and 4 remove both.
**Accepted risks:**
- The owner can still open and download their own soft-deleted document by ID, because `authorize()` allows it.
- There is no restore and no purge yet, so deleted file bytes stay in the database.
- A rejected name or category returns 400 but is not audited.
- Edit and delete share the global CSRF protection (T12) but have no CSRF test of their own.

## T17: Reading the audit trail, and reading it without permission (2026-10-22)
**Attack:** a non-admin (owner, reader, stranger, another owner) or an anonymous caller opens the admin activity view or the verify route to read who touched which document. An admin reads more than they should (file contents, content hashes). A reader of the trail leaves no trace of having looked.
**Defence:** `GET /admin/activity` and `GET /admin/audit/verify` (app/routes/admin.py) call `authorize()` with the `view_audit` action, which only an active admin holds. Anonymous callers get 401. Everyone else gets 404, so the admin area is not advertised, and the refusal is written to the audit log (`admin_access`, denied). Reading the trail is itself audited: the read and its audit row commit in one transaction (`audit_view`, `audit_verify`), so there is no answer without a record. Filter values are bound parameters; bad values return 400; page size is capped at 500. The view never returns file contents, `storage_key`, the content hash, or the chain hashes.
**Status:** TESTED in tests/test_admin_activity.py (26 tests). Written tests-first. The first run before the routes existed was 22 failed and 4 passed; the 4 were the non-admin refusals, which pass only because a missing route also returns 404.
**Mutation checks (2026-10-22), restoring after each:**
1. `view_audit` changed to `read`: 20 failed (every admin test gets 404).
2. The whole `authorize` block deleted: 5 failed (all four non-admin tests got 200, and the refusal audit).
3. The 401 check deleted: test_anonymous_is_refused failed with a server error, so the route fails closed.
4. The audit write in the refusal block deleted: test_refused_admin_attempt_is_audited failed.
5. The audit write in `activity` deleted: test_viewing_the_activity_is_audited failed.
6. The audit write in `verify` deleted: test_verify_reports_an_intact_chain_and_is_audited failed.
7. The `sha256` filter removed: test_no_hashes_or_storage_keys failed.
8. The `outcome` check deleted: test_bad_filters_are_400[outcome] failed.
9. Sort order reversed: test_newest_first and test_paging_with_before_id failed.
10. Page cap removed: test_limit_is_respected_and_capped failed.
**Live check (2026-10-23):** on the deployed site an anonymous request to `/admin/activity` and to `/documents` returned 401. Logged in as the demo admin, `/admin/activity` returned events and `/admin/audit/verify` returned `{"first_bad_row":null,"intact":true}`. The check wrote `audit_view` and `audit_verify` rows to the live audit log. I did not test the admin routes on the live site as a non-admin.
**Weak test found and fixed before the routes existed:** my first limit test only failed if the table held more than 500 rows, so it could have passed with no cap in the code. I rewrote it to lower the cap to 3 with `monkeypatch`, and mutation 10 then failed it.
**Accepted risks:**
- The detail of an event can contain document names (upload, edit), even for a document that is later soft-deleted, so an admin can see names that the document list hides.
- A failed login stores the email as typed (T8). If someone typed a password into the email box, an admin can now read it in this view.
- The admin also sees IP addresses.
- `verify` reads the whole audit table, so it gets slower as the log grows. The route test only checks an intact chain; tampering is tested at function level in tests/test_audit.py, not through the route.
- Every view adds an audit row, and nothing rate limits these routes.
- There is a single admin role with no second approver, and no alerting. "Something worth noticing" is left to the admin to filter for, for example `outcome=denied`.
- The demo admin password is in the README (T10), so anyone who reads it can read the whole audit trail: document names, IP addresses and emails typed at failed logins. I accept this because the brief requires a credential for each role, and the accounts should be deleted or have their passwords changed after judging.
- /admin/audit/verify is a GET that writes an audit row. A cross-site link could make a logged-in admin's browser add a row, but it cannot read the response.

## T18: Attacking the deployed site as each role (2026-10-24)
**What I did:** with the browser console on the live site I called nine routes as the reader, the editor, the stranger, the admin and an anonymous user, and checked headers and anonymous requests with curl. Then I read the admin activity page to see whether each probe was recorded.
**Results:**
- Reader: detail and download 200; list grants, edit, self-grant 404; upload 403; admin routes 404.
- Editor (a viewer with an edit grant): as the reader, but edit 200.
- Stranger (the same account after the grant was removed): detail, download and every other route 404. The grant removal took effect on the next request.
- Admin: detail 200, download 404, grants, edit and self-grant 404, upload 403, activity and verify 200.
- Anonymous: every route 401.
- A POST without a CSRF token returned 400 for every role while logged in, so CSRF is enforced on the live site for logged-in users (closes the gap noted in T12).
- Owner: <fill in the owner run, or delete this line>.
**Audit check:** every refused attempt appears on the admin page with the right person, action and document, in the order I made them, and "Verify audit chain" reported the chain intact. Anonymous upload and admin attempts (401) are not recorded, as T3 and T17 say.
**Headers on the live login page:** Content-Security-Policy with script-src 'self', X-Frame-Options DENY, Referrer-Policy same-origin, X-Content-Type-Options nosniff, Cache-Control no-store and Strict-Transport-Security.
**Findings and what I did:**
1. The audit log's IP column held Render's internal addresses (10.x), and one user's requests within one second showed different ones. `ProxyFix(x_for=1)` does not give the real caller on Render. I added `client_ip()` (app/clientip.py), which reads Cloudflare's CF-Connecting-IP only when TRUST_CF_CONNECTING_IP is switched on, validates it as an address, and falls back to the connection address otherwise. Tested in tests/test_client_ip.py. <live result of the spoof check: fill in what you saw>
2. The login limit counted per address, so on Render everyone shared a few counters: strangers could lock each other out, and an attacker spread over them gets several times the allowance. The limit is now 5 attempts per minute per account (lower-cased email), plus a coarse 60 per minute per address. Tested in tests/test_login_limit.py. The cost: anyone can keep a named account at its limit, so it will answer 429 for a minute at a time.
3. The Flask `session` cookie, which carries the CSRF secret, had no Secure flag. It now does on Render (COOKIE_SECURE=1). Tested in tests/test_cookie_flags.py.
**Mutation checks (2026-10-24):** <fill in from the table above>
**Accepted risks:**
- If Render stops using Cloudflare, or Cloudflare stops sending CF-Connecting-IP, the audit falls back to Render's internal addresses without any error.
- Registration is still not rate limited.
- The limit is kept in memory, one process, and resets on every restart.
- 429 refusals are not audited.
**Not covered:** the browser pass (hostile names in the list, detail and activity pages, the Back button after logout, role buttons, an expired token) is recorded in T19.
