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
## T8: Brute-force login (2026-10-19)
**Attack:** guessing passwords by repeated POSTs to /login.
**Defence:** Flask-Limiter, 5 POSTs per minute per IP (app/routes/auth_routes.py).
**Status:** BUILT, observed manually (6th attempt returned 429). Automated test PLANNED.
**Known weaknesses:** per-IP, so shared networks share a counter; memory storage is
per process and resets on restart; 429 responses are not written to the audit log.