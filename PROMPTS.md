# PROMPTS.md

AI tools used: Claude (chat) for planning, schema design, code drafts, test drafts and
explanations. No coding agent has been used so far.

## Context files reused across the week
- `AGENTS.md`: project rules (security rules, roles, working style). Committed on
  day 1. I will give it to any coding agent at the start of a session if I use one.

## Working method (applied to every security-relevant change)
- Write the tests first and commit them while they fail, then write the code.
- Commit working code before any experiment, because `git restore` only brings back
  committed code.
- After the tests pass, break the code on purpose (mutation check), confirm the expected
  test fails, then restore. A test that has never failed proves nothing.
- Run `pytest --collect-only` to confirm a test is really in the file.



## Entry 1: AI silently changed the database library in AGENTS.md (2026-10-19)
**Tool:** Claude (chat)
**Category:** other (project rules / consistency)

**What I asked:** For a rules file (`AGENTS.md`) containing the project's security
rules and stack.

**What it produced:** The plan said "SQLAlchemy or psycopg". When it wrote the
final `AGENTS.md`, it said "PostgreSQL (psycopg)" and dropped SQLAlchemy.

**What was wrong:** It changed a stack decision without asking me. I had expected
SQLAlchemy, so the rules file no longer matched what I planned to build. Any
tool reading that file would have generated code with the wrong library. The wrong
line was in the first AGENTS.md commit (a1b7c8b).

**What I did instead:** I noticed the mismatch and told the AI. We compared the
options and chose SQLAlchemy Core with parameterised `text()` queries, because
`db/schema.sql` stays the single source of truth and every query, including the
authorisation check, is visible in the code. I updated `AGENTS.md` to match.

**Commits:**
- wrong line: https://github.com/Yakshitha123-wq/trustvault/commit/a1b7c8b14d863a12cd8016065fc7c4cb4ebb4d90
- fix: https://github.com/Yakshitha123-wq/trustvault/commit/35d9235075daf269bd2ee8acd1f2b834c500463b

**How I checked:** I compared `AGENTS.md` with the packages in `requirements.txt`
to confirm they agree.



## Entry 2: Audit writer stored a placeholder hash (2026-10-19)
**Tool:** Claude (chat)
**Category:** audit trail

**What I asked:** For `app/audit.py`, a function that appends a hash-chained row to
`audit_log`.

**What it produced:** A `write_audit` that inserted `'pending'` as `row_hash`, with the
real hash function written but never called.

**What was wrong:** The audit table forbids UPDATE (privileges and trigger), so the
placeholder could never be replaced. Every row would have had a meaningless hash and
the chain would verify nothing. The AI pointed this out itself in the same reply,
after writing the code.

**What I did instead:** Used the second version, which picks the timestamp in Python,
computes the hash, then inserts once. Also added `verify_chain`.

**Commit:** https://github.com/Yakshitha123-wq/trustvault/commit/bb851e1b4a17fd4d4f387f2c80f2070caeb30ac9

**How I checked:** `tests/test_audit.py::test_chain_verifies_after_several_writes` passes.



## Entry 3: git restore wiped my uncommitted work (2026-10-19)
**Tool:** Claude (chat)
**Category:** other (process)

**What I asked:** How to undo a temporary edit during a mutation check.

**What it produced:** An instruction to run `git restore app/audit.py`.

**What was wrong:** It did not tell me to check the file was committed first.
`app/audit.py` had never been committed with real code, so the restore reverted it to
the empty skeleton and `verify_chain` disappeared (ImportError: cannot import name
'verify_chain'). `git log -- app/audit.py` showed only the skeleton commit.

**What I did instead:** Recreated the file, committed it, and only then repeated the
mutation check. New rule for myself: commit before mutating, restore only afterwards.

**Commit:** https://github.com/Yakshitha123-wq/trustvault/commit/bb851e1b4a17fd4d4f387f2c80f2070caeb30ac9

**How I checked:** the four tests passed again after the recreate.



## Entry 4: My first audit test could not fail (2026-10-19)
**Tool:** Claude (chat)
**Category:** audit trail

**What I asked:** For a test that the audit hash chain works.

**What it produced:** A test that wrote three rows and called `verify_chain`.

**What was wrong:** It only covered the happy path. It never changed a row, so it
would pass even if `verify_chain` checked nothing.

**What I did instead:** Added tests where the app role is refused, the trigger blocks
the owner, and a middle row is tampered with (trigger disabled inside a transaction
that is rolled back). I then ran a mutation check: with the hash comparison commented
out, `test_tampering_with_a_row_is_detected` failed with "tampering was NOT detected",
and passed again after restoring.

**Commit:** https://github.com/Yakshitha123-wq/trustvault/commit/a11b261e36e4917dd27c0a0380668ada0e2a48fc

**How I checked:** the mutation run described above.



## Entry 5: authorize() depended on a field get_current_user() did not return (2026-10-20)
**Tool:** Claude (chat)
**Category:** authorisation

**What I asked:** For `authorize(user, document, action, grants)`, matching the 48-case
test matrix I wrote first, and for the `auth.py` it depends on.

**What it produced:** An `authorize()` whose first check refuses any user without a
truthy `is_active`. The `get_current_user()` it had given me earlier selected only
id, email, name and role.

**What was wrong:** The two pieces were each fine alone but wrong together. Every
logged-in user, owners included, would have been refused on every document, because
`user.get("is_active")` would be `None`. My unit tests could not catch it, because they
pass hand-made dicts instead of the real `get_current_user()` output. The AI flagged
the mismatch when it gave me `authorize()`, and again when I pasted my `auth.py`,
which still lacked the field.

**What I did instead:** Added `u.is_active` to the SELECT in `get_current_user()`
(app/auth.py, line 53). The `AND u.is_active` in the WHERE clause stays, so a disabled
user is refused twice, once by the query and once by `authorize()`. I later added
`tests/test_session_user.py`, which logs in through a real session and checks that
`get_current_user()` returns `is_active` (commit
https://github.com/Yakshitha123-wq/trustvault/commit/5122848a59574ff4069d2c46dddc76464022efc5).

**A second finding, from my own mutation runs:** when I removed the `is_active` check,
only one test failed (`test_disabled_user_with_a_grant_is_still_refused`). The DISABLED
matrix rows still passed because that test user holds no grant, so the matrix alone did
not guard the rule. While replacing that test I twice left a gap (the disabled owner,
then the disabled grant-holder) and only found it by listing the collected tests with
`pytest --collect-only`. I now have two tests, `test_disabled_owner_is_refused` and
`test_disabled_user_with_a_grant_is_refused`, each checking all six actions.

**Commits:**
- authorize() and the is_active fix: https://github.com/Yakshitha123-wq/trustvault/commit/498f9e9d85ab9dbd89037c8f740c463da6745c9c
- stronger disabled-user tests: https://github.com/Yakshitha123-wq/trustvault/commit/4f38e09badcb077a4b5e0921c8098c55d45dd542

**How I checked:** 53 tests pass. I broke `authorize()` five ways, and each break made
the expected tests fail:
1. soft-deleted block commented out: `test_soft_deleted_document_is_owner_only`
2. `is_active` check removed: `test_disabled_owner_is_refused` and
   `test_disabled_user_with_a_grant_is_refused` (2 failed, 51 passed)
3. `pass` instead of `allowed |= ADMIN_ALLOWS`: the ADMIN view_meta and view_audit rows
4. `edit` added to the read grant: the READER edit row
5. unknown-action check replaced with `pass`: `test_unknown_action_is_denied`
After each break I ran `git restore app/authz.py` and confirmed the tests passed again.



## Entry 6: Three of my new route tests passed before the route existed (2026-10-20)
**Tool:** Claude (chat)
**Category:** access control

**What I asked:** For tests first, then code, for `GET /documents/<id>`
(tests/test_documents_access.py), covering owner, reader, stranger, admin,
anonymous, a missing document, a malformed ID, revocation, and an audit row for a
refused attempt.

**What it produced:** Nine tests. I ran them before writing any route code: 6 failed
and 3 passed. The three that passed were `test_stranger_gets_404`,
`test_missing_and_forbidden_look_identical` and `test_not_a_uuid_is_404_not_500`.

**What was wrong:** Those three passed because a route that does not exist also
returns 404, so they said nothing about whether access is enforced. If I had only
looked at "9 passed" at the end, I would have trusted tests that had not yet shown
they could fail. The AI pointed this out after I pasted the run, so its tests were
weaker than they looked until I checked.

**What I did instead:** The AI gave me `app/access.py` (`get_document_or_404`) and the
route. I read it, got all 9 tests passing (full suite 68), and then ran four mutation
checks on the committed code, restoring the file with `git restore` after each:
1. Removed the `authorize(...)` call from `get_document_or_404`: 5 tests failed
   (`test_stranger_gets_404`, `test_anonymous_is_refused`,
   `test_missing_and_forbidden_look_identical`, `test_revocation_is_immediate`,
   `test_refused_attempt_is_audited`). So the 404 tests can fail.
2. Removed the `write_audit(...)` call: only `test_refused_attempt_is_audited` failed.
3. Set `grants = {}` before the authorize call: `test_reader_can_see_metadata` and
   `test_revocation_is_immediate` failed.
4. Added `storage_key` to the JSON in documents.py: only
   `test_admin_can_see_metadata_only` failed.
No mutation left every test green. After the last restore, `pytest -q` showed
68 passed.

**Commits:**
- tests first: https://github.com/Yakshitha123-wq/trustvault/commit/71b9b4661ca30079b255f62184a196ee0d118a32
- route and access code: https://github.com/Yakshitha123-wq/trustvault/commit/5e6b641bcec30547b539a40bb1ea65f57401a656

**How I checked:** the four mutation runs above, plus the 6-failed, 3-passed output
from before the route existed.



## Entry 7: AI planned file storage the host would delete (2026-10-21)
**Tool:** Claude (chat)
**Category:** other (storage design)

**What I asked:** For the storage design and the project rules in `AGENTS.md`.

**What it produced:** Rule 4 of `AGENTS.md` and the `storage_key` column assumed files
would live in a private directory under random names. Nothing in the deployment guidance
mentioned that the host's disk is temporary.

**What was wrong:** Render free web services have an ephemeral filesystem, so local files
are lost on every redeploy, restart and spin-down (after 15 minutes idle). Uploads would
have disappeared while the database still listed them, and a judge would get an error on
download. The AI only raised this on 2026-10-21, after the app was deployed and just before
building upload, and it checked Render's documentation then. I had not noticed it myself.

**What I did instead:** Stored file bytes in Postgres, in a new `document_blobs` table
(db/migrations/002_document_blobs.sql), so files survive restarts and the upload and its
audit row can commit in one transaction. Updated rule 4 of `AGENTS.md`. I wrote the upload
and download tests before the code, but I forgot to commit them, so the code commit
(65e441f) comes first and the tests commit (67da176) came about an hour later. The git
history therefore does not show the tests-first order that it shows for the document route
(71b9b46 then 5e6b641). I then ran eight mutation checks on the upload and download code,
and each one failed the test it should have.

**Commits:**
- table and role grant: https://github.com/Yakshitha123-wq/trustvault/commit/9fe3788431ac5466985c83f520e4f17a20928243
- upload, download and blob storage: https://github.com/Yakshitha123-wq/trustvault/commit/65e441f2bea4b799c5fd995f9194f62acebecea6
- upload and download tests: https://github.com/Yakshitha123-wq/trustvault/commit/67da1761a4a485f4dc2191eace627bf2df7f3392
- AGENTS.md rule 4 updated: https://github.com/Yakshitha123-wq/trustvault/commit/641256e6ddd7e3b6483e8459bbd70c5109f376b5

**How I checked:** the upload and download tests pass (89 in the full suite). On the live
site I uploaded a PDF with curl, downloaded it, and the SHA-256 hashes matched. Then I ran
Manual Deploy (Deploy latest commit) on Render and downloaded the same document again,
and the hash was still identical.



## Entry 8: Every test ran with CSRF switched off, so nothing tested it (2026-10-21)
**Tool:** Claude (chat)
**Category:** access control

**What I asked:** For test fixtures and route tests for documents (`conftest.py`,
`tests/test_documents_access.py`, `tests/test_upload_download.py`).

**What it produced:** An `app` fixture that sets `WTF_CSRF_ENABLED: False` so the test
client can POST without a token. All the route tests use it and pass.

**What was wrong:** With CSRF off in every test, nothing proved the app rejects a POST
that has no token. If `CSRFProtect` were removed from `create_app`, no test would fail.
The AI raised this when I asked how to check upload on the live site without a browser
form. Until then I had believed the suite covered it.

**What I did instead:** I checked the live site with `curl.exe`: an upload POST with no
token and no session cookie returned 400. I then added `tests/test_csrf.py`, which builds
an app with CSRF left on. Mutation check: with `WTF_CSRF_ENABLED` set to False in that test
it failed with 201 instead of 400; restored, it passed, and the full suite was at 90
passed. When I later wrote the grant and revoke tests, I added a CSRF test for each
(tests/test_grants.py). With CSRF off in the test client, both failed with 200 instead
of 400.

**Commit:** https://github.com/Yakshitha123-wq/trustvault/commit/8b60b8be5d0a9ee8412db3e622c55e59b8265c37

**How I checked:** the live curl result and the mutation runs described above.



## Entry 9: No test covered an anonymous caller listing grants (2026-10-22)
**Tool:** Claude (chat)
**Category:** access control

**What I asked:** For grant, revoke and list-grants tests written before the routes
(tests/test_grants.py).

**What it produced:** 33 tests, with anonymous tests for grant and revoke but none for
listing grants. I committed them while they failed (20 failed, 13 passed), then added the
routes in app/routes/sharing.py.

**What was wrong:** When I removed the `authorize` call from `get_document_or_404`
(mutation 4), 18 tests failed, but none was an anonymous list request. With the check gone,
an anonymous caller would have received the grantees' emails and nothing would have
failed. The AI noticed this when I pasted the mutation output; I had not noticed it myself.

**What I did instead:** Added `test_anonymous_cannot_list_grants` and repeated mutation 4.
It failed with `assert 200 in (401, 302)` (19 failed, 15 passed instead of 18 and 15), then
passed after I restored the file.

**Commit:** https://github.com/Yakshitha123-wq/trustvault/commit/87a90752e8d60850d7055320a21e1ea6516f1f95

**How I checked:** the repeated mutation run above, plus seven other mutation checks on
the grant, revoke and list routes, each of which failed the tests it should (listed in
THREATS.md, T13). One of them showed that the database CHECK constraint on
`grants.permission` is a second layer: with the route's permission check removed, bad
values failed with a database error instead of a clean 400.