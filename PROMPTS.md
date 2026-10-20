# PROMPTS.md

AI tools used: Claude (chat) for planning, schema design, code drafts, test drafts and
explanations. No coding agent has been used so far.

## Context files reused across the week
- `AGENTS.md`: project rules (security rules, roles, working style). Committed on
  day 1. I will give it to any coding agent at the start of a session if I use one.

---

## Entry 1: AI silently changed the database library in AGENTS.md (2026-10-19)
**Tool:** Claude (chat)
**Category:** other (project rules / consistency)

**What I asked:** For a rules file (`AGENTS.md`) containing the project's security
rules and stack.

**What it produced:** The plan said "SQLAlchemy or psycopg". When it wrote the
final `AGENTS.md`, it said "PostgreSQL (psycopg)" and dropped SQLAlchemy.

**What was wrong:** It changed a stack decision without asking me. I had expected
SQLAlchemy, so the rules file no longer matched what I planned to build. Any
tool reading that file would have generated code with the wrong library. The
change is in commit a1b7c8b.

**What I did instead:** I noticed the mismatch and told the AI. We compared the
options and chose SQLAlchemy Core with parameterised `text()` queries, because
`db/schema.sql` stays the single source of truth and every query, including the
authorisation check, is visible in the code. I updated `AGENTS.md` to match.

**Commit:** https://github.com/Yakshitha123-wq/trustvault/commit/35d9235075daf269bd2ee8acd1f2b834c500463b

**How I checked:** I compared `AGENTS.md` with the packages in `requirements.txt`
to confirm they agree.

---

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

---

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

---

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

---

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
user is refused twice, once by the query and once by `authorize()`. Route tests that use
the real session path are still to be written.

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