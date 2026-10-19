# PROMPTS.md

AI tools used: Claude (chat) for planning, schema design, code drafts and explanations.
No coding agent has been used so far.

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