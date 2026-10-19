# PROMPTS.md

AI tools used: Claude (chat) for planning, schema design and explanations.
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