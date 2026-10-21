# TrustVault: project rules for the AI assistant

## Product
Secure document-sharing platform. Stack: Flask, Jinja, PostgreSQL via SQLAlchemy
(Core, parameterised queries only), Bootstrap 5 + HTMX (served from our own /static),
pytest, gunicorn, Render.
## Non-negotiable security rules
1. Every route that touches a document, version, thumbnail, search result or audit
   entry about a document MUST call authz.authorize(user, document, action).
   Deny by default. Never rely on hidden buttons or client-side checks.
2. Permissions are never cached in the session or a token. Read grants from the DB on
   every request. Sessions are server-side (token hash stored in the sessions table).
3. Revoking a grant or disabling a user takes effect on the very next request.
   Any download link issued earlier must re-check authorisation when used.
4.  Files are stored as bytes in the database (table document_blobs), because the free
   host's disk is ephemeral. Never use the user's filename as a path. Downloads go through
   the authorised endpoint with Content-Disposition: attachment and
   X-Content-Type-Options: nosniff.
5. Uploads: size limit, extension allowlist, magic-byte check, store sha256.
6. audit_log is append-only (DB privileges + trigger + hash chain). Log denied attempts
   too. A failed audit write must fail the action.
7. Return 404 (not 403) for documents the user has no access to, so existence isn't leaked.
8. Parameterised SQL only. Jinja autoescape stays on. No |safe on user data.
   CSRF on every state-changing request. Passwords with argon2.

## Roles
- admin: manages users, sees document metadata and the audit trail. Cannot read file
  contents without an explicit grant.
- owner: uploads documents, grants and revokes access on their own documents.
- viewer: sees only what has been granted to them.
Only the document owner grants or revokes access.

## Working style
- Small changes only. Show the diff and explain each security-relevant line.
- Write the failing test first for any authorisation behaviour.
- Never invent endpoints, libraries or config. Say "I'm not sure" instead.
- Do not add features I did not ask for.
- Never put secrets, passwords or API keys in any file that gets committed.