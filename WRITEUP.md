# WRITEUP

## What TrustVault is
A document-sharing platform for a company where the wrong person cannot reach a file, and the record shows who did. It has three roles (admin, owner, viewer), per-document `read` and `edit` grants, upload, search, edit, soft delete, a tamper-evident audit trail and an admin activity view. It runs on Flask and PostgreSQL, and is deployed on Render: https://trustvault-tb2y.onrender.com

## The decisions that matter
1. **One place decides access.** `authorize()` in `app/authz.py` denies by default. Every document route goes through `get_document_or_404()`, which reads the document and its grants from the database on every request. Nothing about access is kept in the session or in a link, so removing a grant works on the next request, even for a session already open. I checked this on the live site (T18).
2. **No existence leaks.** A person who may not touch a document gets the same 404 as for a document that does not exist.
3. **The admin is not a super-reader.** An admin sees document metadata and the audit trail, never file contents, and cannot edit, delete, share or upload. A person with this much visibility should not also be able to read everything.
4. **The audit log cannot be altered through the app.** The application's database role has only SELECT and INSERT on it, a trigger blocks UPDATE, DELETE and TRUNCATE for every role, and every row carries a hash of the previous one. The audit row is written in the same transaction as the action, and a failed audit write fails the action. Refused attempts are recorded too.
5. **Files live in Postgres.** The free host wipes its disk on every deploy, so bytes are stored in `document_blobs`. The filename is never used as a path. The column `storage_key` is left over from the earlier on-disk plan and is never returned by any route.
6. **Pages are empty shells.** All data comes from the same JSON routes the tests exercise, put into the page with `textContent`. The Content-Security-Policy allows scripts only from the site itself, with no inline script or style. So the access rules are written once, and stored text cannot turn into script.

## How I worked
For every security-relevant change I wrote the tests first and committed them failing, wrote the code, then broke one line on purpose to see the right test fail, and restored it. Results are in `THREATS.md` (T1 to T20). `PROMPTS.md` records eleven places where the AI I used was wrong, how I found out, and what I did.

## How I used AI, and where it was wrong
I used Claude (chat) only, for planning, drafts of code and tests, and explanations. No coding agent. It was wrong in ways that matter for security: it said `ProxyFix` would give the real client address on Render (it did not, so the audit log's IP column and the login limiter were both wrong); its first rule for the document list contradicted its own admin rule; several of its tests passed before the route existed or could not fail; it planned file storage on a disk the host wipes; it treated a HEAD request to /login as a failed login; and it told me to `git restore` a file I had never committed. I found these by running the whole suite, by breaking one line at a time, and by attacking the deployed site. Details and commit links are in `PROMPTS.md` (entries 1 to 12).

## What the live site taught me
Reading the admin activity page after attacking my own site as each role showed three problems no test had caught (T18):
- The audit log's IP column held Render's internal addresses, because `ProxyFix` does not give the real caller on Render. The address is now read from Cloudflare's header, and only when that is switched on.
- The login limit counted per internal address, so everyone shared a few counters. It is now per account, plus a coarse per-address limit.
- The Flask `session` cookie, which carries the CSRF secret, lacked the Secure flag.

## What I left out on purpose
Groups and folder inheritance (inheritance is how "access to a folder shows forty files" happens), links shared with people outside the company, versions, restore or purge of deleted documents, and AI suggestions for who should see a document. Each would add more places where access can be decided, and I preferred one rule I could test fully.

## What is unfinished or weak
- Rate limits are kept in memory in one process and reset on restart. Registration is not rate limited. 429 refusals are not audited.
- Anyone can keep a named account at its login limit, so it answers 429 for a minute at a time.
- Rows in the audit log written before the real-address fix keep Render's internal addresses; the log is append-only.
- If Render stops using Cloudflare, the audit falls back to internal addresses without an error.
- Someone who controls the database owner account could disable the trigger and rewrite the whole chain. The app never uses that account. Publishing the latest chain hash outside the database would help.
- Only the start of an uploaded file is checked, and there is no virus scan.
- The access check and the file read are separate transactions, so a revoke landing in those milliseconds can still let one download through (it is audited).
- The demo passwords are in the README, because the brief requires a credential for each role. I will change them after judging. Render's free database expires on 19 November 2026.
- The browser pass was done in one browser, and the JavaScript has no unit tests.

## Where to look
`API.md` (every endpoint and who may call it), `THREATS.md` (attacks, defences, tests, accepted risks), `PROMPTS.md` (AI use), `README.md` (run, test, deploy), `app/authz.py` and `app/access.py` (the permission model), `tests/` (270 test cases).