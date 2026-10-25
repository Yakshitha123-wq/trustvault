# TrustVault

A document-sharing platform where the wrong person cannot reach a file and the record shows who did reach it. Built for the Snovasys Fresher Hiring Challenge 2026.

**Live site:** https://trustvault-tb2y.onrender.com
The free host sleeps when idle, so the first load can take about a minute.

## Demo accounts (live site)

| Role | Email | Password |
|---|---|---|
| Admin | admin@trustvault.example | wU252hCYAmmpIUML |
| Owner | owner@trustvault.example | _PlOKzs2upnPuoP3 |
| Viewer | viewer@trustvault.example | GI92mb0llYya38l0 |

The site has sample documents. Login is limited to 5 attempts per minute per account, so after a few wrong passwords an account answers "too many attempts" and clears again after a minute. These accounts exist only for judging, and their passwords will be changed afterwards.

## What each role can do

| Role | Can |
|---|---|
| Owner | upload documents; read, rename, share and delete their own; give another user read or edit access and take it back; see who has access |
| Viewer (also anyone who registers) | open and download documents shared with them; rename them if they were given edit access |
| Admin | see the name, owner and category of every document, and the audit trail, but never file contents. Cannot edit, delete or share. |

## How access is decided (the permission model)

- Every document has one owner. The owner can share it with named people as **read** (see and download) or **edit** (also rename). Grants are per document: nothing is inherited from folders or groups.
- One function, `authorize()` in `app/authz.py`, decides every access. It denies by default. Every document route goes through `get_document_or_404()` (`app/access.py`), which reads the document and its grants from the database **on every request**. Nothing about access is kept in the session or in a link, so removing a grant works on the next request, including for a session that is already open.
- A person who may not touch a document gets the same 404 as for a document that does not exist, so ids cannot be probed.
- The pages are empty shells. All data comes from the same JSON routes that the tests exercise, so no rule is written twice.

## The audit trail

Uploads, downloads, edits, deletes, grants, revokes, logins, password resets, reads of the audit trail, and **refused attempts** are written to `audit_log` in the same database transaction as the action. The log cannot be altered through the app: the application's database role has only SELECT and INSERT on it, a database trigger blocks UPDATE, DELETE and TRUNCATE for every role, and each row carries a hash of the previous one. The admin page has a "Verify audit chain" button.

## Files

Uploaded files are stored as bytes in Postgres (`document_blobs`), not on disk, because the free host's disk is wiped on every deploy. Allowed types: pdf, png, jpg, jpeg, txt; up to 5 MB; the file's first bytes must match its extension. Downloads are sent as attachments with `nosniff`.

## Documents in this repository

| File | Contents |
|---|---|
| `API.md` | every endpoint and who may call it |
| `THREATS.md` | how this could be broken, what I did, and what I knowingly accepted |
| `PROMPTS.md` | how I used AI and where it was wrong |
| `WRITEUP.md` | what I built, what I left out, and what is unfinished |

## Run it locally (Windows PowerShell, Python 3.11, PostgreSQL 16)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Create the database and the restricted application role (run as the database owner):

powershell
psql -U postgres -c "CREATE DATABASE trustvault;"
psql -U postgres -d trustvault -f db/schema.sql
`db/migrations/002_document_blobs.sql` is only for a database created before the `document_blobs` table was added to `schema.sql`. A fresh install does not need it.

Open `db/roles.sql`, replace `CHANGE_ME` with a long random password in your working copy (do not commit it), then:

owershell
psql -U postgres -d trustvault -f db/roles.sql


Set the environment and start the app:

powershell
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:DATABASE_URL = "postgresql://trustvault_app:YOUR-PASSWORD@localhost:5432/trustvault"
python -m scripts.seed          # prints three passwords once, save them
flask --app app run


Open http://127.0.0.1:5000. To reset a user's password: `python -m scripts.reset_password someone@example.com`.

## Run the tests

The tests need a separate database ending in `_test` (they refuse to run on any other). Create it the same way (`trustvault_test`, `schema.sql`, `roles.sql`), then:

powershell
$env:SECRET_KEY = "any-string"
$env:DATABASE_URL = "postgresql://trustvault_app:YOUR-PASSWORD@localhost:5432/trustvault_test"
$env:TEST_OWNER_DATABASE_URL = "postgresql://postgres:YOUR-POSTGRES-PASSWORD@localhost:5432/trustvault_test"
pytest -q --tb=line


`TEST_OWNER_DATABASE_URL` is only used by the audit tests that check the database trigger. Use `tb=line` so a failure never prints a connection string.

## Deploy on Render

1. Create a Render PostgreSQL database and a Web Service from this repository.
2. Build command: `pip install -r requirements.txt`. Start command: `gunicorn "app:create_app()"`.
3. From your own computer, run `db/schema.sql` and then `db/roles.sql` against the new database using its **External Database URL**, and set a strong password for `trustvault_app`.
4. Web service environment variables:
   - `SECRET_KEY` (required): a long random value
   - `DATABASE_URL`: the **application role's** URL (`trustvault_app`), never the owner's
   - `COOKIE_SECURE=1`: marks the CSRF-token cookie Secure
   - `TRUST_CF_CONNECTING_IP=1`: reads the caller's address from Cloudflare's header, which Render sits behind. Leave it off anywhere else.
5. Seed the three accounts once with `python -m scripts.seed`, using the external database host, and save the printed passwords.

Render's free database expires on **19 November 2026**.

## What I built and what I did not

Built: authentication with three roles; per-document read and edit grants that the owner gives and takes back; upload with validation; search by name, owner, category and date; edit and soft delete; a tamper-evident audit trail; an admin activity view; browser pages with a strict Content-Security-Policy; and automated tests, many of them checked by breaking one line and watching a test fail (the results are in `THREATS.md`).

Deliberately not built: groups and folder inheritance (inheritance is how "access to a folder shows forty files" happens), links shared with people outside the company, versions, restore or purge of deleted documents, and AI suggestions for who should see a document.

Known limits are listed in `THREATS.md` and `WRITEUP.md`.