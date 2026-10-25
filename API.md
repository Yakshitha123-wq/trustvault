# API

TrustVault has a JSON API and a few thin HTML pages. This file says who may call each endpoint. Access is decided in one place: `authorize()` in app/authz.py. Every document route goes through `get_document_or_404()` in app/access.py, which reads the document and its grants from the database on every request.

## Roles and permissions
- **admin**: sees the name, owner and category of every non-deleted document and the whole audit trail. Cannot read, edit, delete, share or upload.
- **owner**: uploads documents and controls their own: read, edit, delete, share, and see who has access.
- **viewer** (also anyone who registers): sees only documents shared with them.
- A grant is `read` (read and download) or `edit` (also rename and recategorise). Only the owner can delete or share. Grants are given and taken back by the owner only.

## Conventions
- A logged-in user carries a `tv_session` cookie. Anonymous callers get 401 on JSON routes; page routes redirect to `/login` with 302.
- A document the caller may not touch answers 404, the same as one that does not exist.
- Every POST needs a CSRF token: the form field `csrf_token` or the header `X-CSRFToken` (pages put it in `<meta name="csrf-token">`). Without one, or with an expired one (tokens last one hour): 400.
- Login is limited to 5 attempts per minute per account (lower-cased email) and 60 per minute per address: 429.
- Uploads: pdf, png, jpg, jpeg or txt, up to 5 MB, and the first bytes must match the extension.
- Uploads, downloads, edits, deletes, grants, revokes, logins, refused attempts and reads of the audit trail are written to the audit log. Anonymous 401s on upload and admin routes are not.

## Endpoints
| Method | Path | Who may call it | Notes |
|---|---|---|---|
| GET | `/` | anyone | Redirects to `/app`. |
| GET | `/health` | anyone | `{"status":"ok"}`. |
| GET | `/health/db` | anyone | `{"db":"ok"}`. Shows only that the database answers. |
| GET, POST | `/register` | anyone | Fields `name`, `email`, `password` (10+ characters). Always creates a viewer; the role is never read from the request. |
| GET, POST | `/login` | anyone | Fields `email`, `password`. Success: 302 to `/app` and a session cookie. Wrong details: 401. Limited: 429. |
| POST | `/logout` | logged-in user | Deletes the caller's session. |
| GET | `/app` | any logged-in user | Page shell. Data comes from `GET /documents`. |
| GET | `/app/upload` | any logged-in user | Page shell. The upload route refuses everyone but owners. |
| GET | `/app/documents/<doc_id>` | any logged-in user | Page shell with no document data. A malformed id gives 404. |
| GET | `/app/admin` | admin | 404 for everyone else. Page shell. |
| GET | `/documents` | any logged-in user | Your documents, documents shared with you, and (admin) metadata of all non-deleted ones. Filters: `q`, `owner`, `category`, `from`, `to` (YYYY-MM-DD). At most 100. Bad dates: 400. |
| POST | `/documents` | owner role | Multipart `file` and optional `category`. 201 with `{id, name}`; 400 or 413 for a bad file; 403 for other roles. |
| GET | `/documents/<doc_id>` | owner, anyone with a grant, admin | Metadata and a `can` object (read, edit, delete, share). 404 for everyone else. |
| GET | `/documents/<doc_id>/download` | owner, read or edit grant | The file as an attachment, with `nosniff`. The admin gets 404. Audited. |
| POST | `/documents/<doc_id>/edit` | owner, edit grant | Fields `name` and/or `category`. A name must keep its extension. |
| POST | `/documents/<doc_id>/delete` | owner only | Soft delete. |
| GET | `/documents/<doc_id>/grants` | owner only | Who has access and at what level. |
| POST | `/documents/<doc_id>/grants` | owner only | Fields `email` and `permission` (`read` or `edit`). Bad permission: 400. Unknown email: 404. Granting to yourself: 400. |
| POST | `/documents/<doc_id>/grants/<user_id>/revoke` | owner only | Takes effect on the next request, including for sessions already open. |
| GET | `/admin/activity` | admin only | Newest first. Filters: `document_id`, `actor_id`, `action`, `outcome`, `from`, `to`, `limit` (1 to 500), `before_id`. Never returns file contents, storage keys or hashes. Reading it is audited. Others get 404 (audited). |
| GET | `/admin/audit/verify` | admin only | `{"intact": true, "first_bad_row": null}`. Checks the hash chain over the whole log. Audited. |
| GET | `/static/<path:filename>` | anyone | The site's own CSS and JavaScript only. |

Soft-deleted documents are hidden from lists; the owner can still open one by id.