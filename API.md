# API

All routes are served by the Flask app. A logged-in user carries a `tv_session` cookie.
**Every POST needs a CSRF token**, sent as the form field `csrf_token` or the header
`X-CSRFToken` (the page puts the token in `<meta name="csrf-token">`). Over HTTPS the browser
must also send a Referer. A missing or expired token returns 400 (tokens last one hour).

A user without access to a document gets the same **404** as for a document that does not
exist. An anonymous caller gets **401** on JSON routes and a redirect to `/login` on pages.
Every refused request to a document route is written to the audit log.

## Roles
- **admin**: sees document metadata and the audit trail. Never file contents, and cannot change anything.
- **owner**: uploads documents and controls who may read or edit them.
- **viewer**: sees only documents shared with them. Self-registration always creates a viewer.

## Public
| Method and path | Who | What |
|---|---|---|
| `GET /` | anyone | redirects to `/app` |
| `GET /health`, `GET /health/db` | anyone | `{"status":"ok"}`, `{"db":"ok"}` |
| `GET /register`, `POST /register` | anyone | form fields `name`, `email`, `password` (10+ characters). Always creates a viewer. |
| `GET /login`, `POST /login` | anyone | form fields `email`, `password`. 5 POSTs per minute per IP (429 after that). Wrong login: 401. Success: redirect to `/app` and sets the session cookie. |
| `GET /static/<file>` | anyone | the page scripts and stylesheet |

## Pages (HTML shells, no document data inside)
| Path | Who |
|---|---|
| `/app`, `/app/upload`, `/app/documents/<id>` | any logged-in user (otherwise redirect to `/login`) |
| `/app/admin` | admin only (404 for everyone else) |
| `POST /logout` | any logged-in user. Deletes the session. |

The pages load their data through the JSON routes below, so the access rules live only there.

## Documents
| Method and path | Who may call it | Notes |
|---|---|---|
| `GET /documents` | any logged-in user | Lists only documents the caller may see: their own, ones shared with them, and for admins the metadata of every non-deleted document. Optional filters `q` (name), `owner`, `category`, `from`, `to` (dates, YYYY-MM-DD). Max 100 results. Bad dates: 400. |
| `POST /documents` | owners only | Multipart: `file` (pdf, png, jpg, jpeg, txt, up to 5 MB, content checked against the extension), optional `category`. 201 with `{id, name}`. 401 anonymous, 403 other roles, 400 or 413 for a bad file. |
| `GET /documents/<id>` | the owner, holders of a read or edit grant, admins | Metadata and a `can` object (read, edit, delete, share). 404 for everyone else. |
| `GET /documents/<id>/download` | the owner, holders of a read or edit grant | The file as an attachment. **Admins get 404**: they may not read contents. Each download is audited. |
| `POST /documents/<id>/edit` | the owner, holders of an edit grant | Form fields `name` and/or `category`. A name must keep its file extension. Nothing else can be changed. |
| `POST /documents/<id>/delete` | the owner only | Soft delete. The document disappears for everyone but the owner's direct link. |

## Sharing
| Method and path | Who may call it | Notes |
|---|---|---|
| `GET /documents/<id>/grants` | the owner only | who has access and at what level |
| `POST /documents/<id>/grants` | the owner only | form fields `email`, `permission` (`read` or `edit`). Takes effect on the next request. Invalid permission: 400. Unknown email: 404. Granting to yourself: 400. |
| `POST /documents/<id>/grants/<user_id>/revoke` | the owner only | Takes effect immediately, including for sessions already open. |

## Administration
| Method and path | Who may call it | Notes |
|---|---|---|
| `GET /admin/activity` | admin only (404 for everyone else, audited) | Newest first. Filters `document_id`, `actor_id`, `action`, `outcome` (allowed or denied), `from`, `to`, `limit` (1 to 500), `before_id` (paging). Never returns file contents, storage keys or hashes. Each view is itself audited. |
| `GET /admin/audit/verify` | admin only | `{"intact": true, "first_bad_row": null}`. Checks the hash chain over the whole log. Audited. |
soft-deleted documents are hidden from lists but the owner can still open them by id.