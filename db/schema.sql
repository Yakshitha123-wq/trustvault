-- TrustVault schema (PostgreSQL 13+)
-- Run as the database owner, NOT as the app role.

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         citext UNIQUE NOT NULL,
  name          text NOT NULL,
  password_hash text NOT NULL,
  role          text NOT NULL CHECK (role IN ('admin','owner','viewer')),
  is_active     boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Only a hash of the session token is stored, so a database leak
-- does not leak usable sessions.
CREATE TABLE sessions (
  token_hash  text PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

CREATE TABLE documents (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id    uuid NOT NULL REFERENCES users(id),
  name        text NOT NULL,            -- display name only, never used as a path
  category    text NOT NULL DEFAULT 'general',
  storage_key text UNIQUE NOT NULL,     -- random, unrelated to the name
  mime_type   text NOT NULL,
  size_bytes  bigint NOT NULL,
  sha256      text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  deleted_at  timestamptz               -- soft delete
);
CREATE INDEX documents_owner_idx    ON documents(owner_id);
CREATE INDEX documents_category_idx ON documents(category);
CREATE INDEX documents_created_idx  ON documents(created_at);

CREATE TABLE grants (
  document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  permission  text NOT NULL CHECK (permission IN ('read','edit')),
  granted_by  uuid NOT NULL REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (document_id, user_id)    -- one grant per person per document
);
CREATE INDEX grants_user_idx ON grants(user_id);

CREATE TABLE audit_log (
  id             bigserial PRIMARY KEY,
  ts             timestamptz NOT NULL DEFAULT now(),
  actor_id       uuid,                  -- null for anonymous / failed logins
  action         text NOT NULL,         -- upload, download, update, delete, grant, revoke, login_failed ...
  outcome        text NOT NULL CHECK (outcome IN ('allowed','denied')),
  document_id    uuid,
  target_user_id uuid,
  ip             inet,
  detail         jsonb NOT NULL DEFAULT '{}',
  prev_hash      text NOT NULL,
  row_hash       text NOT NULL
);
-- Deliberately no foreign keys: audit records must survive deletion of
-- users and documents.
CREATE INDEX audit_doc_idx   ON audit_log(document_id);
CREATE INDEX audit_actor_idx ON audit_log(actor_id);
CREATE INDEX audit_ts_idx    ON audit_log(ts);

-- Append-only, enforced by a trigger (and by privileges, see db/roles.sql).
CREATE OR REPLACE FUNCTION audit_no_change() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_immutable ON audit_log;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_no_change();

DROP TRIGGER IF EXISTS audit_no_truncate ON audit_log;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_no_change();