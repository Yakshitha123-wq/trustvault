CREATE TABLE IF NOT EXISTS document_blobs (
  document_id uuid PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
  content     bytea NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON document_blobs TO trustvault_app;