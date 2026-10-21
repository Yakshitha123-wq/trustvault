-- Run once as the database owner, AFTER schema.sql. Replace CHANGE_ME with a long
-- random password, and do NOT commit the real password.
CREATE ROLE trustvault_app LOGIN PASSWORD 'CHANGE_ME';

GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, documents, grants, document_blobs TO trustvault_app;
GRANT SELECT, INSERT ON audit_log TO trustvault_app;   -- no UPDATE, no DELETE
GRANT USAGE ON SEQUENCE audit_log_id_seq TO trustvault_app;