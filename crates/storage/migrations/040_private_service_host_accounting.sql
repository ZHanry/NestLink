-- A private-only service does not register or depend on a public edge. Preserve
-- existing definition JSON and signed target hashes byte for byte. SQLite's
-- documented table rebuild runs with FK enforcement disabled outside this
-- transaction; the caller checks every FK before committing and re-enables it.
CREATE TABLE services_private_migration (
 id TEXT PRIMARY KEY,
 account_id TEXT NOT NULL REFERENCES accounts(id),
 management_session_id TEXT NOT NULL REFERENCES management_sessions(id),
 host_device_id TEXT NOT NULL REFERENCES devices(id),
 edge_node_id TEXT REFERENCES data_nodes(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 definition_json TEXT NOT NULL CHECK(json_valid(definition_json) AND length(definition_json)<=16384),
 definition_sha256 BLOB NOT NULL CHECK(length(definition_sha256)=32),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
) STRICT;
INSERT INTO services_private_migration
 SELECT id,account_id,management_session_id,host_device_id,edge_node_id,
        revision,definition_json,definition_sha256,revoked FROM services;
DROP TABLE services;
ALTER TABLE services_private_migration RENAME TO services;
CREATE INDEX services_owner ON services(account_id,id);
