-- Service promises have independent ownership and restart fencing.
CREATE TABLE service_edge_namespaces (
 node_id TEXT PRIMARY KEY REFERENCES data_nodes(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 config_json TEXT NOT NULL CHECK(json_valid(config_json) AND length(config_json)<=16384)
) STRICT;
CREATE TABLE service_publication_settings (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 control_runtime_id TEXT,
 restore_fenced INTEGER NOT NULL DEFAULT 0 CHECK(restore_fenced IN (0,1))
) STRICT;
INSERT INTO service_publication_settings(singleton) VALUES(1);
CREATE TABLE service_node_polls (
 node_id TEXT PRIMARY KEY REFERENCES data_nodes(id),
 control_runtime_id TEXT NOT NULL,
 runtime_id TEXT NOT NULL,
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 request_sequence INTEGER NOT NULL CHECK(request_sequence>0)
) STRICT;
CREATE TABLE service_publications (
 id TEXT PRIMARY KEY,
 service_id TEXT NOT NULL REFERENCES services(id),
 account_id TEXT NOT NULL REFERENCES accounts(id),
 node_id TEXT NOT NULL REFERENCES data_nodes(id),
 service_revision INTEGER NOT NULL CHECK(service_revision>0),
 generation INTEGER NOT NULL CHECK(generation>0),
 control_runtime_id TEXT NOT NULL,
 ingress_key TEXT NOT NULL CHECK(length(ingress_key)<=320),
 namespace_revision INTEGER NOT NULL CHECK(namespace_revision>0),
 claims_json TEXT NOT NULL CHECK(json_valid(claims_json) AND length(claims_json)<=32768),
 promised_until INTEGER NOT NULL CHECK(promised_until>0),
 maximum_connections INTEGER NOT NULL CHECK(maximum_connections BETWEEN 1 AND 128),
 bytes_per_second INTEGER NOT NULL CHECK(bytes_per_second BETWEEN 1 AND 1073741824),
 maximum_bytes INTEGER NOT NULL CHECK(maximum_bytes BETWEEN 1 AND 1099511627776),
 -- 0: renewable; 1: draining, still owns its promise; 2: physically expired.
 state INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0,1,2)),
 UNIQUE(service_id,generation)
) STRICT;
CREATE UNIQUE INDEX service_ingress_owner ON service_publications(ingress_key) WHERE state IN (0,1);
CREATE UNIQUE INDEX service_definition_owner ON service_publications(service_id) WHERE state IN (0,1);
CREATE INDEX service_publication_promises ON service_publications(promised_until,account_id,node_id);
