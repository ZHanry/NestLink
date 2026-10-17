CREATE TABLE node_endpoints (
 node_id TEXT PRIMARY KEY REFERENCES data_nodes(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 endpoints_json TEXT NOT NULL CHECK(json_valid(endpoints_json))
) STRICT;
