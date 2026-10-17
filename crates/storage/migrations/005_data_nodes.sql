CREATE TABLE data_nodes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  public_key BLOB NOT NULL UNIQUE CHECK(length(public_key)=32),
  roles_json TEXT NOT NULL CHECK(json_valid(roles_json)),
  max_connections INTEGER NOT NULL CHECK(max_connections BETWEEN 1 AND 100000),
  bytes_per_second INTEGER NOT NULL CHECK(bytes_per_second BETWEEN 1 AND 1073741824),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
  lease_sequence INTEGER NOT NULL DEFAULT 0 CHECK(lease_sequence>=0),
  last_issued_at INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE used_node_challenges (
  request_id TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
) STRICT;
