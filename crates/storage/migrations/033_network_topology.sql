-- A global relay role is not a space topology publishing capability.
-- Publisher IDs and report high watermarks survive withdrawal and expiry.
CREATE TABLE network_topology_publishers (
 space_id TEXT NOT NULL REFERENCES network_authorities(space_id),
 publisher_id TEXT NOT NULL,
 node_id TEXT NOT NULL REFERENCES data_nodes(id),
 runtime_id TEXT NOT NULL,
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 policy_epoch INTEGER NOT NULL CHECK(policy_epoch>0),
 claims BLOB NOT NULL CHECK(length(claims)>0 AND length(claims)<=16384),
 signature BLOB NOT NULL CHECK(length(signature)=64),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>0),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 PRIMARY KEY(space_id,publisher_id)
) STRICT;
CREATE UNIQUE INDEX network_topology_one_publisher
 ON network_topology_publishers(space_id,node_id) WHERE revoked=0;
CREATE TABLE network_topology_heads (
 space_id TEXT NOT NULL REFERENCES network_authorities(space_id),
 node_id TEXT NOT NULL REFERENCES data_nodes(id),
 runtime_id TEXT NOT NULL,
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 sequence INTEGER NOT NULL CHECK(sequence>0),
 publisher_id TEXT NOT NULL,
 report_digest BLOB NOT NULL CHECK(length(report_digest)=32),
 report_claims BLOB NOT NULL CHECK(length(report_claims)>0 AND length(report_claims)<=16384),
 report_signature BLOB NOT NULL CHECK(length(report_signature)=64),
 advertisement BLOB NOT NULL CHECK(length(advertisement)>0 AND length(advertisement)<=17408),
 advertisement_signature BLOB NOT NULL CHECK(length(advertisement_signature)=64),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>0),
 accepted_at_ms INTEGER NOT NULL CHECK(accepted_at_ms>0),
 withdrawn INTEGER NOT NULL DEFAULT 0 CHECK(withdrawn IN (0,1)),
 PRIMARY KEY(space_id,node_id),
 FOREIGN KEY(space_id,publisher_id) REFERENCES network_topology_publishers(space_id,publisher_id)
) STRICT;
CREATE TABLE network_topology_cursors (
 space_id TEXT PRIMARY KEY REFERENCES network_authorities(space_id),
 policy_epoch INTEGER NOT NULL CHECK(policy_epoch>0),
 cursor INTEGER NOT NULL DEFAULT 0 CHECK(cursor>=0),
 retained_after INTEGER NOT NULL DEFAULT 0 CHECK(retained_after>=0),
 last_observed_ms INTEGER NOT NULL CHECK(last_observed_ms>0)
) STRICT;
-- A retained, bounded change journal. An old cursor must fetch a full snapshot.
CREATE TABLE network_topology_changes (
 space_id TEXT NOT NULL REFERENCES network_topology_cursors(space_id),
 cursor INTEGER NOT NULL CHECK(cursor>0),
 change_json TEXT NOT NULL CHECK(json_valid(change_json) AND length(change_json)<=131072),
 PRIMARY KEY(space_id,cursor)
) STRICT;
