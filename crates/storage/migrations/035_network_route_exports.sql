-- Explicit manager-approved publication rights for a registered node key.
-- IDs and signed bytes are permanent tombstones, including after expiration.
CREATE TABLE network_route_exports (
 space_id TEXT NOT NULL REFERENCES network_authorities(space_id),
 grant_id TEXT NOT NULL,
 node_id TEXT NOT NULL REFERENCES data_nodes(id),
 public_key BLOB NOT NULL CHECK(length(public_key)=32),
 policy_epoch INTEGER NOT NULL CHECK(policy_epoch>0),
 digest BLOB NOT NULL CHECK(length(digest)=32),
 claims BLOB NOT NULL CHECK(length(claims)>0 AND length(claims)<=16384),
 signature BLOB NOT NULL CHECK(length(signature)=64),
 issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>0),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>issued_at_ms),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 PRIMARY KEY(space_id,grant_id),
 UNIQUE(space_id,digest)
) STRICT;
CREATE INDEX network_route_exports_current
 ON network_route_exports(space_id,policy_epoch,expires_at_ms);
CREATE TABLE network_topology_publisher_exports (
 space_id TEXT NOT NULL,
 publisher_id TEXT NOT NULL,
 grant_id TEXT NOT NULL,
 PRIMARY KEY(space_id,publisher_id,grant_id),
 FOREIGN KEY(space_id,publisher_id) REFERENCES network_topology_publishers(space_id,publisher_id),
 FOREIGN KEY(space_id,grant_id) REFERENCES network_route_exports(space_id,grant_id)
) STRICT;
CREATE INDEX network_topology_export_publishers
 ON network_topology_publisher_exports(space_id,grant_id,publisher_id);
