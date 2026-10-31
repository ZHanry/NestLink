-- Exact real/alias pairs are immutable signed tombstones. Revocation never
-- releases the old namespace promise before its original signed deadline.
CREATE TABLE network_subnet_mappings (
 space_id TEXT NOT NULL REFERENCES network_authorities(space_id),
 grant_id TEXT NOT NULL,
 node_id TEXT NOT NULL REFERENCES data_nodes(id),
 export_grant_id TEXT NOT NULL,
 public_key BLOB NOT NULL CHECK(length(public_key)=32),
 runtime_id TEXT NOT NULL,
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 policy_epoch INTEGER NOT NULL CHECK(policy_epoch>0),
 mapping_revision INTEGER NOT NULL CHECK(mapping_revision>0),
 digest BLOB NOT NULL CHECK(length(digest)=32),
 claims BLOB NOT NULL CHECK(length(claims)>0 AND length(claims)<=4096),
 signature BLOB NOT NULL CHECK(length(signature)=64),
 issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>0),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>issued_at_ms),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 PRIMARY KEY(space_id,grant_id),
 UNIQUE(space_id,digest),
 FOREIGN KEY(space_id,export_grant_id) REFERENCES network_route_exports(space_id,grant_id)
) STRICT;
CREATE INDEX network_subnet_mappings_promises ON network_subnet_mappings(space_id,expires_at_ms);
CREATE INDEX network_subnet_mappings_exports ON network_subnet_mappings(space_id,export_grant_id);
