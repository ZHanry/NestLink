-- Observation refreshes do not renew immutable transit grants. These durable
-- fences record the original authority and every uninterrupted observation.
CREATE TABLE network_remote_chain_topology_bindings (
 route_id TEXT NOT NULL,
 position INTEGER NOT NULL CHECK(position IN (0,1)),
 original_publisher_digest BLOB NOT NULL CHECK(length(original_publisher_digest)=32),
 original_sequence INTEGER NOT NULL CHECK(original_sequence>0),
 latest_sequence INTEGER NOT NULL CHECK(latest_sequence>=original_sequence),
 observed_until INTEGER NOT NULL CHECK(observed_until>0),
 PRIMARY KEY(route_id,position),
 FOREIGN KEY(route_id,position) REFERENCES network_remote_chain_hops(route_id,position)
) STRICT;

-- Old rows have only a digest of the initial envelope, so historical continuity
-- cannot be reconstructed after head replacement. Retire them, preserving both
-- original promises in all_relay_capacity until their existing deadlines.
UPDATE network_remote_paths SET revoked=1 WHERE EXISTS (
 SELECT 1 FROM network_remote_chains c
 WHERE c.space_id=network_remote_paths.space_id
 AND c.path_grant_id=network_remote_paths.path_grant_id
);
UPDATE network_remote_chain_hops SET closed=1;
