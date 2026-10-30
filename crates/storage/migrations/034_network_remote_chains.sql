-- Both immutable transit promises are inserted by one immediate transaction.
-- A route consumes one full allocation on each relay; revocation retains both
-- original capacity holds until expiry, just like the existing one-hop owner.
CREATE TABLE network_remote_chains (
 route_id TEXT PRIMARY KEY,
 space_id TEXT NOT NULL,
 path_grant_id TEXT NOT NULL,
 topology_digests BLOB NOT NULL CHECK(length(topology_digests)=64),
 UNIQUE(space_id,path_grant_id),
 FOREIGN KEY(space_id,path_grant_id) REFERENCES network_remote_paths(space_id,path_grant_id)
) STRICT;
CREATE TABLE network_remote_chain_hops (
 route_id TEXT NOT NULL REFERENCES network_remote_chains(route_id),
 position INTEGER NOT NULL CHECK(position IN (0,1)),
 space_id TEXT NOT NULL,
 transit_grant_id TEXT NOT NULL,
 node_id TEXT NOT NULL REFERENCES data_nodes(id),
 node_key BLOB NOT NULL CHECK(length(node_key)=32),
 runtime_id TEXT NOT NULL,
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 endpoint_revision INTEGER NOT NULL CHECK(endpoint_revision>0),
 security_epoch INTEGER NOT NULL CHECK(security_epoch>0),
 policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
 quota_revision INTEGER NOT NULL CHECK(quota_revision>0),
 control_runtime_id TEXT NOT NULL,
 controller_account_id TEXT NOT NULL REFERENCES accounts(id),
 host_account_id TEXT NOT NULL REFERENCES accounts(id),
 byte_limit INTEGER NOT NULL CHECK(byte_limit>0),
 promised_until INTEGER NOT NULL CHECK(promised_until>0),
 closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0,1)),
 transit_claims BLOB NOT NULL CHECK(length(transit_claims)>0 AND length(transit_claims)<=16384),
 transit_signature BLOB NOT NULL CHECK(length(transit_signature)=64),
 PRIMARY KEY(route_id,position),
 UNIQUE(space_id,transit_grant_id),
 UNIQUE(route_id,node_id)
) STRICT;
CREATE INDEX network_remote_chain_hops_expiry ON network_remote_chain_hops(promised_until);
CREATE INDEX network_remote_chain_hops_node ON network_remote_chain_hops(node_id,promised_until);
DROP VIEW all_relay_capacity;
CREATE VIEW all_relay_capacity AS
 SELECT id,kind,controller_account_id,host_account_id,node_id,promised_until FROM relay_reservations
 UNION ALL
 SELECT allocation_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_relays
 UNION ALL
 SELECT route_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_chain_hops;
