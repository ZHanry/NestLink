-- A route set is distinct from a fixed single route or ordered two-hop chain.
-- Each immutable member owns a full allocation in the existing shared quota.
CREATE TABLE network_remote_route_sets (
 set_id TEXT PRIMARY KEY,
 space_id TEXT NOT NULL,
 path_grant_id TEXT NOT NULL,
 UNIQUE(space_id,path_grant_id),
 UNIQUE(set_id,space_id),
 FOREIGN KEY(space_id,path_grant_id) REFERENCES network_remote_paths(space_id,path_grant_id)
) STRICT;
CREATE TABLE network_remote_route_set_members (
 allocation_id TEXT PRIMARY KEY,
 set_id TEXT NOT NULL,
 position INTEGER NOT NULL CHECK(position IN (0,1)),
 space_id TEXT NOT NULL,
 transit_grant_id TEXT NOT NULL,
 node_id TEXT NOT NULL REFERENCES data_nodes(id),
 node_key BLOB NOT NULL CHECK(length(node_key)=32),
 runtime_id TEXT NOT NULL,
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 endpoint_revision INTEGER NOT NULL CHECK(endpoint_revision>0),
 node_endpoints_json TEXT NOT NULL,
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
 UNIQUE(set_id,position),
 UNIQUE(set_id,node_id),
 UNIQUE(space_id,transit_grant_id),
 FOREIGN KEY(set_id,space_id) REFERENCES network_remote_route_sets(set_id,space_id)
) STRICT;
CREATE INDEX network_remote_route_set_members_expiry ON network_remote_route_set_members(promised_until);
CREATE INDEX network_remote_route_set_members_node ON network_remote_route_set_members(node_id,promised_until);
DROP VIEW all_relay_capacity;
CREATE VIEW all_relay_capacity AS
 SELECT id,kind,controller_account_id,host_account_id,node_id,promised_until FROM relay_reservations
 UNION ALL
 SELECT allocation_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_relays
 UNION ALL
 SELECT route_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_chain_hops
 UNION ALL
 SELECT allocation_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_route_set_members;
