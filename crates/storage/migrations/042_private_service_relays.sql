-- Private business authority has its own immutable route; capacity remains in
-- the original shared relay reservation view and service usage grant.
CREATE TABLE private_service_relay_hops (
 grant_id TEXT NOT NULL REFERENCES private_service_leases(grant_id),
 position INTEGER NOT NULL CHECK(position IN(0,1)),
 route_id TEXT NOT NULL,
 space_id TEXT NOT NULL,
 transit_grant_id TEXT NOT NULL UNIQUE,
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
 closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN(0,1)),
 transit_claims BLOB NOT NULL,
 transit_signature BLOB NOT NULL CHECK(length(transit_signature)=64),
 allocation_json TEXT NOT NULL,
 original_publisher_digest BLOB,
 original_sequence INTEGER,
 latest_sequence INTEGER,
 observed_until INTEGER,
 PRIMARY KEY(grant_id,position),
 UNIQUE(route_id,position),
 UNIQUE(grant_id,node_id)
) STRICT;
CREATE INDEX private_service_relay_hops_node ON private_service_relay_hops(node_id,promised_until);
-- Receipts now cover either original allocation table. The accepting owner
-- checks that exact immutable allocation before inserting a receipt.
ALTER TABLE relay_close_receipts RENAME TO relay_close_receipts_legacy;
CREATE TABLE relay_close_receipts (
 allocation_id TEXT PRIMARY KEY,
 close_digest BLOB NOT NULL CHECK(length(close_digest)=32),
 close_claims BLOB NOT NULL CHECK(length(close_claims)<=4096),
 close_signature BLOB NOT NULL CHECK(length(close_signature)=64),
 accepted_at INTEGER NOT NULL CHECK(accepted_at>0),
 ack_claims BLOB NOT NULL CHECK(length(ack_claims)<=4096)
) STRICT;
INSERT INTO relay_close_receipts SELECT * FROM relay_close_receipts_legacy;
DROP TABLE relay_close_receipts_legacy;
DROP VIEW all_relay_capacity;
CREATE VIEW all_relay_capacity AS
 SELECT id,kind,controller_account_id,host_account_id,node_id,promised_until FROM relay_reservations
 UNION ALL SELECT allocation_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_relays
 UNION ALL SELECT route_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_chain_hops
 UNION ALL SELECT allocation_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_route_set_members
 UNION ALL SELECT transit_grant_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM private_service_relay_hops;
