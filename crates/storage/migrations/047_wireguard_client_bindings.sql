-- WireGuard maps an independent standard-client key to an original packet
-- business graph. It owns no replacement NetworkAccess or spendable balance.
CREATE TABLE network_wireguard_clients (
 space_id TEXT NOT NULL REFERENCES network_authorities(space_id),
 client_id TEXT NOT NULL CHECK(length(client_id)=36),
 account_id TEXT NOT NULL REFERENCES accounts(id),
 installation_id TEXT NOT NULL REFERENCES devices(id),
 portal_node_id TEXT NOT NULL REFERENCES data_nodes(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 total_byte_ceiling INTEGER NOT NULL CHECK(total_byte_ceiling>0),
 committed_bytes INTEGER NOT NULL CHECK(committed_bytes>0 AND committed_bytes<=total_byte_ceiling),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)),
 PRIMARY KEY(space_id,client_id)
) STRICT;
CREATE TABLE network_wireguard_bindings (
 space_id TEXT NOT NULL,
 grant_id TEXT NOT NULL CHECK(length(grant_id)=36),
 client_id TEXT NOT NULL,
 client_revision INTEGER NOT NULL CHECK(client_revision>0),
 access_grant_id TEXT NOT NULL,
 public_key BLOB NOT NULL CHECK(length(public_key)=32),
 client_address TEXT NOT NULL,
 claims BLOB NOT NULL CHECK(length(claims) BETWEEN 1 AND 4096),
 signature BLOB NOT NULL CHECK(length(signature)=64),
 digest BLOB NOT NULL CHECK(length(digest)=32),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>0),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)),
 PRIMARY KEY(space_id,grant_id),
 UNIQUE(space_id,access_grant_id),
 FOREIGN KEY(space_id,client_id) REFERENCES network_wireguard_clients(space_id,client_id),
 FOREIGN KEY(space_id,access_grant_id) REFERENCES network_packet_access(space_id,access_grant_id)
) STRICT;
CREATE INDEX network_wireguard_binding_namespace ON network_wireguard_bindings(client_address,expires_at_ms);
