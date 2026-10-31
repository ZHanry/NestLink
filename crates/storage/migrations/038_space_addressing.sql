-- Management facts only. These tables grant no IP access and install no DNS.
CREATE TABLE network_space_address_directories (
 space_id TEXT PRIMARY KEY REFERENCES network_spaces(space_id),
 revision INTEGER NOT NULL CHECK(revision>0),
 last_observed_ms INTEGER NOT NULL CHECK(last_observed_ms>0)
) STRICT;
CREATE TABLE network_space_addresses (
 space_id TEXT NOT NULL REFERENCES network_spaces(space_id),
 installation_id TEXT NOT NULL REFERENCES devices(id),
 account_id TEXT NOT NULL REFERENCES accounts(id),
 public_key BLOB NOT NULL CHECK(length(public_key)=32),
 account_member_epoch INTEGER NOT NULL CHECK(account_member_epoch>0),
 membership_epoch INTEGER NOT NULL CHECK(membership_epoch>0),
 address_epoch INTEGER NOT NULL CHECK(address_epoch>0),
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 63),
 ipv4 TEXT NOT NULL,
 ipv6 TEXT NOT NULL,
 allocation_slot INTEGER NOT NULL CHECK(allocation_slot>0),
 reserved INTEGER NOT NULL CHECK(reserved IN (0,1)),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 PRIMARY KEY(space_id,installation_id)
) STRICT;
-- Also fence stale bindings until a manager explicitly revokes them.
CREATE UNIQUE INDEX network_space_address_name
 ON network_space_addresses(space_id,name) WHERE revoked=0;
CREATE UNIQUE INDEX network_space_address_ipv4
 ON network_space_addresses(ipv4) WHERE revoked=0;
CREATE UNIQUE INDEX network_space_address_ipv6
 ON network_space_addresses(ipv6) WHERE revoked=0;
CREATE INDEX network_space_address_account
 ON network_space_addresses(space_id,account_id);
