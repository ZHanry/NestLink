-- Independent authority namespace; no legacy role or permit is reinterpreted.
CREATE TABLE network_authorities (
 space_id TEXT PRIMARY KEY,
 public_key BLOB NOT NULL CHECK(length(public_key)=32),
 revision INTEGER NOT NULL CHECK(revision>0),
 policy_epoch INTEGER NOT NULL CHECK(policy_epoch>0),
 security_epoch INTEGER NOT NULL CHECK(security_epoch>0),
 last_observed_ms INTEGER NOT NULL CHECK(last_observed_ms>0),
 restore_fenced INTEGER NOT NULL DEFAULT 0 CHECK(restore_fenced IN (0,1))
) STRICT;
CREATE TABLE network_memberships (
 space_id TEXT NOT NULL REFERENCES network_authorities(space_id),
 installation_id TEXT NOT NULL REFERENCES devices(id),
 public_key BLOB NOT NULL CHECK(length(public_key)=32),
 membership_epoch INTEGER NOT NULL CHECK(membership_epoch>0),
 role TEXT NOT NULL CHECK(role IN ('owner','admin','member','guest')),
 revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),
 PRIMARY KEY(space_id,installation_id)
) STRICT;
CREATE TABLE network_grants (
 space_id TEXT NOT NULL REFERENCES network_authorities(space_id),
 grant_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind='membership'),
 installation_id TEXT NOT NULL,
 membership_epoch INTEGER NOT NULL CHECK(membership_epoch>0),
 policy_epoch INTEGER NOT NULL CHECK(policy_epoch>0),
 digest BLOB NOT NULL CHECK(length(digest)=32),
 claims BLOB NOT NULL CHECK(length(claims)>0 AND length(claims)<=16384),
 signature BLOB NOT NULL CHECK(length(signature)=64),
 issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>0),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>issued_at_ms),
 PRIMARY KEY(space_id,grant_id),
 FOREIGN KEY(space_id,installation_id) REFERENCES network_memberships(space_id,installation_id)
) STRICT;
CREATE INDEX network_grants_current ON network_grants(space_id,policy_epoch,expires_at_ms);
CREATE TABLE network_grant_revocations (
 space_id TEXT NOT NULL,
 grant_id TEXT NOT NULL,
 revoked_at_ms INTEGER NOT NULL CHECK(revoked_at_ms>0),
 PRIMARY KEY(space_id,grant_id),
 FOREIGN KEY(space_id,grant_id) REFERENCES network_grants(space_id,grant_id)
) STRICT;
