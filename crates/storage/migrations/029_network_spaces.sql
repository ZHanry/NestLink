-- Product delegation reuses the existing authority, device memberships and epochs.
CREATE TABLE network_spaces (
 space_id TEXT PRIMARY KEY REFERENCES network_authorities(space_id),
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
 archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0,1))
) STRICT;
CREATE TABLE network_space_members (
 space_id TEXT NOT NULL REFERENCES network_spaces(space_id),
 account_id TEXT NOT NULL REFERENCES accounts(id),
 role TEXT NOT NULL CHECK(role IN ('owner','admin','member','guest')),
 member_epoch INTEGER NOT NULL CHECK(member_epoch>0),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 PRIMARY KEY(space_id,account_id)
) STRICT;
CREATE UNIQUE INDEX network_space_one_owner ON network_space_members(space_id)
 WHERE role='owner' AND revoked=0;
CREATE TABLE network_space_invitations (
 space_id TEXT NOT NULL REFERENCES network_spaces(space_id),
 invitation_id TEXT NOT NULL,
 token_hash BLOB NOT NULL CHECK(length(token_hash)=32),
 role TEXT NOT NULL CHECK(role IN ('admin','member','guest')),
 target_account_id TEXT REFERENCES accounts(id),
 issuer_account_id TEXT NOT NULL,
 issuer_member_epoch INTEGER NOT NULL CHECK(issuer_member_epoch>0),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>0),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 consumed_by TEXT REFERENCES accounts(id),
 PRIMARY KEY(space_id,invitation_id),
 FOREIGN KEY(space_id,issuer_account_id) REFERENCES network_space_members(space_id,account_id)
) STRICT;
CREATE TABLE network_space_audit (
 sequence INTEGER PRIMARY KEY REFERENCES audit(sequence) ON DELETE CASCADE,
 space_id TEXT NOT NULL REFERENCES network_spaces(space_id),
 action TEXT NOT NULL,
 target_id TEXT NOT NULL,
 actor_account_id TEXT NOT NULL REFERENCES accounts(id),
 at_ms INTEGER NOT NULL CHECK(at_ms>0)
) STRICT;
CREATE INDEX network_space_audit_page ON network_space_audit(space_id,sequence DESC);
