-- Current authorities keep generation zero and their exact existing key.
-- Retired public keys and permanent authority revocation are durable facts.
ALTER TABLE network_authorities ADD COLUMN signing_generation INTEGER NOT NULL DEFAULT 0 CHECK(signing_generation>=0);
ALTER TABLE network_authorities ADD COLUMN authority_revoked INTEGER NOT NULL DEFAULT 0 CHECK(authority_revoked IN (0,1));
CREATE TABLE network_authority_key_history (
 space_id TEXT NOT NULL REFERENCES network_authorities(space_id),
 public_key BLOB NOT NULL CHECK(length(public_key)=32),
 signing_generation INTEGER NOT NULL CHECK(signing_generation>=0),
 activated_policy_epoch INTEGER NOT NULL CHECK(activated_policy_epoch>0),
 activated_at_ms INTEGER NOT NULL CHECK(activated_at_ms>0),
 retired_at_ms INTEGER CHECK(retired_at_ms IS NULL OR retired_at_ms>=activated_at_ms),
 PRIMARY KEY(space_id,public_key)
) STRICT;
INSERT INTO network_authority_key_history(space_id,public_key,signing_generation,activated_policy_epoch,activated_at_ms)
 SELECT space_id,public_key,0,policy_epoch,last_observed_ms FROM network_authorities;
