CREATE TABLE management_refresh_receipts (
  session_id TEXT PRIMARY KEY REFERENCES management_sessions(id) ON DELETE CASCADE,
  previous_sha256 BLOB NOT NULL CHECK(length(previous_sha256)=32),
  previous_generation INTEGER NOT NULL,
  response_ciphertext BLOB NOT NULL,
  expires INTEGER NOT NULL
) STRICT;
CREATE INDEX refresh_receipt_expiry ON management_refresh_receipts(expires);

CREATE INDEX remote_pending_inbox ON remote_requests(status,host_device_id,expires,id);
