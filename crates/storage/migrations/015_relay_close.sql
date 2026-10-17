CREATE TABLE relay_close_receipts (
 allocation_id TEXT PRIMARY KEY REFERENCES relay_reservations(id),
 close_digest BLOB NOT NULL CHECK(length(close_digest)=32),
 close_claims BLOB NOT NULL CHECK(length(close_claims)<=4096),
 close_signature BLOB NOT NULL CHECK(length(close_signature)=64),
 accepted_at INTEGER NOT NULL CHECK(accepted_at>0),
 ack_claims BLOB NOT NULL CHECK(length(ack_claims)<=4096)
) STRICT;
