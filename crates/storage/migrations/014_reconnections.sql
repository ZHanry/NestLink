-- One pending exchange and one immutable latest receipt per approved resource.
CREATE TABLE reconnection_offers (
  session_id TEXT PRIMARY KEY REFERENCES remote_requests(id),
  previous_permit_json TEXT NOT NULL CHECK(json_valid(previous_permit_json)),
  offer_json TEXT NOT NULL CHECK(json_valid(offer_json) AND length(offer_json)<=4096),
  host_signature TEXT
) STRICT;
CREATE TABLE reconnection_receipts (
  session_id TEXT PRIMARY KEY REFERENCES remote_requests(id),
  request_sha256 BLOB NOT NULL CHECK(length(request_sha256)=32),
  previous_permit_json TEXT NOT NULL CHECK(json_valid(previous_permit_json)),
  next_permit_json TEXT NOT NULL CHECK(json_valid(next_permit_json)),
  submission_json TEXT NOT NULL CHECK(json_valid(submission_json) AND length(submission_json)<=4096)
) STRICT;
