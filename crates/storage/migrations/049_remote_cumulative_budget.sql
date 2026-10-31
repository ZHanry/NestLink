-- Remote business has its own original total ledger. A relay allocation is
-- never substituted for direct bytes; online and offline promises debit here.
CREATE TABLE remote_budget_limits (
 scope_kind TEXT NOT NULL CHECK(scope_kind IN ('account','device','resource')),
 scope_key TEXT NOT NULL CHECK(length(scope_key)=36),
 maximum_bytes INTEGER NOT NULL CHECK(maximum_bytes BETWEEN 0 AND 9223372036854775807),
 maximum_file_write_bytes INTEGER NOT NULL CHECK(maximum_file_write_bytes BETWEEN 0 AND maximum_bytes),
 maximum_connection_attempts INTEGER NOT NULL CHECK(maximum_connection_attempts BETWEEN 0 AND 9223372036854775807),
 revision INTEGER NOT NULL CHECK(revision>0),
 PRIMARY KEY(scope_kind,scope_key)
) STRICT;
CREATE TABLE remote_budget_ledgers (
 scope_kind TEXT NOT NULL,
 scope_key TEXT NOT NULL,
 promised_bytes INTEGER NOT NULL DEFAULT 0 CHECK(promised_bytes>=0),
 promised_file_write_bytes INTEGER NOT NULL DEFAULT 0 CHECK(promised_file_write_bytes>=0),
 promised_connection_attempts INTEGER NOT NULL DEFAULT 0 CHECK(promised_connection_attempts>=0),
 PRIMARY KEY(scope_kind,scope_key),
 FOREIGN KEY(scope_kind,scope_key) REFERENCES remote_budget_limits(scope_kind,scope_key)
) STRICT;
CREATE TABLE remote_usage_budgets (
 reservation_id TEXT PRIMARY KEY,
 session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id),
 claims_json TEXT NOT NULL CHECK(json_valid(claims_json) AND length(claims_json)<=8192)
) STRICT;
CREATE TABLE offline_remote_reservations (
 reservation_id TEXT PRIMARY KEY,
 bundle_id TEXT NOT NULL UNIQUE,
 session_id TEXT NOT NULL REFERENCES sessions(id),
 promised_bytes INTEGER NOT NULL CHECK(promised_bytes>0),
 promised_file_write_bytes INTEGER NOT NULL CHECK(promised_file_write_bytes>=0),
 promised_connection_attempts INTEGER NOT NULL CHECK(promised_connection_attempts>0)
) STRICT;
