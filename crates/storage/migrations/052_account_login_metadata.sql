-- Display metadata is independent from enrolled device identities and space membership.
CREATE TABLE management_login_metadata (
    session_id TEXT PRIMARY KEY REFERENCES management_sessions(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    client TEXT NOT NULL,
    platform TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    last_active_at INTEGER NOT NULL CHECK(last_active_at >= created_at)
);
