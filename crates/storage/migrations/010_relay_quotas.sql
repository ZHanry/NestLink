CREATE TABLE relay_quotas (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    revision INTEGER NOT NULL CHECK(revision>0),
    max_allocations INTEGER NOT NULL CHECK(max_allocations BETWEEN 0 AND 128),
    max_account_endpoints INTEGER NOT NULL CHECK(max_account_endpoints BETWEEN 0 AND 256),
    bytes_per_second INTEGER NOT NULL CHECK(bytes_per_second BETWEEN 1 AND 1073741824),
    bytes_per_allocation INTEGER NOT NULL CHECK(bytes_per_allocation BETWEEN 1 AND 1099511627776)
) STRICT;
INSERT INTO relay_quotas VALUES(1,1,128,16,16777216,1073741824);
