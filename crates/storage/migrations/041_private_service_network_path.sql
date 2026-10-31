-- One immutable network grant set for the original private business reservation.
-- Its lifetime and policy epochs never renew the business lease or allowance.
ALTER TABLE private_service_leases ADD COLUMN network_json TEXT
 CHECK(network_json IS NULL OR (json_valid(network_json) AND length(network_json)<=262144));
