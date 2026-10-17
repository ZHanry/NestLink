-- 0.2 removes authenticator enrollment and recovery codes from all clients.
-- Preserve accounts and password hashes; invalidate existing management login.
UPDATE account_security SET totp_ciphertext=NULL, totp_pending=NULL,
    totp_pending_expires=NULL, totp_last_step=NULL;
DELETE FROM recovery_codes;
UPDATE management_sessions SET revoked=1;
