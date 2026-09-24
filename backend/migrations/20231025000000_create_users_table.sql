CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    handle          TEXT UNIQUE NOT NULL,
    identity_pubkey BYTEA NOT NULL,
    signed_prekey   BYTEA NOT NULL,
    kyber_pubkey    BYTEA,          -- for later PQXDH, nullable for now
    created_week    DATE NOT NULL   -- coarse, not exact timestamp
);
CREATE INDEX IF NOT EXISTS idx_users_handle ON users(handle);
