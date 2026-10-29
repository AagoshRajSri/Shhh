-- Migration: 20261030000000_split_routing_token.sql
-- Description: Split routing_token into public inbox_id and private receive_secret hash.
-- Note: Pre-launch breaking change. Existing registrations lacking receive_secret are invalidated.

TRUNCATE TABLE users;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS inbox_id UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN IF NOT EXISTS receive_secret_hash BYTEA NOT NULL,
    ADD COLUMN IF NOT EXISTS auth_scheme VARCHAR(32) NOT NULL DEFAULT 'hash-v1';

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_inbox_id ON users(inbox_id);
CREATE INDEX IF NOT EXISTS idx_users_secret_hash ON users(receive_secret_hash);
