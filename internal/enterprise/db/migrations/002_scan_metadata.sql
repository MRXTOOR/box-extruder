-- Jenkins CI metadata on scans (idempotent; column may already exist from 001)
ALTER TABLE scans ADD COLUMN IF NOT EXISTS metadata JSONB;
