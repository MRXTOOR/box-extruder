-- CI key ownership and scan source tracking
ALTER TABLE ci_tokens ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id);
ALTER TABLE ci_tokens ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES users(id);

ALTER TABLE scans ADD COLUMN IF NOT EXISTS ci_token_id UUID REFERENCES ci_tokens(id);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS source VARCHAR(32) NOT NULL DEFAULT 'web';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS metadata JSONB;

CREATE INDEX IF NOT EXISTS idx_scans_ci_token_id ON scans(ci_token_id);
CREATE INDEX IF NOT EXISTS idx_ci_tokens_owner ON ci_tokens(owner_user_id);
