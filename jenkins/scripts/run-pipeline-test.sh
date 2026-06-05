#!/usr/bin/env bash
# End-to-end test pipeline without Jenkins:
#   - ensure ci_tokens schema
#   - issue CI token (dast-cli ci setup)
#   - run dast-scan.sh in ci-runner with DAST_CI_TOKEN (same as Jenkinsfile.test)
#
# Usage:
#   docker compose -f deploy/docker-compose.yml up -d
#   bash jenkins/scripts/run-pipeline-test.sh
#
# Env overrides: DAST_API_URL, DAST_TARGET, DB_HOST, SCAN_TIMEOUT_MINUTES
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
JENKINS_DIR="$(cd "$(dirname "$0")/.." && pwd)"

log() { echo "[pipeline-test] $*"; }
die() { log "FAIL: $*"; exit 1; }

API_URL="${DAST_API_URL:-http://host.docker.internal:8080}"
API_URL="${API_URL%/}"
TARGET="${DAST_TARGET:-https://example.com}"
DB_HOST="${DB_HOST:-host.docker.internal}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-dast}"
DB_PASS="${DB_PASS:-dast}"
DB_NAME="${DB_NAME:-dast}"
TIMEOUT_MIN="${SCAN_TIMEOUT_MINUTES:-8}"
TOKEN_NAME="${CI_TOKEN_NAME:-pipeline-test}"
OUT="$JENKINS_DIR/out-pipeline-test"

log "API: $API_URL  target: $TARGET  timeout: ${TIMEOUT_MIN}m"

code=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 "$API_URL/health" 2>/dev/null || echo "000")
[[ "$code" == "200" ]] || die "DAST API not reachable (HTTP $code). Run: docker compose -f deploy/docker-compose.yml up -d"

if [[ "${REBUILD_SERVER:-}" == "true" ]]; then
  log "Rebuild dast-server (linux binary + image)..."
  (cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/dast-server ./cmd/server)
  (cd "$ROOT/deploy" && docker compose build dast-server && docker compose up -d dast-server)
  sleep 3
fi

log "Ensure ci_tokens table..."
if command -v psql >/dev/null 2>&1; then
  PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -q <<'SQL' || true
CREATE TABLE IF NOT EXISTS ci_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_ci_tokens_user ON ci_tokens(user_id);
SQL
else
  docker exec dast-postgres psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -q <<'SQL' || true
CREATE TABLE IF NOT EXISTS ci_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_ci_tokens_user ON ci_tokens(user_id);
SQL
fi

log "Build dast-cli..."
(cd "$ROOT" && go build -o "$JENKINS_DIR/.tmp/dast-cli" ./cmd/cli)

log "Issue CI token (ci setup --name=$TOKEN_NAME)..."
SETUP_OUT=$("$JENKINS_DIR/.tmp/dast-cli" ci setup \
  --name="$TOKEN_NAME" \
  --api-url="$API_URL" \
  --verify \
  --insecure=true \
  --db-host="$DB_HOST" \
  --db-port="$DB_PORT" \
  --db-user="$DB_USER" \
  --db-pass="$DB_PASS" \
  --db-name="$DB_NAME" \
  --password="${CI_USER_PASSWORD:-ci-test-secret}" 2>&1) || die "ci setup failed: $SETUP_OUT"
echo "$SETUP_OUT"

CI_TOKEN=$(echo "$SETUP_OUT" | sed -n 's/^ci_token: //p')
[[ -n "$CI_TOKEN" ]] || die "could not parse ci_token from setup output"
printf '%s' "$CI_TOKEN" > "$OUT/.ci-token"
chmod 600 "$OUT/.ci-token" 2>/dev/null || true

log "Build ci-runner image..."
docker build -t appsec-dast/ci-runner:test -f "$JENKINS_DIR/Dockerfile" "$JENKINS_DIR"

rm -rf "$OUT"
mkdir -p "$OUT"

log "Run pipeline step (dast-scan.sh + DAST_CI_TOKEN)..."
docker run --rm \
  -v "$OUT:/work" \
  -e DAST_API_URL="$API_URL" \
  -e DAST_CI_TOKEN="$CI_TOKEN" \
  -e DAST_TARGET="$TARGET" \
  -e DAST_INSECURE_SKIP_VERIFY=true \
  -e DAST_TIMEOUT_MINUTES="$TIMEOUT_MIN" \
  -e DAST_FAIL_ON=CRITICAL \
  -e DAST_ARCHIVE_REPORTS=true \
  -e DAST_REPORT_FORMATS=html \
  -e DAST_POLL_SECONDS=10 \
  --add-host=host.docker.internal:host-gateway \
  appsec-dast/ci-runner:test

jq -e '.passed == true and .jobId != ""' "$OUT/dast-result.json" >/dev/null \
  || die "pipeline test failed — see $OUT/dast-result.json"

log "OK: test pipeline passed (jobId=$(jq -r .jobId "$OUT/dast-result.json"))"
log "Artifacts: $OUT/"
log ""
log "Jenkins: create Secret text credential id=dast-ci-pipeline-test"
log "  (token saved locally: $OUT/.ci-token — do not commit)"
log "Job definition: jenkins/examples/Jenkinsfile.test"
