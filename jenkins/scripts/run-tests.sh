#!/usr/bin/env bash
# Jenkins CI runner smoke tests (no Jenkins required).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
JENKINS_DIR="$(cd "$(dirname "$0")/.." && pwd)"

log() { echo "[jenkins-test] $*"; }
die() { log "FAIL: $*"; exit 1; }

API_URL="${DAST_API_URL:-http://host.docker.internal:8080}"
API_URL="${API_URL%/}"
DAST_USER="${DAST_USER:-admin}"
DAST_PASS="${DAST_PASS:-admin123}"
TARGET="${DAST_TARGET:-https://example.com}"

log "Go unit tests (discovery)..."
(cd "$ROOT" && go test ./internal/auth/discovery/... -count=1) || die "go test failed"

log "Build ci-runner image..."
docker build -t appsec-dast/ci-runner:test -f "$JENKINS_DIR/Dockerfile" "$JENKINS_DIR"

log "API health: $API_URL/health"
code=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 "$API_URL/health" || echo "000")
[[ "$code" == "200" ]] || die "DAST API not reachable (HTTP $code). Start: docker compose -f deploy/docker-compose.yml up -d"

log "Smoke: platform auth + create scan (no wait)"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if [[ -n "${DAST_CI_TOKEN:-}" ]]; then
  AUTH_MODE="ci-token"
  log "Using DAST_CI_TOKEN"
else
  AUTH_MODE="login"
fi

docker run --rm \
  -v "$WORK:/work" \
  -e DAST_API_URL="$API_URL" \
  -e DAST_USER="$DAST_USER" \
  -e DAST_PASS="$DAST_PASS" \
  -e DAST_CI_TOKEN="${DAST_CI_TOKEN:-}" \
  -e DAST_TARGET="$TARGET" \
  -e DAST_INSECURE_SKIP_VERIFY=true \
  -e AUTH_MODE="$AUTH_MODE" \
  --add-host=host.docker.internal:host-gateway \
  --entrypoint /bin/sh \
  appsec-dast/ci-runner:test -c '
    set -e
    if [[ "$AUTH_MODE" == "ci-token" ]]; then
      printf "Authorization: Bearer %s" "$DAST_CI_TOKEN" > /work/h
    else
      jq -n --arg l "$DAST_USER" --arg p "$DAST_PASS" "{login:\$l,password:\$p}" > /work/login.json
      code=$(curl -sS -o /work/r.json -w "%{http_code}" -X POST -H "Content-Type: application/json" \
        --data @/work/login.json "$DAST_API_URL/api/v1/auth/login")
      test "$code" = "200"
      token=$(jq -r ".token" /work/r.json)
      printf "Authorization: Bearer %s" "$token" > /work/h
    fi
    jq -n --arg t "$DAST_TARGET" "{targetUrl:\$t,insecureSkipVerify:true}" > /work/c.json
    code=$(curl -sS -o /work/r.json -w "%{http_code}" -X POST -H "Content-Type: application/json" -H @/work/h \
      --data @/work/c.json "$DAST_API_URL/api/v1/scans")
    [[ "$code" == "201" || "$code" == "200" ]]
    jq -e ".jobId != \"\"" /work/r.json >/dev/null
    echo "smoke jobId=$(jq -r .jobId /work/r.json)"
  ' || die "API smoke failed"

if [[ "${DAST_FULL_SCAN:-}" == "true" ]]; then
  TIMEOUT="${DAST_TIMEOUT_MINUTES:-60}"
  OUT="$JENKINS_DIR/out-test"
  rm -rf "$OUT"
  mkdir -p "$OUT"
  log "Full scan (DAST_FULL_SCAN=true, timeout=${TIMEOUT}m)..."
  docker run --rm \
    -v "$OUT:/work" \
    -e DAST_API_URL="$API_URL" \
    -e DAST_USER="$DAST_USER" \
    -e DAST_PASS="$DAST_PASS" \
    -e DAST_TARGET="$TARGET" \
    -e DAST_INSECURE_SKIP_VERIFY=true \
    -e DAST_TIMEOUT_MINUTES="$TIMEOUT" \
    -e DAST_FAIL_ON=HIGH \
    -e DAST_ARCHIVE_REPORTS=false \
    --add-host=host.docker.internal:host-gateway \
    appsec-dast/ci-runner:test
  jq -e '.passed == true and .jobId != ""' "$OUT/dast-result.json" >/dev/null || die "full scan gate failed"
  rm -rf "$OUT"
  log "OK: full scan passed"
else
  log "OK: smoke passed (set DAST_FULL_SCAN=true for end-to-end wait)"
fi
