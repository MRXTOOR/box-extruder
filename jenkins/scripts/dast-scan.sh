#!/usr/bin/env bash
# dast-scan.sh — run a DAST scan via API (Docker / Jenkins CI).
# Required: DAST_API_URL, DAST_USER, DAST_PASS, DAST_TARGET.
# Optional: APP_USER, APP_PASS (app login); DAST_AUTH_URL (else server auto-detects).
set -euo pipefail

WORK="${DAST_WORK_DIR:-/work}"
mkdir -p "$WORK"

: "${DAST_API_URL:?DAST_API_URL is required}"
: "${DAST_TARGET:?DAST_TARGET is required}"
if [[ -z "${DAST_CI_TOKEN:-}" ]]; then
  : "${DAST_USER:?DAST_USER is required when DAST_CI_TOKEN is not set}"
  : "${DAST_PASS:?DAST_PASS is required when DAST_CI_TOKEN is not set}"
fi

DAST_API_URL="${DAST_API_URL%/}"
POLL_SECONDS="${DAST_POLL_SECONDS:-15}"
TIMEOUT_MINUTES="${DAST_TIMEOUT_MINUTES:-60}"
FAIL_ON_SCAN_ERROR="${DAST_FAIL_ON_SCAN_ERROR:-true}"
INSECURE_SKIP_VERIFY="${DAST_INSECURE_SKIP_VERIFY:-false}"
REPORT_FORMATS="${DAST_REPORT_FORMATS:-docx,html,pdf}"
ARCHIVE_REPORTS="${DAST_ARCHIVE_REPORTS:-true}"

CURL=(curl -sS --connect-timeout 15 --max-time 180)
[[ "${DAST_API_INSECURE:-false}" == "true" ]] && CURL+=(-k)
[[ -n "${DAST_CA:-}" && -f "$DAST_CA" ]] && CURL+=(--cacert "$DAST_CA")

log() { echo "[DAST] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

curl_code() {
  local out="$1"; shift
  "${CURL[@]}" -o "$out" -w '%{http_code}' "$@"
}

AUTH_HDR="$WORK/auth.headers"
cleanup() { rm -f "$AUTH_HDR" "$WORK"/*.json 2>/dev/null || true; }
trap cleanup EXIT

# --- platform auth: CI token preferred, else login/password ---
if [[ -n "${DAST_CI_TOKEN:-}" ]]; then
  log "using DAST_CI_TOKEN (no login)"
  printf 'Authorization: Bearer %s' "$DAST_CI_TOKEN" > "$AUTH_HDR"
else
  jq -n --arg login "$DAST_USER" --arg password "$DAST_PASS" '{login:$login,password:$password}' > "$WORK/login.json"
  code=$(curl_code "$WORK/login_resp.json" -X POST -H 'Content-Type: application/json' \
    --data @"$WORK/login.json" "$DAST_API_URL/api/v1/auth/login")
  rm -f "$WORK/login.json"
  [[ "$code" == "200" ]] || die "login failed (HTTP $code)"

  TOKEN=$(jq -r '.token // empty' "$WORK/login_resp.json")
  rm -f "$WORK/login_resp.json"
  [[ -n "$TOKEN" ]] || die "login response missing token"
  printf 'Authorization: Bearer %s' "$TOKEN" > "$AUTH_HDR"
fi

# --- create scan ---
jq -n \
  --arg target "$DAST_TARGET" \
  --argjson insecure "$( [[ "$INSECURE_SKIP_VERIFY" == "true" ]] && echo true || echo false )" \
  --arg authUrl "${DAST_AUTH_URL:-}" \
  --arg verifyUrl "${DAST_VERIFY_URL:-}" \
  --arg appUser "${APP_USER:-}" \
  --arg appPass "${APP_PASS:-}" \
  --arg startPoints "${DAST_START_POINTS:-}" \
  --arg katanaDepth "${DAST_KATANA_DEPTH:-}" \
  --arg katanaMaxUrls "${DAST_KATANA_MAX_URLS:-}" \
  --arg zapSpiderMinutes "${DAST_ZAP_SPIDER_MINUTES:-}" \
  --arg zapPassiveSecs "${DAST_ZAP_PASSIVE_SECS:-}" \
  '{
    targetUrl: $target,
    insecureSkipVerify: $insecure
  }
  + (if $authUrl != "" then {authUrl: $authUrl} else {} end)
  + (if $verifyUrl != "" then {verifyUrl: $verifyUrl} else {} end)
  + (if $appUser != "" then {login: $appUser, password: $appPass} else {} end)
  + (if $startPoints != "" then {startPoints: $startPoints} else {} end)
  + (if $katanaDepth != "" then {katanaDepth: ($katanaDepth | tonumber)} else {} end)
  + (if $katanaMaxUrls != "" then {katanaMaxUrls: ($katanaMaxUrls | tonumber)} else {} end)
  + (if $zapSpiderMinutes != "" then {zapSpiderMinutes: ($zapSpiderMinutes | tonumber)} else {} end)
  + (if $zapPassiveSecs != "" then {zapPassiveSecs: ($zapPassiveSecs | tonumber)} else {} end)' > "$WORK/create.json"

code=$(curl_code "$WORK/create_resp.json" -X POST -H 'Content-Type: application/json' -H @"$AUTH_HDR" \
  --data @"$WORK/create.json" "$DAST_API_URL/api/v1/scans")
rm -f "$WORK/create.json"
[[ "$code" == "200" || "$code" == "201" ]] || die "create scan failed (HTTP $code): $(cat "$WORK/create_resp.json" 2>/dev/null || true)"

JOB_ID=$(jq -r '.jobId // .id // empty' "$WORK/create_resp.json")
rm -f "$WORK/create_resp.json"
[[ -n "$JOB_ID" ]] || die "create scan response missing jobId"

log "scan queued: jobId=$JOB_ID target=$DAST_TARGET"
[[ -n "${DAST_UI_URL:-}" ]] && log "follow: ${DAST_UI_URL%/}/scans/$JOB_ID"

# --- poll ---
terminal=(SUCCEEDED FAILED CANCELLED CANCELED PARTIAL_SUCCESS)
max_iters=$(( TIMEOUT_MINUTES * 60 / POLL_SECONDS ))
(( max_iters < 1 )) && max_iters=1
final_status=""

for ((i = 1; i <= max_iters; i++)); do
  code=$(curl_code "$WORK/status.json" -H @"$AUTH_HDR" "$DAST_API_URL/api/v1/scans/$JOB_ID/status")
  [[ "$code" == "200" ]] || die "status check failed (HTTP $code)"
  st=$(jq -r '.status // empty' "$WORK/status.json")
  prog=$(jq -r '.progress // 0' "$WORK/status.json")
  log "$JOB_ID status=$st progress=${prog}% (poll $i/$max_iters)"
  for t in "${terminal[@]}"; do
    if [[ "$st" == "$t" ]]; then
      final_status="$st"
      break 2
    fi
  done
  sleep "$POLL_SECONDS"
done

if [[ -z "$final_status" ]]; then
  log "timeout after ${TIMEOUT_MINUTES}m; cancelling $JOB_ID"
  "${CURL[@]}" -o /dev/null -X POST -H @"$AUTH_HDR" "$DAST_API_URL/api/v1/scans/$JOB_ID/cancel" || true
  die "scan did not finish within ${TIMEOUT_MINUTES} minutes"
fi

# --- fetch scan + reports ---
code=$(curl_code "$WORK/scan.json" -H @"$AUTH_HDR" "$DAST_API_URL/api/v1/scans/$JOB_ID")
[[ "$code" == "200" ]] || die "fetch scan failed (HTTP $code)"

jq '.findings // []' "$WORK/scan.json" > "$WORK/dast-findings-${JOB_ID}.json"

if [[ "$ARCHIVE_REPORTS" == "true" ]]; then
  IFS=',' read -ra formats <<< "$REPORT_FORMATS"
  for fmt in "${formats[@]}"; do
    fmt=$(echo "$fmt" | tr -d ' ')
    [[ -z "$fmt" ]] && continue
    ext="$fmt"
    [[ "$fmt" == "endpoints" || "$fmt" == "discovered-urls" ]] && ext="txt"
    out="$WORK/dast-report-${JOB_ID}.${ext}"
    rc=$(curl_code "$out" -H @"$AUTH_HDR" "$DAST_API_URL/api/v1/scans/$JOB_ID/reports?format=$fmt" || echo "000")
    [[ "$rc" == "200" ]] || { log "report '$fmt' not available (HTTP $rc)"; rm -f "$out"; }
  done
fi

count_sev() {
  jq -r --arg s "$1" '[.findings[]? | (.severity // "INFO") | ascii_upcase] | map(select(. == $s)) | length' "$WORK/scan.json"
}

crit=$(count_sev CRITICAL)
high=$(count_sev HIGH)
med=$(count_sev MEDIUM)
low=$(count_sev LOW)
info=$(count_sev INFO)
total=$(jq '(.findings // []) | length' "$WORK/scan.json")

log "----------------------------------------"
log "Scan $JOB_ID finished: $final_status"
log "Findings: CRITICAL=$crit HIGH=$high MEDIUM=$med LOW=$low INFO=$info (total=$total)"
log "----------------------------------------"

passed=true
violations=()

if [[ "$FAIL_ON_SCAN_ERROR" == "true" && "$final_status" == "FAILED" ]]; then
  passed=false
  violations+=("scan ended with status FAILED")
fi

sev_rank() {
  case "${1^^}" in
    INFO) echo 0 ;; LOW) echo 1 ;; MEDIUM) echo 2 ;; HIGH) echo 3 ;; CRITICAL) echo 4 ;; *) echo 0 ;;
  esac
}

if [[ -n "${DAST_FAIL_ON:-}" ]]; then
  min=$(sev_rank "$DAST_FAIL_ON")
  declare -A cnt=([CRITICAL]=$crit [HIGH]=$high [MEDIUM]=$med [LOW]=$low [INFO]=$info)
  for sev in CRITICAL HIGH MEDIUM LOW INFO; do
    if [[ $(sev_rank "$sev") -ge $min && ${cnt[$sev]} -gt 0 ]]; then
      passed=false
      violations+=("${cnt[$sev]} finding(s) at severity $sev (failOn=${DAST_FAIL_ON^^})")
    fi
  done
fi

check_max() {
  [[ -z "${2:-}" ]] && return
  if [[ "$1" -gt "$2" ]]; then
    passed=false
    violations+=("$1 finding(s) exceeds maximum of $2")
  fi
}
check_max "$crit" "${DAST_MAX_CRITICAL:-}"
check_max "$high" "${DAST_MAX_HIGH:-}"
check_max "$med" "${DAST_MAX_MEDIUM:-}"
check_max "$low" "${DAST_MAX_LOW:-}"

violations_json='[]'
if [[ ${#violations[@]} -gt 0 ]]; then
  violations_json=$(printf '%s\n' "${violations[@]}" | jq -R . | jq -s .)
fi

jq -n \
  --arg jobId "$JOB_ID" \
  --arg status "$final_status" \
  --argjson total "$total" \
  --argjson passed "$( [[ "$passed" == true ]] && echo true || echo false )" \
  --argjson counts "$(jq -n --argjson c "$crit" --argjson h "$high" --argjson m "$med" --argjson l "$low" --argjson i "$info" \
    '{CRITICAL:$c,HIGH:$h,MEDIUM:$m,LOW:$l,INFO:$i}')" \
  --argjson violations "$violations_json" \
  '{jobId:$jobId,status:$status,total:$total,passed:$passed,counts:$counts,violations:$violations}' \
  > "$WORK/dast-result.json"

if [[ "$passed" != true ]]; then
  for v in "${violations[@]}"; do log "GATE VIOLATION: $v"; done
  die "quality gate failed for scan $JOB_ID"
fi

log "quality gate passed for scan $JOB_ID"
cat "$WORK/dast-result.json"
