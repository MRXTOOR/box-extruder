#!/usr/bin/env bash
# AppSec-DAST Jenkins runner: HTTP client for platform API (auth, scan, poll, reports).
set -euo pipefail

WORK="${DAST_WORK_DIR:-/work}"
CONFIG="${WORK}/config.json"
TOKEN_FILE="${WORK}/auth.headers"

log() {
    echo "[DAST] $*"
}

die() {
    echo "[DAST] ERROR: $*" >&2
    exit 1
}

require_config() {
    if [[ ! -f "$CONFIG" ]]; then
        die "config not found: ${CONFIG}"
    fi
}

jq_val() {
    local key="$1"
    local def="${2:-}"
    local v
    v="$(jq -r "${key} // empty" "$CONFIG")"
    if [[ -z "$v" || "$v" == "null" ]]; then
        echo "$def"
    else
        echo "$v"
    fi
}

jq_bool() {
    local key="$1"
    local def="${2:-false}"
    local v
    v="$(jq -r "${key} // \"${def}\"" "$CONFIG")"
    case "${v,,}" in
        true|1|yes|on) echo "true" ;;
        *) echo "false" ;;
    esac
}

build_curl_opts() {
    CURL_OPTS=(-sS --connect-timeout 15 --max-time 180)
    if [[ "$(jq_bool apiInsecure false)" == "true" ]]; then
        CURL_OPTS+=(-k)
    fi
    if [[ -n "${DAST_CA:-}" && -f "${DAST_CA}" ]]; then
        CURL_OPTS+=(--cacert "${DAST_CA}")
    fi
}

api_auth() {
    local use_ci
    use_ci="$(jq_bool useCiToken false)"
    if [[ "$use_ci" == "true" && -n "${DAST_CI_TOKEN:-}" ]]; then
        printf 'Authorization: Bearer %s' "$DAST_CI_TOKEN" >"$TOKEN_FILE"
        return 0
    fi

    if [[ -z "${DAST_USER:-}" || -z "${DAST_PASS:-}" ]]; then
        die "platform auth requires DAST_CI_TOKEN or DAST_USER/DAST_PASS"
    fi

    jq -n --arg login "$DAST_USER" --arg password "$DAST_PASS" \
        '{login: $login, password: $password}' >"${WORK}/login.json"

    local code
    code="$(curl "${CURL_OPTS[@]}" -o "${WORK}/login_resp.json" -w '%{http_code}' \
        -X POST "${API_URL}/api/v1/auth/login" \
        -H 'Content-Type: application/json' \
        --data @"${WORK}/login.json")"
    rm -f "${WORK}/login.json"

    if [[ "$code" != "200" ]]; then
        die "login failed (HTTP ${code}). Check apiUrl and credentials."
    fi

    local token
    token="$(jq -r '.token // empty' "${WORK}/login_resp.json")"
    rm -f "${WORK}/login_resp.json"
    if [[ -z "$token" ]]; then
        die "login response did not contain a token"
    fi
    printf 'Authorization: Bearer %s' "$token" >"$TOKEN_FILE"
}

api_create_scan() {
    local body="${WORK}/create.json"
    local target insecure auth_url verify_url start_points
    target="$(jq_val target)"
    insecure="$(jq_bool insecureSkipVerify false)"

    jq -n \
        --arg targetUrl "$target" \
        --argjson insecureSkipVerify "$([[ "$insecure" == "true" ]] && echo true || echo false)" \
        '{targetUrl: $targetUrl, insecureSkipVerify: $insecureSkipVerify}' >"$body"

    auth_url="$(jq_val authUrl)"
    verify_url="$(jq_val verifyUrl)"
    if [[ -n "$auth_url" ]]; then
        jq --arg v "$auth_url" '. + {authUrl: $v}' "$body" >"${body}.tmp" && mv "${body}.tmp" "$body"
    fi
    if [[ -n "$verify_url" ]]; then
        jq --arg v "$verify_url" '. + {verifyUrl: $v}' "$body" >"${body}.tmp" && mv "${body}.tmp" "$body"
    fi

    if [[ -n "${APP_USER:-}" && -n "${APP_PASS:-}" ]]; then
        jq --arg login "$APP_USER" --arg password "$APP_PASS" \
            '. + {login: $login, password: $password}' "$body" >"${body}.tmp" && mv "${body}.tmp" "$body"
    fi

    local kd km zs zp
    kd="$(jq -r '.katanaDepth // empty' "$CONFIG")"
    km="$(jq -r '.katanaMaxUrls // empty' "$CONFIG")"
    zs="$(jq -r '.zapSpiderMinutes // empty' "$CONFIG")"
    zp="$(jq -r '.zapPassiveSecs // empty' "$CONFIG")"
    [[ -n "$kd" && "$kd" != "null" ]] && jq --argjson v "$kd" '. + {katanaDepth: $v}' "$body" >"${body}.tmp" && mv "${body}.tmp" "$body"
    [[ -n "$km" && "$km" != "null" ]] && jq --argjson v "$km" '. + {katanaMaxUrls: $v}' "$body" >"${body}.tmp" && mv "${body}.tmp" "$body"
    [[ -n "$zs" && "$zs" != "null" ]] && jq --argjson v "$zs" '. + {zapSpiderMinutes: $v}' "$body" >"${body}.tmp" && mv "${body}.tmp" "$body"
    [[ -n "$zp" && "$zp" != "null" ]] && jq --argjson v "$zp" '. + {zapPassiveSecs: $v}' "$body" >"${body}.tmp" && mv "${body}.tmp" "$body"

    start_points="$(jq -r '.startPoints // empty | if type == "array" then join("\n") else . end' "$CONFIG" 2>/dev/null || true)"
    if [[ -n "$start_points" && "$start_points" != "null" ]]; then
        jq --arg sp "$start_points" '. + {startPoints: $sp}' "$body" >"${body}.tmp" && mv "${body}.tmp" "$body"
    fi

    local code
    code="$(curl "${CURL_OPTS[@]}" -o "${WORK}/create_resp.json" -w '%{http_code}' \
        -X POST "${API_URL}/api/v1/scans" \
        -H 'Content-Type: application/json' \
        -H @"${TOKEN_FILE}" \
        --data @"${body}")"
    rm -f "$body"

    if [[ "$code" != "201" && "$code" != "200" ]]; then
        local detail
        detail="$(cat "${WORK}/create_resp.json" 2>/dev/null || echo '(no response body)')"
        die "create scan failed (HTTP ${code}): ${detail}"
    fi

    local job_id
    job_id="$(jq -r '.jobId // .id // empty' "${WORK}/create_resp.json")"
    rm -f "${WORK}/create_resp.json"
    if [[ -z "$job_id" ]]; then
        die "create scan response did not contain a jobId"
    fi
    echo "$job_id"
}

api_post_ci_metadata() {
    local job_id="$1"
    local use_ci
    use_ci="$(jq_bool useCiToken false)"
    if [[ "$use_ci" != "true" ]]; then
        return 0
    fi

    local body="${WORK}/ci-meta.json"
    jq -n \
        --arg buildUrl "${BUILD_URL:-}" \
        --arg jobName "${JOB_NAME:-}" \
        --arg buildNumber "${BUILD_NUMBER:-}" \
        '{
            buildUrl: (if $buildUrl == "" then empty else $buildUrl end),
            jobName: (if $jobName == "" then empty else $jobName end),
            buildNumber: (if $buildNumber == "" then empty else $buildNumber end)
        } | with_entries(select(.value != null))' >"$body"

    if [[ "$(jq 'length' "$body")" -eq 0 ]]; then
        rm -f "$body"
        return 0
    fi

    curl "${CURL_OPTS[@]}" -o /dev/null \
        -X POST "${API_URL}/api/v1/scans/${job_id}/ci-metadata" \
        -H 'Content-Type: application/json' \
        -H @"${TOKEN_FILE}" \
        --data @"${body}" || true
    rm -f "$body"
}

api_get_status() {
    local job_id="$1"
    local code
    code="$(curl "${CURL_OPTS[@]}" -o "${WORK}/status.json" -w '%{http_code}' \
        -H @"${TOKEN_FILE}" \
        "${API_URL}/api/v1/scans/${job_id}/status")"
    if [[ "$code" != "200" ]]; then
        die "status check failed (HTTP ${code})"
    fi
}

api_get_scan() {
    local job_id="$1"
    local code
    code="$(curl "${CURL_OPTS[@]}" -o "${WORK}/scan.json" -w '%{http_code}' \
        -H @"${TOKEN_FILE}" \
        "${API_URL}/api/v1/scans/${job_id}")"
    if [[ "$code" != "200" ]]; then
        die "fetching scan result failed (HTTP ${code})"
    fi
}

api_cancel() {
    local job_id="$1"
    curl "${CURL_OPTS[@]}" -o /dev/null \
        -X POST "${API_URL}/api/v1/scans/${job_id}/cancel" \
        -H @"${TOKEN_FILE}" || true
}

poll_until_done() {
    local job_id="$1"
    local timeout_min poll_sec max_iters i status progress
    timeout_min="$(jq_val timeoutMinutes 60)"
    poll_sec="$(jq_val pollSeconds 15)"
    max_iters=$(( (timeout_min * 60) / poll_sec ))
    [[ "$max_iters" -lt 1 ]] && max_iters=1

    local terminal=("SUCCEEDED" "FAILED" "CANCELLED" "CANCELED" "PARTIAL_SUCCESS")

    for ((i = 1; i <= max_iters; i++)); do
        api_get_status "$job_id"
        status="$(jq -r '.status // empty' "${WORK}/status.json")"
        progress="$(jq -r '.progress // 0' "${WORK}/status.json")"
        log "${job_id} status=${status} progress=${progress}% (poll ${i}/${max_iters})"

        local done=false
        local t
        for t in "${terminal[@]}"; do
            if [[ "$status" == "$t" ]]; then
                done=true
                break
            fi
        done
        if [[ "$done" == "true" ]]; then
            return 0
        fi
        sleep "$poll_sec"
    done

    log "timeout reached after ${timeout_min} min; cancelling scan ${job_id}"
    api_cancel "$job_id"
    die "scan ${job_id} did not finish within ${timeout_min} minutes"
}

download_reports() {
    local job_id="$1"
    local archive
    archive="$(jq_bool archiveReports true)"
    if [[ "$archive" != "true" ]]; then
        return 0
    fi

    local fmt ext out code
    while IFS= read -r fmt; do
        [[ -z "$fmt" ]] && continue
        case "$fmt" in
            endpoints|discovered-urls) ext="txt" ;;
            *) ext="$fmt" ;;
        esac
        out="${WORK}/dast-report-${job_id}.${ext}"
        code="$(curl "${CURL_OPTS[@]}" -o "$out" -w '%{http_code}' \
            -H @"${TOKEN_FILE}" \
            "${API_URL}/api/v1/scans/${job_id}/reports?format=${fmt}")"
        if [[ "$code" != "200" ]]; then
            log "report '${fmt}' not available (HTTP ${code})"
            rm -f "$out"
        fi
    done < <(jq -r '.reportFormats[]? // empty' "$CONFIG")
}

write_findings_file() {
    local job_id="$1"
    local out="${WORK}/dast-findings-${job_id}.json"
    jq '.findings // []' "${WORK}/scan.json" >"$out"
}

write_result_json() {
    local job_id="$1"
    local findings_file="${WORK}/dast-findings-${job_id}.json"
    local status
    status="$(jq -r '.status // empty' "${WORK}/status.json")"
    jq -n \
        --arg jobId "$job_id" \
        --arg status "$status" \
        --arg findingsFile "$findings_file" \
        '{jobId: $jobId, status: $status, findingsFile: $findingsFile}' >"${WORK}/result.json"
}

main() {
    require_config
    API_URL="$(jq_val apiUrl)"
    API_URL="${API_URL%/}"

    build_curl_opts
    api_auth

    local job_id target_name ui_url
    job_id="$(api_create_scan)"
    target_name="$(jq_val targetName)"
    ui_url="$(jq_val uiUrl)"
    local label="${target_name:-$(jq_val target)}"
    log "scan queued: jobId=${job_id} target=${label}"
    if [[ -n "$ui_url" ]]; then
        log "follow progress: ${ui_url}/scans/${job_id}"
    fi

    api_post_ci_metadata "$job_id"
    poll_until_done "$job_id"
    api_get_scan "$job_id"
    write_findings_file "$job_id"
    download_reports "$job_id"
    write_result_json "$job_id"

    rm -f "$TOKEN_FILE"
    log "runner finished: jobId=${job_id}"
}

main "$@"
