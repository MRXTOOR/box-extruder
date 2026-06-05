import com.appsec.dast.QualityGate

/**
 * dastScan runs a DAST scan against the AppSec-DAST platform from a Jenkins
 * pipeline: it authenticates, creates the scan, waits for completion, downloads
 * reports as build artifacts, and applies a severity-based quality gate.
 *
 * See vars/dastScan.txt for the full parameter reference.
 */
def call(Map args = [:]) {
    Map cfg = normalizeConfig(args)
    applyAppCredentialsEnv(cfg)
    String work = '.dast'
    sh "rm -rf '${work}' && mkdir -p '${work}'"

    Map result = null
    withCredentials(buildBindings(cfg)) {
        if (cfg.runnerImage) {
            result = runInDocker(cfg, work)
        } else {
            result = runOnAgent(cfg, work)
        }
        archiveArtifacts artifacts: "${work}/dast-*", allowEmptyArchive: true
    }
    return result
}

/** runOnAgent executes the scan with curl on the Jenkins agent (legacy). */
private Map runOnAgent(Map cfg, String work) {
    String curlOpts = buildCurlOpts(cfg)
    String tokenFile = "${work}/auth.headers"
    try {
        apiAuth(cfg.apiUrl, curlOpts, work, tokenFile, cfg)
        String jobId = apiCreateScan(cfg.apiUrl, curlOpts, work, tokenFile, cfg)
        echoScanQueued(cfg, jobId)
        Map finalStatus = pollUntilDone(cfg.apiUrl, curlOpts, tokenFile, work, jobId, cfg)
        Map scan = apiGetScan(cfg.apiUrl, curlOpts, tokenFile, work, jobId)
        writeJSON file: "${work}/dast-findings-${jobId}.json", json: (scan.findings ?: [])
        if (cfg.archiveReports) {
            downloadReports(cfg.apiUrl, curlOpts, tokenFile, work, jobId, cfg)
        }
        return applyGate(scan, finalStatus, cfg, jobId)
    } finally {
        sh "rm -f '${tokenFile}' '${work}'/*.json || true"
    }
}

/**
 * runInDocker runs /opt/dast/dast-scan.sh inside the CI runner image.
 * Requires the Docker Pipeline plugin on Jenkins.
 */
private Map runInDocker(Map cfg, String work) {
    String absWork = sh(returnStdout: true, script: "cd '${work}' && pwd").trim()
    List dockerEnv = dockerEnvFlags(cfg)
    String caMount = ''
    if (cfg.caCertId && env.DAST_CA) {
        caMount = "-v '${env.DAST_CA}:/ca.pem:ro' -e DAST_CA=/ca.pem"
    }

    docker.image(cfg.runnerImage).inside(
        "-u 0:0 -v '${absWork}:/work' -w /work ${caMount} ${dockerEnv.join(' ')}"
    ) {
        sh '/opt/dast/dast-scan.sh'
    }
    if (!fileExists("${work}/dast-result.json")) {
        error '[DAST] docker scan did not produce dast-result.json'
    }
    Map result = readJSON(file: "${work}/dast-result.json")
    if (!result.passed) {
        error "[DAST] quality gate failed for scan ${result.jobId}"
    }
    echo "[DAST] quality gate passed for scan ${result.jobId}"
    return result
}

private boolean hasPlatformToken(Map cfg) {
    return cfg.apiTokenCredentialId || cfg.apiToken
}

private List dockerEnvFlags(Map cfg) {
    List flags = [
        "-e DAST_API_URL='${cfg.apiUrl}'",
        "-e DAST_TARGET='${cfg.target}'",
        "-e DAST_WORK_DIR=/work",
    ]
    if (hasPlatformToken(cfg)) {
        flags.add('-e DAST_CI_TOKEN')
    } else {
        flags.add('-e DAST_USER', '-e DAST_PASS')
    }
    flags.addAll([
        "-e DAST_POLL_SECONDS=${cfg.pollSeconds}",
        "-e DAST_TIMEOUT_MINUTES=${cfg.timeoutMinutes}",
        "-e DAST_FAIL_ON_SCAN_ERROR=${cfg.failOnScanError}",
        "-e DAST_INSECURE_SKIP_VERIFY=${cfg.insecureSkipVerify}",
        "-e DAST_API_INSECURE=${cfg.apiInsecure}",
        "-e DAST_ARCHIVE_REPORTS=${cfg.archiveReports}",
        "-e DAST_REPORT_FORMATS='${cfg.reportFormats.join(',')}'",
    ])
    if (cfg.uiUrl) {
        flags.add("-e DAST_UI_URL='${cfg.uiUrl}'")
    }
    if (cfg.authUrl) {
        flags.add("-e DAST_AUTH_URL='${cfg.authUrl}'")
    }
    if (cfg.verifyUrl) {
        flags.add("-e DAST_VERIFY_URL='${cfg.verifyUrl}'")
    }
    if (hasAppCredentials(cfg)) {
        flags.add('-e APP_USER', '-e APP_PASS')
    }
    if (cfg.katanaDepth != null) {
        flags.add("-e DAST_KATANA_DEPTH=${cfg.katanaDepth}")
    }
    if (cfg.katanaMaxUrls != null) {
        flags.add("-e DAST_KATANA_MAX_URLS=${cfg.katanaMaxUrls}")
    }
    if (cfg.zapSpiderMinutes != null) {
        flags.add("-e DAST_ZAP_SPIDER_MINUTES=${cfg.zapSpiderMinutes}")
    }
    if (cfg.zapPassiveSecs != null) {
        flags.add("-e DAST_ZAP_PASSIVE_SECS=${cfg.zapPassiveSecs}")
    }
    if (cfg.startPoints) {
        flags.add("-e DAST_START_POINTS='${cfg.startPoints.join('\\n')}'")
    }
    if (cfg.failOn) {
        flags.add("-e DAST_FAIL_ON='${cfg.failOn}'")
    }
    if (cfg.maxCritical != null) {
        flags.add("-e DAST_MAX_CRITICAL=${cfg.maxCritical}")
    }
    if (cfg.maxHigh != null) {
        flags.add("-e DAST_MAX_HIGH=${cfg.maxHigh}")
    }
    if (cfg.maxMedium != null) {
        flags.add("-e DAST_MAX_MEDIUM=${cfg.maxMedium}")
    }
    if (cfg.maxLow != null) {
        flags.add("-e DAST_MAX_LOW=${cfg.maxLow}")
    }
    return flags
}

private void echoScanQueued(Map cfg, String jobId) {
    echo "[DAST] scan queued: jobId=${jobId} target=${cfg.target}"
    if (cfg.uiUrl) {
        echo "[DAST] follow progress: ${cfg.uiUrl}/scans/${jobId}"
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

private Map normalizeConfig(Map a) {
    requireArg(a, 'apiUrl')
    requireArg(a, 'target')
    if (!a.apiTokenCredentialId && !a.apiToken && !a.apiCredentialsId) {
        error "dastScan: provide apiTokenCredentialId (CI UUID) or apiCredentialsId (login/password)"
    }

    Map c = [:]
    c.apiUrl = a.apiUrl.toString().replaceAll('/+$', '')
    c.uiUrl = a.uiUrl ? a.uiUrl.toString().replaceAll('/+$', '') : null
    c.apiCredentialsId = a.apiCredentialsId
    c.apiTokenCredentialId = a.apiTokenCredentialId
    c.apiToken = a.apiToken
    if (c.apiTokenCredentialId && c.apiCredentialsId) {
        error "dastScan: use either apiTokenCredentialId or apiCredentialsId, not both"
    }
    if (c.apiToken && (c.apiTokenCredentialId || c.apiCredentialsId)) {
        error "dastScan: apiToken is for tests only; use apiTokenCredentialId or apiCredentialsId in pipelines"
    }

    c.target = a.target
    c.appAuthCredentialsId = a.appAuthCredentialsId
    c.appLogin = a.appLogin ?: a.login
    c.appPassword = a.appPassword ?: a.password
    c.authUrl = a.authUrl
    c.verifyUrl = a.verifyUrl

    if (c.appLogin && !c.appPassword) {
        error "dastScan: appPassword (or password) is required when appLogin (or login) is set"
    }
    if (c.appPassword && !c.appLogin) {
        error "dastScan: appLogin (or login) is required when appPassword (or password) is set"
    }
    if (c.appAuthCredentialsId && (c.appLogin || c.appPassword)) {
        error "dastScan: use either appAuthCredentialsId or appLogin/appPassword, not both"
    }

    // TLS handling.
    c.insecureSkipVerify = asBool(a.insecureSkipVerify, false) // skip cert checks on the TARGET app
    c.apiInsecure = asBool(a.apiInsecure, false)               // skip cert checks on the DAST API itself
    c.caCertId = a.caCertId                                    // Jenkins "Secret file" credential: CA bundle for the API

    // Scan tuning (all optional, server defaults apply when null).
    c.katanaDepth = a.katanaDepth
    c.katanaMaxUrls = a.katanaMaxUrls
    c.zapSpiderMinutes = a.zapSpiderMinutes
    c.zapPassiveSecs = a.zapPassiveSecs
    c.startPoints = (a.startPoints ?: []) as List

    // Quality gate.
    c.failOn = a.failOn
    c.maxCritical = a.maxCritical
    c.maxHigh = a.maxHigh
    c.maxMedium = a.maxMedium
    c.maxLow = a.maxLow
    c.failOnScanError = asBool(a.failOnScanError, true)

    // Execution.
    c.timeoutMinutes = (a.timeoutMinutes ?: 60) as int
    c.pollSeconds = (a.pollSeconds ?: 15) as int
    c.reportFormats = (a.reportFormats ?: ['docx', 'html', 'pdf']) as List
    c.archiveReports = asBool(a.archiveReports, true)

    // Docker CI runner (default). Pass runnerImage: false to use curl on the agent.
    if (a.runnerImage == false || a.useDocker == false) {
        c.runnerImage = null
    } else {
        c.runnerImage = (a.runnerImage ?: 'appsec-dast/ci-runner:latest').toString()
    }
    return c
}

private void requireArg(Map a, String key) {
    if (!a.containsKey(key) || a[key] == null || a[key].toString().trim().isEmpty()) {
        error "dastScan: required parameter '${key}' is missing"
    }
}

private boolean asBool(Object v, boolean dflt) {
    if (v == null) {
        return dflt
    }
    return v.toString().trim().toLowerCase() in ['true', '1', 'yes', 'on']
}

private boolean hasAppCredentials(Map cfg) {
    return cfg.appAuthCredentialsId || cfg.appLogin
}

private void applyAppCredentialsEnv(Map cfg) {
    if (cfg.appLogin) {
        env.APP_USER = cfg.appLogin.toString()
        env.APP_PASS = cfg.appPassword.toString()
    }
}

private List buildBindings(Map cfg) {
    List b = []
    if (cfg.apiTokenCredentialId) {
        b.add(string(credentialsId: cfg.apiTokenCredentialId, variable: 'DAST_CI_TOKEN'))
    } else if (cfg.apiCredentialsId) {
        b.add(usernamePassword(credentialsId: cfg.apiCredentialsId, usernameVariable: 'DAST_USER', passwordVariable: 'DAST_PASS'))
    } else if (cfg.apiToken) {
        env.DAST_CI_TOKEN = cfg.apiToken.toString()
    }
    if (cfg.appAuthCredentialsId) {
        b.add(usernamePassword(credentialsId: cfg.appAuthCredentialsId, usernameVariable: 'APP_USER', passwordVariable: 'APP_PASS'))
    }
    if (cfg.caCertId) {
        b.add(file(credentialsId: cfg.caCertId, variable: 'DAST_CA'))
    }
    return b
}

private String buildCurlOpts(Map cfg) {
    List opts = ['-sS', '--connect-timeout', '15', '--max-time', '180']
    if (cfg.apiInsecure) {
        opts.add('-k')
    }
    if (cfg.caCertId) {
        // $DAST_CA is expanded by the shell inside the withCredentials block.
        opts.add('--cacert "$DAST_CA"')
    }
    return opts.join(' ')
}

// ---------------------------------------------------------------------------
// API calls (secrets are passed via files, never inlined into the sh script)
// ---------------------------------------------------------------------------

private void apiAuth(String base, String curlOpts, String work, String tokenFile, Map cfg) {
    if (hasPlatformToken(cfg) && env.DAST_CI_TOKEN) {
        writeFile file: tokenFile, text: "Authorization: Bearer ${env.DAST_CI_TOKEN}"
        return
    }
    writeJSON file: "${work}/login.json", json: [login: env.DAST_USER, password: env.DAST_PASS]
    String code = sh(returnStdout: true, script: """
        curl ${curlOpts} -o '${work}/login_resp.json' -w '%{http_code}' \
            -X POST '${base}/api/v1/auth/login' \
            -H 'Content-Type: application/json' \
            --data @'${work}/login.json'
    """).trim()
    sh "rm -f '${work}/login.json'"
    if (code != '200') {
        error "[DAST] login failed (HTTP ${code}). Check apiUrl and apiCredentialsId."
    }
    def resp = readJSON file: "${work}/login_resp.json"
    sh "rm -f '${work}/login_resp.json'"
    if (!resp.token) {
        error '[DAST] login response did not contain a token'
    }
    writeFile file: tokenFile, text: "Authorization: Bearer ${resp.token}"
}

private String apiCreateScan(String base, String curlOpts, String work, String tokenFile, Map cfg) {
    Map body = [targetUrl: cfg.target, insecureSkipVerify: cfg.insecureSkipVerify]
    if (cfg.authUrl) {
        body.authUrl = cfg.authUrl
    }
    if (cfg.verifyUrl) {
        body.verifyUrl = cfg.verifyUrl
    }
    if (hasAppCredentials(cfg)) {
        body.login = env.APP_USER
        body.password = env.APP_PASS
    }
    if (cfg.katanaDepth != null) {
        body.katanaDepth = cfg.katanaDepth as int
    }
    if (cfg.katanaMaxUrls != null) {
        body.katanaMaxUrls = cfg.katanaMaxUrls as int
    }
    if (cfg.zapSpiderMinutes != null) {
        body.zapSpiderMinutes = cfg.zapSpiderMinutes as int
    }
    if (cfg.zapPassiveSecs != null) {
        body.zapPassiveSecs = cfg.zapPassiveSecs as int
    }
    if (cfg.startPoints) {
        body.startPoints = cfg.startPoints.join('\n')
    }

    writeJSON file: "${work}/create.json", json: body
    String code = sh(returnStdout: true, script: """
        curl ${curlOpts} -o '${work}/create_resp.json' -w '%{http_code}' \
            -X POST '${base}/api/v1/scans' \
            -H 'Content-Type: application/json' \
            -H @'${tokenFile}' \
            --data @'${work}/create.json'
    """).trim()
    sh "rm -f '${work}/create.json'"
    if (code != '201' && code != '200') {
        String detail = readFileSafe("${work}/create_resp.json")
        error "[DAST] create scan failed (HTTP ${code}): ${detail}"
    }
    def resp = readJSON file: "${work}/create_resp.json"
    String jobId = resp.jobId ?: resp.id
    if (!jobId) {
        error '[DAST] create scan response did not contain a jobId'
    }
    return jobId
}

private Map apiGetStatus(String base, String curlOpts, String tokenFile, String work, String jobId) {
    String code = sh(returnStdout: true, script: """
        curl ${curlOpts} -o '${work}/status.json' -w '%{http_code}' \
            -H @'${tokenFile}' \
            '${base}/api/v1/scans/${jobId}/status'
    """).trim()
    if (code != '200') {
        error "[DAST] status check failed (HTTP ${code})"
    }
    return readJSON(file: "${work}/status.json")
}

private Map apiGetScan(String base, String curlOpts, String tokenFile, String work, String jobId) {
    String code = sh(returnStdout: true, script: """
        curl ${curlOpts} -o '${work}/scan.json' -w '%{http_code}' \
            -H @'${tokenFile}' \
            '${base}/api/v1/scans/${jobId}'
    """).trim()
    if (code != '200') {
        error "[DAST] fetching scan result failed (HTTP ${code})"
    }
    return readJSON(file: "${work}/scan.json")
}

private void apiCancel(String base, String curlOpts, String tokenFile, String work, String jobId) {
    sh(returnStatus: true, script: """
        curl ${curlOpts} -o /dev/null \
            -X POST '${base}/api/v1/scans/${jobId}/cancel' \
            -H @'${tokenFile}'
    """)
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

private Map pollUntilDone(String base, String curlOpts, String tokenFile, String work, String jobId, Map cfg) {
    List terminal = ['SUCCEEDED', 'FAILED', 'CANCELLED', 'CANCELED', 'PARTIAL_SUCCESS']
    int maxIters = ((cfg.timeoutMinutes * 60) / cfg.pollSeconds) as int
    if (maxIters < 1) {
        maxIters = 1
    }
    Map last = [:]
    for (int i = 0; i < maxIters; i++) {
        last = apiGetStatus(base, curlOpts, tokenFile, work, jobId)
        echo "[DAST] ${jobId} status=${last.status} progress=${last.progress ?: 0}% (poll ${i + 1}/${maxIters})"
        boolean done = false
        for (String t : terminal) {
            if (t == last.status) {
                done = true
            }
        }
        if (done) {
            return last
        }
        sleep(time: cfg.pollSeconds, unit: 'SECONDS')
    }
    echo "[DAST] timeout reached after ${cfg.timeoutMinutes} min; cancelling scan ${jobId}"
    apiCancel(base, curlOpts, tokenFile, work, jobId)
    error "[DAST] scan ${jobId} did not finish within ${cfg.timeoutMinutes} minutes"
}

private void downloadReports(String base, String curlOpts, String tokenFile, String work, String jobId, Map cfg) {
    for (String fmt : cfg.reportFormats) {
        String ext = (fmt == 'endpoints' || fmt == 'discovered-urls') ? 'txt' : fmt
        String out = "${work}/dast-report-${jobId}.${ext}"
        String code = sh(returnStdout: true, script: """
            curl ${curlOpts} -o '${out}' -w '%{http_code}' \
                -H @'${tokenFile}' \
                '${base}/api/v1/scans/${jobId}/reports?format=${fmt}'
        """).trim()
        if (code != '200') {
            echo "[DAST] report '${fmt}' not available (HTTP ${code})"
            sh "rm -f '${out}'"
        }
    }
}

private Map applyGate(Map scan, Map finalStatus, Map cfg, String jobId) {
    List findings = (scan.findings ?: []) as List
    Map counts = QualityGate.countBySeverity(findings)

    echo '[DAST] ----------------------------------------'
    echo "[DAST] Scan ${jobId} finished: ${finalStatus.status}"
    echo "[DAST] Findings: CRITICAL=${counts.CRITICAL} HIGH=${counts.HIGH} MEDIUM=${counts.MEDIUM} LOW=${counts.LOW} INFO=${counts.INFO}"
    echo '[DAST] ----------------------------------------'

    Map result = [
        jobId      : jobId,
        status     : finalStatus.status,
        counts     : counts,
        total      : findings.size(),
        passed     : true,
        violations : [],
    ]

    if (cfg.failOnScanError && (finalStatus.status == 'FAILED')) {
        result.passed = false
        result.violations = ['scan ended with status FAILED']
        error "[DAST] scan ${jobId} failed on the platform (status=FAILED)"
    }

    List violations = QualityGate.evaluate(counts, [
        failOn     : cfg.failOn,
        maxCritical: cfg.maxCritical,
        maxHigh    : cfg.maxHigh,
        maxMedium  : cfg.maxMedium,
        maxLow     : cfg.maxLow,
    ])
    result.violations = violations

    if (violations) {
        for (String v : violations) {
            echo "[DAST] GATE VIOLATION: ${v}"
        }
        result.passed = false
        error "[DAST] quality gate failed for scan ${jobId}"
    }

    echo "[DAST] quality gate passed for scan ${jobId}"
    return result
}

private String readFileSafe(String path) {
    try {
        return readFile(file: path).trim()
    } catch (ignored) {
        return '(no response body)'
    }
}
