import com.appsec.dast.QualityGate

/**
 * dastScan runs a DAST scan against the AppSec-DAST platform from a Jenkins /
 * GitLab (Jenkins-compatible) pipeline: CI token auth, create scan, poll, DOCX
 * artifact, quality gate. Requires curl on the agent (no Docker runner image).
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
        result = runOnAgent(cfg, work)
        attachReportPaths(result, work)
        archiveArtifacts artifacts: "${work}/dast-*", allowEmptyArchive: true
    }
    return result
}

private Map runOnAgent(Map cfg, String work) {
    String curlOpts = buildCurlOpts(cfg)
    String tokenFile = "${work}/auth.headers"
    try {
        apiAuth(cfg.apiUrl, curlOpts, work, tokenFile, cfg)
        String jobId = apiCreateScan(cfg.apiUrl, curlOpts, work, tokenFile, cfg)
        echoScanQueued(cfg, jobId)
        apiPostCIMetadata(cfg.apiUrl, curlOpts, tokenFile, work, jobId, cfg)
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

private boolean hasPlatformToken(Map cfg) {
    return cfg.apiTokenCredentialId || cfg.apiToken
}

private void echoScanQueued(Map cfg, String jobId) {
    String label = cfg.targetName ?: cfg.target
    echo "[DAST] scan queued: jobId=${jobId} target=${label}"
    if (cfg.uiUrl) {
        echo "[DAST] follow progress: ${cfg.uiUrl}/scans/${jobId}"
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

private Map normalizeConfig(Map a) {
    a = applyLegacySferaAliases(a)
    a = applyFriendlyAliases(a)
    requireArg(a, 'apiUrl')
    requireArg(a, 'target')
    if (!a.apiTokenCredentialId && !a.apiToken && !a.apiCredentialsId) {
        error "dastScan: provide apiTokenCredentialId (CI key dast_<uuid> from UI) or apiCredentialsId"
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
        error "dastScan: apiToken is for tests only; use apiTokenCredentialId in pipelines"
    }

    c.target = a.target.toString().trim()
    c.targetName = a.targetName ? a.targetName.toString().trim() : null
    c.appAuthCredentialsId = a.appAuthCredentialsId
    c.appLogin = a.appLogin ?: a.login
    c.appPassword = a.appPassword ?: a.password
    c.authUrl = a.authUrl ? a.authUrl.toString().trim() : null
    c.verifyUrl = a.verifyUrl ? a.verifyUrl.toString().trim() : null

    if (c.appLogin && !c.appPassword) {
        error "dastScan: password is required when login is set"
    }
    if (c.appPassword && !c.appLogin) {
        error "dastScan: login is required when password is set"
    }
    if (c.appAuthCredentialsId && (c.appLogin || c.appPassword)) {
        error "dastScan: use either appAuthCredentialsId or login/password, not both"
    }

    c.insecureSkipVerify = asBool(a.insecureSkipVerify, false)
    c.apiInsecure = asBool(a.apiInsecure, false)
    c.caCertId = a.caCertId

    c.katanaDepth = a.katanaDepth
    c.katanaMaxUrls = a.katanaMaxUrls
    c.zapSpiderMinutes = a.zapSpiderMinutes
    c.zapPassiveSecs = a.zapPassiveSecs
    c.startPoints = normalizeStartPoints(a)

    c.failOn = a.failOn
    c.maxCritical = a.maxCritical
    c.maxHigh = a.maxHigh
    c.maxMedium = a.maxMedium
    c.maxLow = a.maxLow
    c.failOnScanError = asBool(a.failOnScanError, true)

    c.timeoutMinutes = (a.timeoutMinutes ?: 60) as int
    c.pollSeconds = (a.pollSeconds ?: 15) as int
    c.reportFormats = (a.reportFormats ?: ['docx']) as List
    c.archiveReports = asBool(a.archiveReports, true)
    return c
}

/** Friendly names used in GitLab / new pipelines. */
private Map applyFriendlyAliases(Map a) {
    Map m = new LinkedHashMap(a)
    alias(m, 'target', 'targetUrl')
    alias(m, 'apiTokenCredentialId', 'ciTokenCredentialId')
    alias(m, 'apiTokenCredentialId', 'ciTokenId')
    alias(m, 'apiToken', 'ciToken')
    alias(m, 'login', 'appLogin')
    alias(m, 'password', 'appPassword')
    if (!m.startPoints && m.startPoint) {
        m.startPoints = [m.startPoint.toString().trim()]
    }
    return m
}

/** Maps legacy Sfera SL parameter names (global_appsec_check_dast_zap_*) to dastScan keys. */
private Map applyLegacySferaAliases(Map a) {
    Map m = new LinkedHashMap(a)
    alias(m, 'apiUrl', 'DAST_API_URL')
    alias(m, 'target', 'DAST_TARGET_URL_TO_SCAN')
    alias(m, 'authUrl', 'DAST_TARGET_AUTH_URL')
    alias(m, 'verifyUrl', 'DAST_TARGET_MARKER_URL')
    alias(m, 'login', 'DAST_WEB_USR')
    alias(m, 'password', 'DAST_WEB_PSW')
    alias(m, 'startPoints', 'DAST_START_POINTS')
    if (!m.apiTokenCredentialId && !m.apiCredentialsId && !m.apiToken) {
        if (m.DAST_CI_TOKEN_CRED) {
            m.apiTokenCredentialId = m.DAST_CI_TOKEN_CRED
        } else if (m.DAST_AUTH_TOKEN) {
            String t = m.DAST_AUTH_TOKEN.toString().trim()
            if (t.startsWith('dast_')) {
                m.apiToken = t
            } else {
                m.apiTokenCredentialId = t
            }
        }
    }
    return m
}

private List normalizeStartPoints(Map a) {
    if (a.startPoints instanceof List) {
        return (a.startPoints as List).collect { it?.toString()?.trim() }.findAll { it }
    }
    if (a.startPoints instanceof String && a.startPoints.trim()) {
        return a.startPoints.split(/\r?\n/).collect { it.trim() }.findAll { it }
    }
    if (a.DAST_START_POINTS instanceof String && a.DAST_START_POINTS.trim()) {
        return a.DAST_START_POINTS.split(/\r?\n/).collect { it.trim() }.findAll { it }
    }
    return []
}

private void alias(Map m, String canonical, String legacy) {
    if ((!m.containsKey(canonical) || m[canonical] == null || m[canonical].toString().trim().isEmpty())
            && m.containsKey(legacy) && m[legacy] != null && m[legacy].toString().trim()) {
        m[canonical] = m[legacy]
    }
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
        opts.add('--cacert "$DAST_CA"')
    }
    return opts.join(' ')
}

// ---------------------------------------------------------------------------
// API calls
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

private void apiPostCIMetadata(String base, String curlOpts, String tokenFile, String work, String jobId, Map cfg) {
    if (!hasPlatformToken(cfg)) {
        return
    }
    Map body = [:]
    if (env.BUILD_URL?.trim()) {
        body.buildUrl = env.BUILD_URL.trim()
    }
    if (env.JOB_NAME?.trim()) {
        body.jobName = env.JOB_NAME.trim()
    }
    if (env.BUILD_NUMBER?.trim()) {
        body.buildNumber = env.BUILD_NUMBER.trim()
    }
    if (body.isEmpty()) {
        return
    }
    writeJSON file: "${work}/ci-meta.json", json: body
    sh(returnStatus: true, script: """
        curl ${curlOpts} -o /dev/null \
            -X POST '${base}/api/v1/scans/${jobId}/ci-metadata' \
            -H 'Content-Type: application/json' \
            -H @'${tokenFile}' \
            --data @'${work}/ci-meta.json'
    """)
    sh "rm -f '${work}/ci-meta.json'"
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

private void attachReportPaths(Map result, String work) {
    if (!result?.jobId) {
        return
    }
    String jobId = result.jobId.toString()
    String docx = "${work}/dast-report-${jobId}.docx"
    if (fileExists(docx)) {
        result.reportDocx = docx
    }
    String findings = "${work}/dast-findings-${jobId}.json"
    if (fileExists(findings)) {
        result.findingsJson = findings
    }
}
