import com.appsec.dast.QualityGate

/**
 * dastScan runs a DAST scan against the AppSec-DAST platform from a Jenkins /
 * GitLab (Jenkins-compatible) pipeline via a minimal Docker runner image.
 *
 * See vars/dastScan.txt for the full parameter reference.
 */
def call(Map args = [:]) {
    Map cfg = normalizeConfig(args)
    applyAppCredentialsEnv(cfg)
    String work = '.dast'
    sh "rm -rf '${work}' && mkdir -p '${work}'"
    writeJSON file: "${work}/config.json", json: buildRunnerConfig(cfg)

    Map result = null
    withCredentials(buildBindings(cfg)) {
        ensureRunnerImage(cfg)
        runViaDocker(cfg, work)
        Map scan = readJSON file: "${work}/scan.json"
        Map finalStatus = readJSON file: "${work}/status.json"
        String jobId = (scan.jobId ?: scan.id ?: readJSON(file: "${work}/result.json").jobId)?.toString()
        if (!jobId) {
            error '[DAST] runner did not produce a jobId'
        }
        result = applyGate(scan, finalStatus, cfg, jobId)
        attachReportPaths(result, work)
        archiveArtifacts artifacts: "${work}/dast-*", allowEmptyArchive: true
    }
    return result
}

private void runViaDocker(Map cfg, String work) {
    String suffix = sh(returnStdout: true, script: 'date +%s').trim()
    String containerName = "dast-runner-${env.BUILD_NUMBER ?: '0'}-${suffix}"
    String envArgs = buildDockerEnvArgs(cfg)
    String caMount = ''
    if (cfg.caCertId) {
        caMount = '-v "${DAST_CA}:${DAST_CA}:ro" -e DAST_CA="${DAST_CA}"'
    }
    try {
        sh """
            docker run --rm --name '${containerName}' \\
                -v '${pwd()}/${work}:/work' \\
                ${caMount} \\
                ${envArgs} \\
                '${cfg.runnerImage}'
        """
    } finally {
        // Safety net: remove container if --rm did not run (aborted build, SIGKILL, etc.)
        sh(returnStatus: true, script: "docker rm -f '${containerName}' >/dev/null 2>&1 || true")
    }
}

private String buildDockerEnvArgs(Map cfg) {
    List args = ['-e BUILD_URL', '-e JOB_NAME', '-e BUILD_NUMBER']
    if (hasPlatformToken(cfg)) {
        args.add('-e DAST_CI_TOKEN')
    } else if (cfg.apiCredentialsId) {
        args.add('-e DAST_USER')
        args.add('-e DAST_PASS')
    }
    if (hasAppCredentials(cfg)) {
        args.add('-e APP_USER')
        args.add('-e APP_PASS')
    }
    return args.join(' \\\n            ')
}

private void ensureRunnerImage(Map cfg) {
    if (cfg.registryCredentialsId) {
        String registry = cfg.registryUrl ?: registryHostFromImage(cfg.runnerImage)
        if (!registry?.trim()) {
            error 'dastScan: registryUrl required when registryCredentialsId is set and cannot be inferred from runnerImage'
        }
        withCredentials([usernamePassword(
            credentialsId: cfg.registryCredentialsId,
            usernameVariable: 'REGISTRY_USER',
            passwordVariable: 'REGISTRY_PASS',
        )]) {
            int loginRc = sh(returnStatus: true, script: """
                set +x
                echo "\${REGISTRY_PASS}" | docker login --username "\${REGISTRY_USER}" --password-stdin '${registry}'
                set -x
            """)
            if (loginRc != 0) {
                error "[DAST] docker login failed for registry ${registry}"
            }
            try {
                pullRunnerImage(cfg.runnerImage)
            } finally {
                sh(returnStatus: true, script: "docker logout '${registry}' || true")
            }
        }
    } else {
        pullRunnerImage(cfg.runnerImage)
    }
}

private void pullRunnerImage(String image) {
    int rc = sh(returnStatus: true, script: "docker inspect '${image}' > /dev/null 2>&1")
    if (rc == 0) {
        echo "[DAST] runner image ${image} found on agent"
    } else {
        echo "[DAST] pulling runner image ${image}"
        sh "docker pull -q '${image}'"
    }
}

private String registryHostFromImage(String image) {
    String name = image
    int colon = name.lastIndexOf(':')
    if (colon > 0 && !name.substring(colon - 1).contains('/')) {
        name = name.substring(0, colon)
    }
    int slash = name.indexOf('/')
    if (slash < 0) {
        return ''
    }
    String first = name.substring(0, slash)
    if (first.contains('.') || first.contains(':') || first == 'localhost') {
        return first
    }
    return ''
}

private Map buildRunnerConfig(Map cfg) {
    Map json = [
        apiUrl            : cfg.apiUrl,
        target            : cfg.target,
        insecureSkipVerify: cfg.insecureSkipVerify,
        apiInsecure       : cfg.apiInsecure,
        timeoutMinutes    : cfg.timeoutMinutes,
        pollSeconds       : cfg.pollSeconds,
        reportFormats     : cfg.reportFormats,
        archiveReports    : cfg.archiveReports,
        useCiToken        : hasPlatformToken(cfg),
    ]
    if (cfg.targetName) {
        json.targetName = cfg.targetName
    }
    if (cfg.uiUrl) {
        json.uiUrl = cfg.uiUrl
    }
    if (cfg.authUrl) {
        json.authUrl = cfg.authUrl
    }
    if (cfg.verifyUrl) {
        json.verifyUrl = cfg.verifyUrl
    }
    if (cfg.katanaDepth != null) {
        json.katanaDepth = cfg.katanaDepth
    }
    if (cfg.katanaMaxUrls != null) {
        json.katanaMaxUrls = cfg.katanaMaxUrls
    }
    if (cfg.zapSpiderMinutes != null) {
        json.zapSpiderMinutes = cfg.zapSpiderMinutes
    }
    if (cfg.zapPassiveSecs != null) {
        json.zapPassiveSecs = cfg.zapPassiveSecs
    }
    if (cfg.startPoints) {
        json.startPoints = cfg.startPoints
    }
    return json
}

private boolean hasPlatformToken(Map cfg) {
    return cfg.apiTokenCredentialId || cfg.apiToken
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

private Map normalizeConfig(Map a) {
    applyLegacySferaAliases(a)
    applyFriendlyAliases(a)
    requireArg(a, 'runnerImage')
    requireArg(a, 'apiUrl')
    requireArg(a, 'target')
    if (!a.apiTokenCredentialId && !a.apiToken && !a.apiCredentialsId) {
        error "dastScan: provide apiTokenCredentialId (CI key dast_<uuid> from UI) or apiCredentialsId"
    }

    Map c = [:]
    c.runnerImage = a.runnerImage.toString().trim()
    c.registryCredentialsId = a.registryCredentialsId
    c.registryUrl = a.registryUrl ? a.registryUrl.toString().trim() : null
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
private void applyFriendlyAliases(Map a) {
    alias(a, 'runnerImage', 'DAST_RUNNER_IMAGE')
    alias(a, 'target', 'targetUrl')
    alias(a, 'apiTokenCredentialId', 'ciTokenCredentialId')
    alias(a, 'apiTokenCredentialId', 'ciTokenId')
    alias(a, 'apiToken', 'ciToken')
    alias(a, 'login', 'appLogin')
    alias(a, 'password', 'appPassword')
    if (!a.startPoints && a.startPoint) {
        a.startPoints = [a.startPoint.toString().trim()]
    }
}

/** Maps legacy Sfera SL parameter names (global_appsec_check_dast_zap_*) to dastScan keys. */
private void applyLegacySferaAliases(Map a) {
    alias(a, 'runnerImage', 'DAST_RUNNER_IMAGE')
    alias(a, 'apiUrl', 'DAST_API_URL')
    alias(a, 'target', 'DAST_TARGET_URL_TO_SCAN')
    alias(a, 'authUrl', 'DAST_TARGET_AUTH_URL')
    alias(a, 'verifyUrl', 'DAST_TARGET_MARKER_URL')
    alias(a, 'login', 'DAST_WEB_USR')
    alias(a, 'password', 'DAST_WEB_PSW')
    alias(a, 'startPoints', 'DAST_START_POINTS')
    if (!a.apiTokenCredentialId && !a.apiCredentialsId && !a.apiToken) {
        if (a.DAST_CI_TOKEN_CRED) {
            a.apiTokenCredentialId = a.DAST_CI_TOKEN_CRED
        } else if (a.DAST_AUTH_TOKEN) {
            String t = a.DAST_AUTH_TOKEN.toString().trim()
            if (t.startsWith('dast_')) {
                a.apiToken = t
            } else {
                a.apiTokenCredentialId = t
            }
        }
    }
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

// ---------------------------------------------------------------------------
// Quality gate
// ---------------------------------------------------------------------------

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
