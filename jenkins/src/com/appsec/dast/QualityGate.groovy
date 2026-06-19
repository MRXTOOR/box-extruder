package com.appsec.dast

class QualityGate implements Serializable {

    static final List<String> ORDER = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    static int rank(String severity) {
        if (severity == null) {
            return 0
        }
        int i = ORDER.indexOf(severity.trim().toUpperCase())
        return i < 0 ? 0 : i
    }

    static Map<String, Integer> countBySeverity(List findings) {
        Map<String, Integer> counts = [INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0]
        if (findings == null) {
            return counts
        }
        for (def f : findings) {
            String sev = (f?.severity ?: 'INFO').toString().trim().toUpperCase()
            if (counts.containsKey(sev)) {
                counts[sev] = counts[sev] + 1
            } else {
                counts['INFO'] = counts['INFO'] + 1
            }
        }
        return counts
    }


    static List<String> evaluate(Map<String, Integer> counts, Map thresholds) {
        List<String> violations = []
        if (thresholds == null) {
            return violations
        }

        String failOn = thresholds.failOn
        if (failOn) {
            int min = rank(failOn.toString())
            for (String sev : ORDER) {
                int c = counts[sev] ?: 0
                if (rank(sev) >= min && c > 0) {
                    violations.add("${c} finding(s) at severity ${sev} (failOn=${failOn.toString().toUpperCase()})".toString())
                }
            }
        }

        addMaxViolation(violations, counts, 'CRITICAL', asInt(thresholds.maxCritical))
        addMaxViolation(violations, counts, 'HIGH', asInt(thresholds.maxHigh))
        addMaxViolation(violations, counts, 'MEDIUM', asInt(thresholds.maxMedium))
        addMaxViolation(violations, counts, 'LOW', asInt(thresholds.maxLow))
        return violations
    }

    private static void addMaxViolation(List<String> violations, Map counts, String sev, Integer max) {
        if (max == null) {
            return
        }
        int c = counts[sev] ?: 0
        if (c > max) {
            violations.add("${c} ${sev} finding(s) exceeds allowed maximum of ${max}".toString())
        }
    }

    private static Integer asInt(Object v) {
        if (v == null) {
            return null
        }
        return v as Integer
    }
}
