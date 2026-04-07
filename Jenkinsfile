pipeline {
  agent any
  environment {
    DAST_WORK = "${WORKSPACE}/dast-work"
    // Fail build if confirmed finding at or above this severity
    DAST_FAIL_ON_SEVERITY = "HIGH"
    // Optional: fail job when auth verification fails (header/cookie flows)
    // DAST_AUTH_FAIL_POLICY = "fail"
  }
  stages {
    stage('DAST scan') {
      steps {
        sh '''
          mkdir -p "$DAST_WORK"
          docker build -t dast-scan:ci -f Dockerfile .
        '''
        // Быстрый CI: только встроенный Nuclei + заглушки шагов. Полная связка с Docker/katana/nuclei:
        // examples/scan-pipeline-full.yaml и флаги -skip-katana -skip-zap -skip-nuclei по необходимости.
        sh '''
          docker run --rm \
            -v "$DAST_WORK:/workspace/work" \
            -v "$WORKSPACE:/cfg:ro" \
            -e DAST_FAIL_ON_SEVERITY \
            -e DAST_AUTH_FAIL_POLICY \
            -e DAST_BEARER_TOKEN \
            dast-scan:ci run \
            -f /cfg/examples/scan-as-code.yaml \
            -work /workspace/work \
            -skip-zap
        '''
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'dast-work/jobs/**/findings/*.json,dast-work/jobs/**/reports/*', allowEmptyArchive: true
    }
  }
}
