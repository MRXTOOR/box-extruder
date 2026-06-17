# AppSec-DAST — Shared Library (GitLab / Sfera)

Каталог `jenkins/` подключается в оркестраторе как **Pipeline Shared Library** с именем, например, `appsec-dast` или `global_appsec_check_dast_sfera_lib`.

```
jenkins/
├── vars/
│   └── dastScan.groovy          # библиотека — вызов dastScan(...)
├── src/com/appsec/dast/
│   └── QualityGate.groovy       # quality gate (нужен для dastScan)
├── runner/                      # минимальный Docker-образ для агента
│   ├── Dockerfile
│   ├── dast-scan.sh
│   └── README.md
└── README.md                    # этот файл
```

**На агенте пайплайна:** Docker (образ runner публикуется в ваш registry; curl на агенте не нужен). Контейнер runner удаляется после скана (`docker run --rm` + `docker rm -f` в `finally`).

## Runner-образ

Сборка и публикация — см. [`runner/README.md`](runner/README.md).

В пайплайне укажите полное имя образа через `runnerImage` (без жёсткого дефолта в библиотеке):

```groovy
runnerImage: 'your-registry.example.com/appsec-dast/runner:1.0.0'
```

## Подключение

1. Указать репозиторий / путь к каталогу `jenkins/` в настройках Shared Library.
2. Собрать и запушить runner-образ в registry (см. `jenkins/runner/`).
3. Создать credential **Secret text** с CI-ключом `dast_<uuid>` (выдаётся в ЛК AppSec-DAST или админом).
4. При необходимости — credential для `docker login` в registry (`registryCredentialsId`).
5. В Jenkinsfile:

```groovy
@Library('appsec-dast') _
```

## Тестовые данные (пример)

| Параметр | Тестовое значение |
|----------|-------------------|
| Runner image | `your-registry/appsec-dast/runner:1.0.0` |
| URL платформы | `http://appsec-dast.internal` |
| CI-ключ (credential ID) | `dast-ci-staging` → значение `dast_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| Имя цели | `staging-myapp` |
| Target URL | `https://staging.myapp.example.com/` |
| Login | `test_user@example.com` |
| Password | `test_password` |
| Auth URL | `https://staging.myapp.example.com/api/v1/auth/login` |
| Start points | `https://staging.myapp.example.com/app/` |
| Katana depth | `10` |
| Katana max URLs | `3000` |
| ZAP Spider (мин) | `15` |
| ZAP passive (сек) | `180` |
| Quality gate | `HIGH` |
| Таймаут (мин) | `120` |

## Пример пайплайна

```groovy
@Library('global_appsec_check_dast_sfera_lib@1.0.1') _

pipeline {
    agent any

    environment {
        DAST_API_URL       = 'http://appsec-dast.internal'
        DAST_CI_TOKEN_CRED = 'dast-ci-staging'
        DAST_RUNNER_IMAGE  = 'your-registry/appsec-dast/runner:1.0.0'
    }

    stages {
        stage('DAST scan') {
            steps {
                script {
                    def result = dastScan(
                        runnerImage: env.DAST_RUNNER_IMAGE,
                        registryCredentialsId: 'your-docker-cred',  // опционально

                        apiUrl: env.DAST_API_URL,
                        apiTokenCredentialId: env.DAST_CI_TOKEN_CRED,

                        targetName: 'staging-myapp',
                        target: 'https://staging.myapp.example.com/',

                        login: 'test_user@example.com',
                        password: 'test_password',
                        authUrl: 'https://staging.myapp.example.com/api/v1/auth/login',

                        startPoints: [
                            'https://staging.myapp.example.com/app/',
                            'https://staging.myapp.example.com/api/docs',
                        ],

                        katanaDepth: 10,
                        katanaMaxUrls: 3000,
                        zapSpiderMinutes: 15,
                        zapPassiveSecs: 180,

                        failOn: 'HIGH',
                        timeoutMinutes: 120,
                        pollSeconds: 20,
                        reportFormats: ['docx'],
                    )

                    echo "Scan jobId=${result.jobId} status=${result.status} passed=${result.passed}"
                    echo "DOCX report: ${result.reportDocx}"
                }
            }
        }
    }
}
