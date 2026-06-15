# AppSec-DAST — Shared Library (GitLab / Sfera)

Каталог `jenkins/` подключается в оркестраторе как **Pipeline Shared Library** с именем, например, `appsec-dast`.

```
jenkins/
├── vars/
│   └── dastScan.groovy          # библиотека — вызов dastScan(...)
├── src/com/appsec/dast/
│   └── QualityGate.groovy       # quality gate (нужен для dastScan)
└── README.md                    # этот файл
```

**На агенте пайплайна:** `curl` (Docker-образ не нужен).

## Подключение

1. Указать репозиторий / путь к каталогу `jenkins/` в настройках Shared Library.
2. Создать credential **Secret text** с CI-ключом `dast_<uuid>` (выдаётся в ЛК AppSec-DAST или админом).
3. В Jenkinsfile:

```groovy
@Library('appsec-dast') _
```

## Тестовые данные (пример)

Замените на свои значения перед запуском в проде.

| Параметр | Тестовое значение |
|----------|-------------------|
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
@Library('appsec-dast') _

pipeline {
    agent any

    environment {
        DAST_API_URL       = 'http://appsec-dast.internal'
        DAST_CI_TOKEN_CRED = 'dast-ci-staging'   // Secret text: dast_<uuid>
    }

    stages {
        stage('DAST scan') {
            steps {
                script {
                    def result = dastScan(
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
```

## Параметры `dastScan(...)`

| Параметр | Описание |
|----------|----------|
| `apiUrl` | URL платформы AppSec-DAST |
| `apiTokenCredentialId` | ID credential с CI-ключом `dast_<uuid>` |
| `target` | URL сканируемого приложения |
| `targetName` | Имя цели (для логов) |
| `login` / `password` | Учётка приложения |
| `appAuthCredentialsId` | Jenkins credential вместо login/password |
| `authUrl` | Endpoint авторизации (login API) |
| `verifyUrl` | URL проверки сессии (опционально) |
| `startPoints` | Список URL или многострочная строка |
| `katanaDepth`, `katanaMaxUrls`, `zapSpiderMinutes`, `zapPassiveSecs` | Настройки скана |
| `failOn`, `timeoutMinutes`, `reportFormats` | Quality gate и отчёт |

## Результат

- `result.jobId` — ID скана на платформе
- `result.reportDocx` — путь к DOCX в `.dast/`
- Артефакты сборки: `.dast/dast-*`
- Скан виден в UI у владельца CI-ключа с меткой **CI**
