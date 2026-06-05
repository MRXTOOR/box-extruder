# Интеграция с Jenkins CI

Jenkins Shared Library для запуска DAST-сканирований AppSec-DAST прямо из пайплайнов.
Разработчик подключает библиотеку, в одном шаге `dastScan(...)` указывает цель, данные
авторизации, настройки сертификатов и параметры сканирования — пайплайн создаёт скан,
ждёт результат, сохраняет отчёты как артефакты и роняет сборку по quality gate.

## Структура

```
jenkins/
├── Dockerfile               # образ appsec-dast/ci-runner (curl + jq + dast-scan.sh)
├── docker-compose.yml       # локальный запуск: docker compose run --rm ci-runner
├── scripts/dast-scan.sh     # логика скана (внутри контейнера)
├── vars/
│   ├── dastScan.groovy      # шаг dastScan(...) — по умолчанию через Docker
│   └── dastScan.txt
├── src/com/appsec/dast/
│   └── QualityGate.groovy
├── examples/
│   ├── Jenkinsfile
│   ├── Jenkinsfile.ci-token
│   ├── Jenkinsfile.test          # smoke job для Jenkins / CI
│   ├── Jenkinsfile.docker-agent
│   └── Jenkinsfile.parameterized
└── README.md
```

## Как это работает (Docker по умолчанию)

```
Jenkins agent
   dastScan(...)  ──docker run──>  ci-runner container  ──HTTPS──>  DAST API
                                   /opt/dast/dast-scan.sh
   quality gate <── dast-result.json + exit code
```

Шаг `dastScan` по умолчанию поднимает образ **`appsec-dast/ci-runner:latest`** (не нужен `curl` на агенте).
Отключить Docker: `runnerImage: false` — тогда используется `curl` на агенте.

## Сборка образа CI runner

```bash
# из корня репозитория
docker build -t appsec-dast/ci-runner:latest -f jenkins/Dockerfile jenkins/

# вместе со стеком DAST (профиль ci)
docker compose -f deploy/docker-compose.yml --profile ci build dast-ci-runner
```

## Локальный запуск скана из Docker (без Jenkins)

```bash
cd deploy && docker compose up -d
cd ../jenkins
cp .env.example .env   # задайте DAST_USER, DAST_PASS, DAST_TARGET
docker compose build
docker compose run --rm ci-runner
# артефакты: jenkins/out/
```

Если DAST в compose, а runner — отдельно, укажите `DAST_API_URL=http://host.docker.internal:8080`.
Если runner в той же сети compose: `DAST_API_URL=http://dast-server:8080`.

## Требования

- Jenkins-плагины: **Pipeline Utility Steps**, **Credentials Binding**, **Docker Pipeline**.
- На агенте Jenkins: **Docker** (для режима по умолчанию).
- Сетевой доступ контейнера `ci-runner` до DAST API.

## Настройка (один раз администратором Jenkins)

### 1. CI UUID-токен (рекомендуется для команд без Web UI)

Админ AppSec выдаёт команде долгоживущий токен `dast_<uuid>` — в пайплайне не нужны
логин/пароль платформы DAST.

```bash
go build -o /tmp/dast-cli ./cmd/cli

# Всё в одном: пользователь ci-<name>, токен, проверка API
/tmp/dast-cli ci setup \
  --name=consumer-api \
  --api-url=http://dast-server:8080 \
  --verify \
  --db-host=<postgres-host>

# Или вручную для существующего пользователя:
/tmp/dast-cli ci-token create --user=ci-jenkins --name=consumer-api --db-host=<host>
/tmp/dast-cli ci-token verify --api-url=http://dast-server:8080 --token=dast_<uuid>
```

Передайте команде шаблон [`docs/examples/ci-token-handoff.yaml`](../docs/examples/ci-token-handoff.yaml).

### 2. Сервисная учётка DAST (fallback)

Если токен не используется, создайте пользователя с паролем:

```bash
/tmp/dast-cli user add --login=ci-jenkins --password='<сильный-пароль>' --role=specialist --db-host=<host>
```

### 3. Credentials в Jenkins

`Manage Jenkins → Credentials` → добавьте:

| ID (пример)            | Тип                | Назначение                                        |
|------------------------|--------------------|---------------------------------------------------|
| `dast-ci-consumer-api` | Secret text        | CI UUID-токен `dast_<uuid>` (**рекомендуется**)   |
| `dast-api`             | Username/Password  | Сервисная учётка DAST API (fallback)              |
| `myapp-login`          | Username/Password  | Логин в сканируемое приложение (опционально)      |
| `corp-ca-bundle`       | Secret file        | CA-бандл для проверки TLS DAST API (опц.)          |

### 4. Подключение библиотеки

`Manage Jenkins → System → Global Pipeline Libraries` → Add:

- **Name**: `dast`
- **Default version**: `main` (или тег/ветка)
- **Retrieval method**: Modern SCM → Git → URL репозитория
- **Important**: Jenkins ожидает каталоги `vars/` и `src/` в **корне** репозитория
  библиотеки. Опубликуйте содержимое каталога `jenkins/` как корень отдельного
  Git-репозитория (или настройте sparse/subtree так, чтобы `vars/` и `src/`
  оказались в корне).

> Можно также подключать библиотеку «на лету» прямо в Jenkinsfile через
> `library(identifier: 'dast@main', retriever: modernSCM([...]))`, если не хотите
> заводить глобальную библиотеку.

## Использование (разработчиком)

1. Создайте **Pipeline** job.
2. Подключите библиотеку и вызовите шаг:

**С CI-токеном (рекомендуется):**

```groovy
dastScan(
  apiUrl: 'https://dast.example.com:8080',
  apiTokenCredentialId: 'dast-ci-consumer-api',
  target: 'https://staging.myapp.example.com',
  login: 'ci-user@example.com',
  password: 'staging-secret',
  failOn: 'HIGH'
)
```

**С логином/паролем платформы (fallback):**

```groovy
dastScan(
  apiUrl: 'https://dast.example.com:8080',
  apiCredentialsId: 'dast-api',
  target: 'https://staging.myapp.example.com',
  failOn: 'HIGH'
)
```

`authUrl` можно не указывать — платформа подберёт endpoint логина автоматически.
Примеры: `examples/Jenkinsfile.ci-token`, `examples/Jenkinsfile.parameterized`.

### Тестовый пайплайн

**В Jenkins:** создайте Pipeline job, укажите `jenkins/examples/Jenkinsfile.test`, добавьте credential
`dast-ci-pipeline-test` (Secret text с токеном от `dast-cli ci setup --name=pipeline-test`).

**Локально (без Jenkins)** — полный прогон как в job:

```bash
docker compose -f deploy/docker-compose.yml up -d
# после обновления кода с CI-токенами — пересобрать server:
REBUILD_SERVER=true bash jenkins/scripts/run-pipeline-test.sh
# артефакты: jenkins/out-pipeline-test/  (токен: .ci-token, не коммитить)
```

Windows: `powershell -File jenkins/scripts/run-pipeline-test.ps1` (нужен Git Bash).

Быстрый smoke API (без ожидания скана):

```bash
bash jenkins/scripts/run-tests.sh
# с CI-токеном: DAST_CI_TOKEN=dast_<uuid> bash jenkins/scripts/run-tests.sh
```

## Параметры `dastScan(...)`

| Параметр               | Тип       | По умолчанию   | Описание                                                        |
|------------------------|-----------|----------------|----------------------------------------------------------------|
| `apiUrl`               | String    | —              | Базовый URL DAST API. **Обязателен.**                          |
| `apiTokenCredentialId` | String    | —              | Secret text с CI UUID `dast_<uuid>` (**приоритет**).           |
| `apiCredentialsId`     | String    | —              | Username/Password для DAST (fallback, если нет токена).        |
| `apiToken`             | String    | —              | Inline-токен только для тестов (не для production).            |
| `target`               | String    | —              | URL цели. **Обязателен.**                                      |
| `login` / `password`   | String    | —              | Учётка приложения (самый частый случай в CI).                  |
| `appLogin` / `appPassword` | String | —           | Синонимы `login` / `password`.                                 |
| `uiUrl`                | String    | —              | URL веб-UI для ссылки на скан в логе.                          |
| `appAuthCredentialsId` | String    | —              | Jenkins credential вместо `login`/`password`.                  |
| `authUrl`              | String    | —              | Явный URL логина (опционально; иначе автоподбор).              |
| `verifyUrl`            | String    | —              | URL проверки сессии цели.                                      |
| `insecureSkipVerify`   | boolean   | `false`        | Не проверять TLS-сертификат **цели**.                          |
| `apiInsecure`          | boolean   | `false`        | Не проверять TLS-сертификат **DAST API** (`curl -k`).          |
| `caCertId`             | String    | —              | Secret file credential — CA-бандл для DAST API.                |
| `katanaDepth`          | int       | сервер         | Глубина обхода Katana.                                         |
| `katanaMaxUrls`        | int       | сервер         | Лимит URL Katana.                                              |
| `zapSpiderMinutes`     | int       | сервер         | Минут на ZAP spider.                                           |
| `zapPassiveSecs`       | int       | сервер         | Секунд пассивного анализа ZAP.                                 |
| `startPoints`          | List      | `[]`           | Доп. стартовые URL.                                            |
| `failOn`               | String    | —              | Минимальный severity, роняющий сборку (INFO..CRITICAL).        |
| `maxCritical`/`maxHigh`/`maxMedium`/`maxLow` | int | — | Максимум находок по уровню.                            |
| `failOnScanError`      | boolean   | `true`         | Ронять сборку при статусе скана FAILED.                        |
| `timeoutMinutes`       | int       | `60`           | Таймаут ожидания (по истечении скан отменяется).              |
| `pollSeconds`          | int       | `15`           | Интервал опроса статуса.                                       |
| `reportFormats`        | List      | `['docx','html','pdf']` | Форматы: `docx`, `html`, `pdf`, `endpoints`.          |
| `archiveReports`       | boolean   | `true`         | Сохранять отчёты + `findings.json` как артефакты.             |
| `runnerImage`          | String    | `appsec-dast/ci-runner:latest` | Docker-образ runner. `false` — curl на агенте. |
| `useDocker`            | boolean   | `true`         | `false` = то же, что `runnerImage: false`.                     |

## Quality gate

Сборка падает, если:

- `failOn` задан и есть находки этого уровня или выше; **или**
- превышен любой из `maxCritical` / `maxHigh` / `maxMedium` / `maxLow`; **или**
- скан завершился статусом `FAILED` и `failOnScanError = true`.

Шаг возвращает Map: `jobId`, `status`, `counts`, `total`, `passed`, `violations`.

## Безопасность

- Секреты передаются в `curl` только через файлы (`--data @file`, `-H @file`),
  никогда не попадают в текст shell-команды и не светятся в логе.
- Используйте отдельную сервисную учётку DAST с минимальной ролью.
- Временные файлы с телами запросов и заголовком авторизации удаляются после шага.

## Диагностика

| Симптом                              | Причина / решение                                              |
|--------------------------------------|---------------------------------------------------------------|
| `login failed (HTTP 401)`            | Неверная учётка `apiCredentialsId`.                           |
| `create scan failed (HTTP 400)`      | Невалидный `target`, или ошибка авторизации в цель (см. тело).|
| `report '...' not available`         | Скан не дошёл до этапа отчёта (FAILED/CANCELLED).             |
| `did not finish within N minutes`    | Увеличьте `timeoutMinutes`.                                   |
| TLS-ошибка к API                     | Задайте `caCertId` или (только для теста) `apiInsecure: true`.|
| `readJSON` not found                 | Установите плагин **Pipeline Utility Steps**.                 |
