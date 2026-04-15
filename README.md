# box-extruder

Лёгкий DAST-оркестратор для web-целей (Katana + ZAP + Nuclei) с отчётами в JSON/Markdown/HTML(DOCX через pandoc).

## Быстрый старт

### Docker (рекомендуемый способ — работает на Windows/macOS/Linux)

**Вариант 1: Docker-in-Docker (полная изоляция)**

```bash
# Сборка и запуск
make docker-build
make docker-up

# Или через docker compose напрямую:
docker compose up -d
```

Откройте `http://localhost:8080` — Web UI готов к работе!

**Вариант 2: Docker socket mount (легче, но требует доступ к host Docker)**

```bash
docker compose -f docker-compose.socket.yml up -d
```

**Остановка:**

```bash
make docker-down
# или
docker compose down
```

**Логи:**

```bash
make docker-logs
# или
docker logs -f dast-scanner
```

### Локальная разработка

```bash
go test ./...
./scan run -f examples/scan-juice-shop.yaml -demo -work work
```

## Web UI (основной UX)

```bash
go build -o scan ./cmd/scan
./scan serve -addr :8080 -work work
```

Откройте `http://localhost:8080`:
- введите `Target URL`, `Login/Email`, `Password` (и опционально auth/verify URL),
- UI вызовет `POST /api/v1/auth/discover`,
- при успешном auto-discovery создаст и запустит job,
- покажет live-статус и ссылки на отчёты.

## Перенос на Windows

1. **Установите Docker Desktop** для Windows с <https://www.docker.com/products/docker-desktop>

2. **Склонируйте репозиторий:**

```bash
git clone <your-repo-url>
cd box-extruder
```

1. **Запустите:**

```bash
# В PowerShell или Git Bash:
make docker-build
make docker-up

# Или напрямую:
docker compose up -d
```

1. **Откройте браузер:** <http://localhost:8080>

> **Важно:** DinD (Docker-in-Docker) требует `privileged: true`, что работает на Linux. На Windows/macOS используйте `docker-compose.socket.yml` или убедитесь что Docker Desktop поддерживает nested containers.

## Где смотреть результаты

- Отчёты: `work/jobs/<job-id>/reports/`
- Находки: `work/jobs/<job-id>/findings/`
- Evidence: `work/jobs/<job-id>/evidence/`
- Логи: `work/jobs/<job-id>/logs/orchestrator.log`

## Аутентификация

Поддерживается цепочка провайдеров в `auth.providers`:

- `header`
- `cookieJar`
- `juiceShopLogin`
- `oidcClientCredentials`
- `genericLogin` (универсальный login endpoint + verify)

### Универсальный login без ручного Bearer

Используйте `type: genericLogin` и задайте flow в `genericLogin`:

- `loginUrl`, `loginMethod`, `contentType` (`application/json` или `application/x-www-form-urlencoded`)
- `credentialFields` (например `email -> email`, `password -> password`)
- `tokenPath`/`tokenPaths` для извлечения токена из JSON
- `verifyUrl`, `verifyMethod`, `verifyExpectedStatus`

Если задать `interactiveInputs`, CLI сам попросит значения в терминале при `scan run` (пароль можно скрыть через `sensitive: true`).
Готовый пример: `examples/scan-generic-login.yaml`.

## Полезные env

- `DAST_SQLI_PAYLOADS=0` — отключить SQLi payload-пробы
- `DAST_XSS_PAYLOADS=0` — отключить XSS payload-пробы
- `DAST_ZAP_ACTIVE_SCAN=0` — отключить active scan в ZAP Automation
- `DAST_ZAP_ACTIVE_SCAN_MAX_MINUTES=10` — лимит active scan

