# box-extruder

Лёгкий DAST-оркестратор для web-целей (Katana + ZAP + Nuclei) с отчётами в JSON/Markdown/HTML(DOCX через pandoc).

## Быстрый старт

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

