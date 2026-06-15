# AppSec-DAST

Платформа для автоматизированного динамического анализа безопасности веб-приложений (DAST).

### Требования

- Docker и Docker Compose
- PostgreSQL 15+
- Redis 7+

### Запуск

Файл стека: `deploy/docker-compose.yml`. Сборка и запуск только через Docker — скрипты на хосте не нужны.

```bash
cd deploy
docker compose up -d --build
```

Из корня репозитория:

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```

При старте `dast-server` и `dast-worker` автоматически применяют SQL-миграции из встроенного каталога `internal/enterprise/db/migrations/` (учёт в `schema_migrations`). На существующих томах Postgres дополнительных шагов не требуется.

### Доступные сервисы

| Сервис | Порт | URL |
|--------|------|-----|
| Frontend | 80 | http://localhost |
| API | 8080 | http://localhost:8080 |
| PostgreSQL | 5432 | localhost:5432 |
| Redis | 6379 | localhost:6379 |

## Управление пользователями (веб-интерфейс)

Все операции с пользователями и CI-ключами выполняются через UI — отдельный CLI не используется.

### Первый администратор

При первом запуске включите bootstrap в `deploy/.env`:

```env
BOOTSTRAP_ADMIN_ENABLED=true
BOOTSTRAP_ADMIN_LOGIN=admin
BOOTSTRAP_ADMIN_PASSWORD=change_me_strong_admin_password
BOOTSTRAP_ADMIN_ROLE=admin
```

После создания учётки установите `BOOTSTRAP_ADMIN_ENABLED=false` и перезапустите `dast-server`.

### Веб-админка

| Раздел | URL | Возможности |
|--------|-----|-------------|
| Пользователи | `/admin/users` | Создание, смена роли, удаление |
| CI-ключи | `/admin/ci-keys` | Список ключей, история сканов, отзыв |
| Карточка пользователя | `/admin/users/{id}` | Генерация CI-ключа для владельца |

### Личный кабинет

| Раздел | URL | Возможности |
|--------|-----|-------------|
| Мои CI-ключи | `/ci-keys` | Мониторинг Jenkins-сканов по выданным ключам, журнал, дамп |

### Роли

- `admin` — полный доступ, админ-панель
- `specialist` — сканы через UI, просмотр своих CI-ключей в ЛК

## API

### Авторизация

```bash
# Логин
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login": "admin", "password": "admin123"}'

# Ответ
# {"token": "eyJ...", "user": "admin", "role": "admin"}
```

### Использование токена

```bash
TOKEN="your_token"

# Создать сканирование
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://example.com"}'

# Список сканирований
curl http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN"

# Статус сканирования
curl http://localhost:8080/api/v1/scans/{id}/status \
  -H "Authorization: Bearer $TOKEN"

# Отчет (требуется JWT)
curl http://localhost:8080/api/v1/scans/{id}/reports?format=html \
  -H "Authorization: Bearer $TOKEN"

# Эндпоинты (требуется JWT)
curl http://localhost:8080/api/v1/scans/{id}/endpoints \
  -H "Authorization: Bearer $TOKEN"

# Discover login/forms по targetUrl
curl -X POST http://localhost:8080/api/v1/auth/discover \
  -H "Content-Type: application/json" \
  -d '{"targetUrl":"http://localhost:3001"}'

# Restart: новая запись в scans + новый jobId (тот же config)
curl -X POST http://localhost:8080/api/v1/scans/{id}/restart \
  -H "Authorization: Bearer $TOKEN"
```

Поведение API:

- `POST /auth/discover` — возвращает `forms` и `loginUrls`, найденные на странице цели.
- `GET /scans/{id}/reports` и `/endpoints` — только с JWT; доступ владельцу скана или `admin`.
- Findings после скана сохраняются воркером в таблицу `findings` (БД); файлы job остаются как артефакты.
- `POST /scans/{id}/restart` — создаёт **новую** строку в `scans` с новым `jobId` и ставит задачу с исходным YAML-конфигом.

## CI/CD: интеграция с Sfera / Jenkins

Shared Library для пайплайнов — каталог [`jenkins/`](jenkins/README.md). DevOps подключает `vars/` и `src/` в оркестраторе; пример пайплайна и тестовые данные — в [`jenkins/README.md`](jenkins/README.md).

```groovy
@Library('appsec-dast') _

def result = dastScan(
    apiUrl: 'https://appsec-dast.internal',
    apiTokenCredentialId: 'dast-ci-myapp',
    target: 'https://staging.myapp.example.com',
    failOn: 'HIGH',
    reportFormats: ['docx'],
)
// result.reportDocx — путь к DOCX, артефакт .dast/dast-report-<jobId>.docx
```

CI-токен выдаётся в **веб-интерфейсе** (`Мои CI-ключи` или `Админ → CI-ключи`). Скан попадает в историю владельца с меткой CI.

**Отчёт DOCX** — корпоративный шаблон (`internal/report/templates/enterprise-reference.docx`), пример — `docs/examples/dast-enterprise-report-example.md`.

Подробности API шага — [`jenkins/README.md`](jenkins/README.md) и `jenkins/vars/dastScan.txt`.

## Конфигурация

### Docker Compose

Основные переменные окружения в `deploy/docker-compose.yml`:

```yaml
environment:
  - DB_HOST=postgres
  - DB_PORT=5432
  - DB_USER=dast
  - DB_PASS=dast
  - DB_NAME=dast
  - REDIS_HOST=redis
  - REDIS_PORT=6379
  - JWT_SECRET=changeme
  - WORK_DIR=/workspace/work
```

### Окружения

- `postgres` - хост PostgreSQL
- `redis` - хост Redis
- `JWT_SECRET` - секретный ключ для JWT токенов

## Перетегирование образов

После переименования проекта на AppSec-DAST:

```bash
# Перетег образов
docker tag box-extruder-dast-server:latest docker-ppbd-prod.sfera-t1.ru/appsec-docker-private/appsec-dast/dast-server:1.0.0
docker tag box-extruder-dast-worker:latest docker-ppbd-prod.sfera-t1.ru/appsec-docker-private/appsec-dast/dast-worker:1.0.0
docker tag box-extruder-frontend:latest docker-ppbd-prod.sfera-t1.ru/appsec-docker-private/appsec-dast/frontend:1.0.0
docker tag box-extruder-nginx:latest docker-ppbd-prod.sfera-t1.ru/appsec-docker-private/appsec-dast/nginx:1.0.0

# Пуш в registry
docker push docker-ppbd-prod.sfera-t1.ru/appsec-docker-private/appsec-dast/dast-server:1.0.0
docker push docker-ppbd-prod.sfera-t1.ru/appsec-docker-private/appsec-dast/dast-worker:1.0.0
docker push docker-ppbd-prod.sfera-t1.ru/appsec-docker-private/appsec-dast/frontend:1.0.0
docker push docker-ppbd-prod.sfera-t1.ru/appsec-docker-private/appsec-dast/nginx:1.0.0
```

## Устранение неполадок

### Проверка статуса контейнеров

```bash
docker ps
```

### Просмотр логов

```bash
# API
docker logs dast-server

# Воркер
docker logs dast-worker

# Nginx (статика + прокси /api)
docker logs dast-nginx
```

### Проверка здоровья

```bash
curl http://localhost:8080/health
curl http://localhost/api/health
```

### Перезапуск сервисов

```bash
cd deploy
docker compose restart
```