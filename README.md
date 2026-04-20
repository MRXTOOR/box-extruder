# DAST Scanner - Dynamic Application Security Testing Platform

Автоматизированная платформа для динамического анализа безопасности веб-приложений.

### Компоненты

| Компонент | Описание | Порт |
|-----------|----------|------|
| **Nginx** | Фронтенд (React) | 80 |
| **Server** | Go API сервер | 8080 |
| **PostgreSQL** | База данных | 5432 |
| **Redis** | Очередь задач и кэш | 6379 |
| **Worker** | Исполнение сканов | - |

## Быстрый старт

### Требования

- Docker 20.10+
- Docker Compose 2.0+

### Запуск

```bash
git clone <repo-url>
cd box-extruder

docker compose -f docker-compose.full.yml up -d

http://localhost
```

### Учётные данные по умолчанию

- **Login**: `admin`
- **Password**: `admin`

## Развёртывание

### Конфигурация

1. Создайте `.env` файл:

```bash
# PostgreSQL
POSTGRES_USER=dast
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=dast

# Redis
REDIS_PASSWORD=your_redis_password

# JWT
JWT_SECRET=your_jwt_secret_min_32_chars

# Опционально - изменить порты
SERVER_PORT=8080
NGINX_PORT=80
```

2. Запустите:

```bash
docker compose -f docker-compose.full.yml up -d --build
```

### Проверка статуса

```bash
# Статус контейнеров
docker compose -f docker-compose.full.yml ps

# Логи
docker compose -f docker-compose.full.yml logs -f
```

## API

### Авторизация

Если работа проводиться через терминал\программу для запросов

```bash
# Вход
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login":"admin","password":"admin"}'

# Ответ
{"token":"eyJhbGci...","role":"admin","user":"admin"}
```

### Управление сканами

```bash
TOKEN="your_token"

# Создать скан
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "targetUrl": "https://example.com",
    "authUrl": "https://example.com/login",
    "login": "user@example.com",
    "password": "secret"
  }'

# Список сканов
curl http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN"

# Статус скана
curl http://localhost:8080/api/v1/scans/{scan_id}/status \
  -H "Authorization: Bearer $TOKEN"

# Удалить скан
curl -X DELETE http://localhost:8080/api/v1/scans/{scan_id} \
  -H "Authorization: Bearer $TOKEN"
```

### Отчёты

```bash
# Markdown
curl http://localhost:8080/api/v1/scans/{scan_id}/reports \
  -H "Authorization: Bearer $TOKEN" \
  -o report.md

# HTML
curl "http://localhost:8080/api/v1/scans/{scan_id}/reports?format=html" \
  -H "Authorization: Bearer $TOKEN" \
  -o report.html

# DOCX
curl "http://localhost:8080/api/v1/scans/{scan_id}/reports?format=docx" \
  -H "Authorization: Bearer $TOKEN" \
  -o report.docx

# Эндпоинты (TXT)
curl "http://localhost:8080/api/v1/scans/{scan_id}/reports?format=endpoints" \
  -H "Authorization: Bearer $TOKEN" \
  -o endpoints.txt
```

## Управление пользователями

### Через CLI

```bash
# Подключиться к контейнеру
docker exec -it dast-server sh

# Создать пользователя
dast-server user add --login=user --password=pass --role=specialist

# Изменить пароль
dast-server user password --login=user --password=newpass

# Удалить пользователя
dast-server user delete --login=user

# Сделать админом
dast-server user role --login=user --role=admin
```

### Через базу данных

```bash
# Подключиться к PostgreSQL
docker exec -it dast-postgres psql -U dast -d dast

# Добавить пользователя (пароль хешируется через bcrypt)
INSERT INTO users (login, password_hash, role) VALUES (
  'newuser',
  '$2a$10$hashed_password_here',
  'specialist'
);

# Список пользователей
SELECT id, login, role FROM users;
```

## Конфигурация сканирования

### Параметры сканирования

```yaml
version: "1.0"
job:
  name: "my-scan"

targets:
  - type: "web"
    baseUrl: "https://example.com"
    startPoints:
      - "https://example.com/login"

scope:
  allow:
    - ".*example\\.com.*"
  deny:
    - ".*logout.*"
  maxUrls: 5000

auth:
  strategy: "providerChain"
  providers:
    - type: "genericLogin"
      id: "login-form"
      genericLogin:
        loginURL: "https://example.com/login"
        usernameField: "email"
        passwordField: "password"
        submitField: "button[type=submit]"
        checkURL: "https://example.com/dashboard"
        expectedStatus: 200

scan:
  plan:
    - stepType: "katana"
      enabled: true
      katanaDepth: 3
      katanaMaxUrls: 5000
    - stepType: "zapBaseline"
      enabled: true
      zapAutomationFramework: true
      zapMaxSpiderMinutes: 30
      zapPassiveWaitSeconds: 120
    - stepType: "nucleiTemplates"
      enabled: true
```

## Устранение проблем

### Логи

```bash
# Все сервисы
docker compose -f docker-compose.full.yml logs

# Конкретный сервис
docker compose -f docker-compose.full.yml logs dast-server
docker compose -f docker-compose.full.yml logs dast-worker
```

### Частые проблемы

1. **ZAP занят порт 9090**
   ```bash
   # Проверить занятые порты
   netstat -tlnp | grep 9090

   # Остановить конфликтующий процесс
   ```

2. **PostgreSQL не подключается**
   ```bash
   # Проверить статус
   docker compose -f docker-compose.full.yml logs postgres

   # Проверить подключение
   docker exec -it dast-postgres pg_isready
   ```

3. **Worker не выполняет задачи**
   ```bash
   # Проверить очередь Redis
   docker exec -it dast-redis redis-cli LLEN dast:queue

   # Проверить логи worker
   docker compose -f docker-compose.full.yml logs dast-worker
   ```