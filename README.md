# AppSec-DAST

Платформа для автоматизированного динамического анализа безопасности веб-приложений (DAST).

## Быстрый старт

### Требования

- Docker и Docker Compose
- PostgreSQL 15+
- Redis 7+

### Запуск

```bash
cd deploy
docker compose up -d
```

### Доступные сервисы

| Сервис | Порт | URL |
|--------|------|-----|
| Frontend | 80 | http://localhost |
| API | 8080 | http://localhost:8080 |
| PostgreSQL | 5432 | localhost:5432 |
| Redis | 6379 | localhost:6379 |

## Управление пользователями

### Создание пользователя (локально)

```bash
# Собрать CLI
cd /mnt/projects/code/box-extruder
go build -o /tmp/dast-cli ./cmd/cli

# Создать пользователя
/tmp/dast-cli user add --login=username --password=password --role=specialist --db-host=localhost
```

### Роли

- `admin` - полный доступ
- `specialist` - ограниченный доступ

### Создание пользователя в контейнере БД

```bash
# Через psql напрямую
docker exec -i dast-postgres psql -U dast -d dast -c "
INSERT INTO users (login, password_hash, role) 
VALUES ('username', '\$2a\$10\$hash', 'specialist');
"
```

### Список пользователей

```bash
/tmp/dast-cli user list --db-host=localhost
```

### Удаление пользователя

```bash
/tmp/dast-cli user delete --login=username --db-host=localhost
```

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

# Отчет
curl http://localhost:8080/api/v1/scans/{id}/reports \
  -H "Authorization: Bearer $TOKEN"
```

## Конфигурация

### Docker Compose

Основные переменные окружения в `docker-compose.enterprise.yml`:

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
# Сервер
docker logs deploy-dast-server

# Фронтенд
docker logs deploy-frontend

# Nginx
docker logs deploy-nginx
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