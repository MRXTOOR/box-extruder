# Docker для DAST Orchestrator

## Быстрый старт (Windows/macOS/Linux)

### Способ 1: Docker Compose (рекомендуется для Windows/macOS)

```bash
# Сборка образа
docker build -f Dockerfile.dind -t box-extruder/dast-scanner:latest .

# Запуск
docker compose up -d

# Проверить статус
docker ps
docker logs -f dast-scanner
```

Откройте **http://localhost:8080** — Web UI готов!

### Способ 2: Docker Socket (Linux, требует доступ к host Docker)

```bash
docker compose -f docker-compose.socket.yml up -d
```

## Структура файлов

- `Dockerfile.dind` — Docker-in-Docker образ с ZAP, Katana, Nuclei
- `docker-compose.yml` — полная конфигурация DinD
- `docker-compose.socket.yml` — альтернатива с Docker socket mount
- `docker-entrypoint.sh` — скрипт запуска с Docker daemon

## Переменные окружения

| Переменная | Описание | По умолчанию |
|------------|----------|--------------|
| `DAST_SERVE_ADDR` | Адрес API сервера | `0.0.0.0:8080` |
| `DAST_PULL_IMAGES` | Pull ZAP/Katana images при старте | `1` |
| `DAST_WORKDIR` | Рабочая директория | `/workspace/work` |

## Тома (Volumes)

- `dast-work` — persist work directory (отчеты, находки, логи)
- `./templates` — шаблоны Nuclei (read-only)
- `./examples` — примеры конфигураций (read-only)

## Использование

### Web UI
```
http://localhost:8080
```

### CLI внутри контейнера
```bash
# Запустить сканирование
docker exec -it dast-scanner scan run -f examples/scan-as-code.yaml -demo

# Посмотреть логи оркестратора
docker exec -it dast-scanner scan logs

# Review находки
docker exec -it dast-scanner review
```

## Troubleshooting

### DinD не запускается на Windows/macOS
DinD требует `privileged: true`, что может не работать на Windows/macOS.

**Решение:** Используйте `docker-compose.socket.yml`:
```bash
docker compose -f docker-compose.socket.yml up -d
```

### Контейнер не может pull образы
Проверьте интернет-соединение и Docker registry access.

Можно отключить автоматический pull:
```yaml
environment:
  - DAST_PULL_IMAGES=0
```

### Медленный запуск
Docker daemon внутри контейнера занимает 20-40 секунд на старт — это нормально.
