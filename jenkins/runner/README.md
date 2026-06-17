# AppSec-DAST Jenkins Runner

Минимальный Docker-образ для вызова HTTP API платформы AppSec-DAST из Jenkins Shared Library (`dastScan`).

Содержит: `bash`, `curl`, `jq`, `ca-certificates`. Базовый образ — **debian:bookworm-slim**.

## Сборка

Из **корня репозитория** (рекомендуется — путь к контексту указан явно):

```bash
docker build -t appsec-dast-runner:1.0.0 -f jenkins/runner/Dockerfile jenkins/runner
```

PowerShell (Windows):

```powershell
docker build -t appsec-dast-runner:1.0.0 -f jenkins/runner/Dockerfile jenkins/runner
```

Либо из каталога `jenkins/runner` — **точка в конце обязательна** (контекст сборки):

```bash
cd jenkins/runner
docker build -t appsec-dast-runner:1.0.0 -f Dockerfile .
```

Если видите `docker buildx build requires 1 argument` — не хватает последнего аргумента (путь к контексту: `.` или `jenkins/runner`).

Версия образа — в файле [`VERSION`](VERSION).

## Публикация в registry

```bash
VERSION=$(cat jenkins/runner/VERSION)
REGISTRY=your-registry.example.com/appsec-dast

docker tag appsec-dast-runner:${VERSION} ${REGISTRY}/runner:${VERSION}
docker push ${REGISTRY}/runner:${VERSION}
```

PowerShell:

```powershell
$VERSION = Get-Content jenkins/runner/VERSION
$REGISTRY = "your-registry.example.com/appsec-dast"

docker tag "appsec-dast-runner:$VERSION" "$REGISTRY/runner:$VERSION"
docker push "$REGISTRY/runner:$VERSION"
```

В пайплайне укажите полное имя образа:

```groovy
dastScan(
    runnerImage: "${REGISTRY}/runner:${VERSION}",
    ...
)
```

## Локальный тест (без Jenkins)

```bash
mkdir -p /tmp/dast-work
cat > /tmp/dast-work/config.json <<'EOF'
{
  "apiUrl": "http://localhost:8080",
  "target": "https://example.com/",
  "useCiToken": true,
  "timeoutMinutes": 120,
  "pollSeconds": 15,
  "reportFormats": ["docx"],
  "archiveReports": true
}
EOF

docker run --rm --name dast-runner-test \
  -v /tmp/dast-work:/work \
  -e DAST_CI_TOKEN=dast_your-token-here \
  appsec-dast-runner:1.0.0

# контейнер удалится сам (--rm); при сбое можно принудительно:
# docker rm -f dast-runner-test
```

Результаты появятся в `/tmp/dast-work/`: `scan.json`, `status.json`, `result.json`, `dast-report-<jobId>.docx`.

## Переменные окружения (секреты)

| Переменная | Описание |
|------------|----------|
| `DAST_CI_TOKEN` | CI-ключ `dast_<uuid>` |
| `DAST_USER` / `DAST_PASS` | Логин платформы (если нет CI-токена) |
| `APP_USER` / `APP_PASS` | Учётка сканируемого приложения |
| `DAST_CA` | Путь к CA-сертификату (файл) |
| `BUILD_URL`, `JOB_NAME`, `BUILD_NUMBER` | CI metadata (опционально) |

Параметры скана (без секретов) передаются в `/work/config.json` — формируется `dastScan.groovy`.
