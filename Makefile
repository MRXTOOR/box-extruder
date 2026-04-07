# Образы для пайплайна (переопределение: make web ZAP_DOCKER_IMAGE=...)
ZAP_DOCKER_IMAGE ?= ghcr.io/zaproxy/zaproxy:stable
KATANA_DOCKER_IMAGE ?= projectdiscovery/katana:latest

# Web UI: адрес и каталог заданий (от корня репозитория)
WEB_ADDR ?= :8080
WORK_DIR ?= work

# Сборка CLI в текущий каталог (тогда: ./scan run ...)
.PHONY: build
build:
	go build -o scan ./cmd/scan

# Установка в $(go env GOPATH)/bin — после этого команда `scan` доступна в PATH
.PHONY: install
install:
	go install ./cmd/scan

.PHONY: test
test:
	go test ./...

# Зависимости для локального UI: Go-модули + образы Docker (ZAP, Katana).
# Оркестратор не «видит» образы сами по себе — нужны DAST_* (их выставляет make web).
.PHONY: deps
deps:
	@command -v go >/dev/null 2>&1 || { echo "error: go not found in PATH"; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo "error: docker not found in PATH"; exit 1; }
	go mod download
	docker pull $(ZAP_DOCKER_IMAGE)
	docker pull $(KATANA_DOCKER_IMAGE)

# Собрать бинарь, подтянуть образы и запустить HTTP API + статику web/ (http://127.0.0.1:8080/ по умолчанию).
# Nuclei в дефолтном плане UI — встроенный движок по YAML; бинарь nuclei не обязателен.
.PHONY: web
web: build deps
	DAST_ZAP_DOCKER_IMAGE=$(ZAP_DOCKER_IMAGE) \
	DAST_KATANA_DOCKER_IMAGE=$(KATANA_DOCKER_IMAGE) \
	./scan serve -addr $(WEB_ADDR) -work $(WORK_DIR)

# Демо без установки в PATH
.PHONY: run-demo
run-demo: build
	./scan run -f examples/scan-as-code.yaml -demo -skip-zap

# ZAP Automation Framework (Docker): spider + Ajax spider — долго, нужен docker
.PHONY: run-zap-af
run-zap-af: build
	./scan run -f examples/scan-with-zap-automation.yaml -demo -work work

# Официальный nuclei в PATH (или DAST_NUCLEI_BIN); без бинаря: -skip-nuclei
.PHONY: run-nuclei-cli
run-nuclei-cli: build
	./scan run -f examples/scan-with-nuclei-cli.yaml -demo -skip-zap -work work

# Katana в PATH (или DAST_KATANA_BIN); без бинаря: -skip-katana
.PHONY: run-katana
run-katana: build
	./scan run -f examples/scan-with-katana.yaml -demo -skip-zap -work work

# Полная связка Katana → ZAP AF → Nuclei (лента URL). Katana в Docker без локального бинаря.
.PHONY: run-pipeline-full
run-pipeline-full: build
	DAST_KATANA_DOCKER_IMAGE=$(KATANA_DOCKER_IMAGE) ./scan run -f examples/scan-pipeline-full.yaml -demo -work work

# OWASP Juice Shop (docker compose) — цель с реальными классами уязвимостей для демо/CTF.
# Сначала: make juice-shop-up  →  http://127.0.0.1:3000/
# Пароль для examples/scan-juice-shop.yaml (провайдер juiceShopLogin): export DAST_JUICESHOP_PASSWORD='...'
.PHONY: juice-shop-up
juice-shop-up:
	docker compose -f examples/docker-compose.juice-shop.yaml up -d

.PHONY: juice-shop-down
juice-shop-down:
	docker compose -f examples/docker-compose.juice-shop.yaml down

.PHONY: run-juice-shop-demo
run-juice-shop-demo: build
	DAST_KATANA_DOCKER_IMAGE=$(KATANA_DOCKER_IMAGE) ./scan run -f examples/scan-juice-shop.yaml -demo -work work
