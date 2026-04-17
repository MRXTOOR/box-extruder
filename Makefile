ZAP_DOCKER_IMAGE ?= ghcr.io/zaproxy/zaproxy:stable
KATANA_DOCKER_IMAGE ?= projectdiscovery/katana:latest

WEB_ADDR ?= :8080
WORK_DIR ?= work

DOCKER_IMAGE ?= box-extruder/dast-scanner:latest
DOCKER_COMPOSE ?= docker-compose.yml

.PHONY: build
build:
	go build -o scan ./cmd/scan

.PHONY: install
install:
	go install ./cmd/scan

.PHONY: test
test:
	go test ./...

.PHONY: deps
deps:
	@command -v go >/dev/null 2>&1 || { echo "error: go not found in PATH"; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo "error: docker not found in PATH"; exit 1; }
	go mod download
	docker pull $(ZAP_DOCKER_IMAGE)
	docker pull $(KATANA_DOCKER_IMAGE)

.PHONY: web
web: build deps
	DAST_ZAP_DOCKER_IMAGE=$(ZAP_DOCKER_IMAGE) \
	DAST_KATANA_DOCKER_IMAGE=$(KATANA_DOCKER_IMAGE) \
	./scan serve -addr $(WEB_ADDR) -work $(WORK_DIR)

.PHONY: run-demo
run-demo: build
	./scan run -f examples/scan-as-code.yaml -demo -skip-zap

.PHONY: run-zap-af
run-zap-af: build
	./scan run -f examples/scan-with-zap-automation.yaml -demo -work work

.PHONY: run-nuclei-cli
run-nuclei-cli: build
	./scan run -f examples/scan-with-nuclei-cli.yaml -demo -skip-zap -work work

.PHONY: run-katana
run-katana: build
	./scan run -f examples/scan-with-katana.yaml -demo -skip-zap -work work

.PHONY: run-pipeline-full
run-pipeline-full: build
	DAST_KATANA_DOCKER_IMAGE=$(KATANA_DOCKER_IMAGE) ./scan run -f examples/scan-pipeline-full.yaml -demo -work work

.PHONY: juice-shop-up
juice-shop-up:
	docker compose -f examples/docker-compose.juice-shop.yaml up -d

.PHONY: juice-shop-down
juice-shop-down:
	docker compose -f examples/docker-compose.juice-shop.yaml down

.PHONY: run-juice-shop-demo
run-juice-shop-demo: build
	DAST_KATANA_DOCKER_IMAGE=$(KATANA_DOCKER_IMAGE) ./scan run -f examples/scan-juice-shop.yaml -demo -work work

.PHONY: docker-build
docker-build:
	docker build -f Dockerfile.dind -t $(DOCKER_IMAGE) .

.PHONY: docker-up
docker-up:
	docker compose -f $(DOCKER_COMPOSE) up -d
	@echo "DAST scanner is running on http://localhost:8080"
	@echo "Logs: docker logs -f dast-scanner"

.PHONY: docker-down
docker-down:
	docker compose -f $(DOCKER_COMPOSE) down

.PHONY: docker-logs
docker-logs:
	docker compose -f $(DOCKER_COMPOSE) logs -f

.PHONY: docker-socket-up
docker-socket-up:
	docker compose -f docker-compose.socket.yml up -d
	@echo "DAST scanner is running on http://localhost:8080"
	@echo "Logs: docker logs -f dast-scanner"

.PHONY: docker-socket-down
docker-socket-down:
	docker compose -f docker-compose.socket.yml down
