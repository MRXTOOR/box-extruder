#!/bin/bash
set -e

# Если первый аргумент "serve" — запускаем Docker daemon + API server
if [ "$1" = "serve" ]; then
    echo "=== DAST Orchestrator (Docker-in-Docker) ==="
    echo "Starting Docker daemon..."
    
    # Запускаем Docker daemon в фоне
    dockerd &>/var/log/dockerd.log &
    DOCKERD_PID=$!
    
    # Ждем пока Docker daemon запустится
    echo "Waiting for Docker daemon to be ready..."
    for i in $(seq 1 30); do
        if docker info &>/dev/null; then
            echo "Docker daemon is ready!"
            break
        fi
        if [ $i -eq 30 ]; then
            echo "ERROR: Docker daemon failed to start"
            cat /var/log/dockerd.log
            exit 1
        fi
        sleep 1
    done
    
    # Pull images если нужно
    if [ "$DAST_PULL_IMAGES" != "0" ]; then
        echo "Pulling ZAP image..."
        docker pull ghcr.io/zaproxy/zaproxy:stable || echo "WARN: Failed to pull ZAP image"
        
        echo "Pulling Katana image..."
        docker pull projectdiscovery/katana:latest || echo "WARN: Failed to pull Katana image"
    fi
    
    echo "Starting DAST API server on $DAST_SERVE_ADDR..."
    exec /usr/local/bin/scan serve "$@"
else
    # Обычный запуск (scan run и т.д.)
    exec /usr/local/bin/scan "$@"
fi
