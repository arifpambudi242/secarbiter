#!/usr/bin/env bash
# Network policy script for isolated pentest sandbox
set -euo pipefail

NETWORK_NAME="pentest-sandbox-net"

# Create internal bridge network without gateway if total isolation is needed
if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    docker network create \
        --driver bridge \
        --opt "com.docker.network.bridge.enable_icc=false" \
        "$NETWORK_NAME"
    echo "[INFO] Network $NETWORK_NAME created successfully."
else
    echo "[INFO] Network $NETWORK_NAME already exists."
fi
