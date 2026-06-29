#!/bin/bash
# hermes-verify-tests.sh - Run all unit tests (excluding dht-core SQLite tests)

echo "=== Unit Tests ==="

echo "[1] nullnode-crypto..."
cargo test -p nullnode-crypto --lib --quiet 2>&1 | tail -1

echo "[2] nullnode-protocol..."
cargo test -p nullnode-protocol --lib --quiet 2>&1 | tail -1

echo "[3] nullnode-p2p..."
cargo test -p nullnode-p2p --lib --quiet 2>&1 | tail -1

echo "[4] nullnode-relay..."
cargo test -p nullnode-relay --quiet 2>&1 | tail -1

echo "[5] nullnode-client..."
cargo test -p nullnode-client --quiet 2>&1 | tail -1

echo "=== Tests Complete ==="
