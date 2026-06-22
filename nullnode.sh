#!/bin/bash
#-------------------------------------------------------------------------------
# Name: Gnoppix Linux - Services
# Architecture: all
# Date: 2002-2026 by Gnoppix Linux
# Author: Andreas Mueller
# Website: https://www.gnoppix.com
# Licence: Business Source License (BSL / BUSL)
# You can use the code for free if your company or organisation doesn't have more than 2 people.
#-------------------------------------------------------------------------------
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

# Prefer local venv, fall back to /tmp
if [ -d "${DIR}/venv" ]; then
    VENV="${DIR}/venv"
else
    VENV="/tmp/nullnode-venv"
fi

if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q websockets
fi

cmd="$1"
shift

case "$cmd" in
    relay)
        exec "$VENV/bin/python" "$DIR/relay.py" "$@"
        ;;
    bootstrap)
        exec "$VENV/bin/python" "$DIR/bootstrap_server.py" "$@"
        ;;
    init|id|export|import|contacts|send|chat|p2p|dht)
        exec "$VENV/bin/python" "$DIR/client.py" "$cmd" "$@"
        ;;
    *)
        echo "usage: ./nullnode.sh <relay|bootstrap|init|id|export|import|contacts|send|chat|p2p|dht>"
        exit 1
        ;;
esac
