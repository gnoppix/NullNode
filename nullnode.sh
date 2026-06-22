#!/bin/bash
#-------------------------------------------------------------------------------
# Name: Gnoppix Linux - Services
# Architecture: all
# Date: 2002-2006 by Gnoppix Linux
# Author: Andreas Mueller
# Website: https://www.gnoppix.com
# Licence: Business Source License (BSL / BUSL)
#-------------------------------------------------------------------------------
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="/tmp/nullnode-venv"

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
    init|id|export|import|contacts|send|chat|p2p|dht)
        exec "$VENV/bin/python" "$DIR/client.py" "$cmd" "$@"
        ;;
    *)
        echo "usage: ./nullnode.sh <relay|init|id|export|import|contacts|send|chat|p2p|dht>"
        exit 1
        ;;
esac
