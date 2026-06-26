#!/bin/sh
# Fix volume ownership if needed
if [ -d /home/nullnode/.nullnode ]; then
    chown -R nullnode:nullnode /home/nullnode/.nullnode 2>/dev/null || true
fi
exec "$@"
