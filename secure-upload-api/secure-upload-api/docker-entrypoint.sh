#!/bin/bash
set -e

echo "Starting ClamAV daemon..."
clamd &
CLAMD_PID=$!

# Wait for clamd to be ready
echo "Waiting for ClamAV to initialise..."
for i in $(seq 1 30); do
    if clamdscan --ping 2>/dev/null; then
        echo "ClamAV ready."
        break
    fi
    sleep 2
done

echo "Starting Secure Upload API..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 "$@"
