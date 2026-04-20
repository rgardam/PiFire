#!/usr/bin/env bash
set -e
cd /app

mkdir -p /app/logs /app/history /app/recipes /app/backups

python /app/docker/seed_settings.py

python /app/control.py &
CONTROL_PID=$!

gunicorn -k eventlet -b 0.0.0.0:8000 -w 1 app:app &
WEB_PID=$!

trap 'kill -TERM $CONTROL_PID $WEB_PID 2>/dev/null; wait' TERM INT

wait -n
EXIT_CODE=$?
kill -TERM $CONTROL_PID $WEB_PID 2>/dev/null || true
exit $EXIT_CODE
