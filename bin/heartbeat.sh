#!/bin/bash
HEARTBEAT_FILE="${HEARTBEAT_FILE:-/var/run/ase/last_success.txt}"
MAX_AGE="${MAX_AGE:-86400}" # 24 hours

if [ ! -f "$HEARTBEAT_FILE" ]; then
    logger -t ase-heartbeat "ALERT: heartbeat file missing at $HEARTBEAT_FILE"
    exit 1
fi

file_age=$(( $(date +%s) - $(stat -c %Y "$HEARTBEAT_FILE") ))
if [ "$file_age" -gt "$MAX_AGE" ]; then
    logger -t ase-heartbeat "ALERT: last success was ${file_age}s ago (threshold: ${MAX_AGE}s)"
    exit 1
fi
