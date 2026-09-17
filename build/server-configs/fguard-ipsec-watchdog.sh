#!/bin/bash
# FGUARD - IPSec tunnel watchdog
# Initiates the IPSec child SA if tunnel is not ESTABLISHED.
# Run via cron every 2 minutes.
#
# flock: only one instance runs at a time (prevents process pile-up if swanctl hangs)
# timeout: swanctl --initiate capped at 30s so it can never block indefinitely
CHILD_NAME="tavros"
LOG="/var/log/fguard-ipsec-watchdog.log"
LOCK="/var/run/fguard-ipsec-watchdog.lock"

exec 9>"$LOCK"
flock -n 9 || exit 0

STATUS=$(timeout 10 swanctl --list-sas 2>/dev/null | grep -c "ESTABLISHED")
if [[ "$STATUS" -eq 0 ]]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S'): Tunnel not ESTABLISHED, triggering initiate" >> "$LOG"
    timeout 30 swanctl --initiate --child "$CHILD_NAME" >> "$LOG" 2>&1
    echo "$(date '+%Y-%m-%d %H:%M:%S'): initiate exit code: $?" >> "$LOG"
fi
