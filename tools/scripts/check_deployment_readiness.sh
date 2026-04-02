#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOC_FILE="$ROOT_DIR/docs/phase3-productionization.md"
PHASE2_SUMMARY="$ROOT_DIR/output/phase2_validation/summary.csv"
PHASE3_SUMMARY="$ROOT_DIR/output/phase3_overhead/summary.csv"
SOAK_SUMMARY="$ROOT_DIR/output/phase3_soak/summary.csv"
SERVICE_FILE="$ROOT_DIR/tools/daemon/deadlock-detector.service"
ENV_FILE="$ROOT_DIR/tools/daemon/deadlock-detector.env"

failures=0

require_file() {
    local path="$1"
    local label="$2"

    if [[ -f "$path" ]]; then
        echo "[ok] $label"
    else
        echo "[fail] missing $label: $path"
        failures=$((failures + 1))
    fi
}

require_file "$DOC_FILE" "productionization guide"
require_file "$SERVICE_FILE" "systemd service"
require_file "$ENV_FILE" "service env file"
require_file "$PHASE2_SUMMARY" "phase 2 validation summary"
require_file "$PHASE3_SUMMARY" "phase 3 overhead summary"
require_file "$SOAK_SUMMARY" "phase 3 soak summary"

if [[ -f "$PHASE2_SUMMARY" ]]; then
    benign_alerts="$(awk -F',' '$1=="phase2_benign_lock_order" {print $2}' "$PHASE2_SUMMARY")"
    deadlock_alerts="$(awk -F',' '$1=="phase2_deadlock_cycle" {print $2}' "$PHASE2_SUMMARY")"

    benign_alerts="${benign_alerts:-0}"
    deadlock_alerts="${deadlock_alerts:-0}"

    if [[ "$benign_alerts" -eq 0 ]]; then
        echo "[ok] phase 2 benign case has zero alerts"
    else
        echo "[fail] phase 2 benign case is noisy: $benign_alerts alerts"
        failures=$((failures + 1))
    fi

    if [[ "$deadlock_alerts" -ge 1 ]]; then
        echo "[ok] phase 2 deadlock case produced alerts"
    else
        echo "[fail] phase 2 deadlock case did not produce an alert"
        failures=$((failures + 1))
    fi
fi

if [[ -f "$PHASE3_SUMMARY" ]]; then
    average_overhead="$(awk -F',' 'NR>1 {sum+=$4; n++} END {if(n>0) printf "%.2f", sum/n; else print "0.00"}' "$PHASE3_SUMMARY")"
    average_overhead="${average_overhead:-0.00}"

    if awk -v overhead="$average_overhead" 'BEGIN {exit !(overhead <= 1.00)}'; then
        echo "[ok] average overhead is within 1%: ${average_overhead}%"
    else
        echo "[warn] average overhead exceeds 1%: ${average_overhead}%"
    fi
fi

if [[ -f "$SOAK_SUMMARY" ]]; then
    soak_duration="$(awk -F',' 'NR==2 {print $1}' "$SOAK_SUMMARY")"
    soak_alerts="$(awk -F',' 'NR==2 {print $4}' "$SOAK_SUMMARY")"
    soak_restart_hits="$(awk -F',' 'NR==2 {print $7}' "$SOAK_SUMMARY")"

    soak_duration="${soak_duration:-0}"
    soak_alerts="${soak_alerts:-0}"
    soak_restart_hits="${soak_restart_hits:-0}"

    if [[ "$soak_duration" -ge 60 ]]; then
        echo "[ok] soak ran for at least 60 seconds"
    else
        echo "[fail] soak duration too short: ${soak_duration}s"
        failures=$((failures + 1))
    fi

    if [[ "$soak_restart_hits" -eq 0 ]]; then
        echo "[ok] soak showed no restart loop signals"
    else
        echo "[fail] soak log shows restart loop signals: $soak_restart_hits"
        failures=$((failures + 1))
    fi

    if [[ "$soak_alerts" -eq 0 ]]; then
        echo "[ok] soak remained quiet on the benign canary"
    else
        echo "[fail] soak produced noisy benign-canary alerts: $soak_alerts"
        failures=$((failures + 1))
    fi
fi

echo
echo "readiness: $([[ "$failures" -eq 0 ]] && echo PASS || echo FAIL)"

exit "$failures"