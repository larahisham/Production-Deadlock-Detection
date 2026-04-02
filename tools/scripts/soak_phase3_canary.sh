#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EBPF_DIR="$ROOT_DIR/src/ebpf"
BENCH_DIR="$ROOT_DIR/tests/benchmarks"
OUT_DIR="$ROOT_DIR/output/phase3_soak"
WORKLOAD_BIN="$BENCH_DIR/phase2_benign_lock_order"
WORKLOAD_SRC="$BENCH_DIR/phase2_benign_lock_order.c"
SOAK_SECONDS="${SOAK_SECONDS:-120}"
SCOPE_COMM="${SCOPE_COMM:-phase2_benign_lock_order}"

mkdir -p "$OUT_DIR"

now_epoch() {
    date +%s
}

start_workload_once() {
    local log_file="$1"

    timeout 9 "$WORKLOAD_BIN" >"$log_file" 2>&1 || true
}

echo "[1/6] building loader"
pushd "$EBPF_DIR" >/dev/null
make all >/dev/null
popd >/dev/null

if [[ ! -x "$WORKLOAD_BIN" ]]; then
    echo "[2/6] building benchmark workload"
    gcc -O2 -pthread "$WORKLOAD_SRC" -o "$WORKLOAD_BIN"
else
    echo "[2/6] benchmark workload already built"
fi

echo "[3/6] starting canary loader for ${SOAK_SECONDS}s"
sudo -v >/dev/null
pushd "$EBPF_DIR" >/dev/null
TARGET_COMM="$SCOPE_COMM" \
STATIC_FINDINGS_PATH="../../output/static_findings.csv" \
PROFILER_PATTERNS_PATH="../../output/profiler_filters.txt" \
ALLOW_PROFILER_SIGNALS=0 \
sudo --preserve-env=TARGET_COMM,STATIC_FINDINGS_PATH,PROFILER_PATTERNS_PATH,ALLOW_PROFILER_SIGNALS \
    timeout "$SOAK_SECONDS" ./loader >"$OUT_DIR/soak_loader.log" 2>&1 &
loader_pid=$!
popd >/dev/null

sleep 1

echo "[4/6] exercising workload during soak"
start_epoch="$(now_epoch)"
workload_runs=0
while [[ $(( $(now_epoch) - start_epoch )) -lt "$SOAK_SECONDS" ]]; do
    start_workload_once "$OUT_DIR/workload_${workload_runs}.log"
    workload_runs=$((workload_runs + 1))
done

wait "$loader_pid" || true

echo "[5/6] summarizing canary"
alerts="$(grep -c "\[ALERT/" "$OUT_DIR/soak_loader.log" || true)"
dashboard_events="$(awk '/\[dashboard\] events=/{split($0, a, "events="); if (length(a) > 1) {split(a[2], b, " "); v=b[1]+0; if (v>m) m=v;}} END {print m+0}' "$OUT_DIR/soak_loader.log")"
dashboard_alerts="$(awk '/\[dashboard\] alerts=/{split($0, a, "alerts="); if (length(a) > 1) {split(a[2], b, " "); v=b[1]+0; if (v>m) m=v;}} END {print m+0}' "$OUT_DIR/soak_loader.log")"
restart_hits="$(grep -c "restart" "$OUT_DIR/soak_loader.log" || true)"

cat >"$OUT_DIR/summary.csv" <<EOF
duration_seconds,scope_comm,workload_runs,alerts,dashboard_events,dashboard_alerts,restart_hits
$SOAK_SECONDS,$SCOPE_COMM,$workload_runs,$alerts,$dashboard_events,$dashboard_alerts,$restart_hits
EOF

cat >"$OUT_DIR/status.txt" <<EOF
duration_seconds=$SOAK_SECONDS
scope_comm=$SCOPE_COMM
workload_runs=$workload_runs
alerts=$alerts
dashboard_events=$dashboard_events
dashboard_alerts=$dashboard_alerts
restart_hits=$restart_hits
EOF

echo "[6/6] done"
cat "$OUT_DIR/summary.csv"
echo "results: $OUT_DIR"