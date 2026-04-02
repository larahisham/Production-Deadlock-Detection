#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EBPF_DIR="$ROOT_DIR/src/ebpf"
BENCH_DIR="$ROOT_DIR/tests/benchmarks"
OUT_DIR="$ROOT_DIR/output/phase2_validation"

mkdir -p "$OUT_DIR"

echo "[1/6] Building eBPF loader"
pushd "$EBPF_DIR" >/dev/null
make clean >/dev/null
make all >/dev/null
popd >/dev/null

echo "[2/6] Building benchmark workloads"
gcc -O2 -pthread "$BENCH_DIR/phase2_benign_lock_order.c" -o "$BENCH_DIR/phase2_benign_lock_order"
gcc -O2 -pthread "$BENCH_DIR/phase2_deadlock_cycle.c" -o "$BENCH_DIR/phase2_deadlock_cycle"

run_case() {
    local case_name="$1"
    local workload_bin="$2"
    local loader_log="$OUT_DIR/${case_name}_loader.log"
    local workload_log="$OUT_DIR/${case_name}_workload.log"

    echo "[case:$case_name] priming sudo"
    sudo -v

    echo "[case:$case_name] starting scoped loader"
    pushd "$EBPF_DIR" >/dev/null
    TARGET_COMM="$case_name" \
    STATIC_FINDINGS_PATH="../../output/static_findings.csv" \
    PROFILER_PATTERNS_PATH="../../output/profiler_filters.txt" \
    ALLOW_PROFILER_SIGNALS=0 \
    sudo --preserve-env=TARGET_COMM,STATIC_FINDINGS_PATH,PROFILER_PATTERNS_PATH,ALLOW_PROFILER_SIGNALS \
        timeout 10 ./loader >"$loader_log" 2>&1 &
    local loader_pid=$!
    popd >/dev/null

    sleep 1

    echo "[case:$case_name] running workload"
    timeout 9 "$workload_bin" >"$workload_log" 2>&1 || true

    wait "$loader_pid" || true

    local alert_count
    local filtered_max
    local events_max

    alert_count=$(grep -c "\[ALERT/" "$loader_log" || true)

    filtered_max=$(awk '/\[dashboard\] alerts=/{
        split($0, a, "filtered=");
        if (length(a) > 1) {
            split(a[2], b, " ");
            v=b[1]+0;
            if (v>m) m=v;
        }
    } END {print m+0}' "$loader_log")

    events_max=$(awk '/\[dashboard\] events=/{
        split($0, a, "events=");
        if (length(a) > 1) {
            split(a[2], b, " ");
            v=b[1]+0;
            if (v>m) m=v;
        }
    } END {print m+0}' "$loader_log")

    filtered_max="${filtered_max:-0}"
    events_max="${events_max:-0}"

    echo "$case_name,$alert_count,$events_max,$filtered_max" >>"$OUT_DIR/summary.csv"
}

echo "case,alerts,events,filtered" >"$OUT_DIR/summary.csv"

echo "[3/6] Running benign scenario (expect low/no alerts)"
run_case "phase2_benign_lock_order" "$BENCH_DIR/phase2_benign_lock_order"

echo "[4/6] Running deadlock scenario (expect alerts)"
run_case "phase2_deadlock_cycle" "$BENCH_DIR/phase2_deadlock_cycle"

echo "[5/6] Calculating precision-style quick metric"
benign_alerts=$(awk -F',' '$1=="phase2_benign_lock_order" {print $2}' "$OUT_DIR/summary.csv")
deadlock_alerts=$(awk -F',' '$1=="phase2_deadlock_cycle" {print $2}' "$OUT_DIR/summary.csv")

benign_alerts="${benign_alerts:-0}"
deadlock_alerts="${deadlock_alerts:-0}"

if [[ "$deadlock_alerts" -gt 0 ]]; then
    detection_score="PASS"
else
    detection_score="FAIL"
fi

if [[ "$benign_alerts" -eq 0 ]]; then
    noise_score="PASS"
else
    noise_score="WARN"
fi

echo "[6/6] Validation summary"
cat "$OUT_DIR/summary.csv"
echo "detection_score=$detection_score"
echo "noise_score=$noise_score"

echo "logs written under: $OUT_DIR"
