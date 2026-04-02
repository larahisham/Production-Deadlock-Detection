#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EBPF_DIR="$ROOT_DIR/src/ebpf"
BENCH_DIR="$ROOT_DIR/tests/benchmarks"
OUT_DIR="$ROOT_DIR/output/phase3_overhead"
ITERATIONS="${ITERATIONS:-3}"
WORKLOAD_BIN="$BENCH_DIR/phase2_benign_lock_order"
WORKLOAD_SRC="$BENCH_DIR/phase2_benign_lock_order.c"

mkdir -p "$OUT_DIR"

now_ms() {
    date +%s%3N
}

measure_workload_ms() {
    local log_file="$1"
    local start_ms
    local end_ms

    start_ms="$(now_ms)"
    timeout 9 "$WORKLOAD_BIN" >"$log_file" 2>&1 || true
    end_ms="$(now_ms)"

    echo $((end_ms - start_ms))
}

max_loader_rss_kb() {
    local loader_pid="$1"
    local rss_kb
    local max_rss=0

    while kill -0 "$loader_pid" 2>/dev/null; do
        rss_kb="$(ps -o rss= -p "$loader_pid" 2>/dev/null | tr -d ' ' || true)"
        rss_kb="${rss_kb:-0}"
        if [[ "$rss_kb" -gt "$max_rss" ]]; then
            max_rss="$rss_kb"
        fi
        sleep 0.2
    done

    echo "$max_rss"
}

extract_max_events() {
    local log_file="$1"

    awk '/\[dashboard\] events=/{
        split($0, a, "events=");
        if (length(a) > 1) {
            split(a[2], b, " ");
            v=b[1]+0;
            if (v>m) m=v;
        }
    } END {print m+0}' "$log_file"
}

extract_alerts() {
    local log_file="$1"

    grep -c "\[ALERT/" "$log_file" || true
}

echo "[1/5] building loader"
pushd "$EBPF_DIR" >/dev/null
make all >/dev/null
popd >/dev/null

if [[ ! -x "$WORKLOAD_BIN" ]]; then
    echo "[2/5] building benchmark workload"
    gcc -O2 -pthread "$WORKLOAD_SRC" -o "$WORKLOAD_BIN"
else
    echo "[2/5] benchmark workload already built"
fi

echo "[3/5] running baseline vs monitored iterations (count=$ITERATIONS)"
echo "iteration,baseline_ms,monitored_ms,overhead_pct,events,alerts,loader_max_rss_kb" >"$OUT_DIR/summary.csv"

for i in $(seq 1 "$ITERATIONS"); do
    baseline_log="$OUT_DIR/baseline_${i}.log"
    workload_log="$OUT_DIR/monitored_workload_${i}.log"
    loader_log="$OUT_DIR/monitored_loader_${i}.log"

    baseline_ms="$(measure_workload_ms "$baseline_log")"

    sudo -v >/dev/null
    pushd "$EBPF_DIR" >/dev/null
    TARGET_COMM="phase2_benign_lock_order" \
    STATIC_FINDINGS_PATH="../../output/static_findings.csv" \
    PROFILER_PATTERNS_PATH="../../output/profiler_filters.txt" \
    ALLOW_PROFILER_SIGNALS=0 \
    sudo --preserve-env=TARGET_COMM,STATIC_FINDINGS_PATH,PROFILER_PATTERNS_PATH,ALLOW_PROFILER_SIGNALS \
        timeout 10 ./loader >"$loader_log" 2>&1 &
    loader_pid=$!
    popd >/dev/null

    sleep 1
    monitored_ms="$(measure_workload_ms "$workload_log")"

    loader_rss_kb="$(max_loader_rss_kb "$loader_pid")"
    wait "$loader_pid" || true

    events="$(extract_max_events "$loader_log")"
    alerts="$(extract_alerts "$loader_log")"

    if [[ "$baseline_ms" -gt 0 ]]; then
        overhead_pct="$(awk -v b="$baseline_ms" -v m="$monitored_ms" 'BEGIN {printf "%.2f", ((m-b)/b)*100.0}')"
    else
        overhead_pct="0.00"
    fi

    echo "$i,$baseline_ms,$monitored_ms,$overhead_pct,$events,$alerts,$loader_rss_kb" >>"$OUT_DIR/summary.csv"
    echo "  iteration=$i baseline_ms=$baseline_ms monitored_ms=$monitored_ms overhead_pct=$overhead_pct events=$events alerts=$alerts loader_max_rss_kb=$loader_rss_kb"
done

echo "[4/5] aggregating"
avg_overhead="$(awk -F',' 'NR>1 {sum+=$4; n++} END {if(n>0) printf "%.2f", sum/n; else print "0.00"}' "$OUT_DIR/summary.csv")"
avg_events="$(awk -F',' 'NR>1 {sum+=$5; n++} END {if(n>0) printf "%.0f", sum/n; else print "0"}' "$OUT_DIR/summary.csv")"
avg_rss_kb="$(awk -F',' 'NR>1 {sum+=$7; n++} END {if(n>0) printf "%.0f", sum/n; else print "0"}' "$OUT_DIR/summary.csv")"

cat >"$OUT_DIR/tuning_recommendations.txt" <<EOF
average_overhead_pct=$avg_overhead
average_events=$avg_events
average_loader_rss_kb=$avg_rss_kb

recommendations:
- If average_overhead_pct > 10, tighten scope via TARGET_COMM/TARGET_PIDS/TARGET_CGROUP_IDS.
- If average_events is very high for your environment, increase min wait thresholds in static findings.
- If alert noise appears in production, keep ALLOW_PROFILER_SIGNALS=0 and expand profiler patterns.
- If loader memory is high, reduce map max entries in deadlock.bpf.c and redeploy after validation.
EOF

echo "[5/5] done"
cat "$OUT_DIR/summary.csv"
echo "average_overhead_pct=$avg_overhead"
echo "results: $OUT_DIR"
