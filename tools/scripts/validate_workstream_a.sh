#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EBPF_DIR="$ROOT_DIR/src/ebpf"
FIX_DIR="$ROOT_DIR/tests/fixtures"
OUT_DIR="$ROOT_DIR/output/workstream_a_validation"
SOCKET_PATH="/tmp/deadlock-detector.sock"

mkdir -p "$OUT_DIR"

echo "[1/7] Build loader + preload tracer + dwarf helper"
pushd "$EBPF_DIR" >/dev/null
make clean >/dev/null
make all >/dev/null
popd >/dev/null

echo "[2/7] Build Rust std deadlock fixture"
rustc "$FIX_DIR/rust_std_deadlock.rs" -O -o "$FIX_DIR/rust_std_deadlock"

echo "[3/7] Build Java deadlock fixture"
if command -v javac >/dev/null 2>&1; then
    javac "$FIX_DIR/java_deadlock.java"
else
    echo "[warn] javac not available, skipping Java build"
fi

echo "[4/7] Optionally build parking_lot/tokio fixtures via cargo"
if command -v cargo >/dev/null 2>&1; then
    TMP_CARGO="$OUT_DIR/cargo_tmp"
    rm -rf "$TMP_CARGO"
    mkdir -p "$TMP_CARGO/src"

    cat >"$TMP_CARGO/Cargo.toml" <<'EOF'
[package]
name = "workstream_a_tmp"
version = "0.1.0"
edition = "2021"

[dependencies]
parking_lot = "0.12"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time"] }
EOF

    cp "$FIX_DIR/parking_lot_deadlock.rs" "$TMP_CARGO/src/main.rs"
    cargo build --release --manifest-path "$TMP_CARGO/Cargo.toml" >/dev/null
    cp "$TMP_CARGO/target/release/workstream_a_tmp" "$FIX_DIR/parking_lot_deadlock"

    cp "$FIX_DIR/tokio_deadlock.rs" "$TMP_CARGO/src/main.rs"
    cargo build --release --manifest-path "$TMP_CARGO/Cargo.toml" >/dev/null
    cp "$TMP_CARGO/target/release/workstream_a_tmp" "$FIX_DIR/tokio_deadlock"
else
    echo "[warn] cargo not available, skipping parking_lot/tokio build"
fi

echo "[5/7] Generate rust symbol hints from built fixtures"
"$ROOT_DIR/tools/lock-symbols/find_rust_symbols.sh" \
    "$FIX_DIR/rust_std_deadlock" \
    "$FIX_DIR/parking_lot_deadlock" \
    "$FIX_DIR/tokio_deadlock" >/dev/null 2>&1 || true

echo "[6/7] Run detector against rust_std_deadlock"
sudo -v
pushd "$EBPF_DIR" >/dev/null
TARGET_COMM=rust_std_deadlock \
RUST_MUTEX_SYMBOLS_PATH="../../output/rust_mutex_symbols.txt" \
LOCK_DWARF_MAP_PATH="../../output/lock_dwarf_map.txt" \
ALLOW_PROFILER_SIGNALS=0 \
STATIC_FINDINGS_PATH="../../output/static_findings.csv" \
PROFILER_PATTERNS_PATH="../../output/profiler_filters.txt" \
sudo --preserve-env=TARGET_COMM,RUST_MUTEX_SYMBOLS_PATH,LOCK_DWARF_MAP_PATH,ALLOW_PROFILER_SIGNALS,STATIC_FINDINGS_PATH,PROFILER_PATTERNS_PATH \
    timeout 12 ./loader >"$OUT_DIR/rust_loader.log" 2>&1 &
LOADER_PID=$!
popd >/dev/null

sleep 1
(timeout 10 "$FIX_DIR/rust_std_deadlock" >"$OUT_DIR/rust_std_deadlock.log" 2>&1 || true)
wait "$LOADER_PID" || true

echo "[7/7] Optional preload socket smoke test"
if [[ -S "$SOCKET_PATH" ]]; then
    echo "preload_socket=present" >"$OUT_DIR/preload_status.txt"
else
    echo "preload_socket=not_present" >"$OUT_DIR/preload_status.txt"
fi

alerts=$(grep -c "\[ALERT/" "$OUT_DIR/rust_loader.log" || true)
source_hits=$(grep -Ec "source=rust_std|source=parking_lot|source=preload" "$OUT_DIR/rust_loader.log" || true)

echo "alerts=$alerts" >"$OUT_DIR/summary.txt"
echo "source_hits=$source_hits" >>"$OUT_DIR/summary.txt"
echo "logs=$OUT_DIR" >>"$OUT_DIR/summary.txt"

cat "$OUT_DIR/summary.txt"
