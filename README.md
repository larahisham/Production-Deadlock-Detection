# Production Deadlock Detection

Production deadlocks are expensive, noisy, and hard to root-cause under live traffic. This project turns lock contention telemetry into production-grade deadlock-risk alerts using eBPF + userspace analysis.

It traces lock and wait behavior in near real time, builds a wait-for graph in userspace, detects blocking cycles, and emits actionable alerts with severity and remediation hints. It also includes deployment assets: overhead benchmarks, canary soak, daemonization, CLI operations, and runbooks.

## Why This Exists

Deadlock incidents are painful in production because:
- Symptoms look like random latency spikes, stalls, and timeout storms.
- Postmortems often miss transient lock interactions.
- Stack dumps alone usually do not prove who is blocked by whom.

This detector addresses that by continuously observing lock behavior and correlating blocked threads with likely owners while filtering expected noise.

## Architecture At A Glance

1. eBPF probes collect lock lifecycle events (`block`, `unblock`, `acquire`, `release`).
2. Events flow through a ring buffer into the userspace loader.
3. The loader builds a bounded wait-for graph and checks for blocking cycles.
4. Quality filters, static correlation, cooldowns, and repeat thresholds reduce false positives.
5. Operators consume dashboard summaries and actionable alerts.

Key implementation files:
- eBPF program: [src/ebpf/deadlock.bpf.c](src/ebpf/deadlock.bpf.c)
- Userspace analysis engine: [src/ebpf/loader.c](src/ebpf/loader.c)
- CLI operations: [tools/cli/deadlockctl](tools/cli/deadlockctl)

## Measured Results

Current repository artifacts show:
- Overhead: `0.00%` average in [output/phase3_overhead/summary.csv](output/phase3_overhead/summary.csv)
- Signal quality: benign `0 alerts`, deadlock case `1 alert` in [output/phase2_validation/summary.csv](output/phase2_validation/summary.csv)
- Canary soak: `60s`, `0 alerts`, `0 restart hits` in [output/phase3_soak/summary.csv](output/phase3_soak/summary.csv)

Use the deployment gate to verify the same on your machine:

```bash
bash tools/cli/deadlockctl readiness
```

## Quick Demo In 5 Minutes

This demo compiles the detector, runs signal-quality checks, runs a short canary soak, and prints readiness.

### 1) Build

```bash
tools/cli/deadlockctl build
```

### 2) Run phase-2 signal check

```bash
tools/cli/deadlockctl validate-phase2
```

Expected: benign case stays quiet, deadlock case produces alerts.

### 3) Run a 60-second canary soak

```bash
SOAK_SECONDS=60 tools/cli/deadlockctl soak
```

Expected: no restart-loop signal, and for the scoped benign canary, no alerts.

### 4) Run deployment readiness gate

```bash
tools/cli/deadlockctl readiness
```

Expected final line:

```text
readiness: PASS
```

If readiness fails, use:
- [docs/phase3-productionization.md](docs/phase3-productionization.md)
- [docs/runbook-operations.md](docs/runbook-operations.md)

## What Problem This Solves

Deadlocks are expensive to diagnose in production because:
- They often appear as random latency spikes, thread stalls, or timeout storms.
- Traditional postmortems miss transient lock interactions.
- Stack dumps alone do not always reveal cross-thread lock-order inversion.

This project solves that by continuously observing lock behavior and translating low-level events into operator-facing signals.

## Why This Approach

### Why eBPF
- Kernel-safe instrumentation without patching application code.
- Low-overhead, event-driven telemetry.
- Works on live systems where reproducing deadlocks is difficult.

### Why userspace graph analysis
- eBPF programs must stay verifier-safe and bounded.
- Cycle detection and scoring are easier and safer in userspace.
- Operational logic (filtering, dedup, severity, correlation) can evolve rapidly.

## What Is Implemented

## Phase 1: Core Detection Pipeline
- Real blocked-edge tracking.
- Wait and hold timing fields.
- Userspace wait-for graph engine.
- Actionable alert payloads with lock, thread, wait, and source context.

## Phase 2: Signal Quality
- False-positive filtering by process, comm, and cgroup scope.
- Profiler suppression support.
- Static findings correlation and scoring boosts.
- Dedup, cooldown, repeat thresholds, and active-block scans.
- Rust/runtime-aware heuristics.
- State aging and garbage collection.

## Phase 3: Productionization
- Overhead benchmarking and tuning script.
- 24/7 daemonization via systemd unit and env file.
- CLI operations and dashboard stream wrapper.
- Operator docs and runbook.

## How It Works

## 1) eBPF Event Collection
The eBPF program in [src/ebpf/deadlock.bpf.c](src/ebpf/deadlock.bpf.c) collects lock lifecycle and wait events from:
- Kernel mutex probes:
  - kprobe mutex_lock
  - kretprobe mutex_lock
  - kprobe mutex_unlock
- Userspace pthread probes:
  - uprobe pthread_mutex_lock
  - uretprobe pthread_mutex_lock
  - uprobe pthread_mutex_unlock
- Futex tracepoints:
  - sys_enter_futex
  - sys_exit_futex

It publishes normalized lock events through a ring buffer map, with fields such as pid, tid, owner_tid, lock address, source, timestamp, wait_ns, and hold_ns.

## 2) Userspace Analysis and Alerts
The loader in [src/ebpf/loader.c](src/ebpf/loader.c):
- Attaches all probes and consumes ring buffer events.
- Maintains blocked edges and lock statistics.
- Performs bounded cycle checks over wait edges.
- Applies quality filters and thresholds.
- Emits alerts with severity and remediation hints.
- Prints dashboard summaries (events, filtered, alerts, slowest locks).

## 3) Scope and Noise Control
Runtime controls include:
- TARGET_PIDS
- TARGET_CGROUP_IDS
- TARGET_COMM
- ALLOW_PROFILER_SIGNALS
- STATIC_FINDINGS_PATH
- PROFILER_PATTERNS_PATH

These controls are used in both ad hoc and daemonized operation.

## Architecture Overview

1. eBPF probes generate lock and wait events.
2. Events flow through ring buffer map.
3. Loader consumes events and updates graph state.
4. Cycle/risk evaluation triggers deduplicated alerts.
5. Dashboard/log output feeds operators and scripts.

## Repository Highlights

- eBPF program: [src/ebpf/deadlock.bpf.c](src/ebpf/deadlock.bpf.c)
- Userspace loader: [src/ebpf/loader.c](src/ebpf/loader.c)
- Build rules: [src/ebpf/Makefile](src/ebpf/Makefile)
- CLI: [tools/cli/deadlockctl](tools/cli/deadlockctl)
- Phase 2 validation harness: [tools/scripts/validate_phase2_signal_quality.sh](tools/scripts/validate_phase2_signal_quality.sh)
- Phase 3 overhead benchmark: [tools/scripts/benchmark_phase3_overhead.sh](tools/scripts/benchmark_phase3_overhead.sh)
- Service install helper: [tools/scripts/install_phase3_service.sh](tools/scripts/install_phase3_service.sh)
- systemd service: [tools/daemon/deadlock-detector.service](tools/daemon/deadlock-detector.service)
- Service env defaults: [tools/daemon/deadlock-detector.env](tools/daemon/deadlock-detector.env)
- Productionization guide: [docs/phase3-productionization.md](docs/phase3-productionization.md)
- Operator runbook: [docs/runbook-operations.md](docs/runbook-operations.md)

## Prerequisites

- Linux host with eBPF support.
- clang (for BPF object build).
- gcc, libbpf, libelf, zlib development libs.
- sudo/root privileges for probe attachment.

## Build

From repository root:

```bash
cd src/ebpf
make all
```

This builds:
- deadlock.bpf.o
- loader

## Quick Start

## Option 0: Interactive terminal UI (cute mode)

```bash
tools/cli/deadlockctl ui
```

Includes a spider splash screen, interactive command menu, and cute success/error panels.

## Option A: CLI (recommended)

```bash
tools/cli/deadlockctl build
tools/cli/deadlockctl start
tools/cli/deadlockctl dashboard
```

Stop:

```bash
tools/cli/deadlockctl stop
```

## Option B: Direct loader run

```bash
cd src/ebpf
sudo ./loader
```

## Validation and Benchmarks

## Phase 2 signal-quality validation

```bash
tools/scripts/validate_phase2_signal_quality.sh
```

Artifacts are written to output/phase2_validation.

## Phase 3 overhead benchmarking

```bash
ITERATIONS=3 tools/scripts/benchmark_phase3_overhead.sh
```

Artifacts are written to output/phase3_overhead.

## Phase 3 canary soak

```bash
SOAK_SECONDS=60 tools/scripts/soak_phase3_canary.sh
```

Artifacts are written to output/phase3_soak.

## 24/7 Daemonization (systemd)

Install and start:

```bash
sudo tools/scripts/install_phase3_service.sh
```

Service controls:

```bash
sudo systemctl status deadlock-detector
sudo systemctl restart deadlock-detector
sudo journalctl -u deadlock-detector -f
```

Configuration file:
- /etc/default/deadlock-detector

## Alert Model

A typical alert includes:
- blocked thread and owner thread IDs
- lock address
- source (mutex, pthread, futex)
- wait duration
- severity score
- operator action hints

Alerts are intentionally gated by cycle checks, repeat logic, and cooldown to reduce noise.

## Operational Guidance

Start with narrow scope in production:
- Set TARGET_COMM for initial rollout.
- Add PID or cgroup scope for high-volume hosts.
- Keep profiler suppression enabled unless debugging profiler behavior.

Use runbook for incident response:
- [docs/runbook-operations.md](docs/runbook-operations.md)

## Known Limitations

- This is a practical detector, not a formal proof engine.
- Address-based lock identity may vary across process restarts.
- Futex-heavy workloads can still require tuning for optimal precision.
- Kernel/BTF/libbpf compatibility may require environment-specific adjustments.

## Project Outcome

This project now provides:
- A functioning deadlock-risk detector with actionable alerts.
- Production-oriented controls for noise and overhead.
- Repeatable validation and benchmark workflows.
- Operator-ready daemon, CLI, and runbook support.

In short, it turns lock contention telemetry into an operational deadlock early-warning system suitable for staged production rollout.
