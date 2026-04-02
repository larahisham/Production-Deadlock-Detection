# Deadlock Detector Operator Runbook

## Purpose

This runbook defines routine operations and incident response steps for the production deadlock detector.

## Preconditions

- Detector host has kernel and permissions required for eBPF loading.
- Detector binary built at `src/ebpf/loader`.
- Static and profiler config files exist under `output/`.

## Daily Checks

1. Verify service health:

```bash
tools/cli/deadlockctl status
```

2. Verify dashboard activity:

```bash
tools/cli/deadlockctl dashboard
```

3. Confirm alert stream is not noisy and filters are effective.

## Incident: High Alert Volume

1. Confirm source process names in alerts.
2. Tighten scope in environment values:
- `TARGET_COMM`
- `TARGET_PIDS`
- `TARGET_CGROUP_IDS`
3. Keep profiler suppression enabled:
- `ALLOW_PROFILER_SIGNALS=0`
4. Restart detector:

```bash
tools/cli/deadlockctl restart
```

## Incident: Detector Overhead Too High

1. Run benchmark suite:

```bash
tools/cli/deadlockctl benchmark
```

2. Review:
- `output/phase3_overhead/summary.csv`
- `output/phase3_overhead/tuning_recommendations.txt`

3. Apply tuning recommendations and re-measure.

## Incident: Loader Crash or Restart Loop

1. Inspect logs:

```bash
tools/cli/deadlockctl logs
```

2. If systemd-managed, inspect service details:

```bash
sudo systemctl status deadlock-detector
```

3. Validate binary and object:

```bash
tools/cli/deadlockctl build
```

4. Restart and monitor dashboard lines.

## Rollback Procedure

1. Stop detector:

```bash
tools/cli/deadlockctl stop
```

2. Revert to previous known-good commit and rebuild.
3. Start detector and verify low-noise operation.

## Post-Incident Checklist

1. Capture timeline, affected processes, and lock addresses from alerts.
2. Add static correlation rule if pattern is recurring.
3. Update thresholds only with benchmark evidence.
4. Record action items for follow-up lock-order fixes in services.
