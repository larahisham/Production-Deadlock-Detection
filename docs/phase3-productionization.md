# Phase 3 Productionization Guide

This guide defines the minimum bar for rolling the detector into production and the operational steps for a staged rollout.

## Deployment Gate

Treat the system as deployable only when all of the following are true in the target environment:

1. The eBPF loader builds successfully.
2. Phase 2 validation passes with `phase2_benign_lock_order=0 alerts` and `phase2_deadlock_cycle>=1 alert`.
3. Phase 3 overhead stays within the agreed budget for the target workload.
4. The service starts cleanly under `systemd` and a soak/canary run completes without restart-loop signals.
5. Operator alerts are actionable and remain low-noise under the intended scope.

The repository includes a helper gate at `tools/cli/deadlockctl readiness` that checks the local artifacts used by the release process.
The soak workflow is at `tools/cli/deadlockctl soak`.

## Recommended Rollout Sequence

### 1. Build and validate locally

```bash
tools/cli/deadlockctl build
tools/cli/deadlockctl validate-phase2
tools/cli/deadlockctl benchmark
tools/cli/deadlockctl soak
tools/cli/deadlockctl readiness
```

### 2. Install the service on one host

```bash
sudo tools/scripts/install_phase3_service.sh
sudo systemctl status deadlock-detector
```

### 3. Start with a narrow scope

Use one or more of the following filters for the canary:

- `TARGET_COMM`
- `TARGET_PIDS`
- `TARGET_CGROUP_IDS`
- `ALLOW_PROFILER_SIGNALS=0`

The default profile is intentionally conservative so the first rollout favors signal quality over breadth.

### 4. Observe the canary

Monitor these outputs during the initial window:

- `tools/cli/deadlockctl dashboard`
- `tools/cli/deadlockctl logs`
- `output/phase3_overhead/summary.csv`
- `output/phase2_validation/summary.csv`

Look for:

- repeated alerts on the same blocked/owner pair
- sustained growth in `filtered` counts that suggests noisy scope selection
- slowest-lock summaries that point to a repeatable hot path
- stable RSS and no restart loops in the service
- zero alerts, or at most an accepted noise budget, on the benign canary before rollout expands

### 5. Expand scope only after the canary is clean

Broaden the deployment in this order:

1. Add more PIDs for the same service.
2. Expand to a cgroup.
3. Expand to the host-wide profile only when alert noise remains bounded.

## Operator Rules

- Keep profiler suppression enabled unless you are explicitly validating profiler behavior.
- Prefer narrow scope first; broad host-wide attachment is the last rollout step.
- Review static findings before widening scope, especially for services with known lock hotspots.
- Use the dashboard summary to identify the slowest wait and hold paths before escalating to application owners.

## Alert Expectations

A useful alert should contain:

- blocked thread and owner thread IDs
- lock address
- wait duration
- source runtime or lock family
- severity score
- remediation hint

If an alert does not point to a blocked thread and a likely owner, it is not actionable enough for production use.

## Rollback Criteria

Rollback immediately if any of the following occur:

- sustained restart loop
- overhead exceeds the agreed threshold for the environment
- a benign workload produces repeated alerts
- the detector floods operators with alerts that do not map to concrete lock paths

Rollback steps:

```bash
tools/cli/deadlockctl stop
sudo systemctl disable deadlock-detector
```

If the host was installed via the service helper, you can remove the unit and config with the uninstall workflow in `tools/cli/deadlockctl`.

## Production Tuning Checklist

- Set `TARGET_COMM` before broadening to multiple services.
- Keep `ALLOW_PROFILER_SIGNALS=0` for normal operations.
- Update `STATIC_FINDINGS_PATH` when new known lock inversions are confirmed.
- Update `PROFILER_PATTERNS_PATH` when new profiler tools appear in the environment.
- Re-run `tools/cli/deadlockctl benchmark` after each tuning change.

## Support Boundaries

This project is intended to surface blocking behavior early and clearly. It is not a formal proof engine and it still depends on environment-specific validation for the final production sign-off.