---
name: pipeline-failures
description: Common kola/artifact investigation patterns for CoreOS Jenkins CI - shared foundation for pipeline failure analysis
---

# Pipeline Failures — Common Patterns

Shared knowledge for investigating Jenkins CI pipeline failures in the CoreOS build system.

> Related: `rhcos-pipeline-failures` (RHCOS-specific jobs and workflow), `fcos-ci-failures` (fcos-ci instance and test-override job), `pipeline-jira` (creating failure issues)

## Interpreting Kola Test Failures

The `kola-failures` output includes a `rerun_failed` field:

| Field Value | Meaning | Action |
|-------------|---------|--------|
| `"rerun_failed": true` | Test consistently fails | This is likely the root cause - investigate package changes |
| `"rerun_failed": false` | Test passed on rerun (flaky) | NOT the root cause - look for other errors in logs |

**Decision Tree:**

1. **Test failures with `rerun_failed: true`** → Find last known good build, compare packages to identify regression
2. **Test failures with `rerun_failed: false` only** → Flaky tests, NOT root cause. Check logs for compose/infrastructure errors
3. **No test failures** → Build/infrastructure failure, analyze logs

### Check Kola Test Failures

```bash
# Get kola test failure summary
coreos-tools jenkins builds kola-failures <job-name> <build-number>

# Filter for actual failures (tests that failed on rerun)
coreos-tools jenkins builds kola-failures <job-name> <build-number> | jq '[.failures[] | select(.rerun_failed == true)]'
```

## Analyzing Kola Test Artifacts

When tests fail with `rerun_failed: true`, download and examine kola artifacts:

### Download Kola Artifacts

```bash
# List artifacts (look for kola-*.tar.xz files)
coreos-tools jenkins builds artifacts <job-name> <build-number>

# Download kola artifacts
coreos-tools jenkins builds artifacts <job-name> <build-number> --download kola-<hash>.tar.xz -o /tmp/kola.tar.xz

# Extract
mkdir -p /tmp/kola && tar -xf /tmp/kola.tar.xz -C /tmp/kola
```

### Artifact Structure

```
kola/
├── reports/report.json          # Overall test results
├── <test-name>/
│   └── <uuid>/
│       ├── journal.txt          # systemd journal (primary log)
│       ├── console.txt          # VM console output
│       └── ignition.json        # Ignition config used
└── rerun/                       # Rerun attempts (same structure)
    └── <test-name>/
```

### Analyzing Failures

```bash
# Find test directories
find /tmp/kola -type d -name "*<test-pattern>*"

# Search for errors in journal
rg "Error:|Failed|error:" /tmp/kola/kola/<test-name>/*/journal.txt

# Check Ignition config for missing files
cat /tmp/kola/kola/<test-name>/*/ignition.json | jq '.storage'

# Compare initial run vs rerun
rg "" /tmp/kola/kola/<test>/*/journal.txt > /tmp/initial.txt
rg "" /tmp/kola/kola/rerun/<test>/*/journal.txt > /tmp/rerun.txt
```

### What to Look For

- **Missing files in Ignition**: Empty `storage` section when files should be injected
- **Systemd unit failures**: Services failing with exit codes
- **Kernel errors**: Buffer I/O errors, driver failures
- **Boot issues**: ignition.firstboot, ostree deployment errors

## Log Analysis Patterns

```bash
# Get build info (parameters, trigger cause, duration)
coreos-tools jenkins builds info <job-name> <build-number>

# Download console log for analysis
coreos-tools jenkins builds log <job-name> <build-number> | jq -r '.console_log[]' > /tmp/build.log

# General errors
rg "^error:|FATAL:|failed to|cannot |Error:" /tmp/build.log | tail -20

# Infrastructure issues
rg "timeout|timed out|Connection refused|503|500|temporarily unavailable" /tmp/build.log

# Stage failures
rg "FAILED|UNSTABLE" /tmp/build.log
```

### Pattern Recognition

| Pattern | Category | Typical Action |
|---------|----------|----------------|
| `ERROR:` or `FATAL:` | Build/compose error | Investigate package or cosa change |
| Timeout errors | Infrastructure | Retry, check resources |
| Network/connectivity | Transient | Retry |
| `Permission denied` | SELinux/config | Investigate policy changes |
| `No space left on device` | Disk exhaustion | Clean up or expand storage |

## Triggering Retries

```bash
# Check if a build is already running first
coreos-tools jenkins builds list <job-name> -n 5

# Trigger retry - parameters vary by job/instance, see specific skill for details
coreos-tools jenkins jobs build <job-name> -p <KEY>=<value>
```

See `rhcos-pipeline-failures` or `fcos-ci-failures` for job-specific retry parameters.
