---
name: pipeline-failures
description: Investigate Jenkins CI pipeline failures - failure patterns, root cause analysis, and debugging workflows
---

# Pipeline Failures Investigation

Knowledge for investigating Jenkins CI pipeline failures in the CoreOS build system.

> Related: `rhcos-build-pipeline` (Jenkins jobs), `rhcos-artifacts` (artifacts, diffs, cosa comparison), `jira-workflows` (creating failure issues)

## Investigation Workflow

### 1. Identify the Failure

```bash
# List recent failures
coreos-tools jenkins builds list <job-name> --status FAILURE -n 5

# Check if failure is in build-arch (for build job failures)
coreos-tools jenkins builds list build-arch --status FAILURE -n 5
```

### 2. Get Build Details

```bash
# Get build info (parameters, trigger cause, duration)
coreos-tools jenkins builds info <job-name> <build-number>

# Download console log for analysis
coreos-tools jenkins builds log <job-name> <build-number> | jq -r '.console_log[]' > /tmp/build.log
```

### 3. Check Kola Test Failures

```bash
# Get kola test failure summary
coreos-tools jenkins builds kola-failures <job-name> <build-number>

# Filter for actual failures (tests that failed on rerun)
coreos-tools jenkins builds kola-failures <job-name> <build-number> | jq '[.failures[] | select(.rerun_failed == true)]'
```

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

## Finding Last Known Good Build

```bash
# Find last successful build for same stream (filter out "no new build" entries)
coreos-tools jenkins builds list <job-name> --status SUCCESS --stream <stream> -n 20 | \
  jq '[.[] | select(.description | test("no new build") | not)] | first'
```

## Log Analysis Patterns

```bash
# General errors
grep -E "^error:|FATAL:|failed to|cannot |Error:" /tmp/build.log | tail -20

# Infrastructure issues
grep -E "timeout|timed out|Connection refused|503|500|temporarily unavailable" /tmp/build.log

# Stage failures
grep -E "FAILED|UNSTABLE" /tmp/build.log
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

# Trigger retry
coreos-tools jenkins jobs build <job-name> -p STREAM=<stream> -p FORCE=true
```
