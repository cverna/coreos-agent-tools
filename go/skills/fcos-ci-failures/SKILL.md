---
name: fcos-ci-failures
description: Investigate fcos-ci Jenkins pipeline failures - test-override job, Bodhi-triggered package testing, and fcos-ci-specific workflows
---

# fcos-ci Pipeline Failures

Knowledge for investigating failures in the Fedora CoreOS CI Jenkins instance.

> Related: `pipeline-failures` (common kola/artifact patterns), `fcos-overrides` (Fedora CoreOS package overrides)

## Jenkins Instance & Profile

The fcos-ci Jenkins instance is separate from the RHCOS Jenkins instance and requires the `--profile fcos-ci` flag on all `coreos-tools jenkins` commands.

- **Instance URL:** https://jenkins-coreos-ci.apps.ocp.fedoraproject.org
- **Profile:** `fcos-ci`

```bash
# Always pass --profile fcos-ci for this instance
coreos-tools jenkins builds list <job-name> --profile fcos-ci -n 10
coreos-tools jenkins builds info <job-name> <build-number> --profile fcos-ci
coreos-tools jenkins builds kola-failures <job-name> <build-number> --profile fcos-ci
coreos-tools jenkins builds artifacts <job-name> <build-number> --profile fcos-ci
```

## Job Structure

The fcos-ci instance hosts many upstream project CI jobs (ignition, rpm-ostree, coreos-assembler, etc.) as well as the Bodhi-driven package override testing pipeline:

| Job | Purpose | Analysis approach |
|-----|---------|-------------------|
| `bodhi-trigger` | Watches Bodhi for new updates; triggers `test-override` | Not analyzed directly - check as upstream cause |
| `test-override` | Tests a single Bodhi package update against a FCOS stream | Leaf job - analyze directly |

**`test-override` is a leaf job.** It does not trigger downstream jobs. Analyze its console and kola results directly.

## test-override Job

### Key Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `STREAM` | FCOS stream to test against | `rawhide`, `testing-devel` |
| `OVERRIDES` | Bodhi update URL providing the package(s) to test | `https://bodhi.fedoraproject.org/updates/FEDORA-2026-xxxx` |
| `DESCRIPTION` | Human-readable package NVR(s) being tested | `kernel-7.1.0-0.rc5.37.fc45` |
| `ALLOW_KOLA_UPGRADE_FAILURE` | Whether upgrade test failures are blocking | `true`/`false` |
| `REPORT_TO_RESULTSDB` | Whether to report results to ResultsDB | `true`/`false` |

### Streams

| Stream | Target |
|--------|--------|
| `rawhide` | Fedora rawhide (fc45+) |
| `testing-devel` | Fedora stable testing (fc44) |

### Artifacts

Each `test-override` build produces the same artifact structure as RHCOS build jobs:

```
coreos-assembler-git.json       # cosa version used
coreos-assembler-rpmdb.txt      # full RPM list
kola-x86_64-<hash>.tar.xz       # main kola test results
kola-upgrade-x86_64-<hash>.tar.xz   # upgrade test results
kola-reprovision-x86_64-<hash>.tar.xz  # reprovision test results
```

## Investigation Workflow

### 1. List Recent Builds

```bash
# Recent builds (all statuses)
coreos-tools jenkins builds list test-override --profile fcos-ci -n 10

# Filter by status
coreos-tools jenkins builds list test-override --profile fcos-ci --status FAILURE -n 10
coreos-tools jenkins builds list test-override --profile fcos-ci --status UNSTABLE -n 10

# Filter by stream
coreos-tools jenkins builds list test-override --profile fcos-ci --stream rawhide -n 10
```

### 2. Get Build Details

```bash
coreos-tools jenkins builds info test-override <build-number> --profile fcos-ci
```

Check the build info for:
- `OVERRIDES` parameter — the Bodhi update URL (identifies the package being tested)
- `DESCRIPTION` — the package NVR
- `causes` — should show `bodhi-trigger` as upstream cause

### 3. Interpret the Result

| Result | Description has ✔️? | Meaning |
|--------|---------------------|---------|
| `SUCCESS` | Yes | Package passed all tests |
| `UNSTABLE` | Yes | Some tests failed but all passed on rerun (flaky infra) — package still passed |
| `UNSTABLE` | No | Real test failures — investigate |
| `FAILURE` | — | Build or infrastructure failure — check logs |

**Key distinction:** UNSTABLE with ✔️ in the description and all `rerun_failed: false` means the package itself passed. The UNSTABLE status reflects transient/flaky test infrastructure issues, not a package regression.

### 4. Check Kola Failures

```bash
coreos-tools jenkins builds kola-failures test-override <build-number> --profile fcos-ci

# Check which tests consistently failed (rerun_failed: true)
coreos-tools jenkins builds kola-failures test-override <build-number> --profile fcos-ci | \
  jq '[.failures[] | select(.rerun_failed == true)]'
```

See `pipeline-failures` for the full `rerun_failed` decision tree and kola artifact analysis workflow.

### 5. Find Last Known Good Build (for regression analysis)

```bash
# Last successful build for same stream
coreos-tools jenkins builds list test-override --profile fcos-ci --status SUCCESS --stream <stream> -n 20 | \
  jq 'first'
```

Note: Unlike RHCOS jobs, `test-override` descriptions always contain the package NVR rather than "no new build", so no filtering is needed.

### 6. Compare Builds

```bash
# Compare packages between good and bad builds
coreos-tools jenkins builds diff test-override <good-build> <bad-build> --profile fcos-ci
```

## Triggering Retries

```bash
# Check if a build is already running
coreos-tools jenkins builds list test-override --profile fcos-ci -n 5

# Trigger a retry with the same Bodhi update
coreos-tools jenkins jobs build test-override --profile fcos-ci \
  -p STREAM=<stream> \
  -p OVERRIDES=<bodhi-update-url> \
  -p DESCRIPTION=<package-nvr>
```

The `OVERRIDES` value is the Bodhi update URL from the original build's parameters (e.g. `https://bodhi.fedoraproject.org/updates/FEDORA-2026-xxxx`).

See `pipeline-failures` for general retry guidance.
