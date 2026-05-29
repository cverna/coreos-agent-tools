---
name: rhcos-pipeline-failures
description: Investigate RHCOS Jenkins CI pipeline failures - job hierarchy, root cause analysis, and debugging workflows
---

# RHCOS Pipeline Failures

Knowledge for investigating failures in the RHCOS Jenkins build pipeline.

> Related: `pipeline-failures` (common kola/artifact patterns), `rhcos-build-pipeline` (pipeline scheduling and structure), `rhcos-artifacts` (artifacts, diffs, cosa comparison), `pipeline-jira` (creating failure issues)

## Jenkins Job Hierarchy

Understanding the job hierarchy is critical to avoid analyzing the wrong logs:

| Job | Has downstream? | Analysis approach |
|-----|-----------------|-------------------|
| `build` | **Yes** → triggers `build-arch` per-arch | Check console for which arch failed, then analyze that `build-arch` job |
| `build-arch` | **No** (leaf job) | Analyze directly - kola tests run here |
| `build-node-image` | **No** (independent pipeline) | Analyze directly - does NOT trigger `build-arch` |

**Critical:** `build-node-image` is a **separate pipeline** from `build`/`build-arch`. When investigating `build-node-image`:
- Analyze its console log directly
- Do NOT look for "downstream" `build-arch` jobs - there are none
- A `build-arch` job running at the same time is **coincidental**, not related

**Stream validation:** Always verify the stream matches. A `build-node-image` failure for stream `4.21-9.6` cannot be caused by a `build-arch` for stream `rhel-10.2` - they are completely unrelated builds.

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

See `pipeline-failures` for kola failure interpretation and the `rerun_failed` decision tree.

```bash
# Get kola test failure summary
coreos-tools jenkins builds kola-failures <job-name> <build-number>

# Filter for actual failures (tests that failed on rerun)
coreos-tools jenkins builds kola-failures <job-name> <build-number> | jq '[.failures[] | select(.rerun_failed == true)]'
```

### 4. Analyze Kola Artifacts (if tests failed)

Download and examine kola artifacts when `rerun_failed: true`.
See `pipeline-failures` for the full artifact download and analysis workflow.

### 5. Find Last Known Good Build

```bash
# Find last successful build for same stream (filter out "no new build" entries)
coreos-tools jenkins builds list <job-name> --status SUCCESS --stream <stream> -n 20 | \
  jq '[.[] | select(.description | test("no new build") | not)] | first'
```

### 6. Compare Builds

```bash
# Compare packages between good and bad builds
coreos-tools jenkins builds diff <job> <good-build> <bad-build>

# Compare cosa versions - see "coreos-assembler Regression Detection" section
```

### 7. Investigate Root Cause

Based on what changed:
- **Package updates** → Check changelog, see "Package Changelog Investigation"
- **cosa changes** → Check commits, see "coreos-assembler Regression Detection"
- **No obvious changes** → Search upstream code, see "Upstream Code Investigation"

---

## Package Changelog Investigation

When package updates are suspected as root cause:

### Get Package Build Info

```bash
# Get build details from Brew
brew buildinfo <package-nvr>

# Example
brew buildinfo kernel-6.12.0-211.3.1.el10_2
```

### Extract Package Changelog

```bash
# Download src.rpm and get changelog
brew download-build --rpm <package-nvr>.src.rpm --noprogress
rpm -qp --changelog <package-nvr>.src.rpm | head -100

# Compare two versions
rpm -qp --changelog <new-version>.src.rpm > /tmp/new.log
rpm -qp --changelog <old-version>.src.rpm > /tmp/old.log
```

### Check Package Source Commits (GitLab)

```bash
# For RHEL packages in GitLab
glab api "projects/rpms%2F<package>/repository/compare?from=<old-tag>&to=<new-tag>" | \
  jq -r '.commits[] | "\(.short_id) \(.title)"'
```

### Key Packages to Investigate

| Package | Impact Area |
|---------|-------------|
| kernel/kernel-rt | Boot, drivers, secex, performance |
| ignition | Firstboot, provisioning |
| coreos-installer | Installation, zipl (s390x) |
| ostree/rpm-ostree | Upgrades, deployments |
| systemd | Services, boot ordering |

## coreos-assembler Regression Detection

When cosa versions differ between good and bad builds:

### Compare cosa Versions

```bash
# Download cosa version info
coreos-tools jenkins builds artifacts <job> <bad-build> --download coreos-assembler-git.json -o /tmp/bad-cosa.json
coreos-tools jenkins builds artifacts <job> <good-build> --download coreos-assembler-git.json -o /tmp/good-cosa.json

# Extract commit SHAs
cat /tmp/good-cosa.json | jq -r '.git.commit'
cat /tmp/bad-cosa.json | jq -r '.git.commit'
```

### Find cosa Changes

```bash
# List commits between versions
gh api repos/coreos/coreos-assembler/compare/<old-sha>...<new-sha> \
  --jq '.commits[] | {sha: .sha[0:7], date: .commit.author.date, message: .commit.message | split("\n")[0]}'

# Check which files changed
gh api repos/coreos/coreos-assembler/compare/<old-sha>...<new-sha> \
  --jq '.files[] | {filename: .filename, status: .status, changes: .changes}'

# Get full diff for a specific file
gh api repos/coreos/coreos-assembler/compare/<old-sha>...<new-sha> \
  --jq '.files[] | select(.filename == "<file>") | .patch'
```

## Upstream Code Investigation

For deeper root cause analysis, search upstream CoreOS repositories:

### Search for Code Patterns

```bash
# Search across CoreOS repos
gh search code "<pattern>" --repo coreos/coreos-assembler --repo coreos/ignition \
  --repo coreos/coreos-installer --repo coreos/afterburn \
  --json repository,path,textMatches

# Search OpenShift repos
gh search code "<pattern>" --repo openshift/os --json repository,path
```

### Check Recent Changes to Relevant Files

```bash
# Get commits for a specific file
gh api "repos/<org>/<repo>/commits?path=<file>&per_page=10" | \
  jq '.[] | {sha: .sha[0:7], date: .commit.author.date, message: .commit.message | split("\n")[0]}'

# Get file contents
gh api repos/<org>/<repo>/contents/<path> --jq '.content' | base64 -d
```

### Key Repositories

| Repository | Contains |
|------------|----------|
| `coreos/coreos-assembler` | Build tools, kola tests, qemu harness |
| `coreos/ignition` | Provisioning, firstboot |
| `coreos/coreos-installer` | Installation, s390x zipl, secex |
| `coreos/afterburn` | Cloud metadata, firstboot completion |
| `coreos/fedora-coreos-config` | systemd units, overlays |
| `openshift/os` | RHCOS-specific configs and tests |

## Triggering Retries

```bash
# Check if a build is already running first
coreos-tools jenkins builds list <job-name> -n 5

# Trigger retry
coreos-tools jenkins jobs build <job-name> -p STREAM=<stream> -p FORCE=true
```

See `pipeline-failures` for general retry guidance.
