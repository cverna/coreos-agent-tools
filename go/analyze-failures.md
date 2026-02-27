---
description: Analyze Jenkins build failures and generate a summary with root cause findings
argument-hint: "[job-name] [-n count] [--stream stream-name]"
allowed-tools:
  - Bash
  - Read
  - Write
  - Glob
  - Grep
  - WebFetch
  - AskUserQuestion
---

# Analyze Jenkins Build Failures

Analyze recent failures from a Jenkins job, fetch console logs, compare with last known good builds, identify root causes, and generate a comprehensive summary.

## Arguments

- `job-name`: Jenkins job name to analyze (optional)
- `-n count`: Number of recent failures to analyze (default: 5)
- `--stream stream-name`: Filter by stream (e.g., `c9s`, `rhel-9.8`, `rhel-9.4`)

If no job name is provided, the command will query the last 5 failures from the following jobs: `build`, `build-arch`, `build-node-image`, and `release`, then ask the user which failure to investigate.

## Execution Steps

### Step 1: List Recent Failures

If a specific job name is provided, run:

```bash
coreos-tools jenkins builds list <job-name> --status FAILURE -n <count>
```

If no job name is provided, query failures from all default jobs in parallel:

```bash
coreos-tools jenkins builds list build --status FAILURE -n 5
coreos-tools jenkins builds list build-arch --status FAILURE -n 5
coreos-tools jenkins builds list build-node-image --status FAILURE -n 5
coreos-tools jenkins builds list release --status FAILURE -n 5
```

If a stream is specified, use the `--stream` flag to filter directly:

```bash
coreos-tools jenkins builds list <job-name> --status FAILURE --stream <stream> -n <count>
```

Parse the JSON output to get the list of failed builds with their build numbers and timestamps.

### Step 1b: Ask User to Select Failure (when no job specified)

If no job name was provided, display the combined list of recent failures from all jobs to the user in a clear format showing:
- Job name
- Build number
- Build description (includes stream info like `[c9s]`, `[rhel-9.8]`)
- Timestamp
- Brief status

Then use the AskUserQuestion tool to ask which failure(s) they want to investigate. Present the failures as options for the user to choose from.

### Step 2: Get Build Details

For each failed build, get detailed information:

```bash
coreos-tools jenkins builds info <job-name> <build-number>
```

This provides:
- Build parameters (STREAM, FORCE, etc.)
- Trigger cause (upstream job, user, timer)
- Duration and timestamps

### Step 3: Quick Failure Triage

Immediately run a quick triage to determine the failure type before fetching large log files.

**Check for kola test failures:**

```bash
coreos-tools jenkins builds kola-failures <job-name> <build-number>
```

**Check what packages changed in this build:**

```bash
coreos-tools jenkins builds diff <job-name> <build-number>
```

**Decision:**
- **Test failures found** → Proceed to Step 4 (Find Last Known Good Build) then Step 5 (Compare Packages) to identify which package change caused the regression
- **No test failures** → Skip to Step 6 (Fetch Logs) to investigate build/infrastructure failure

### Step 4: Find Last Known Good Build

For each failed build, find the last successful build for the same stream using the `--stream` flag:

```bash
coreos-tools jenkins builds list <job-name> --status SUCCESS --stream <stream> -n 10
```

Then filter out "no new build" entries if needed:

```bash
coreos-tools jenkins builds list <job-name> --status SUCCESS --stream <stream> -n 20 | jq '[.[] | select(.description | test("no new build") | not)] | first'
```

Get details of the last known good build:

```bash
coreos-tools jenkins builds info <job-name> <good-build-number>
```

### Step 5: Compare Package Changes

Compare packages between the last known good build and the failed build to identify what changed.

**Compare packages between builds:**

```bash
coreos-tools jenkins builds diff <job-name> <good-build-number> <failed-build-number>
```

This returns a computed diff showing added, removed, and changed packages:
```json
{
  "build1": 3399,
  "build2": 3463,
  "stream": "rhel-9.6",
  "added": ["new-package-1.0.0.x86_64 (rhel-9.6-baseos)", ...],
  "removed": ["old-package-2.0.0.x86_64 (rhel-9.4-appstream)", ...],
  "changed": [
    {
      "name": "kernel",
      "build1": "kernel-5.14.0-427.112.1.el9_4.x86_64 (rhel-9.4-server-ose-4.17)",
      "build2": "kernel-5.14.0-570.94.1.el9_6.x86_64 (rhel-9.6-early-kernel)"
    }
  ]
}
```

**Analyze the diff with jq:**

```bash
# List all changed package names
coreos-tools jenkins builds diff <job-name> <good-build> <failed-build> | jq -r '.changed[].name'

# Show kernel changes specifically
coreos-tools jenkins builds diff <job-name> <good-build> <failed-build> | jq '.changed[] | select(.name == "kernel")'

# Count changes
coreos-tools jenkins builds diff <job-name> <good-build> <failed-build> | jq '{added: (.added | length), removed: (.removed | length), changed: (.changed | length)}'
```

**Option B (Manual)**: If you need to compare coreos-assembler versions or other artifacts:

```bash
# Download coreos-assembler-git.json from both builds
coreos-tools jenkins builds artifacts <job-name> <failed-build-number> --download coreos-assembler-git.json -o /tmp/failed-cosa-git.json
coreos-tools jenkins builds artifacts <job-name> <good-build-number> --download coreos-assembler-git.json -o /tmp/good-cosa-git.json

# Compare
diff /tmp/good-cosa-git.json /tmp/failed-cosa-git.json
```

### Step 6: Fetch Logs (If Needed)

**Skip this step if** the triage in Step 3 identified the failing tests and Step 5 identified the likely package change.

**Fetch logs when:**
- Build failed before tests ran (compose failure)
- Need full error context
- Infrastructure failure suspected

Fetch logs for the failed build (and optionally the last good build):

```bash
# Failed build log
coreos-tools jenkins builds log <job-name> <failed-build-number> | jq -r '.console_log[]' > /tmp/failed_build.log

# Last good build log
coreos-tools jenkins builds log <job-name> <good-build-number> | jq -r '.console_log[]' > /tmp/good_build.log
```

### Step 7: Investigate Component Changes

If component versions differ (especially coreos-assembler), use GitHub CLI to find changes:

```bash
# Compare cosa commits between builds
gh api repos/coreos/coreos-assembler/compare/<old-commit>...<new-commit> --jq '.commits[] | {sha: .sha[0:7], date: .commit.author.date, message: .commit.message | split("\n")[0]}'

# Get details of suspicious commits
gh api repos/coreos/coreos-assembler/commits/<commit-sha> --jq '{sha: .sha, author: .commit.author.name, message: .commit.message}'

# Get the diff
gh api repos/coreos/coreos-assembler/commits/<commit-sha> --jq '.files[] | {filename: .filename, patch: .patch}'
```

### Step 8: Analyze Failure Details

If Step 3 (Quick Triage) didn't fully identify the issue, analyze the logs fetched in Step 6.

**For build/compose failures, look for common patterns:**

```bash
# General errors
grep -E "^error:|FATAL:|failed to|cannot |Error:" /tmp/failed_build.log | tail -20

# Infrastructure issues
grep -E "timeout|timed out|Connection refused|503|500|temporarily unavailable" /tmp/failed_build.log

# Stage failures
grep -E "FAILED|UNSTABLE" /tmp/failed_build.log
```

**Common failure patterns:**
- `ERROR:` or `FATAL:` messages → Build/compose error
- Timeout errors → Infrastructure or resource issue
- Network/connectivity issues → Transient failure, retry
- `Permission denied` → SELinux or config issue
- `No space left on device` → Disk exhaustion

### Step 9: Generate Summary

Create a summary report with:

1. **Overview**: Total failures analyzed, date range covered
2. **Failed Build Details**:
   - Build number, stream, and timestamp
   - Error summary (1-2 sentences)
   - Failing test or stage
3. **Last Known Good Build**:
   - Build number and date
   - Key differences from failed build
4. **Component Changes**:
   - coreos-assembler commits between good and bad builds
   - Package version changes
   - Kernel version changes
5. **Root Cause Analysis**:
   - Identified cause with evidence
   - Relevant commits/changes
   - Severity (critical, high, medium, low)
6. **Recommendations**:
   - Specific fix suggestions
   - Links to relevant PRs/issues
   - Workarounds if available

### Step 10: Create JIRA Sub-tasks (Optional)

When requested, create JIRA sub-tasks under the current week's Pipeline Monitoring task to track failures.

IMPORTANT, each new build failure needs to be it's own sub-task, that includes retries that have failed.

First, find the current week's monitoring task:

```bash
jira issue list --project COS --type Task -q "summary ~ 'Pipeline Monitoring'" --plain
```

Then create a sub-task for each failure with appropriate labels:

```bash
jira issue create --type Sub-task --parent <PARENT-KEY> --project COS \
  --summary "<job> #<build-number> - <stream> <brief-description>" \
  --label flake-infrastructure \
  --body "<detailed-markdown-description>" --no-input
```

**Labels to use**:
- `flake-infrastructure`: For transient infrastructure issues (Fedora repo timeouts, GitHub 500 errors, network issues)
- `flake-test`: For flaky test failures
- `bug`: For actual bugs requiring code fixes

The sub-task body should include:
- Build details (job, number, stream, timestamp, duration, Jenkins URL)
- Root cause analysis
- Error messages (in code blocks)
- Source file locations if applicable
- Resolution status and retry build numbers

To add comments to existing issues:

```bash
jira issue comment add <ISSUE-KEY> "<comment-text>" --no-input
```

### Step 11: Trigger Build Retries (Optional)

When requested, trigger a retry for a failed build, IMPORTANT, make sure to check if a build is already running before doing a retry.

```bash
coreos-tools jenkins jobs build <job-name> -p STREAM=<stream> -p FORCE=true
```

**Note**: Use `jobs build` (not `builds trigger`) to trigger new builds.

Monitor the retry status:

```bash
coreos-tools jenkins builds list <job-name> -n 5
```

## Output Format

Present the summary in a clear, readable format with sections and bullet points. Include:
- Jenkins build URLs for reference
- GitHub compare URLs for component changes
- Specific commit SHAs and messages for root causes

## Example Usage

```
/analyze-failures                           # Query all default jobs and let user choose
/analyze-failures build                     # Analyze failures from build job
/analyze-failures build --stream c9s        # Analyze c9s stream failures
/analyze-failures build --stream rhel-9.8   # Analyze rhel-9.8 stream failures
/analyze-failures build -n 3                # Analyze last 3 failures
```

## Prerequisites

- `.env` file in current directory with Jenkins credentials:
  - `JENKINS_URL`
  - `JENKINS_USER`
  - `JENKINS_API_TOKEN`
- `coreos-tools` CLI installed and configured with Jenkins credentials
- `gh` (GitHub CLI) installed and authenticated for commit analysis
- `jq` installed for JSON parsing

## Additional Commands

The coreos-tools jenkins CLI provides additional useful commands:

```bash
# List all jobs
coreos-tools jenkins jobs list

# Get job info (health, last builds)
coreos-tools jenkins jobs info <job-name>

# View build queue
coreos-tools jenkins queue list

# List nodes
coreos-tools jenkins nodes list

# List build artifacts
coreos-tools jenkins builds artifacts <job-name> <build-number>

# Download a specific artifact
coreos-tools jenkins builds artifacts <job-name> <build-number> --download <artifact-name>

# Download artifact to a specific path
coreos-tools jenkins builds artifacts <job-name> <build-number> --download <artifact-name> -o /tmp/output.tar.xz

# Filter builds by stream
coreos-tools jenkins builds list <job-name> --stream rhel-9.6 -n 10

# Filter builds by stream and status
coreos-tools jenkins builds list <job-name> --stream rhel-9.6 --status FAILURE -n 5

# Get kola test failure summary (no artifact download needed)
coreos-tools jenkins builds kola-failures <job-name> <build-number>

# Show package upgrades in a build
coreos-tools jenkins builds diff <job-name> <build-number>

# Compare packages between two builds (shows added/removed/changed)
coreos-tools jenkins builds diff <job-name> <build1> <build2>

# Backwards compatible failures command
coreos-tools jenkins failures <job-name> -n 5
```

Using Brew Web to Find Package Information
Brew (Red Hat's internal Koji instance) is used to track package builds. Access it at: https://brewweb.engineering.redhat.com/brew/
1. Finding a Package
Direct URL (if you know the package ID):
https://brewweb.engineering.redhat.com/brew/packageinfo?packageID=<ID>
Search by name:
https://brewweb.engineering.redhat.com/brew/search?match=glob&type=package&terms=<package-name>
Example:
https://brewweb.engineering.redhat.com/brew/search?match=glob&type=package&terms=conmon-rs
2. Understanding the Package Info Page
The package info page shows three key sections:
Builds Table
| Column | Description |
|--------|-------------|
| NVR | Name-Version-Release (e.g., conmon-rs-0.6.6-0.rhaos4.18.el10.1) |
| Built by | User/bot that triggered the build |
| Finished | Build completion timestamp |
| State | Build status (complete, failed, etc.) |
NVR Naming Convention:
<package>-<version>-<release>.<ocp-version>.<rhel-version>
3. Common Searches
Find all builds for a package:
https://brewweb.engineering.redhat.com/brew/packageinfo?packageID=<ID>
Search for builds by NVR pattern:
https://brewweb.engineering.redhat.com/brew/search?match=glob&type=build&terms=conmon-rs*el10*
Find builds in a specific tag:
https://brewweb.engineering.redhat.com/brew/taginfo?tagID=<tag-id>
4. Checking if a Package is Available for a Stream
To verify a package is available for a specific OCP/RHEL combination:
1. Go to the package info page
2. Check the Builds table for a build matching your target (e.g., el10 for RHEL 10)
3. Check the Tags table for the appropriate tag (e.g., rhaos-4.22-rhel-10)
