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

### Step 3: Find Last Known Good Build

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

### Step 4: Fetch and Compare Logs

Fetch logs for both the failed and last good build:

```bash
# Failed build log
coreos-tools jenkins builds log <job-name> <failed-build-number> | jq -r '.console_log[]' > /tmp/failed_build.log

# Last good build log
coreos-tools jenkins builds log <job-name> <good-build-number> | jq -r '.console_log[]' > /tmp/good_build.log
```

### Step 5: Compare Component Versions

Extract and compare key component versions between builds.

**Option A**: Extract from logs:

```bash
# coreos-assembler version
grep -A 5 "coreos-assembler-git.json" /tmp/failed_build.log | head -10
grep -A 5 "coreos-assembler-git.json" /tmp/good_build.log | head -10

# rpm-ostree version
grep -i "rpm-ostree-[0-9]" /tmp/failed_build.log | head -3
grep -i "rpm-ostree-[0-9]" /tmp/good_build.log | head -3

# Kernel version
grep -i "dracut.*kver" /tmp/failed_build.log | head -1
grep -i "dracut.*kver" /tmp/good_build.log | head -1
```

**Option B**: Download artifacts directly for more detailed comparison:

```bash
# Download coreos-assembler-git.json from failed build
coreos-tools jenkins builds artifacts <job-name> <failed-build-number> --download coreos-assembler-git.json -o /tmp/failed-cosa-git.json

# Download coreos-assembler-git.json from good build
coreos-tools jenkins builds artifacts <job-name> <good-build-number> --download coreos-assembler-git.json -o /tmp/good-cosa-git.json

# Compare
diff /tmp/good-cosa-git.json /tmp/failed-cosa-git.json
```

### Step 6: Investigate Component Changes

If component versions differ (especially coreos-assembler), use GitHub CLI to find changes:

```bash
# Compare cosa commits between builds
gh api repos/coreos/coreos-assembler/compare/<old-commit>...<new-commit> --jq '.commits[] | {sha: .sha[0:7], date: .commit.author.date, message: .commit.message | split("\n")[0]}'

# Get details of suspicious commits
gh api repos/coreos/coreos-assembler/commits/<commit-sha> --jq '{sha: .sha, author: .commit.author.name, message: .commit.message}'

# Get the diff
gh api repos/coreos/coreos-assembler/commits/<commit-sha> --jq '.files[] | {filename: .filename, patch: .patch}'
```

### Step 7: Analyze Failure Details

For the failed build log, identify:
- The specific error message or failure point
- The stage/step where the failure occurred
- Any stack traces or error codes
- Test failures (look for `FAIL:` in kola output)

**For kola test failures, use the dedicated command:**

```bash
coreos-tools jenkins builds kola-failures <job-name> <build-number>
```

This returns a structured summary of all failed kola tests:

```json
{
  "build": {"job": "build", "number": 3463, "stream": "rhel-9.6"},
  "failures": [
    {
      "name": "ext.config.shared.multipath.custom-partition",
      "error": "machine entered emergency.target in initramfs",
      "duration_seconds": 15.92,
      "attempts": 2,
      "rerun_failed": true
    }
  ]
}
```

Fields:
- `name`: Test name
- `error`: Error message from the test
- `duration_seconds`: How long the test ran
- `attempts`: Number of times the test was run (1 = no rerun, 2 = rerun attempted)
- `rerun_failed`: true if the test also failed on rerun, false if it passed on rerun (flaky)

**For other failures, look for common patterns:**
- `ERROR:` or `FATAL:` messages
- Stack traces and exceptions
- Timeout errors
- Network/connectivity issues
- Resource exhaustion (disk, memory)
- Permission denied errors
- Missing dependencies

For manual log inspection:
```bash
grep -E "FAIL:|failed:|ERROR:" /tmp/failed_build.log | tail -20
```

### Step 8: Generate Summary

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

### Step 9: Create JIRA Sub-tasks (Optional)

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

### Step 10: Trigger Build Retries (Optional)

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

# Backwards compatible failures command
coreos-tools jenkins failures <job-name> -n 5
```

## Build Output Fields

The `builds list` command returns the following fields:

| Field | Description |
|-------|-------------|
| `number` | Build number |
| `url` | Jenkins build URL |
| `result` | Build status (SUCCESS, FAILURE, ABORTED, UNSTABLE) |
| `building` | Whether the build is currently running |
| `duration` | Build duration in milliseconds |
| `timestamp` | Build start time |
| `stream` | Stream name from STREAM parameter (e.g., rhel-9.6, 4.17-9.4) |
| `description` | Build description (e.g., `[rhel-9.6][x86_64] ⚡ 9.6.20260225-0`) |
