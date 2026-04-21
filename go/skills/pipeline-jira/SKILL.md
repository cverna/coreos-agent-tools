---
name: pipeline-jira
description: Create JIRA issues for CI pipeline failures - COS project conventions and subtask structure
---

# Pipeline JIRA

JIRA CLI commands and COS project conventions for tracking CI pipeline failures.

> Related: `pipeline-failures`

## JIRA CLI Commands

### Listing Issues

```bash
# List issues with JQL query
jira issue list --project COS --type Task -q "summary ~ 'Pipeline Monitoring'" --plain

# List open issues
jira issue list --project COS --status "Open" --plain

# List issues by component
jira issue list --project COS --component RHCOS --plain
```

### Creating Issues

```bash
# Create a sub-task
jira issue create --type Sub-task --parent <PARENT-KEY> --project COS \
  --summary "<job> #<build-number> - <stream> <brief-description>" \
  --label <label> \
  --body "<detailed-markdown-description>" --no-input

# Create a task
jira issue create --type Task --project COS \
  --summary "<summary>" \
  --body "<description>" --no-input
```

### Managing Issues

```bash
# Add a comment
jira issue comment add <ISSUE-KEY> "<comment-text>" --no-input

# View issue details
jira issue view <ISSUE-KEY>

# Transition issue status
jira issue move <ISSUE-KEY> "In Progress"
```

## COS Project Conventions

### Project: COS

The COS project is used for CoreOS-related issues.

### Pipeline Monitoring Tasks

Weekly Pipeline Monitoring tasks track CI failures.

**Naming convention:** `Pipeline monitoring - Sprint NNN - Ws YYYYMMDD`
- `Ws` = Week starting (Monday)
- One task per week

**Find current week's monitoring task:**

```bash
# Calculate Monday of current week
DOW=$(date +%u)
if [ "$DOW" -eq 1 ]; then
  MONDAY=$(date +%Y%m%d)
else
  MONDAY=$(date -d "last monday" +%Y%m%d)
fi

# Find this week's monitoring task
PARENT=$(jira issue list --project COS --type Task \
  -q "summary ~ 'Pipeline monitoring' AND summary ~ '$MONDAY'" \
  --plain --no-headers | head -1 | awk '{print $2}')
```

## Pre-Creation Deduplication

Before creating any subtask, run these checks to avoid duplicates.

### Step 1: Exact Build Match

Check if this exact build already has a subtask:

```bash
jira issue list --parent $PARENT \
  -q "summary ~ '<job> #<build-number>'" --plain --no-headers
```

**If results found → STOP, do not create duplicate.**

### Step 2: Similar Failure Check

Query for open subtasks with same job, stream, and architecture:

```bash
jira issue list --parent $PARENT -s~Closed \
  -q "summary ~ '<job>' AND summary ~ '<stream>' AND summary ~ '<arch>'" \
  --plain --no-headers
```

**If results found → Review the existing issues and decide:**
- **Same root cause** → Add comment to existing issue instead of creating new
- **Different root cause** → Proceed with creating new subtask

**Comment template for duplicate occurrences:**

```bash
jira issue comment add <EXISTING-KEY> $'Additional occurrence detected:
- **Build:** [#<build>](<jenkins-url>)
- **Timestamp:** <timestamp>

Same failure pattern - consolidating under this issue.' --no-input
```

## Sub-task Structure

Each build failure should be its own sub-task (including retries that failed).

**Summary format:**
```
<job> #<build-number> - <stream> [arch] <brief-description>
```

**Important:** Always use the **full Jenkins stream** (e.g., `4.22-9.8` not `4.22`). The stream value comes from the Jenkins build parameters (`STREAM` or `RELEASE`). For `build-arch`, include the architecture after the stream.

**Examples:**
- `build #3456 - rhel-9.6 kernel regression in selinux test`
- `build-arch #1234 - c9s s390x compose failure - repo timeout`
- `build-node-image #4216 - 4.20-9.6 TLS handshake timeout`
- `release #789 - rhel-9.8 extensions-container build failed`

### Sub-task Body Structure

```markdown
## Build Details
- **Job**: <job-name>
- **Build**: #<build-number>
- **Stream**: <stream>
- **Architecture**: <arch>
- **Timestamp**: <timestamp>
- **Duration**: <duration>
- **Jenkins URL**: <url>

## Root Cause Analysis
- **Classification**: <infrastructure | flake | test_regression | package_change | registry_auth | tooling | unknown>
- **Confidence**: <low | medium | high>

<detailed explanation of what caused the failure, including reasoning>

## Evidence

### Log Excerpt
```
<key error lines from console log>
```

### Patterns Observed
- <pattern 1>
- <pattern 2>

## Upstream Links
<!-- Include any relevant links discovered during investigation -->
- **Related Issues**: <GitHub/GitLab issue URLs>
- **Related PRs**: <PR URLs>
- **Related Commits**: <commit URLs if change was identified>
- **Package Build**: <Brew build URL if package change>
- **Test Source**: <link to test code in upstream repo>

## Resolution
- **Status**: <resolved/unresolved/retry-pending>
- **Retry Build**: #<retry-build-number> (if applicable)
- **Fix PR**: <link> (if applicable)
```

## Labels

| Label | When to Use |
|-------|-------------|
| `flake-infrastructure` | Transient infrastructure issues (repo timeouts, GitHub 500, network) |
| `flake-test` | Flaky test failures (passed on rerun) |
| `bug` | Actual bugs requiring code fixes |

## Issue Linking

For CVE tracking, link OCPBUG issues to RHEL vulnerability issues:

```bash
# Links are created via API, type: "Blocks"
# OCPBUG blocks RHEL (outward)
# RHEL is blocked by OCPBUG (inward)
```
