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

Weekly Pipeline Monitoring tasks track CI failures:

```bash
# Find current week's monitoring task
jira issue list --project COS --type Task -q "summary ~ 'Pipeline Monitoring'" --plain
```

### Sub-task Structure

Each build failure should be its own sub-task (including retries that failed).

**Summary format:**
```
<job> #<build-number> - <stream> <brief-description>
```

**Examples:**
- `build #3456 - rhel-9.6 kernel regression in selinux test`
- `build-arch #1234 - c9s compose failure - repo timeout`
- `release #789 - rhel-9.8 extensions-container build failed`

### Sub-task Body Structure

```markdown
## Build Details
- **Job**: <job-name>
- **Build**: #<build-number>
- **Stream**: <stream>
- **Timestamp**: <timestamp>
- **Duration**: <duration>
- **Jenkins URL**: <url>

## Root Cause Analysis
<description of what caused the failure>

## Error Messages
```
<error messages in code blocks>
```

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
