---
interval: 60m
---

## Automated CI Pipeline Check

Perform a pipeline health check using the agent workflow. Only report if issues are found.

### Step 1: Discovery
Use **@pipeline-monitor** to:
- Check `build`, `build-arch`, and `build-node-image` jobs
- List all jobs in red/unstable state (ignore currently running)
- Identify recent failures with build numbers and timestamps
- Filter out already-tracked failures using Jira as memory
- Auto-close open subtasks where a later successful build exists for the same job+stream(+arch)

**Deduplication rules:**
- **EXACT_MATCH**: Jira issue summary contains this exact build number → Skip triage
- **RELATED_ISSUE**: Open Jira exists for same job+stream+arch (even if different build number) → Skip triage, just add a comment to the existing issue
- **NEW_FAILURE**: No Jira issue found for this job+stream+arch → Proceed to triage

If no new failures found, stop here silently.

### Step 2: Triage Failures
For each **NEW_FAILURE** only (not RELATED_ISSUE), use **@pipeline-investigator** to:
- Gather build metadata and logs
- Classify: `infrastructure` | `flake` | `test_regression` | `package_change` | `registry_auth` | `tooling` | `unknown`
- Produce triage summary

### Step 3: Create Jira
For each triaged failure, use **@pipeline-handoff** to create Jira subtasks.

**Note:** `@pipeline-handoff` handles deduplication automatically by loading the `pipeline-jira` skill and checking for existing issues before creating subtasks.

**Auto-create for all classifications:**
- `infrastructure`
- `registry_auth`
- `package_change`
- `flake`
- `test_regression`
- `tooling`
- `unknown`

### Output
Only if issues found, summarize:
- New failures discovered and triaged
- Jira issues created (with links)
