---
interval: 45m
---

## Automated CI Pipeline Check

Perform a pipeline health check using the agent workflow. Only report if issues are found.

### Step 1: Discovery
Use **@pipeline-monitor** to:
- Check `build`, `build-arch`, and `build-node-image` jobs
- List all jobs in red/unstable state (ignore currently running)
- Identify recent failures with build numbers and timestamps

If no failures found, stop here silently.

### Step 2: Cluster Analysis
If multiple failures exist, use **@cross-build-analyst** to:
- Group failures by likely root cause
- Identify duplicates vs unique problems
- Note: `build-arch` failures trigger `build` failures - track only `build-arch`

### Step 3: Jira Deduplication
For each failure cluster, check if a Jira subtask already exists:
```bash
jira issue list -q "project = COS AND type = Sub-task AND summary ~ '<job> <stream>'" --plain
```
Skip any failure that already has a tracking issue.

If all failures already have Jira issues, stop here silently.

### Step 4: Triage New Failures
For each NEW failure (no existing Jira), use **@pipeline-investigator** to:
- Gather build metadata and logs
- Classify: `infrastructure` | `flake` | `test_regression` | `package_change` | `registry_auth` | `tooling` | `unknown`
- Produce triage summary

### Step 5: Create Jira
Load the **`pipeline-jira`** skill to find the current Pipeline Monitoring parent task.

For each triaged failure, use **@pipeline-handoff** to create Jira subtasks:

**Auto-create** (no human gate):
- `infrastructure`
- `registry_auth`
- `package_change`
- `flake`
- `test_regression`
- `tooling`

**Draft only** (flag for human review):
- `unknown`

### Output
Only if issues found, summarize:
- Failures discovered and clusters identified
- Jira issues created (with links)
- Draft issues pending human review (if any)
