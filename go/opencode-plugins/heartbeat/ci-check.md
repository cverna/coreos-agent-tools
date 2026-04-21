---
interval: 60m
---

## Automated CI Pipeline Check

Perform a pipeline health check using the agent workflow. Only report if issues are found.

### Step 1: Discovery

Use **@pipeline-monitor** to:
- Check `build`, `build-arch`, and `build-node-image` jobs
- List all jobs in red/unstable state (ignore currently running)
- Filter using 3-pass deduplication:
  - **EXACT_MATCH** → skip (already tracked)
  - **RELATED_ISSUE** → add comment to existing ticket, skip triage
  - **SEMANTIC_MATCH** → add comment to existing ticket, skip triage
- Auto-close open subtasks where a later successful build exists

For each **NEW_FAILURE**, add a todo:
```
[pending] TRIAGE | <job> | #<build> | <stream> | <arch>
```

If no new failures found, stop here silently.

### Step 2: Triage

For each pending TRIAGE todo, use **@pipeline-investigator** to:
- Gather build metadata and logs
- Classify the failure
- Produce triage summary with **ROOT_CAUSE**

Update todo when complete:
```
[completed] TRIAGE | <job> | #<build> | <stream> | <arch> | ROOT_CAUSE: <description>
```

### Step 3: Cluster by Root Cause

Review all completed TRIAGE todos and group by similar ROOT_CAUSE.

Use judgment to identify the same underlying issue across different streams/builds:
- "NetworkManager skew" and "NM version mismatch" → same cluster
- "SSH timeout to aarch64 builder" across multiple builds → same cluster
- "chronyd failure in kernel-replace" on different streams → same cluster

Create todos for Jira creation (one per cluster):
```
[pending] JIRA | <root_cause_summary> | builds: #X, #Y, #Z
```

### Step 4: Create Jira

For each pending JIRA todo, use **@pipeline-handoff** to create **ONE subtask per cluster**.

Include all affected builds in the ticket description.

Mark todo completed with Jira key:
```
[completed] JIRA | <root_cause_summary> | COS-XXXX
```

### Output

Only if issues found, summarize:
- New failures discovered and triaged
- Clusters identified (with member builds)
- Jira issues created (with links)
