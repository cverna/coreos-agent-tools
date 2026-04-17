---
description: Run ordered pipeline triage for one failed Jenkins build (Gather → Logs → Classify → Summarize → GATE)
argument-hint: "<job-name> <build-number>"
---

# Pipeline Triage

Run a structured triage workflow for a single failed Jenkins build.

## Arguments

- `$1` — Jenkins job name (e.g., `build`, `build-arch`, `release`)
- `$2` — Build number (integer)

If arguments are not provided, ask the user for the job name and build number.

## Workflow

Load and follow the **`pipeline-triage-workflow`** skill end-to-end:

1. **Stage 1 - Gather**: Collect build metadata
2. **Stage 2 - Logs**: Pull console log and extract key errors
3. **Stage 3 - Classify**: Categorize the failure type
4. **Stage 4 - Summarize**: Produce handoff package for humans
5. **GATE**: Stop and wait for approval before any Jira or Jenkins actions

## Commands

```bash
# Stage 1: Gather metadata
coreos-tools jenkins builds info $1 $2
coreos-tools jenkins jobs info $1

# Stage 2: Get logs
coreos-tools jenkins builds log $1 $2 | jq -r '.console_log[]' > /tmp/build.log

# Check kola failures if applicable
coreos-tools jenkins builds kola-failures $1 $2

# Stage 3-4: Analysis and summary (agent reasoning)
```

## Output format

Use structured markdown sections:

```markdown
### Gather
- **Job:** …
- **Build:** …
- **Status / result:** …
- **Stream / parameters:** …
- **URL:** …

### Logs (excerpt)
- **Key errors:** …
- **Patterns seen:** …

### Classify
- **Primary:** infrastructure | flake | test_regression | package_change | registry_auth | tooling | unknown
- **Confidence:** low | medium | high
- **Why:** …

### Triage summary
- **One-line summary:** …
- **Evidence:** …
- **Suggested next steps:** …

---
## GATE
Waiting for approval before:
- [ ] Creating Jira issue
- [ ] Triggering Jenkins rerun
```

## After GATE approval

For Jira actions, use the **`pipeline-jira`** skill or **@pipeline-handoff** agent.

## Example usage

```
/pipeline-triage build 3456
/pipeline-triage build-arch 1234
```
