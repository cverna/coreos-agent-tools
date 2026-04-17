---
description: RHCOS Jenkins pipeline health check - discover failing jobs and recommend triage targets
---

# Pipeline Status

Check the current health of the RHCOS Jenkins pipeline and identify failures that need investigation.

## Workflow

1. Use the **@pipeline-monitor** agent behavior to discover failing jobs
2. List recent failures from key jobs: `build`, `build-arch`, `build-node-image`, `release`
3. Identify the **best triage target** based on recency and impact
4. Output using the **Pipeline Monitor — Summary** format

## Commands to run

```bash
# List all jobs and their status
coreos-tools jenkins jobs list

# Check recent failures on key jobs
coreos-tools jenkins builds list build --status FAILURE -n 5
coreos-tools jenkins builds list build-arch --status FAILURE -n 5
coreos-tools jenkins builds list release --status FAILURE -n 5
```

## Output format

```markdown
## Pipeline Monitor — Summary
- **Jobs in bad state:** …
- **Recommended triage target:** `<job>` / `<build-number>`
- **Why this pick:** …
- **Next step:** Run `/pipeline-triage` or ask `@pipeline-investigator` to triage this build.
```

## Next steps

After identifying a failure, use:
- `/pipeline-triage` — Full ordered triage workflow
- `@pipeline-investigator` — Deep investigation of a specific build
