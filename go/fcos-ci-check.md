## Automated fcos-ci Pipeline Check

Perform a pipeline health check for the Fedora CoreOS CI `test-override` job. Only report if issues are found.

Load the **`fcos-ci-failures`** skill for fcos-ci instance context and job-specific knowledge.

### Step 1: Discovery

Check the `test-override` job on the fcos-ci Jenkins instance for recent failures:

```bash
# List recent failures
coreos-tools jenkins builds list test-override --profile fcos-ci --status FAILURE -n 10

# List recent unstable builds
coreos-tools jenkins builds list test-override --profile fcos-ci --status UNSTABLE -n 10
```

**For each UNSTABLE build**, check kola failures before treating it as actionable:

```bash
coreos-tools jenkins builds kola-failures test-override <build-number> --profile fcos-ci
```

- If **all** `rerun_failed: false` → flaky infra, package passed (✔️ in description confirms) → **skip**
- If **any** `rerun_failed: true` → real failure → treat as FAILURE

**Deduplication** — search GitHub for existing open issues before triaging:

```bash
gh issue list --repo cverna/fedora-coreos-rawhide-ci --state open \
  --search "<package-NVR>" --json number,title,url
```

- Exact NVR match in title → **EXACT_MATCH** → skip
- Same package name, different NVR → **RELATED_ISSUE** → add comment to existing issue, skip triage
- No match → **NEW_FAILURE** → triage

**Auto-close resolved issues** — for each open GitHub issue, check if a later successful build exists for the same package:

```bash
# Get build info to extract package NVR
coreos-tools jenkins builds list test-override --profile fcos-ci --status SUCCESS -n 20
```

If a SUCCESS build exists with build# > the failed build# for the same package → close the issue:

```bash
gh issue close <number> --repo cverna/fedora-coreos-rawhide-ci \
  --comment "Auto-closed: test-override #<N> succeeded for <package-NVR> on <stream>, confirming this failure was transient."
```

For each **NEW_FAILURE**, add a todo:

```
[pending] TRIAGE | test-override | #<build> | <stream> | <package-NVR>
```

If no new failures found, stop here silently.

### Step 2: Triage

For each pending TRIAGE todo, use **@.config/opencode/agents/pipeline-investigator** to:
- Use `--profile fcos-ci` for all Jenkins commands
- Note that `test-override` is a **leaf job** — analyze it directly, there are no downstream jobs
- Extract key parameters from build info: `OVERRIDES` (Bodhi URL), `DESCRIPTION` (package NVR), `STREAM`
- Gather kola failures focusing on `rerun_failed: true` tests
- Classify the failure
- Produce triage summary with **ROOT_CAUSE**

Update todo when complete:

```
[completed] TRIAGE | test-override | #<build> | <stream> | <package-NVR> | ROOT_CAUSE: <description>
```

### Step 3: Cluster by Root Cause

Review all completed TRIAGE todos and group by similar ROOT_CAUSE.

Use judgment to identify the same underlying issue across different packages/streams:
- Same kola test failing for multiple packages → same cluster
- "podman exit code 125" across different kernel builds → same cluster
- Infrastructure timeouts across multiple builds → same cluster (infra issue, may not need a GitHub issue)

Create todos for GitHub issue creation (one per cluster):

```
[pending] GITHUB | <root_cause_summary> | builds: #X, #Y | packages: <NVR1>, <NVR2>
```

### Step 4: Create GitHub Issue

For each pending GITHUB todo, create **one issue per cluster** in `cverna/fedora-coreos-rawhide-ci`.

**Title format:**
- Single failure: `[test-override] <package-NVR> failed on <stream>`
- Cluster: `[test-override] <root-cause-summary> (<N> packages affected)`

**Body must include:**
- Bodhi update URL(s) (from `OVERRIDES` parameter)
- Jenkins build URL(s)
- Stream(s) affected
- ROOT_CAUSE and failure classification
- Kola test failures (`rerun_failed: true` only) with test names and error messages
- Suggested next steps

```bash
gh issue create --repo cverna/fedora-coreos-rawhide-ci \
  --title "[test-override] <title>" \
  --label "bug" \
  --body "<body>"
```

Mark todo completed with the issue URL:

```
[completed] GITHUB | <root_cause_summary> | https://github.com/cverna/fedora-coreos-rawhide-ci/issues/<N>
```

### Output

Only if issues found, summarize:
- New failures discovered and triaged
- Clusters identified (with member builds and packages)
- GitHub issues created (with URLs)
- Issues auto-closed (if any)
