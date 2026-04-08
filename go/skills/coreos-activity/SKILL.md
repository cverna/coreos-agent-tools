---
name: coreos-activity
description: CoreOS GitHub/GitLab activity summaries - issues, PRs, releases for CoreOS org, openshift/os, and fedora/bootc
---

# CoreOS Activity Summary

Generate comprehensive activity summaries for the CoreOS ecosystem, including:
- **GitHub**: CoreOS organization and `openshift/os` repository
- **GitLab**: `fedora/bootc` group (base images, docs, testing)

Covers issues, pull/merge requests, releases, and contributor metrics.

> Related: `rhcos-repositories`, `fcos-overrides`

## Time Range Options

> **Platform Note:** Commands below use macOS `date -v` syntax. On Linux, use `date -d` instead.
> Examples are shown as macOS primary with Linux alternatives in comments.

| Range | macOS | Linux |
|-------|-------|-------|
| Last 24 hours | `date -v-1d +%Y-%m-%d` | `date -d '1 day ago' +%Y-%m-%d` |
| Last 7 days | `date -v-7d +%Y-%m-%d` | `date -d '7 days ago' +%Y-%m-%d` |
| Last 30 days | `date -v-30d +%Y-%m-%d` | `date -d '30 days ago' +%Y-%m-%d` |

## Bot Exclusion

Filter automated accounts using these regex patterns in jq:

| Platform | Regex Pattern | Example Bots |
|----------|---------------|--------------|
| GitHub (CoreOS) | `bot\|dependabot\|konflux\|coreosbot\|gemini-code-assist` | dependabot[bot], coreosbot-releng, gemini-code-assist[bot] |
| GitHub (openshift/os) | above + `\|openshift\|ci-robot` | openshift-merge-robot, openshift-ci[bot], openshift-ci-robot |
| GitLab | `bot\|renovate\|platform-engineering` | platform-engineering-bot |

> **Comment filtering:** Use the same patterns when filtering **comments** in detail fetches,
> not just when filtering issue/PR **authors** in search results. Bot review comments
> (e.g., gemini-code-assist priority markers, openshift-ci /retest notices) add significant noise.

## Core Commands (GitHub)

### Command Template

```bash
gh search {issues|prs} {SCOPE} {FILTER} ">=$(date -v-7d +%Y-%m-%d)" \
  --limit 100 --json repository,title,author,number,url \
  --jq '.[] | select(.author.login | test("BOT_PATTERN"; "i") | not)'
# Linux: use date -d '7 days ago' instead of date -v-7d
```

### Query Variations

| Query | Type | SCOPE | FILTER | BOT_PATTERN |
|-------|------|-------|--------|-------------|
| New issues (CoreOS) | `issues` | `--owner coreos` | `--created` | `bot\|dependabot\|konflux\|coreosbot\|gemini-code-assist` |
| New issues (openshift/os) | `issues` | `--repo openshift/os` | `--created` | add `\|openshift\|ci-robot` to above |
| Closed issues | `issues` | (same scopes) | `--closed` | (same patterns) |
| New PRs | `prs` | (same scopes) | `--created` | (same patterns) |
| Merged PRs | `prs` | (same scopes) | `--merged` | (same patterns) |

### Releases

```bash
for repo in coreos-assembler ignition bootupd afterburn zincati chunkah go-oidc butane; do
  gh release list --repo coreos/$repo --limit 3 2>/dev/null
done
```

## Most Active Items

Find items with genuine recent activity. **Important:** `--sort comments` returns lifetime counts - always verify freshness.

### Find Candidates

> **Important:** `gh search issues` only returns issues, NOT pull requests.
> You must run **both** `gh search issues` and `gh search prs` to find all active discussions.

```bash
# Recently updated issues (use --sort updated for freshness)
gh search issues --owner coreos --updated ">=$(date -v-7d +%Y-%m-%d)" \
  --sort updated --order desc --limit 100 \
  --json number,title,repository,commentsCount,author,url \
  --jq '.[] | select(.author.login | test("bot|dependabot|konflux|coreosbot|gemini-code-assist"; "i") | not)'

# Recently updated PRs (must search separately - gh search issues does NOT include PRs)
gh search prs --owner coreos --updated ">=$(date -v-7d +%Y-%m-%d)" \
  --sort updated --order desc --limit 100 \
  --json number,title,repository,author,url \
  --jq '.[] | select(.author.login | test("bot|dependabot|konflux|coreosbot|gemini-code-assist"; "i") | not)'
```

> **Note:** `gh search prs` does not support `commentsCount` in JSON output.
> Use the `?since=` API in the verification step to get recent comment counts for PR candidates.

> **Minimum Coverage:** Always verify at least 50 PR candidates and all issue candidates.
> Use the batch parallel verification command to efficiently check all candidates.
> Do NOT manually select a subset based on intuition -- this leads to missing active discussions.

### Verify Recent Comments

> **CRITICAL:** You MUST verify **ALL** candidates -- both issue candidates AND PR candidates.
> PR candidates are easy to overlook because `gh search prs` lacks `commentsCount`, but PRs
> often have the most active discussions. Skipping PR verification will cause you to miss
> important discussions. Run `?since=` for every candidate from both searches.

Use `?since=` API parameter to count comments *within* the reporting period.

**For both issues and PRs**, use the issues API (GitHub's issues API covers PR comments too):

```bash
SINCE_DATE=$(date -v-7d +%Y-%m-%d)
# Linux: SINCE_DATE=$(date -d '7 days ago' +%Y-%m-%d)
# This works for BOTH issues and PRs (GitHub treats PR comments as issue comments)
gh api "repos/coreos/<repo>/issues/<number>/comments?since=${SINCE_DATE}T00:00:00Z" --jq 'length'
```

**For PRs with review comments** (inline code review discussions), also check:

```bash
gh api "repos/coreos/<repo>/pulls/<number>/comments?since=${SINCE_DATE}T00:00:00Z" --jq 'length'
```

> **Tip:** Sum both counts (issue comments + PR review comments) to get the total recent activity for a PR.

**Freshness rule:** Only include items with 2+ recent comments in "Most Active Discussions". Items with 0 recent comments are stale even if total count is high.

> **Important:** Always use `?since=` when fetching comment content too, not just for counting. Without it, `.[-10:]` returns the last 10 comments of *all time*, which may be months old.

### Batch Verification (Parallel)

Verify ALL candidates efficiently using parallel background jobs (~3 seconds for 100 items):

```bash
SINCE=$(date -v-7d +%Y-%m-%d)
# Linux: SINCE=$(date -d '7 days ago' +%Y-%m-%d)

# PR candidates (checks both issue comments and review comments)
gh search prs --owner coreos --updated ">=$SINCE" --sort updated --order desc --limit 100 \
  --json number,repository --jq '.[] | "\(.repository.name)/\(.number)"' | \
while read item; do
  (
    repo="${item%/*}"; num="${item#*/}"
    ic=$(gh api "repos/coreos/$repo/issues/$num/comments?since=${SINCE}T00:00:00Z" --jq 'length' 2>/dev/null || echo 0)
    rc=$(gh api "repos/coreos/$repo/pulls/$num/comments?since=${SINCE}T00:00:00Z" --jq 'length' 2>/dev/null || echo 0)
    total=$((ic + rc))
    [ "$total" -ge 2 ] && echo "$repo#$num: $total"
  ) &
done; wait

# Issue candidates (issue comments only)
gh search issues --owner coreos --updated ">=$SINCE" --sort updated --order desc --limit 100 \
  --json number,repository --jq '.[] | "\(.repository.name)/\(.number)"' | \
while read item; do
  (
    repo="${item%/*}"; num="${item#*/}"
    count=$(gh api "repos/coreos/$repo/issues/$num/comments?since=${SINCE}T00:00:00Z" --jq 'length' 2>/dev/null || echo 0)
    [ "$count" -ge 2 ] && echo "$repo#$num: $count"
  ) &
done; wait
```

> **Performance:** 100 candidates verify in ~3 seconds using parallel background jobs.
> Pipe through `sort -t: -k2 -rn` to rank by activity.

#### openshift/os candidates

Run the same verification for openshift/os separately (uses `repos/openshift/os` API paths):

```bash
# openshift/os PR candidates
gh search prs --repo openshift/os --updated ">=$SINCE" --sort updated --order desc --limit 100 \
  --json number,repository --jq '.[] | "\(.repository.name)/\(.number)"' | \
while read item; do
  (
    repo="${item%/*}"; num="${item#*/}"
    ic=$(gh api "repos/openshift/$repo/issues/$num/comments?since=${SINCE}T00:00:00Z" --jq 'length' 2>/dev/null || echo 0)
    rc=$(gh api "repos/openshift/$repo/pulls/$num/comments?since=${SINCE}T00:00:00Z" --jq 'length' 2>/dev/null || echo 0)
    total=$((ic + rc))
    [ "$total" -ge 2 ] && echo "openshift/$repo#$num: $total"
  ) &
done; wait

# openshift/os issue candidates
gh search issues --repo openshift/os --updated ">=$SINCE" --sort updated --order desc --limit 100 \
  --json number,repository --jq '.[] | "\(.repository.name)/\(.number)"' | \
while read item; do
  (
    repo="${item%/*}"; num="${item#*/}"
    count=$(gh api "repos/openshift/$repo/issues/$num/comments?since=${SINCE}T00:00:00Z" --jq 'length' 2>/dev/null || echo 0)
    [ "$count" -ge 2 ] && echo "openshift/$repo#$num: $count"
  ) &
done; wait
```

> **Do NOT manually select a subset of candidates.** Always verify all candidates returned by the search.
> Manual selection leads to missing active discussions (e.g., long-running PRs with recent bursts of activity).

### Batch Detail Fetching (Parallel)

After identifying items with 2+ recent comments, fetch details for all of them in parallel using temp files to avoid interleaved output:

```bash
SINCE=$(date -v-7d +%Y-%m-%d)
# Linux: SINCE=$(date -d '7 days ago' +%Y-%m-%d)
OUTDIR=$(mktemp -d)

# Populate from verification step results (separate PRs and issues)
prs=("fedora-coreos-config/4030" "coreos-assembler/4224" "coreos-assembler/4377")
issues=("chunkah/97" "fedora-coreos-docs/798")
BOT_COMMENT_FILTER='select(.user.login | test("bot|dependabot|konflux|coreosbot|gemini-code-assist"; "i") | not)'

# PRs - includes review comments
for item in "${prs[@]}"; do
  (
    repo="${item%/*}"; num="${item#*/}"
    {
      echo "=== $repo#$num (PR) ==="
      gh pr view $num --repo coreos/$repo --json title,author,state,mergedAt \
        --jq '"\(.title) | @\(.author.login) | \(.state) | merged:\(.mergedAt)"'
      echo "--- Comments ---"
      gh api "repos/coreos/$repo/issues/$num/comments?since=${SINCE}T00:00:00Z" \
        --jq "[.[] | $BOT_COMMENT_FILTER] | .[-5:] | .[] | \"**@\(.user.login)**: \(.body | split(\"\n\")[0])\""
      gh api "repos/coreos/$repo/pulls/$num/comments?since=${SINCE}T00:00:00Z" \
        --jq "[.[] | $BOT_COMMENT_FILTER] | .[-5:] | .[] | \"**@\(.user.login)**: \(.body | split(\"\n\")[0])\""
      echo ""
    } > "$OUTDIR/${repo//\//_}_$num.txt" 2>/dev/null
  ) &
done

# Issues - no review comments
for item in "${issues[@]}"; do
  (
    repo="${item%/*}"; num="${item#*/}"
    {
      echo "=== $repo#$num (Issue) ==="
      gh issue view $num --repo coreos/$repo --json title,author,state \
        --jq '"\(.title) | @\(.author.login) | \(.state)"'
      echo "--- Comments ---"
      gh api "repos/coreos/$repo/issues/$num/comments?since=${SINCE}T00:00:00Z" \
        --jq "[.[] | $BOT_COMMENT_FILTER] | .[-5:] | .[] | \"**@\(.user.login)**: \(.body | split(\"\n\")[0])\""
      echo ""
    } > "$OUTDIR/${repo//\//_}_$num.txt" 2>/dev/null
  ) &
done
wait

# Output all results (alphabetically by filename)
cat "$OUTDIR"/*.txt
rm -rf "$OUTDIR"
```

> **Performance:** Fetches ~15 items in ~2 seconds vs ~30+ seconds sequentially.

> **Tip:** Use array syntax (`prs=(...)`) not space-separated strings to handle repository names with special characters correctly.

> **openshift/os items:** For items from openshift/os, use `--repo openshift/os` instead of
> `--repo coreos/$repo` in `gh pr view` / `gh issue view`, and `repos/openshift/os` in API paths.
> Extend the bot comment filter for openshift/os to also exclude CI bots:
> ```
> BOT_COMMENT_FILTER='select(.user.login | test("bot|dependabot|konflux|coreosbot|gemini-code-assist|openshift-ci|ci-robot"; "i") | not)'
> ```
> This filters out `openshift-ci[bot]` (retest/approval notifications) and `openshift-ci-robot` (Jira tracker messages)
> which are especially noisy in openshift/os PRs.

### Cross-Reference Checking

When a PR body references another PR (e.g., "This replaces #1234" or "Supersedes #1234"):
1. Verify BOTH the current PR AND the referenced PR
2. The older PR may still have active discussion even if a replacement exists
3. Include both in the report if either has 2+ recent comments

Common patterns to watch for:
- "Replaces #NNN" / "Supersedes #NNN"
- "Continuation of #NNN"
- "Split from #NNN"

## Statistics Commands

Combine multiple searches, extract a field, and count occurrences:

```bash
# Template: { search1; search2; ... } | sort | uniq -c | sort -rn
{
  gh search {issues|prs} --owner coreos --created ">=$(date -v-7d +%Y-%m-%d)" \
    --limit 100 --json {repository,author} \
    --jq '.[] | select(.author.login | test("BOT_PATTERN"; "i") | not) | .{FIELD}'
  # Add openshift/os variant as needed
  # Linux: use date -d '7 days ago' instead of date -v-7d
} | sort | uniq -c | sort -rn
```

| Metric | Type | FIELD | Notes |
|--------|------|-------|-------|
| Issues by repo | `issues` | `.repository.name` | |
| PRs by repo | `prs` | `.repository.name` | |
| Top contributors | both | `.author.login` | Combine issues + prs |

### Merged PR Count Verification

The `gh search prs --merged` filter can significantly undercount due to GitHub search API indexing lag.
Cross-reference with detail fetches to get accurate merged counts:

```bash
SINCE=$(date -v-7d +%Y-%m-%d)
# Linux: SINCE=$(date -d '7 days ago' +%Y-%m-%d)

# Check merge status for all PRs created in the period
gh search prs --owner coreos --created ">=$SINCE" --limit 100 \
  --json number,repository --jq '.[] | "\(.repository.name)/\(.number)"' | \
while read item; do
  (
    repo="${item%/*}"; num="${item#*/}"
    merged=$(gh pr view $num --repo coreos/$repo --json mergedAt --jq '.mergedAt' 2>/dev/null)
    [ "$merged" != "null" ] && [ -n "$merged" ] && echo "$repo#$num: merged $merged"
  ) &
done; wait
```

> **When to use:** If the `--merged` search returns significantly fewer results than expected
> (e.g., 2 vs 15+), use this approach to derive accurate counts from the `--created` search.
> The `--merged` search relies on GitHub's search index which can lag hours or days behind.

> **Tip:** You can also count merged PRs from the batch detail fetches (step 7) by checking
> `mergedAt` in the PR view output, avoiding an extra API round-trip.

## Detailed Views

```bash
# Issue/PR details
gh issue view <number> --repo coreos/<repo> --json title,body,author,state,labels
gh pr view <number> --repo coreos/<repo> --json title,body,author,state,mergedAt

# Recent comments on an issue/PR (use ?since= to filter to reporting period)
SINCE_DATE=$(date -v-7d +%Y-%m-%d)
# Linux: SINCE_DATE=$(date -d '7 days ago' +%Y-%m-%d)
gh api "repos/coreos/<repo>/issues/<number>/comments?since=${SINCE_DATE}T00:00:00Z" \
  --jq '[.[] | select(.user.login | test("bot|dependabot|konflux|coreosbot|gemini-code-assist"; "i") | not)] | .[-10:] | .[] | "**@\(.user.login)** (\(.created_at | split("T")[0])): \(.body | split("\n")[0])"'
```

> **PR State Distinction:** A PR with `state: CLOSED` can be either merged or closed without merging. Check `mergedAt`:
> - `mergedAt` has a timestamp → **MERGED**
> - `mergedAt` is null → **CLOSED** (without merge)

## Key Repositories

### Build & Tooling

| Repository | Description |
|------------|-------------|
| `coreos-assembler` | cosa - the build tool for CoreOS images |
| `ignition` | First boot installer and configuration tool |
| `butane` | Human-readable config to Ignition transpiler |
| `afterburn` | Cloud provider agent |
| `bootupd` | Bootloader updater |

### Configuration

| Repository | Description |
|------------|-------------|
| `fedora-coreos-config` | Base configuration for FCOS |
| `rhel-coreos-config` | Base configuration for RHCOS |
| `fedora-coreos-tracker` | Issue tracker for FCOS |
| `openshift/os` | RHCOS issue tracker, extensions, and machine-os-content |

### Pipeline & Release

| Repository | Description |
|------------|-------------|
| `fedora-coreos-pipeline` | Build pipeline for FCOS |
| `fedora-coreos-streams` | Stream metadata and release tracking |
| `fedora-coreos-releng-automation` | Release engineering automation |

### Libraries & Utilities

| Repository | Description |
|------------|-------------|
| `chunkah` | OCI building tool for content-based layers |
| `zincati` | Auto-update agent for FCOS |
| `go-oidc` | Go OpenID Connect client |
| `cargo-vendor-filterer` | Cargo vendor filtering tool |

## Output Format

Structure activity summaries with these sections:

### 1-3. Overview Stats, Active Repos, Contributors

| Metric | GitHub | GitLab |
|--------|--------|--------|
| New Issues | X | X |
| Issues Closed | X | - |
| New PRs/MRs | X | X |
| Merged | X | X |

### 4-5. Notable Issues/PRs

```markdown
### Issue/PR Title (MERGED/OPEN)
**Repo:** [repo#number](url) | **Author:** @username

**Summary:** 2-3 sentence description.
**Impact:** What this affects and proposed solutions.
```

### 6. Most Active Discussions

Only include items with **2+ recent comments** (verify with `?since=` API):

```markdown
### Discussion: The packing algorithm over-merges some components
**Item:** [chunkah#97](url) | **Recent Comments:** 5 (7d) | **Total:** 14

**Discussion Highlights:**
- **@solacelost**: Reported layer caching behavior issues
- **@jlebon**: Testing performance fixes against Silverblue

**Current Status:** Active investigation; performance testing in progress.
```

### 7-9. Releases, FCOS Streams, Key Themes

| Stream | Version | Status |
|--------|---------|--------|
| **next** | 44.20260405.1.1 | Released |
| **testing** | 43.20260331.2.1 | Active |
| **stable** | 43.20260316.3.1 | Active |

Summarize 3-5 observed trends in "Key Themes" section.

## Workflow: Quick 7-Day Summary

1. **Gather GitHub data** - Run CoreOS org, openshift/os issue/PR/release commands in parallel using `gh`
2. **Gather GitLab data** - Run fedora/bootc issue/MR commands in parallel using `glab`
3. **Calculate statistics** - Run grouping/counting commands for both platforms
4. **Identify notable items** - Filter for non-bot activity on both GitHub and GitLab
5. **Find candidate discussions** - Search both `gh search issues` and `gh search prs` (separately) for recently updated items
6. **Verify freshness for ALL candidates** - Use the batch parallel verification commands to check ALL candidates (minimum 50 PRs, all issues). This takes ~3 seconds for 100 items. Filter to items with 2+ recent comments. Do NOT manually select a subset -- verify everything to avoid missing active discussions like long-running PRs. When a candidate references another PR ("replaces #NNN"), verify both.
7. **Fetch details and discussion context** - Use the batch parallel fetching pattern with temp files for all active items from both platforms. This fetches PR/issue metadata and recent comments (`?since=`) in a single parallel step (~2 seconds for 15 items).
8. **Generate overview** - Write high-level summaries including discussion highlights
9. **Compile report** - Format using the unified output structure above

> **Note:** GitHub uses `gh` CLI while GitLab uses `glab` CLI. Commands for both platforms can run in parallel.

> **Important:** Do not rely on `--sort interactions` or `--sort comments` alone - these return cumulative counts and will surface stale discussions. Always verify that comments are recent before including in the activity summary.

## FCOS Stream Release Tracking

Release issues in `fedora-coreos-streams` follow a template checklist format. These track the release process for `next`, `testing`, and `stable` streams.

```bash
# Find release tracking issues
gh search issues --owner coreos --repo coreos/fedora-coreos-streams \
  --created ">=$(date -v-7d +%Y-%m-%d)" \
  --json title,number,state,labels \
  --jq '.[] | select(.title | test("new release on"))'
# Linux: use date -d '7 days ago' instead of date -v-7d
```

## GitLab: fedora/bootc Group

**URL:** https://gitlab.com/fedora/bootc

| Repository | Description |
|------------|-------------|
| `base-images` | Fedora/CentOS bootc base images |
| `docs` | Documentation |
| `tests/bootc-workflow-test` | Integration testing |

### Command Template

```bash
glab {issue|mr} list --group fedora/bootc {--all|--merged} --per-page 100 --output json | \
  jq -r --arg since "$(date -v-7d +%Y-%m-%d)" \
    '.[] | select(.author.username | test("bot|renovate|platform-engineering"; "i") | not) | 
     select(.created_at >= $since) | "\(.references.full): \(.title) (@\(.author.username))"'
# Linux: use date -d '7 days ago' instead of date -v-7d
```

| Query | Command | Filter |
|-------|---------|--------|
| New MRs | `mr list --all --created-after DATE` | `.created_at >= $since` |
| Merged MRs | `mr list --merged` | `.merged_at >= $since` |
| Issues | `issue list --all` | `.created_at >= $since` |

### Details & Statistics

```bash
# MR/Issue details
glab mr view <number> --repo fedora/bootc/<repo> --output json | jq '{title, author: .author.username, state}'

# Top contributors (merged MRs)
glab mr list --group fedora/bootc --merged --per-page 100 --output json | \
  jq -r '.[] | select(.author.username | test("bot"; "i") | not) | .author.username' | \
  sort | uniq -c | sort -rn
```

## Tips

| Platform | Key Tips |
|----------|----------|
| GitHub | Run `gh` commands in parallel; `--limit 100`; `date -v-Nd` macOS / `date -d` Linux |
| GitLab | `--group` queries all subprojects; `--output json`; `--created-after` ISO 8601 |
| Both | Filter bots in jq with `.author.{login\|username} \| test("pattern"; "i")` |
