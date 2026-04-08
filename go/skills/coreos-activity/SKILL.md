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

| Range | Date Filter |
|-------|-------------|
| Last 24 hours | `">=$(date -d '1 day ago' +%Y-%m-%d)"` |
| Last 7 days | `">=$(date -d '7 days ago' +%Y-%m-%d)"` |
| Last 30 days | `">=$(date -d '30 days ago' +%Y-%m-%d)"` |

## Bot Exclusion

Filter automated accounts using these regex patterns in jq:

| Platform | Regex Pattern | Example Bots |
|----------|---------------|--------------|
| GitHub (CoreOS) | `bot\|dependabot\|konflux\|coreosbot` | dependabot[bot], coreosbot-releng |
| GitHub (openshift/os) | above + `\|openshift` | openshift-merge-robot, openshift-ci[bot] |
| GitLab | `bot\|renovate\|platform-engineering` | platform-engineering-bot |

## Core Commands (GitHub)

### Command Template

```bash
gh search {issues|prs} {SCOPE} {FILTER} ">=$(date -d '7 days ago' +%Y-%m-%d)" \
  --limit 100 --json repository,title,author,number,url \
  --jq '.[] | select(.author.login | test("BOT_PATTERN"; "i") | not)'
```

### Query Variations

| Query | Type | SCOPE | FILTER | BOT_PATTERN |
|-------|------|-------|--------|-------------|
| New issues (CoreOS) | `issues` | `--owner coreos` | `--created` | `bot\|dependabot\|konflux\|coreosbot` |
| New issues (openshift/os) | `issues` | `--repo openshift/os` | `--created` | add `\|openshift` to above |
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

```bash
# Recently updated issues/PRs (use --sort updated for freshness)
gh search issues --owner coreos --updated ">=$(date -d '7 days ago' +%Y-%m-%d)" \
  --sort updated --order desc --limit 20 \
  --json number,title,repository,commentsCount,author,url \
  --jq '.[] | select(.author.login | test("bot|dependabot|konflux|coreosbot"; "i") | not)'
```

### Verify Recent Comments

Use `?since=` API parameter to count comments *within* the reporting period:

```bash
SINCE_DATE=$(date -d '7 days ago' +%Y-%m-%d)
gh api "repos/coreos/<repo>/issues/<number>/comments?since=${SINCE_DATE}T00:00:00Z" --jq 'length'
```

**Freshness rule:** Only include items with 2+ recent comments in "Most Active Discussions". Items with 0 recent comments are stale even if total count is high.

## Statistics Commands

Combine multiple searches, extract a field, and count occurrences:

```bash
# Template: { search1; search2; ... } | sort | uniq -c | sort -rn
{
  gh search {issues|prs} --owner coreos --created ">=$(date -d '7 days ago' +%Y-%m-%d)" \
    --limit 100 --json {repository,author} \
    --jq '.[] | select(.author.login | test("BOT_PATTERN"; "i") | not) | .{FIELD}'
  # Add openshift/os variant as needed
} | sort | uniq -c | sort -rn
```

| Metric | Type | FIELD | Notes |
|--------|------|-------|-------|
| Issues by repo | `issues` | `.repository.name` | |
| PRs by repo | `prs` | `.repository.name` | |
| Top contributors | both | `.author.login` | Combine issues + prs |

## Detailed Views

```bash
# Issue/PR details
gh issue view <number> --repo coreos/<repo> --json title,body,author,state,labels
gh pr view <number> --repo coreos/<repo> --json title,body,author,state

# Recent comments on an issue
gh api repos/coreos/<repo>/issues/<number>/comments \
  --jq '.[-10:] | .[] | "**@\(.user.login)** (\(.created_at | split("T")[0])): \(.body | split("\n")[0])"'
```

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
5. **Find candidate discussions** - Get recently updated items with 3+ total comments
6. **Verify freshness** - Use `?since=` API (GitHub) to count comments within the reporting period; only include items with 2+ recent comments in "Most Active Discussions"
7. **Fetch details** - Get body text for notable issues/PRs/MRs from both platforms
8. **Fetch discussion context** - Get recent comments for genuinely active items
9. **Generate overview** - Write high-level summaries including discussion highlights
10. **Compile report** - Format using the unified output structure above

> **Note:** GitHub uses `gh` CLI while GitLab uses `glab` CLI. Commands for both platforms can run in parallel.

> **Important:** Do not rely on `--sort interactions` or `--sort comments` alone - these return cumulative counts and will surface stale discussions. Always verify that comments are recent before including in the activity summary.

## FCOS Stream Release Tracking

Release issues in `fedora-coreos-streams` follow a template checklist format. These track the release process for `next`, `testing`, and `stable` streams.

```bash
# Find release tracking issues
gh search issues --owner coreos --repo coreos/fedora-coreos-streams \
  --created ">=$(date -d '7 days ago' +%Y-%m-%d)" \
  --json title,number,state,labels \
  --jq '.[] | select(.title | test("new release on"))'
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
  jq -r --arg since "$(date -d '7 days ago' +%Y-%m-%d)" \
    '.[] | select(.author.username | test("bot|renovate|platform-engineering"; "i") | not) | 
     select(.created_at >= $since) | "\(.references.full): \(.title) (@\(.author.username))"'
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
| GitHub | Run `gh` commands in parallel; `--limit 100`; `date -d` for Linux |
| GitLab | `--group` queries all subprojects; `--output json`; `--created-after` ISO 8601 |
| Both | Filter bots in jq with `.author.{login\|username} \| test("pattern"; "i")` |
