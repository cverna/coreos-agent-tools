---
name: sprint-planning
description: Sprint Review and Planning for COS project - velocity analysis, carryover management, and sprint composition
---

# Sprint Review and Planning

Guide for conducting Sprint Review and Sprint Planning for COS project.

> Related: `jira-estimation` (for story point scale and estimation guidelines)

## COS Project Conventions

### Sprint Naming
- East team: `CoreOS East - Sprint NNN`
- West team: `CoreOS West - Sprint NNN`

### Sprint Duration
- Typically 3 weeks
- East and West may have slightly different dates

### Custom Fields
- Story Points: `customfield_10028`
- Sprint: `customfield_10020`

### Team Order
Process East team first, then West team.

### Pipeline Monitoring
Each sprint typically has 3 pipeline monitoring tasks (one per week). These can be created upon request - see "Creating Pipeline Monitoring Tasks" section.

## JIRA CLI Commands

### Sprint Discovery

```bash
# List active sprints
jira sprint list --project COS --state active

# List future sprints
jira sprint list --project COS --state future

# Get sprint ID for adding issues
jira sprint list --project COS --state future | grep "Sprint NNN"
```

### Sprint Issues

```bash
# List all issues in a sprint
jira issue list --jql 'project = COS AND sprint = "CoreOS East - Sprint NNN"' --plain --no-truncate

# List closed issues
jira issue list --jql 'project = COS AND sprint = "CoreOS East - Sprint NNN" AND status = Closed' --plain --no-truncate

# List open issues (carryover candidates)
jira issue list --jql 'project = COS AND sprint = "CoreOS East - Sprint NNN" AND status != Closed' --plain --no-truncate
```

### Story Points

```bash
# Get story points for an issue
jira issue view <KEY> --raw | jq '.fields.customfield_10028'

# Batch get story points for multiple issues
for key in COS-1234 COS-1235 COS-1236; do
  jira issue view "$key" --raw 2>/dev/null | jq -r '{key: .key, summary: .fields.summary, status: .fields.status.name, assignee: .fields.assignee.displayName, storyPoints: (.fields.customfield_10028 // 0)} | "\(.key)|\(.status)|\(.assignee // "Unassigned")|\(.storyPoints)|\(.summary)"'
done
```

### Issue Management

```bash
# Create a task
jira issue create --project COS --type Task --summary "<summary>" --no-input

# Add issue to sprint (by sprint ID)
jira sprint add <sprint-id> <issue-key-1> <issue-key-2>

# Transition issue to Closed
jira issue move <KEY> "Closed"

# Add comment
jira issue comment add <KEY> "<comment-text>"
```

### Setting Story Points

> **Note:** Story Points (`customfield_10028`) cannot be reliably set via CLI. Set manually in JIRA UI after creating issues.

## GitHub PR Status Check

### Check PR Status

```bash
# Check single PR
gh pr view <number> --repo <org>/<repo> --json title,state,reviewDecision,mergeable,updatedAt

# Common repositories
gh pr view <n> --repo coreos/coreos-assembler
gh pr view <n> --repo coreos/butane
gh pr view <n> --repo coreos/bootupd
gh pr view <n> --repo coreos/afterburn
gh pr view <n> --repo coreos/ignition
gh pr view <n> --repo coreos/fedora-coreos-pipeline
```

### PR Status Interpretation

| Field | Values | Meaning |
|-------|--------|---------|
| `state` | OPEN, MERGED, CLOSED | PR lifecycle |
| `reviewDecision` | APPROVED, REVIEW_REQUIRED, CHANGES_REQUESTED | Review status |
| `mergeable` | MERGEABLE, CONFLICTING, UNKNOWN | Can be merged |

### Find PRs for Issues

```bash
# Search by keyword
gh search prs --repo coreos/<repo> "<keyword>" --json number,title,state

# List PRs by author
gh pr list --repo coreos/<repo> --author <username> --state all
```

## Sprint Review Workflow

### 1. Gather Sprint Data

```bash
# Get all issues with story points
jira issue list --jql 'project = COS AND sprint = "CoreOS East - Sprint NNN"' --plain --no-truncate

# For each issue, get story points
jira issue view <KEY> --raw | jq '{key, summary: .fields.summary, status: .fields.status.name, points: .fields.customfield_10028}'
```

### 2. Calculate Statistics

| Metric | Formula |
|--------|---------|
| Total Committed | Sum of all story points |
| Completed | Sum of points where status = Closed |
| Completion Rate | Completed / Total x 100 |
| Daily Velocity | Completed / Working Days |

### 3. Identify Themes

Group completed work by category:
- Releases (FCOS next/testing/stable)
- Platform (Azure, AWS, GCP)
- Package additions
- Bug fixes
- Upstream contributions
- Pipeline monitoring

### 4. Team Performance

| Team Member | Closed | Open | Total | Completion % |
|-------------|--------|------|-------|--------------|

### 5. Items Needing Attention

- PRs with conflicts (need rebase)
- Items in Review > 1 week
- Items not started
- Long-running items (> 100 days)

## Sprint Planning Workflow

### 1. Identify Carryover

```bash
# Open items from previous sprint
jira issue list --jql 'project = COS AND sprint = "CoreOS East - Sprint NNN" AND status != Closed' --plain --no-truncate
```

### 2. Check GitHub PR Status

For each item in Review/In Progress, check if PR exists and its status:
- MERGEABLE + REVIEW_REQUIRED = Quick win, needs review
- CONFLICTING = Needs rebase before sprint
- No PR = Verify work has started

### 3. Calculate Projected Load

| Category | Points |
|----------|--------|
| Carryover - In Review | X |
| Carryover - In Progress | X |
| Carryover - New | X |
| New Work | X |
| **Total** | X |

### 4. Velocity Target

Based on previous sprint:
- If completion was < 50%, reduce commitment
- Target 70-80% completion rate
- Account for pipeline monitoring (operational overhead)

### 5. Risk Assessment

| Risk Level | Criteria |
|------------|----------|
| Low | In Review with mergeable PR |
| Medium | In Progress with active work |
| High | Not started, or 8+ point stories |

## Creating Pipeline Monitoring Tasks

> **Note:** Create these tasks only when requested by the user.

Pipeline monitoring tasks follow this pattern:

```bash
# Create pipeline monitoring task
jira issue create --project COS --type Task \
  --summary "Pipeline monitoring - Sprint NNN - Ws YYYYMMDD" \
  --no-input

# Add to sprint (get sprint ID first)
jira sprint add <sprint-id> <issue-key>
```

### Naming Convention
- Format: `Pipeline monitoring - Sprint NNN - Ws YYYYMMDD`
- `Ws` = Week starting
- One task per week of the sprint (typically 3 per sprint)

### Story Points
- East team: 5 points per week
- West team: 2 points per week
- Set manually in JIRA UI after creation

### Example for 3-week Sprint 287 (Apr 13 - May 4)
| Task | Week Starting |
|------|---------------|
| Pipeline monitoring - Sprint 287 - Ws 20260413 | Apr 13 |
| Pipeline monitoring - Sprint 287 - Ws 20260420 | Apr 20 |
| Pipeline monitoring - Sprint 287 - Ws 20260427 | Apr 27 |

## Output Templates

### Sprint Review Summary

```markdown
## Sprint NNN Review - CoreOS East/West

### Sprint Details
- **Sprint:** CoreOS East/West - Sprint NNN
- **Duration:** MMM DD - MMM DD, YYYY

### Sprint Statistics
| Metric | Value |
|--------|-------|
| Total Committed | X pts (N items) |
| Completed | X pts (N items) |
| Completion Rate | X% |

### Completed Work (X pts)

#### Theme 1
| Key | Summary | Owner | Pts |
|-----|---------|-------|-----|

#### Theme 2
...

### Team Performance
| Team Member | Closed | Open | Total | Completion |
|-------------|--------|------|-------|------------|

### Key Accomplishments
1. ...
2. ...

### Items Needing Attention
| Key | Summary | Issue |
|-----|---------|-------|

### Lessons Learned
| What Worked | What Didn't |
|-------------|-------------|
```

### Sprint Planning Summary

```markdown
## Sprint NNN Planning - CoreOS East/West

### Sprint Details
- **Sprint:** CoreOS East/West - Sprint NNN
- **Duration:** MMM DD - MMM DD, YYYY

### Sprint Composition
| Category | Points | Items |
|----------|--------|-------|
| Pipeline Monitoring | X | 3 |
| Carryover - In Review | X | N |
| Carryover - In Progress | X | N |
| Carryover - New | X | N |
| New Work | X | N |
| **Total** | X | N |

### Sprint Backlog
| Key | Summary | Assignee | Pts | Status |
|-----|---------|----------|-----|--------|

### Team Load
| Team Member | Points | Items | Notes |
|-------------|--------|-------|-------|

### Velocity Target
| Metric | Previous | Target |
|--------|----------|--------|
| Committed | X pts | X pts |
| Expected Completion | X pts | X pts |
| Daily Velocity | X pts | X pts |

### Risk Assessment
| Risk | Mitigation |
|------|------------|

### Action Items
| Action | Owner | Due |
|--------|-------|-----|
```

## Velocity Benchmarks

| Velocity | Assessment |
|----------|------------|
| > 5 pts/day | Excellent |
| 3-5 pts/day | Good |
| 2-3 pts/day | Below target |
| < 2 pts/day | Needs attention |

| Completion Rate | Assessment |
|-----------------|------------|
| > 80% | Excellent |
| 70-80% | Good (target) |
| 50-70% | Below target |
| < 50% | Needs attention |

## Tips

1. **Process East first, then West** - They may have different sprint dates
2. **Check PR status for Review items** - Quick wins if mergeable
3. **Watch 8-point stories** - High risk, consider splitting (see `jira-estimation` skill)
4. **Account for pipeline monitoring** - Operational overhead each sprint
5. **Realistic carryover** - Don't carry forward items that weren't started
6. **Close completed items** - Check if PRs were merged but JIRA not updated
7. **Rebase conflicting PRs** - Address before bringing into new sprint
