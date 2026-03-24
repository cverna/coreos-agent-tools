---
name: jira-estimation
description: Estimate Jira story points - scope analysis, comparable stories, and estimation guidelines
---

# Jira Story Point Estimation

Guide for estimating story points on Jira issues with consistent methodology.

## Estimation Process

1. **Gather issue details** - View the issue, description, subtasks, linked issues, epic
2. **Analyze scope** - Identify key work areas, dependencies, unknowns
3. **Find comparable stories** - Search for similar completed stories with points
4. **Apply estimation guidelines** - Use the point scale consistently
5. **Document reasoning** - Add a comment explaining the estimate

## JIRA CLI Commands

### Viewing Issue Details

```bash
# View issue with comments
jira issue view <ISSUE-KEY> --comments 10

# Get full details including custom fields (story points = customfield_10028)
jira issue view <ISSUE-KEY> --raw | jq '{
  key: .key,
  summary: .fields.summary,
  description: .fields.description,
  storyPoints: .fields.customfield_10028,
  status: .fields.status.name,
  assignee: .fields.assignee?.displayName,
  epic: .fields.customfield_10014,
  subtasks: [.fields.subtasks[]? | {key: .key, summary: .fields.summary, status: .fields.status.name}],
  issuelinks: [.fields.issuelinks[]? | {type: .type.name, inward: .inwardIssue?.key, outward: .outwardIssue?.key}]
}'
```

### Finding Comparable Stories

```bash
# Find closed stories with story points matching keywords
jira issue list --jql 'project = COS AND type = Story AND status = Closed AND "Story Points[Number]" > 0 AND summary ~ "<keyword>"' --plain --no-truncate

# Get story points for specific issues
jira issue view <ISSUE-KEY> --raw | jq '{key: .key, summary: .fields.summary, storyPoints: .fields.customfield_10028}'

# Find stories by label
jira issue list --jql 'project = COS AND type = Story AND status = Closed AND "Story Points[Number]" > 0 AND labels = "<label>"' --plain --no-truncate

# Find stories in same epic
jira issue list --jql 'project = COS AND type = Story AND status = Closed AND "Story Points[Number]" > 0 AND "Epic Link" = <EPIC-KEY>' --plain --no-truncate
```

### Setting Story Points

> **Note:** Story Points is custom field `customfield_10028`. The JIRA CLI does not reliably set this field - manual update in the UI is required.

```bash
# Add estimation comment (always do this)
jira issue comment add <ISSUE-KEY> "Estimated at X story points based on:
- <reasoning point 1>
- <reasoning point 2>
- <comparable story reference>"
```

## Story Point Scale

| Points | Complexity | Duration | Notes |
|--------|------------|----------|-------|
| 1 | Trivial | < 1 day | Config change, doc update, simple fix |
| 2 | Simple | 1-2 days | Single component change, well-defined |
| 3 | Moderate | 2-3 days | Feature with clear requirements |
| 5 | Complex | 3-5 days | Multiple components, some unknowns |
| 8+ | Too Large | - | **Must be split into smaller stories** |

## Splitting Large Stories

Stories estimated at 8 points or more should be split. Look for natural boundaries:

### Common Split Patterns

| Pattern | Example |
|---------|---------|
| By component | Frontend / Backend / API |
| By phase | Design / Implement / Test |
| By feature | Core functionality / Edge cases / Error handling |
| By dependency | Upstream work / Integration / Downstream changes |
| By environment | Development / Staging / Production |

### Split Checklist

1. Can each piece deliver incremental value?
2. Are dependencies between pieces clear?
3. Can pieces be worked on by different people if needed?
4. Is each piece independently testable?

## Estimation Factors

Consider these when estimating:

| Factor | Increases Points | Decreases Points |
|--------|------------------|------------------|
| **Dependencies** | External/open blockers | Self-contained work |
| **Clarity** | "Details to be fleshed out" | Clear requirements, prior art |
| **Scope** | Multiple repos/components | Single file/component |
| **Testing** | New test infrastructure needed | Existing test patterns |
| **Coordination** | Cross-team involvement | Single team/person |
| **Familiarity** | New technology/domain | Well-understood area |
| **Risk** | Unknown unknowns | Proven approach |

## Output Format

When providing an estimate, include:

### 1. Issue Summary
```
**Issue:** <KEY> - <Summary>
**Current Points:** <existing or null>
**Status:** <status>
**Assignee:** <name>
```

### 2. Scope Analysis
- Key work areas identified
- Dependencies (open/resolved)
- Unknowns or risks

### 3. Comparable Stories Table
| Key | Summary | Points | Status |
|-----|---------|--------|--------|
| ... | ... | ... | ... |

### 4. Recommendation
```
**Recommended Estimate:** X points

**Reasoning:**
- <point 1>
- <point 2>
- <comparable reference>
```

### 5. Comment Text (ready to paste)
```
Estimated at X story points based on:
- <reasoning>
```

## Finding Issues Needing Estimates

```bash
# Stories in current sprint without estimates
jira issue list --jql 'sprint in openSprints() AND type = Story AND "Story Points[Number]" is EMPTY' --plain --no-truncate

# Stories assigned to you without estimates
jira issue list --jql 'assignee = currentUser() AND type = Story AND "Story Points[Number]" is EMPTY AND status != Closed' --plain --no-truncate
```
