---
name: bug-triage
description: Triage bugs and failures - categorization, severity assessment, and root cause analysis patterns
---

# Bug Triage

Knowledge for triaging bugs, failures, and issues in the CoreOS ecosystem.

## Querying Bugs for Triage

### JQL Query for CoreOS Bugs

Use this JQL to get bugs needing triage across all CoreOS-related projects:

```jql
issuetype = Bug AND (
  Project = "CoreOS OCP" OR 
  project = OCPBUGS AND component = RHCOS AND (assignee != openshift-art-jira-bot OR assignee is EMPTY) OR 
  (project = RHEL AND "AssignedTeam" = rhel-coreos AND component not in (rpm-ostree, ostree, bootc))
)
```

### JIRA CLI Commands

```bash
# List bugs with key columns
jira issue list -q '<JQL>' --plain --columns key,summary,status,priority,assignee,created

# List bugs with labels for triage status
jira issue list -q '<JQL>' --plain --columns key,summary,status,labels

# View specific issue details
jira issue view <ISSUE-KEY>
```

## RHCOS Triage Labels

### Primary Triage Labels

| Label | Purpose | When to Apply |
|-------|---------|---------------|
| `rhcos-triaged` | Bug has been reviewed and triaged by RHCOS team | After initial review and categorization |
| `rhcos-engaged` | RHCOS team is actively investigating/working on the issue | When actively debugging or developing fix |
| `rhcos-waitingonrhel` | Bug is blocked waiting on a fix from the RHEL team | When root cause is in RHEL package |
| `rhcos-bootimage-needed` | Fix requires a new bootimage to be published | When fix landed but needs bootimage bump |
| `rhcos-bootimage-tracker` | Tracking issue for bootimage bumps (automated) | Auto-applied to tracker issues |

### Triage Workflow

1. **New Bug** (no labels) - Bug is filed
2. **rhcos-triaged** - Initial review complete, then one of:
   - **rhcos-engaged** - Actively investigating/developing fix
   - **rhcos-waitingonrhel** - Blocked on RHEL team for fix
   - **rhcos-bootimage-needed** - Fix landed, needs bootimage bump
3. **Closed/Verified** - Fix delivered and confirmed

### Identifying Untriaged Bugs

Bugs needing triage have:
- Status = `New`
- No `rhcos-triaged` label
- No `rhcos-engaged` label

### Other Common Labels

| Label | Purpose |
|-------|---------|
| `RHCOS10` | Bug affects RHCOS 10 (RHEL 10 based) |
| `verified` | Fix has been verified |
| `Telco`, `Telco-5g`, `telco-ran` | Telco/5G related issues |
| `Telco:Core` | Core Telco functionality |
| `mco`, `mco-triaged` | Machine Config Operator related |
| `rpm-ostree` | rpm-ostree component related |
| `sno` | Single Node OpenShift related |
| `QE` | QE team involvement |
| `coreos`, `rhel-coreos` | CoreOS team labels (used in RHEL project) |
| `sustaining` | Sustaining engineering issue |
| `UpgradeBlocker` | Blocks upgrades |
| `UpdateRecommendationsBlocked` | Blocks update recommendations |

## Severity Classification

### JIRA Priority Mapping

| Priority | Criteria | Response Time |
|----------|----------|---------------|
| **Critical** | Pipeline blocked, cluster install broken, upgrade blocker | Immediate |
| **Major** | Core functionality affected, no workaround | Same day |
| **Normal** | Standard bugs, workarounds may exist | Within sprint |
| **Minor** | Low impact, cosmetic issues | Backlog |
| **Undefined** | Needs triage to determine priority | Triage immediately |

## Triage Checklist

When triaging a new bug:

1. **Review the bug description**
   - Understand the reported issue
   - Check for reproducibility information
   - Note affected OCP/RHCOS versions

2. **Check for duplicates**
   - Search for similar issues
   - Link duplicates if found

3. **Identify affected component**
   - Is this RHCOS, MCO, rpm-ostree, ignition, etc.?
   - Is this a kernel/RHEL package issue?

4. **Determine blocking status**
   - Does this block installs?
   - Does this block upgrades?
   - Is this a regression?

5. **Apply appropriate labels**
   - Add `rhcos-triaged` after review
   - Add component labels (`RHCOS10`, `sno`, etc.)
   - Add `rhcos-waitingonrhel` if RHEL dependency
   - Add `rhcos-bootimage-needed` if bootimage required

6. **Set priority**
   - Critical/Major for blockers
   - Normal for standard bugs
   - Minor for low impact

## Root Cause Analysis Structure

When analyzing a failure, document:

1. **Evidence**
   - Build number, job, stream, timestamp
   - Error messages (verbatim, in code blocks)
   - Relevant log snippets

2. **Analysis**
   - What changed between last good and failed build
   - Package changes (use `builds diff`)
   - coreos-assembler changes
   - Infrastructure changes

3. **Conclusion**
   - Identified root cause with confidence level
   - Relevant commits/PRs
   - Whether this is a regression or new issue

4. **Recommendations**
   - Specific fix suggestions
   - Links to relevant PRs/issues
   - Workarounds if available
   - Whether retry is appropriate
