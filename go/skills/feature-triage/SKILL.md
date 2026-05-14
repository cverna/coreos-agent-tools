---
name: feature-triage
description: Triage RFEs in JIRA project RFE, component RHEL CoreOS - closed duplicates and team-review recommendation
---

# Feature Triage

Knowledge for triaging **RFEs** (Request For Enhancement: the issue type used for feature requests here, not bugs) in the **RFE** JIRA project, **RHEL CoreOS** component. Surface likely duplicates against **already closed** RFEs, then decide if the request still needs a **human team review**.

If your JIRA instance names the enhancement issue type differently, adjust the `issuetype` clause.

## Querying RFEs for Triage

### JQL for open RFEs (project RFE, component RHEL CoreOS)

```jql
project = RFE AND component = "RHEL CoreOS" AND issuetype = RFE
  AND status not in (Closed, Done, Resolved, Cancelled)
```

### JIRA CLI commands

**Important:** The `jira` CLI defaults to a personal project ("PITCREW"). Always pass `--project RFE` explicitly or use a full JQL query with `-q`. The `issuetype = RFE` filter may also exclude valid issues — omit it or test without it if results are unexpectedly empty.

```bash
# List open RFEs — use --project RFE to avoid defaulting to the wrong project
jira issue list --project RFE -q 'project = RFE AND component = "RHEL CoreOS" AND status not in (Closed, Done, Resolved, Cancelled)' --plain --columns key,summary,status,priority,assignee,created

# Richer view for triage (resolution and fix versions help when comparing to closed work)
jira issue view <ISSUE-KEY>

# Search closed RFE history by keyword (repeat with distinctive phrases from the request)
# Note: omit issuetype = RFE here — miscategorized issues may still be relevant duplicates
jira issue list --project RFE -q 'project = RFE AND component = "RHEL CoreOS" AND status in (Closed, Done, Resolved) AND (summary ~ "keyword1" OR summary ~ "keyword2")' --plain --no-truncate

# If keyword search returns nothing, fall back to listing ALL closed RFEs and scanning manually
jira issue list --project RFE -q 'project = RFE AND component = "RHEL CoreOS" AND status in (Closed, Done, Resolved)' --plain --columns key,summary,status,priority --no-truncate
```

## Finding previously closed RFEs that duplicate the request

Goal: before spending team time, determine whether the capability was **already delivered**, **already declined**, or **already tracked** under another key.

### 1. Build search terms from the request

From the open RFE, extract:

- **Product nouns** (e.g. bootc, ignition, MCO, ostree)
- **Verbs / outcomes** (e.g. install, upgrade, mirror, airgap)
- **Constraints** (version, platform, Telco)

Prefer **2–4 distinctive phrases** over a single generic word.

### 2. Query closed RFEs in the same scope

Always scope to **project RFE** and **component "RHEL CoreOS"**. Restrict to **closed** terminal states and **issuetype = RFE** (unless the duplicate might have been miscategorized—then widen the type filter deliberately):

```jql
project = RFE AND component = "RHEL CoreOS" AND issuetype = RFE
  AND status in (Closed, Done, Resolved)
  AND (
    summary ~ "phrase-one" OR summary ~ "phrase-two" OR text ~ "distinctive phrase"
  )
```

Run several narrow queries rather than one huge `OR` blob. If the CLI supports it, use `text ~` / description searches for longer phrases.

### 3. Compare candidates, not just titles

For each candidate closed RFE, check:

| Signal | What it means |
|--------|----------------|
| **Resolution** (Done vs Won't Do vs Duplicate) | Done → capability may already exist; Won't Do → policy/product decision may already exist |
| **Fix version / target release** | Shows where it landed; compare to the requester's version |
| **Linked epics / children** | Implementation may span multiple keys; parent may be the better duplicate target |
| **Comments** | Often explain scope cuts or "superseded by X" |

If the closed RFE is clearly the **same intent and scope** as the new request, treat it as a **duplicate for triage purposes** even if wording differs.

### 4. Record links in JIRA

When you find a match:

- Link the new RFE to the closed RFE (e.g. **duplicates** / **is duplicated by** / **relates to**, per project convention).
- In a short comment, cite the closed key and **one sentence** on why it matches (scope + resolution).

**Permission note:** The Jira account used by this agent may not have comment or link permissions on the RFE project. If `jira issue comment add` returns a 400 error, report the triage findings to the user so they can post manually.

## Should a team member review this RFE?

After duplicate research, choose one of the outcomes below and state it explicitly in the triage note or comment.

### Likely **no dedicated review needed** (agent or reporter can proceed)

- **Strong duplicate** of a **Closed/Done** RFE that delivered the requested capability, and the new request does not add a new constraint or version gap that reopens scope.
- **Strong duplicate** of a closed **Duplicate** RFE where the canonical RFE is already identified and still valid.
- **Pure documentation / support** request that is answered by linking to the closed feature or release note (optional: single comment, no meeting).

### **Team review recommended**

- **Partial overlap** only: closed work delivered a subset; the new ask expands platform, version, UX, or support matrix.
- Closed as **Won't Do / Declined** (or similar): the new request may be asking for a **revisit**; only a teammate should confirm product stance.
- **Conflicting** closed RFEs (one delivered, one declined related scope): needs human reconciliation.
- **Strategic, contractual, or security-sensitive** language in the request (even if duplicates exist): default to review.
- **No credible closed match** after reasonable search: treat as **novel**; someone should slot/prioritize/estimate.

### **Team review urgent**

- Release train, customer commitment, or blocker language that does not match any closed delivery in the searched window.
- Duplicates an in-flight epic but **reopens scope** in a way that affects sprint commitments.

## Lightweight triage checklist

When triaging a new RFE:

1. **Read for intent** — outcome desired, user persona, environment (OCP version, RHEL major, bare metal vs cloud).
2. **Search closed duplicates** — follow the section above; document top 1–3 candidates with keys and resolutions.
3. **Decide review** — apply the table in the previous section; one clear sentence: "Team review: yes/no because …".
4. **Labels / fields** — follow team process for priority, epics, and labels; this skill’s scope is **project = RFE** and **component = "RHEL CoreOS"** only.
5. **Handoff** — if review is needed, `@mention` or assign per team norms and paste the duplicate-search summary so the reviewer starts informed.

## Recognizing cross-team scope

Some RFEs touch areas beyond pure RHCOS (e.g., RHEL kernel packaging, CDN/repos infrastructure, OCP release tooling). These are almost always **team review recommended** because:

- No single team owns the full scope
- There may be parallel in-flight work in other projects not visible in `project = RFE`
- Product stance (e.g., "Driver Toolkit is the answer") may already exist but not be recorded in the RFE project

Signals that an RFE crosses team boundaries:
- Mentions RHEL and OpenShift together as separate surfaces
- Involves packaging/repository infrastructure (not just RHCOS image content)
- Has `cee.next_proposed` or similar escalation labels

## What not to do here

- Do not apply **bug-only** triage patterns (repro steps, bootimage bump labels, pipeline RCA) unless the issue is actually a defect; use `bug-triage` instead.
- Do not close as duplicate without **reading** the closed RFE's resolution and scope.
- Do not assume `issuetype = RFE` catches all relevant issues — miscategorized Feature Requests or Stories may be valid duplicates.
