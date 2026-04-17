---
name: pipeline-triage-workflow
description: Ordered agent-style triage for a single failed Jenkins build - gather metadata, logs, classification, summary; human gate before Jira writes
---

# Pipeline Triage Workflow (agentic)

Run **one failed build** through a **fixed sequence** of stages. Each stage has a **single job** and **structured output** for the next. Do **not** stop between stages for "what next?" — only at **GATE** unless blocked by errors.

**Inputs (required):** `JOB` (Jenkins job name), `BUILD` (integer build number).

**Related skills:** `pipeline-failures` (deep patterns, kola analysis), `pipeline-jira` (COS ticket text after GATE).

---

## Stage 1 — Gather (build metadata)

**Agent role:** Collect facts about the failing build.

**Run:**
```bash
coreos-tools jenkins builds info <JOB> <BUILD>
coreos-tools jenkins jobs info <JOB>
```

**Output (write this block before Stage 2):**

```markdown
### Gather
- **Job:** …
- **Build:** …
- **Status / result:** …
- **Stream / parameters (if any):** …
- **URL:** …
```

---

## Stage 2 — Logs (console evidence)

**Agent role:** Pull console log and extract high-signal lines.

**Run:**
```bash
coreos-tools jenkins builds log <JOB> <BUILD> | jq -r '.console_log[]' > /tmp/build.log
```

If the log is huge, capture tail:
```bash
coreos-tools jenkins builds log <JOB> <BUILD> | jq -r '.console_log[]' | tail -n 200
```

**Output:**

```markdown
### Logs (excerpt)
- **Last ~N lines or key errors:** …
- **Patterns seen** (error / timeout / registry / test): …
```

Use grep patterns from `pipeline-failures` when analyzing saved log text (`error:`, `FATAL:`, `timeout`, `unauthorized`, `FAILED`, etc.).

**Optional:** If kola tests failed, add kola summary:
```bash
coreos-tools jenkins builds kola-failures <JOB> <BUILD>
```

---

## Stage 3 — Classify

**Agent role:** Map the failure to a **single primary** category and note confidence.

**Categories (pick one primary):** `infrastructure` | `flake` | `test_regression` | `package_change` | `registry_auth` | `tooling` | `unknown`

**Rules of thumb:**
- Transient network / GitLab / "try rerun" language → **flake** or **infrastructure**
- `unauthorized` pulling images → **registry_auth**
- Kola `rerun_failed: true` (if you have kola output) → **test_regression** / **package_change** per `pipeline-failures`
- Only flakes on rerun → do **not** treat as sole root cause; look for compose errors in log

**Output:**

```markdown
### Classify
- **Primary:** …
- **Confidence:** low | medium | high
- **Why (1–3 bullets):** …
```

---

## Stage 4 — Summarize (triage conclusion)

**Agent role:** Produce the **handoff package** for humans (and later Jira).

**Output:**

```markdown
### Triage summary
- **One-line summary:** …
- **Evidence:** build URL, log pointers
- **Suggested next steps:** (e.g. rerun / open COS subtask / escalate to RHEL / snooze test — **suggest only**)
- **Related downstream jobs to check:** e.g. `build-arch` if `build` failed (see `pipeline-failures`)
```

---

## GATE — Human checkpoint (no Jira / no rerun without approval)

**Stop.** Present the **Gather → Logs → Classify → Summarize** sections to the user.

**Default policy:** Only **suggest** Jira text or rerun. Do **not** run `jira issue create` or `coreos-tools jenkins jobs build` unless the user **explicitly** asks.

After approval, use **`pipeline-jira`** skill for COS conventions and commands.

---

## Execution rules

1. Complete **Stages 1–4 in order** in one run when the user provides `JOB` and `BUILD`.
2. Ask for **JOB** and **BUILD** only if missing; do not ask "what next?" between stages.
3. On CLI errors (auth, network), stop and report; do not invent build data.
4. Use **`coreos-tools jenkins`** commands (Go CLI in the container).
