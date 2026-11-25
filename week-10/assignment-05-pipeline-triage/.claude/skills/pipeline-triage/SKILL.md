---
name: pipeline-triage
description: Run the approved read-only EpicBook pipeline triage script, then analyze the generated report and logs and recommend (never apply) one recovery action. Manual use only.
disable-model-invocation: true
allowed-tools:
  - Bash(./pipeline-triage.sh)
  - Read(./CLAUDE.md)
  - Read(./reports/**)
---

# Pipeline triage (read-only)

Use this skill only when the engineer types `/pipeline-triage`.

## Steps

1. **Read the project rules first.** Read `CLAUDE.md` and follow its Incident Workflow, Safety Rules and Output Rules for everything below.
2. **Gather.** Run exactly `./pipeline-triage.sh` with no arguments and note its exit code (0 healthy, 1 warning, 2 pipeline failure, 3 triage error). Do not run any other command.
3. **Analyze.** Read `reports/pipeline-health-report.txt`. If a pipeline failed or a log could not be retrieved, also read the matching log: `reports/infra-last-run.log` or `reports/app-last-run.log`. Use only these files as evidence.
4. **Report** using the nine Output Rules in `CLAUDE.md`, in this order:
   1. Overall pipeline health
   2. Affected pipeline
   3. Pipeline run ID
   4. Every detected warning or failure
   5. Most likely failure category
   6. Exact sanitized evidence quoted from the report or log
   7. One likely root-cause explanation supported by that evidence
   8. One specific recovery recommendation for the engineer to review
   9. One verification step to perform after the engineer applies the fix
5. **Stop.** The engineer applies any fix manually, then runs this skill again to verify.

## Rules

- If everything is healthy, say so, write "N/A - no failure detected" for items 2 and 4 to 8, and state that no fix is required.
- An exit code of 3 means the triage itself failed. Report that as an error, never as healthy.
- If the evidence does not confirm a cause, say the root cause is not confirmed.
- Never edit, create or delete any file, including the reports.
- Never run git, Terraform, Ansible or Azure CLI commands.
- Never trigger, retry, cancel or approve a pipeline run.
- Never read, print or request credentials of any kind. If a log line is marked as redacted, leave it redacted.
- Recommend a fix, but do not apply it.
