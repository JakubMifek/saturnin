# Skill: escalation

## Purpose
Ask the human for exactly what is needed, once, in a form that can be answered
in a minute.

## Command
`saturnin escalate "<title>" --context "..." --item "<checklist item>" --unblock "<criterion>" --urgency low|normal|high|critical --task <id> --push`

## Guarantees
- The rendered body mentions `@jakubmifek` and always contains a checklist, an
  urgency and explicit unblock criteria; incomplete escalations are refused
  (exit code `2`).

## Procedure
1. Use the governed atomic `--push --task` path: it renders the body, submits
   the GitHub issue, then moves the task to `blocked` with the escalation URL.
2. Do not open issues manually from previews; previews are for drafting only.
3. Keep every other task moving. Escalation is never a reason to idle.
