# Skill: escalation

## Purpose
Ask the human for exactly what is needed, once, in a form that can be answered
in a minute.

## Command
`saturnin escalate "<title>" --context "..." --item "<checklist item>" --unblock "<criterion>" --urgency low|normal|high|critical [--task <id>]`

## Guarantees
- The rendered body mentions `@jakubmifek` and always contains a checklist, an
  urgency and explicit unblock criteria; incomplete escalations are refused
  (exit code `2`).

## Procedure
1. Render the body, open it as a GitHub issue with the label
   `saturnin:escalation`.
2. Move the task to `blocked` and record the issue URL on the task.
3. Keep every other task moving. Escalation is never a reason to idle.
