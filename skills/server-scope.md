# Skill: server-scope

## Purpose
Stay inside rule 7 on the Debian host.

## Command
`saturnin check command "<command>"` - exit `0` allowed, `2` denied.

## Guarantees
- Denies `sudo`/`su`/`doas`/`pkexec` outright.
- `apt` limited to `install|update|list|show`, and only for dependencies of a
  Saturnin-dedicated service.
- `systemctl` limited to the allowed verbs and to `saturnin-*` units.
- Scheduling only through Saturnin user-scope systemd timers.

## Refusals
A denial is final. Route the need into an escalation issue instead of looking
for a way around it.
