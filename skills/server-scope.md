# Skill: server-scope

## Purpose
Stay inside rule 7 on the Debian host.

## Command
`saturnin check command "<command>"` - exit `0` allowed, `2` denied.

## Guarantees
The authoritative command, service and filesystem boundaries live in
[`policies/server_scope.yaml`](../policies/server_scope.yaml). Always run the
command gate above; do not duplicate the policy's allowlists here.

## Refusals
A denial is final. Route the need into an escalation issue instead of looking
for a way around it.
