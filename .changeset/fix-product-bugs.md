---
"@4pp-io/verdaccio-entra": minor
---

### Group overage detection

Detect Entra ID group overage (`_claim_names.groups`) when users belong to >200 groups. Previously, group-based package ACLs silently failed for these users. Now logs an error with mitigation steps while still allowing authentication.

### CLI distribution fix

The `check-config` CLI is now compiled and distributed via `bin` field. Run `npx verdaccio-entra-check` instead of `npm run check-config` (which required `tsx` and source files not included in the package).

### Constructor no longer calls process.exit(1)

Invalid configuration now throws instead of killing the host Verdaccio process. Verdaccio's plugin loader propagates the error and refuses to start, preserving fail-closed behavior without bypassing cleanup.
