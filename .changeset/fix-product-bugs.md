---
"@4pp-io/verdaccio-entra": minor
---

### Group overage detection (breaking: rejects by default)

When a user belongs to >200 Entra groups, Entra omits the `groups` claim entirely. Previously this silently stripped all group-based ACLs. Now authentication is **rejected** by default with a clear error. Set `allowGroupOverage: true` if you do not use group-based package ACLs (app roles are unaffected — they are always in the token).

### `failClosed` config option

Invalid configuration now throws by default, letting Verdaccio skip the plugin and fall back to other auth plugins (e.g. htpasswd). Set `failClosed: true` to call `process.exit(1)` instead — use this in production when Entra is your only auth plugin. Supports `ENTRA_FAIL_CLOSED` env var override.

### CLI distribution fix

The `check-config` CLI is now compiled and distributed via `bin` field. Run `npx verdaccio-entra-check` instead of `npm run check-config` (which required `tsx` and source files not included in the package).

### Fetch timeout in config checker

The JWKS endpoint check now uses a 10-second timeout to prevent hanging CI pipelines on network issues.
