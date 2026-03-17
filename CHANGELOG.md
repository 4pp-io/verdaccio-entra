# @4pp-io/verdaccio-entra

## 0.2.0

### Minor Changes

- [#7](https://github.com/4pp-io/verdaccio-entra/pull/7) [`a8cb4d7`](https://github.com/4pp-io/verdaccio-entra/commit/a8cb4d73ec599db8c10c59d9e3bf39b242a867ed) Thanks [@primeinc](https://github.com/primeinc)! - ### Group overage detection (breaking: rejects by default)

  When a user belongs to >200 Entra groups, Entra omits the `groups` claim entirely. Previously this silently stripped all group-based ACLs. Now authentication is **rejected** by default with a clear error. Set `allowGroupOverage: true` if you do not use group-based package ACLs (app roles are unaffected — they are always in the token).

  ### `failClosed` config option

  Invalid configuration now throws by default, letting Verdaccio skip the plugin and fall back to other auth plugins (e.g. htpasswd). Set `failClosed: true` to call `process.exit(1)` instead — use this in production when Entra is your only auth plugin. Supports `ENTRA_FAIL_CLOSED` env var override.

  ### Token size limit increased

  Increased the default `maxTokenBytes` from `16384` (16KB) to `256000` (256KB) to match [Microsoft's `DefaultMaximumTokenSizeInBytes`](https://learn.microsoft.com/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters.defaultmaximumtokensizeinbytes). Aligned `docs/threat-model.md` and JSDoc with the new default.

  ### First-party Microsoft citations added

  Added explicit links to official Microsoft and Node.js documentation backing the specific values used for default token size, 5-minute clock skew tolerance, AES-256 secret key lengths, and the RS256 token signature algorithm.

  ### CLI distribution fix

  The `check-config` CLI is now compiled and distributed via `bin` field. Run `npx verdaccio-entra-check` instead of `npm run check-config` (which required `tsx` and source files not included in the package).

  ### Fetch timeout in config checker

  The JWKS endpoint check now uses a 10-second timeout to prevent hanging CI pipelines on network issues.

### Patch Changes

- [#10](https://github.com/4pp-io/verdaccio-entra/pull/10) [`a837429`](https://github.com/4pp-io/verdaccio-entra/commit/a8374293b3ccb5338d86639e8650b1ffe5be45de) Thanks [@primeinc](https://github.com/primeinc)! - ### Type safety and logging improvements
  - Banned `as never` type assertions in tests via ESLint rule; replaced with properly typed mocks
  - Added runtime shape guard (`assertEntraPayload`) after JWT verification to catch unexpected token claim types
  - Rewrote all log messages with consistent `entra:` prefix, structured merge objects, and correct severity levels
  - Fixed global fetch stub lifecycle in tests (save/restore via afterAll)

- [#12](https://github.com/4pp-io/verdaccio-entra/pull/12) [`1881079`](https://github.com/4pp-io/verdaccio-entra/commit/1881079318bed64d22fc8d1d1b40ceacfdfb7e6a) Thanks [@primeinc](https://github.com/primeinc)! - Trim README from 170 to 76 lines — minimal config, env var table, done. Move security considerations to docs/SECURITY.md. Delete SDL compliance matrix and security checklist (redundant with threat model). Add \_claim_names/hasgroups to valibot schema for consistency. Pin mock JWKS Docker deps with lockfile. Remove dead \_extractStringArray code. Add Node 22/24 CI test matrix.

- [#11](https://github.com/4pp-io/verdaccio-entra/pull/11) [`f2e6765`](https://github.com/4pp-io/verdaccio-entra/commit/f2e6765bd747054e64c750d3168378946d1f530a) Thanks [@primeinc](https://github.com/primeinc)! - Add Prettier for consistent formatting across the codebase. Normalize all files to 2-space indentation, enforce LF line endings via .gitattributes, and add a format check to CI. The changesets version script now auto-formats so the Version Packages PR stays clean.
