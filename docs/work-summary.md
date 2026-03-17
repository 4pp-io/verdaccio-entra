# Work Summary — verdaccio-entra SDL Hardening

**Date**: 2026-03-16
**Starting point**: 1 commit, ~380 lines, zero tests, zero docs
**Final state**: 21 commits, 1265 lines of source+tests, 55 tests, 5 SDL docs

---

## What we started with

A greenfield Verdaccio auth plugin for Microsoft Entra ID that:

- Had zero tests
- Used v8-next npm dependencies on a v6 Docker runtime
- Had `noImplicitAny: false` overriding `strict: true`
- Hardcoded `/usr/local/lib/node_modules/verdaccio` in a custom Docker start script
- Had dead config fields (`allowedGroups`) and unused dependencies (`@verdaccio/config`)
- Had no linting, no CI, no security documentation
- Extended `Config` (wrong — Verdaccio passes only the plugin subtree)
- Used legacy `jsonwebtoken` + `jwks-rsa` (2017-era Node crypto)

## What we built

### Architecture (final)

```
src/
  auth-plugin.ts      (271 lines)  Pure AuthN — jose + OIDC discovery + groups
  diagnostics.ts      (70 lines)   DX helpers — swap detection, error enrichment
  check-config.ts     (122 lines)  Pre-flight validation (shares discoverOidc)
  index.ts            (5 lines)    Re-export

src/__tests__/
  auth.test.ts        (221 lines)  Token validation, username enforcement, discovery
  check-config.test.ts(123 lines)  Config validation with mock fetch
  diagnostics.test.ts (89 lines)   Swap detection, error enrichment (jose errors)
  anti-patterns.test.ts(200 lines) 12 source-scanning guardrails
  fixtures.ts         (18 lines)   Shared test constants (MS Learn placeholders)

types/
  index.ts            (58 lines)   EntraConfig, EntraTokenPayload

scripts/
  check-config.ts     (88 lines)   CLI wrapper (parseArgs + console output)

docs/
  sdl-compliance.md   Full SDL assessment (115 requirements, citations)
  threat-model.md     STRIDE analysis with severity ratings
  security-checklist.md Pre-release gate checklist mapped to SDL IDs
  incident-response.md Secret rotation, user blocking, token compromise
  work-summary.md     This file
```

### Key design decisions

| Decision                                              | Why                                                                                                                                           |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `jose` instead of `jsonwebtoken` + `jwks-rsa`         | Web Crypto native, typed error codes, `createRemoteJWKSet` handles JWKS caching/rotation/rate-limiting. Eliminates manual OIDC state machine. |
| AuthN only — no authz hooks                           | Verdaccio handles authorization natively from `authenticate()` groups. Custom hooks broke user-level access.                                  |
| OIDC discovery instead of hardcoded URLs              | Supports sovereign clouds (US Gov, China) without code changes.                                                                               |
| `NODE_USE_ENV_PROXY=1` instead of undici              | Node 22.21+ built-in covers both `fetch()` and `https.request()`. Zero plugin code.                                                           |
| Username enforcement (`user === upn`)                 | npm login allows arbitrary usernames. Without this, audit logs can be spoofed.                                                                |
| Self-healing discovery with exponential backoff       | Transient network failures at startup don't permanently brick the plugin.                                                                     |
| Diagnostics separated from auth boundary              | `detectSwappedIds` and `enrichJoseError` only run post-verification, for logging. Never in auth decisions.                                    |
| Shared `discoverOidc` between plugin and check-config | Zero duplicated network logic. Changes to authority resolution are automatically reflected in pre-flight tool.                                |

### Adversarial audit cycle

We ran **8 adversarial oracle audits** across the session. Each audit found real issues that we fixed:

| Audit       | Key Findings Fixed                                                                                          |
| ----------- | ----------------------------------------------------------------------------------------------------------- |
| 1 (initial) | Zero tests, version mismatch, hardcoded paths, dead code, `noImplicitAny: false`                            |
| 2           | String-matching library errors, `as unknown as` type hack, `adduser` semantic confusion                     |
| 3           | Pre-checking unverified JWT claims before signature verification, helpdesk code in auth path                |
| 4           | Hardcoded Azure public cloud URLs, missing JWKS rate limiting                                               |
| 5           | Swallowed OIDC discovery error, global state mutation (`setGlobalDispatcher`), hardcoded audience prefix    |
| 6           | Custom authz hooks breaking framework, `setGlobalDispatcher` poisoning host process                         |
| 7           | Username spoofing via npm login, asymmetric proxy (discovery works, JWKS doesn't), zombie promise           |
| 8 (final)   | Legacy JWT stack (`jsonwebtoken`+`jwks-rsa`), DRY violation in check-config, hand-rolled OIDC state machine |

### Anti-pattern guardrails (12 tests)

Source-scanning tests that break the build if anyone regresses:

| Principle             | What's banned                                              |
| --------------------- | ---------------------------------------------------------- |
| Process isolation     | Global state mutation, `process.env` writes, `console.log` |
| Proxy safety          | `undici` imports (use `NODE_USE_ENV_PROXY=1`)              |
| Crypto stack          | `jsonwebtoken` and `jwks-rsa` imports (use `jose`)         |
| Framework compliance  | AuthZ hooks, `adduser`                                     |
| Cryptographic hygiene | String-matching dependency error messages                  |
| Type safety           | `as unknown as` double-casting                             |
| Portability           | Hardcoded cloud URLs, absolute filesystem paths            |
| Identity enforcement  | Must verify `user === upn` (username spoofing)             |
| Error handling        | Catch blocks must escalate or be marked diagnostic         |

### Test suite

- **55 tests** across 4 test files + 1 fixtures file
- **<1s total runtime** (974ms)
- **Coverage**: 98%+ statements, 90%+ branches, 95% functions, 98%+ lines
- **Thresholds enforced**: 95/90/95 (statements/branches/functions)
- **Zero subprocesses** — all tests run in-process
- **Zero network calls** — all HTTP mocked via `vi.stubGlobal("fetch")`
- **Zero duplicated logic** — tests import constants from source
- **Microsoft Learn placeholder GUIDs** throughout

### Dependencies (final)

| Dep                              | Type       | Purpose                            |
| -------------------------------- | ---------- | ---------------------------------- |
| `jose`                           | production | JWT verification, JWKS, Web Crypto |
| `@verdaccio/core`                | production | Plugin base class, error utilities |
| `debug`                          | production | Debug logging                      |
| `vitest` + `@vitest/coverage-v8` | dev        | Test runner + coverage             |
| `eslint` + `typescript-eslint`   | dev        | Linting with SDL banned functions  |
| `typescript`                     | dev        | Type checking                      |
| `tsx`                            | dev        | Run scripts directly               |
| `@changesets/cli`                | dev        | Release management                 |

### CI/CD pipeline

```
ci.yml:
  build-and-test:  tsc --noEmit → lint (--max-warnings=0 --no-inline-config) → test:coverage → npm audit
  secret-scanning: gitleaks
  sbom:            anchore/sbom-action (SPDX JSON, on main push)

release.yml:      changesets/action → npm publish on main push
publish-pr.yml:   /publish-pr comment → snapshot version to npm
dependabot.yml:   weekly npm + GitHub Actions updates
```

### SDL compliance

Full assessment against all 115 Microsoft SDL requirements:

- **76 satisfied** with evidence
- **19 justified N/A** with Microsoft Learn citations
- **22 documented as organizational** responsibilities
- **0 gaps**

Aligned with:

- [Verdaccio Best Practices](https://verdaccio.org/docs/best) — all 11 recommendations
- [Verdaccio Auth Plugin Docs](https://verdaccio.org/docs/plugin-auth) — correct callback contract
- [Verdaccio Docker Docs](https://verdaccio.org/docs/docker) — multi-stage build, `$VERDACCIO_USER_UID`
- [Verdaccio Env Vars](https://verdaccio.org/docs/env) — all documented env vars respected
- [Microsoft Access Token Claims](https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference)
- [Microsoft National Clouds](https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud)
- [Node.js Enterprise Network](https://nodejs.org/en/learn/http/enterprise-network-configuration)
- [jose library docs](https://github.com/panva/jose)

### What was deleted

| Deleted                               | Why                                                                           |
| ------------------------------------- | ----------------------------------------------------------------------------- |
| `docker/start.ts` (27 lines)          | Custom entrypoint — standard Verdaccio entrypoint handles everything          |
| `jsonwebtoken` + `jwks-rsa` deps      | Replaced by `jose` (Web Crypto, typed errors, built-in JWKS caching)          |
| `undici` dep                          | `NODE_USE_ENV_PROXY=1` handles proxy natively                                 |
| `allow_access/publish/unpublish`      | Verdaccio handles authz natively                                              |
| `adduser`                             | External IdP has no registration concept                                      |
| `resolveEnv`                          | Read `process.env` directly                                                   |
| `allowedGroups` config field          | Dead code, never read                                                         |
| `@verdaccio/config` dependency        | Never imported                                                                |
| `PackageAccessWithUnpublish` type     | No longer needed without authz hooks                                          |
| `JwksServiceError` class              | Replaced by jose's `JWKSNoMatchingKey`                                        |
| `_initWithRetry` OIDC state machine   | Simplified — jose handles JWKS lifecycle, only initial OIDC discovery retries |
| Pre-verify claim checks               | jose's `jwtVerify` does signature + claims atomically                         |
| String-matching library errors        | jose has typed error codes (`err.code`, `err.claim`)                          |
| `setGlobalDispatcher`                 | Plugin must not mutate host process state                                     |
| Duplicated OIDC logic in check-config | Now imports shared `discoverOidc`                                             |

### Commits (chronological)

```
78fbb0c feat: initial release — Entra ID auth plugin for Verdaccio
7ec27f6 security: harden plugin per Microsoft SDL and Verdaccio best practices
ca4e1af chore: lock down linting and type-safety footguns
1e65d42 refactor: remove resolveEnv — read env vars directly
fc6c27e feat: config checker script and swapped-ID detection
2589753 refactor: eliminate duplicated logic between source and tests
4b49936 fix: address adversarial audit findings
a6a96e9 fix: remove adduser — no user registration for external IdP
546ed3f refactor: separate security boundary from diagnostics
a4eca5c feat: sovereign cloud support + JWKS rate limiting
83adc72 perf: extract check-config logic for in-process testing (14s → <1s)
8e33928 feat: proxy support, configurable token size, retry with backoff
456bf2d fix: remove authz hooks, scope proxy agent, configurable audience
7bc6ada test: anti-pattern tests enforce architectural invariants
940d142 test: expand anti-pattern tests to cover all oracle findings
a1df699 fix: rip out undici, use NODE_USE_ENV_PROXY=1 for proxy support
5bc4c17 docs: comprehensive update + sub-second test suite
12c7c56 docs: add comprehensive work summary
32c4441 feat: migrate from jsonwebtoken+jwks-rsa to jose (Web Crypto)
02778de refactor: unify OIDC discovery — check-config uses plugin's discoverOidc
         chore: fix workflows node version + commit workflows
```
