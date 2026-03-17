# Work Summary — verdaccio-entra SDL Hardening

**Date**: 2026-03-16
**Starting point**: 1 commit, ~380 lines, zero tests, zero docs
**Final state**: 16 commits, 1357 lines of source+tests, 56 tests, 4 SDL docs

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

## What we built

### Architecture (final)

```
src/
  auth-plugin.ts      (312 lines)  Pure AuthN — validate token, return groups, done
  diagnostics.ts      (73 lines)   DX helpers — swap detection, error enrichment
  check-config.ts     (147 lines)  Pre-flight validation logic (pure functions)
  index.ts            (5 lines)    Re-export

src/__tests__/
  auth.test.ts        (236 lines)  Token validation, username enforcement, discovery
  check-config.test.ts(154 lines)  Config validation with mock fetcher
  diagnostics.test.ts (82 lines)   Swap detection, error enrichment
  anti-patterns.test.ts(184 lines) 11 source-scanning guardrails
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
```

### Key design decisions

| Decision | Why |
|---|---|
| AuthN only — no `allow_access`/`allow_publish`/`allow_unpublish` | Verdaccio handles authz natively from the groups returned by `authenticate()`. Custom hooks broke user-level access. |
| OIDC discovery instead of hardcoded URLs | Supports sovereign clouds (US Gov, China) without code changes |
| `NODE_USE_ENV_PROXY=1` instead of undici | Node 22.21+ covers both `fetch()` and `https.request()` (jwks-rsa) natively. Zero plugin code. |
| Username enforcement (`user === upn`) | npm login allows arbitrary usernames. Without this check, audit logs can be spoofed. |
| Self-healing discovery with exponential backoff | Transient network failures at startup don't permanently brick the plugin. |
| Diagnostics separated from auth boundary | `detectSwappedIds` and `enrichVerifyError` only run post-verification, for logging. Never in auth decisions. |
| `discoveryRetries` config | Allows tests to use 1 retry (instant), production uses 3 (with backoff). |

### Adversarial audit cycle

We ran **7 adversarial oracle audits** across the session. Each audit found real issues that we fixed:

| Audit | Key Findings Fixed |
|---|---|
| 1 (initial) | Zero tests, version mismatch, hardcoded paths, dead code, `noImplicitAny: false` |
| 2 | String-matching library errors, `as unknown as` type hack, `adduser` semantic confusion |
| 3 | Pre-checking unverified JWT claims before signature verification, helpdesk code in auth path |
| 4 | Hardcoded Azure public cloud URLs, missing JWKS rate limiting |
| 5 | Swallowed OIDC discovery error, global state mutation (`setGlobalDispatcher`), hardcoded audience prefix |
| 6 | Custom authz hooks breaking framework, `setGlobalDispatcher` poisoning host process |
| 7 | Username spoofing via npm login, asymmetric proxy (discovery works, JWKS doesn't), zombie promise |

### Anti-pattern guardrails (11 tests)

Source-scanning tests that break the build if anyone regresses:

| Principle | What's banned |
|---|---|
| Process isolation | Global state mutation, `process.env` writes, `console.log` |
| Proxy safety | `undici` imports (use `NODE_USE_ENV_PROXY=1`) |
| Framework compliance | AuthZ hooks, `adduser` |
| Cryptographic hygiene | String-matching dependency error messages |
| Type safety | `as unknown as` double-casting |
| Portability | Hardcoded cloud URLs, absolute filesystem paths |
| Identity enforcement | Must verify `user === upn` (username spoofing) |
| Error handling | Catch blocks must escalate or be marked diagnostic |

### Test suite

- **56 tests** across 4 test files + 1 fixtures file
- **<1s total runtime** (991ms)
- **Coverage**: 100% statements, 93% branches, 95% functions, 100% lines
- **Thresholds enforced**: 95/90/95 (statements/branches/functions)
- **Zero subprocesses** — check-config tests use mock fetcher injection
- **Zero network calls** — all HTTP mocked via `vi.stubGlobal("fetch")`
- **Zero duplicated logic** — tests import constants from source (GUID_RE, ISSUERS, etc.)
- **Microsoft Learn placeholder GUIDs** — `aaaabbbb-0000-cccc-1111-dddd2222eeee` (tenant), `00001111-aaaa-2222-bbbb-3333cccc4444` (client)
- **Microsoft's public tenant** (`72f988bf-...`) used only in check-config network tests

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
- [Microsoft Access Token Claims](https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference) — correct claim validation
- [Microsoft National Clouds](https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud) — sovereign cloud support via OIDC discovery
- [Node.js Enterprise Network](https://nodejs.org/en/learn/http/enterprise-network-configuration) — `NODE_USE_ENV_PROXY=1` for proxy

### CI pipeline

```
build-and-test:  tsc --noEmit → lint (--max-warnings=0 --no-inline-config) → test:coverage
secret-scanning: gitleaks
sbom:            anchore/sbom-action (SPDX JSON, on main push)
dependabot:      weekly npm + GitHub Actions updates
```

### What was deleted

| Deleted | Why |
|---|---|
| `docker/start.ts` (27 lines) | Custom entrypoint — standard Verdaccio entrypoint handles everything |
| `allow_access/publish/unpublish` | Verdaccio handles authz natively |
| `adduser` | External IdP has no registration concept |
| `resolveEnv` | Read `process.env` directly — Verdaccio doesn't interpolate plugin config |
| `allowedGroups` config field | Dead code, never read |
| `@verdaccio/config` dependency | Never imported |
| `undici` dependency | `NODE_USE_ENV_PROXY=1` handles proxy natively |
| `PackageAccessWithUnpublish` type | No longer needed without authz hooks |
| Pre-verify claim checks | `jwt.verify` handles all claims after signature verification |
| String-matching library errors | Pre-check eliminated, diagnostics run post-verify |
| `setGlobalDispatcher` | Plugin must not mutate host process state |

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
```
