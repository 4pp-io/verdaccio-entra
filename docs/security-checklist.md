# Pre-Release Security Checklist (Microsoft SDL)

Each item maps to a specific SDL requirement ID.

## Requirements & Design (SDL R/D)
- [ ] Threat model reviewed and up-to-date with severity ratings (D-1, D-4)
- [ ] Data flow and trust boundaries documented (D-2)
- [ ] Attack surface analyzed — all entry points identified (D-9)
- [ ] Unused code, dead config, and deprecated interfaces removed (D-10)
- [ ] No secrets in source code — use env vars or secret stores (D-18)

## Dependencies & Supply Chain (SDL SC)
- [ ] `npm audit --audit-level=high --omit=dev` passes (SC-3)
- [ ] No deprecated packages with known CVEs (SC-10)
- [ ] Dependabot or Renovate configured for automated updates (SC-4)
- [ ] `package-lock.json` committed with integrity hashes (SC-6)
- [ ] SBOM generated in CI on release (SC-2, RE-9)

## Implementation (SDL I)
- [ ] All input validated: GUID regex, token size guard, JWT structure (I-1)
- [ ] Error handling: fail safe, no sensitive data in error messages (I-7)
- [ ] Logging: success/failed auth with UPN, no secrets in logs (I-8)
- [ ] No hardcoded paths, secrets, or connection strings (I-9)
- [ ] Deny-all default: access requires `$authenticated` unless explicitly `$all` (I-10)
- [ ] Uses established libraries (`jsonwebtoken`, `jwks-rsa`) not custom crypto (I-14, C-28)

## Code Quality (SDL I/V)
- [ ] `tsc --noEmit` passes with `strict: true` (no `noImplicitAny: false`)
- [ ] ESLint passes with `no-eval`, `no-implied-eval`, `no-new-func` (I-16)
- [ ] No `eval()`, `new Function()`, or dynamic `require()` in source
- [ ] Secret scanning (gitleaks) passes in CI (V-3)

## Cryptographic Standards (SDL C)
- [ ] JWT validation uses RS256 only — `algorithms: ["RS256"]` (C-11, C-14)
- [ ] RSA keys >= 2048-bit (enforced by Entra ID)
- [ ] Issuer and audience claims validated (C-18 equivalent for JWT)
- [ ] JWKS client uses caching with bounded TTL (10 min)
- [ ] Verdaccio secret >= 32 characters documented (C-4)

## Authentication Security
- [ ] `clientId` and `tenantId` validated as GUIDs at startup
- [ ] Token size bounded (16KB default, configurable via maxTokenBytes) before parsing
- [ ] Expired tokens are rejected
- [ ] Unknown/missing `kid` headers are rejected

## Test Coverage (SDL V)
- [ ] All authentication success paths tested
- [ ] All rejection paths tested (expired, wrong audience, wrong issuer, unknown kid, oversized, non-JWT)
- [ ] Constructor validation tested (invalid GUID, missing config, env var resolution)
- [ ] Access control tested (group matching, $all, $anonymous, $authenticated)
- [ ] Publish authorization tested

## Container Security
- [ ] Multi-stage Docker build — source/devDeps never reach runtime image (D-10)
- [ ] Docker image runs as non-root user via `$VERDACCIO_USER_UID` (D-14)
- [ ] `--chown=$VERDACCIO_USER_UID:root` used on all COPY steps (per Verdaccio Docker docs)
- [ ] No hardcoded UIDs or filesystem paths in Dockerfile
- [ ] `listen` config omitted — port controlled by `VERDACCIO_PORT` env var

## Release (SDL RE)
- [ ] Verdaccio JWT lifetime <= 7 days
- [ ] Incident response procedures documented (RE-5)
- [ ] CI pipeline runs: type-check, lint, test, audit, secret scan (V-2, V-3, V-13)
- [ ] SBOM artifact generated (RE-9)
