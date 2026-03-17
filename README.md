# verdaccio-entra

Microsoft Entra ID (Azure AD) auth plugin for [Verdaccio](https://verdaccio.org/) — validates access tokens via JWKS.

## Features

- Validates Entra ID access tokens using JWKS (RS256) with rate-limited key fetching
- Sovereign cloud support (Azure Public, US Government, China) via OIDC discovery
- Username enforcement — npm login username must match Entra identity (anti-spoofing)
- Group and role-based access control from JWT claims (Verdaccio handles authorization natively)
- Self-healing OIDC discovery with exponential backoff retry
- Environment variable override for all config values
- Pre-flight config validation script (`npm run check-config`)
- Docker setup using standard Verdaccio entrypoint with multi-stage build
- Requires Node.js >= 22

## Install

```bash
npm install verdaccio-entra
```

## Configuration

Add to your Verdaccio `config.yaml` (see [best practices](https://verdaccio.org/docs/best)):

```yaml
auth:
  entra:
    clientId: "your-client-id"   # or ENTRA_CLIENT_ID env var
    tenantId: "your-tenant-id"   # or ENTRA_TENANT_ID env var
    # audience: "api://your-client-id"     # or ENTRA_AUDIENCE (default: api://{clientId})
    # authority: "https://login.microsoftonline.us"  # or ENTRA_AUTHORITY (default: public cloud)
    # maxTokenBytes: 16384                 # default: 16KB

# Use $authenticated on all packages — Verdaccio best practice for private registries
# @see https://verdaccio.org/docs/best#strong-package-access-with-authenticated
packages:
  "@my-company/*":
    access: $authenticated
    publish: $authenticated
    unpublish: $authenticated
    # No proxy — prevents dependency confusion on private packages

  "@*/*":
    access: $authenticated
    publish: $authenticated
    proxy: npmjs

  "**":
    access: $authenticated
    publish: $authenticated
    proxy: npmjs

# Separate API and web token lifetimes
# @see https://verdaccio.org/docs/best#expiring-tokens
security:
  api:
    jwt:
      sign:
        expiresIn: 7d
        notBefore: 0
  web:
    sign:
      expiresIn: 1h
```

### Environment Variables

All config values can be overridden via environment variables (takes precedence over config.yaml):

| Env Variable | Config Key | Default | Description |
|---|---|---|---|
| `ENTRA_CLIENT_ID` | `clientId` | — | Application (client) ID from Entra app registration |
| `ENTRA_TENANT_ID` | `tenantId` | — | Directory (tenant) ID |
| `ENTRA_AUDIENCE` | `audience` | `api://{clientId}` | Expected token audience (override for custom App ID URIs) |
| `ENTRA_AUTHORITY` | `authority` | `https://login.microsoftonline.com` | Entra authority URL ([sovereign clouds](https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud)) |

### Proxy Support

For environments behind a corporate egress proxy, set `NODE_USE_ENV_PROXY=1` in the container environment. This is a Node 22.21+ built-in that enables `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` support for both OIDC discovery (`fetch`) and JWKS key fetching (`https.request`).

```bash
docker run -p 4873:4873 \
  -e NODE_USE_ENV_PROXY=1 \
  -e HTTPS_PROXY=http://proxy.corp:8080 \
  -e ENTRA_CLIENT_ID=... \
  -e ENTRA_TENANT_ID=... \
  verdaccio-entra
```

No custom proxy code in the plugin — Node handles it natively. See [Enterprise Network Configuration](https://nodejs.org/en/learn/http/enterprise-network-configuration).

### Pre-flight Validation

Validate your Entra config before starting Verdaccio:

```bash
npm run check-config -- --client-id <guid> --tenant-id <guid>
# or via env vars:
ENTRA_CLIENT_ID=... ENTRA_TENANT_ID=... npm run check-config
```

Checks: GUID format, JWKS endpoint reachability, OIDC discovery, issuer match, swapped ID detection.

## Auth Flow

1. User obtains an Entra access token client-side (e.g., via [MSAL](https://learn.microsoft.com/entra/msal/) or [`@4pp-io/r`](https://www.npmjs.com/package/@4pp-io/r))
2. `npm login --registry=<url>` — username must match your Entra email/UPN
3. Plugin validates the JWT against Entra's JWKS endpoint via OIDC discovery
4. Plugin verifies username matches the token's identity (anti-spoofing)
5. Verdaccio issues its own HS256 JWT and handles all authorization using the Entra groups

## Docker

```bash
docker build -t verdaccio-entra .
docker run -p 4873:4873 \
  -e ENTRA_CLIENT_ID=your-client-id \
  -e ENTRA_TENANT_ID=your-tenant-id \
  verdaccio-entra
```

## Client Setup

For the easiest client-side setup, use [`@4pp-io/r`](https://www.npmjs.com/package/@4pp-io/r):

```bash
npx @4pp-io/r
```

This auto-detects your package manager, configures scoped registries, and authenticates via Windows SSO (WAM) or browser.

## Verdaccio Version Compatibility

| Verdaccio | Status | Docker Tag | This Plugin |
|-----------|--------|------------|-------------|
| 6.x | Current stable | `verdaccio/verdaccio:6` | Fully aligned (runtime + deps) |
| 7.x | Abandoned | — | Untested |
| 8.x | Skipped | — | No release, no Docker image |
| 9.x | Experimental | `nightly-master` | Requires Node 24, untested |

All npm dependencies (`@verdaccio/core`, `@verdaccio/types`, `@verdaccio/auth`) target v6.
The auth plugin interface (`pluginUtils.Auth<T>`) is identical across v6/v8/v9.

See [VERSIONS.md](https://github.com/verdaccio/verdaccio/blob/master/VERSIONS.md) for details.

## Security Considerations

- Deploy behind a reverse proxy with TLS termination and rate limiting
- `security.api.jwt.sign.expiresIn` controls Verdaccio token lifetime (default: 7d in Docker config)
- Verdaccio's JWT `secret` must be at least 32 characters (required since v6 for `createCipheriv`)
- **Username Mutability Risk:** Verdaccio derives package ownership from the username entered during `npm login`, and this plugin validates it against the token's `preferred_username`, `upn`, or `email` claim. **Microsoft Entra ID considers these claims mutable.** If a user's UPN changes (e.g., due to marriage or a legal name change), they will `npm login` with their new name and it will succeed. However, any previously published packages will still display their old username in the metadata. This is a cosmetic artifact of Verdaccio's architecture, not a security vulnerability. Access control remains secure because package access is governed by immutable group claims (`$authenticated` and Entra ID groups/roles), not by string-matching the author's username.
- Username must match Entra identity — prevents audit log spoofing via `npm login`
- Group-based access control requires your Entra app registration to emit `groups` or `roles` claims
- `clientId` and `tenantId` are validated as GUIDs at startup to prevent URL injection
- Token payloads exceeding 16KB (configurable via `maxTokenBytes`) are rejected before JWT parsing
- JWKS key fetching is rate-limited (10 req/min) to prevent kid-spoofing DoS
- Rotating the Verdaccio `secret` invalidates all existing client tokens (forces re-login)
- For corporate proxy environments, set `NODE_USE_ENV_PROXY=1`

## License

MIT
