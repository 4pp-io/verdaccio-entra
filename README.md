# verdaccio-entra

Microsoft Entra ID (Azure AD) auth plugin for [Verdaccio](https://verdaccio.org/) — validates access tokens via JWKS.

## Features

- Validates Entra ID access tokens using JWKS (RS256) with automatic key caching and rotation via [jose](https://github.com/panva/jose)
- Sovereign cloud support (Azure Public, US Government, China) via configurable `authority` URL
- Username enforcement — npm login username must match Entra identity (anti-spoofing)
- Group and role-based access control from JWT claims (Verdaccio handles authorization natively)
- Environment variable override for all config values
- Pre-flight config validation CLI (`npx verdaccio-entra-check`)
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
    # maxTokenBytes: 256000               # default: 256,000 bytes (matches Microsoft's DefaultMaximumTokenSizeInBytes)
    # failClosed: true                    # or ENTRA_FAIL_CLOSED=true — kill process on config error (use when Entra is your only auth plugin)
    # allowGroupOverage: false            # or ENTRA_ALLOW_GROUP_OVERAGE=true — allow auth when >200 groups causes overage (default: reject)

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
| `ENTRA_FAIL_CLOSED` | `failClosed` | `false` | Kill process on config error (`true` = `process.exit(1)`) |
| `ENTRA_ALLOW_GROUP_OVERAGE` | `allowGroupOverage` | `false` | Allow auth when Entra omits groups due to [>200 group memberships](https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference) |

### Proxy Support

For environments behind a corporate egress proxy, set `NODE_USE_ENV_PROXY=1` in the container environment. This is a Node.js core feature ([stable since Node 20.13.0 / 21.7.0](https://nodejs.org/en/learn/http/enterprise-network-configuration)) that enables `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` support for both token fetching (`fetch`) and JWKS key fetching (`https.request`).

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
npx verdaccio-entra-check --client-id <guid> --tenant-id <guid>
# or via env vars:
ENTRA_CLIENT_ID=... ENTRA_TENANT_ID=... npx verdaccio-entra-check
```

Checks: GUID format, swapped ID detection, JWKS endpoint reachability and key shape.

## Auth Flow

1. User obtains an Entra access token client-side (e.g., via [MSAL](https://learn.microsoft.com/entra/msal/) or [`@4pp-io/r`](https://www.npmjs.com/package/@4pp-io/r))
2. `npm login --registry=<url>` — username must match your Entra email/UPN
3. Plugin validates the JWT directly against Entra's JWKS endpoint (deterministic URI, no OIDC discovery)
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

- **Misconfiguration risk:** If `clientId` or `tenantId` are missing or invalid, the plugin throws from its constructor and Verdaccio skips it (falling back to other auth plugins like htpasswd). Set `failClosed: true` in config (or `ENTRA_FAIL_CLOSED=true` in the environment) to kill the process instead — use this in production when Entra is your only auth plugin. For large tenants where Entra may emit a groups overage error and omit group membership, you can relax this behavior by setting `allowGroupOverage: true` (or `ENTRA_ALLOW_GROUP_OVERAGE=true`) so that authentication can still proceed even if all group memberships cannot be resolved.
- Deploy behind a reverse proxy with TLS termination and rate limiting
- `security.api.jwt.sign.expiresIn` controls Verdaccio token lifetime (default: 7d in Docker config)
- Verdaccio's JWT `secret` must be at least 32 characters (required since v6 for `createCipheriv`)
- **Username Mutability Risk:** Verdaccio derives package ownership from the username entered during `npm login`, and this plugin validates it against the token's `preferred_username`, `upn`, or `email` claim. **Microsoft Entra ID considers these claims mutable.** If a user's UPN changes (e.g., due to marriage or a legal name change), they will `npm login` with their new name and it will succeed. However, any previously published packages will still display their old username in the metadata. This is a cosmetic artifact of Verdaccio's architecture, not a security vulnerability. Access control remains secure because package access is governed by immutable group claims (`$authenticated` and Entra ID groups/roles), not by string-matching the author's username.
- Username must match Entra identity — prevents audit log spoofing via `npm login`
- **Prefer App Roles over Groups:** Entra ID `groups` claims contain opaque GUIDs (Object IDs), making `config.yaml` unreadable. [App Roles](https://learn.microsoft.com/entra/identity-platform/howto-add-app-roles-in-apps) emit human-readable strings in the `roles` claim (e.g., `Package.Publisher`). Microsoft [recommends App Roles](https://learn.microsoft.com/security/zero-trust/develop/configure-tokens-group-claims-app-roles#groups-and-app-roles) over groups for application authorization. Both are supported — the plugin merges `groups` and `roles` into the array returned to Verdaccio
- `clientId` and `tenantId` are validated as GUIDs at startup to prevent URL injection
- Token payloads exceeding 256,000 bytes (configurable via `maxTokenBytes`) are rejected before JWT parsing
- JWKS keys are cached and only refetched on cache miss, with a 30-second cooldown between fetches (jose's `createRemoteJWKSet` default) to limit abuse from unknown `kid` values
- Rotating the Verdaccio `secret` invalidates all existing client tokens (forces re-login)
- **Corporate proxy:** Node's native `fetch` (used for JWKS key fetching) and jose's JWKS fetcher both ignore `HTTPS_PROXY` unless `NODE_USE_ENV_PROXY=1` is set. The plugin warns loudly at startup if it detects proxy vars without this flag. See [Enterprise Network Configuration](https://nodejs.org/en/learn/http/enterprise-network-configuration)

## License

MIT
