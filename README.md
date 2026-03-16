# verdaccio-entra

Microsoft Entra ID (Azure AD) auth plugin for [Verdaccio](https://verdaccio.org/) — validates access tokens via JWKS.

## Features

- Validates Entra ID access tokens using JWKS (RS256)
- Supports both v1.0 (`sts.windows.net`) and v2.0 (`login.microsoftonline.com`) token issuers
- Group and role-based access control from JWT claims
- Environment variable resolution in config (`${ENV_VAR}`)
- Uses Verdaccio's native login flow — no custom middleware needed
- Docker setup using standard Verdaccio entrypoint with multi-stage build

## Install

```bash
npm install verdaccio-entra
```

## Configuration

Add to your Verdaccio `config.yaml` (see [best practices](https://verdaccio.org/docs/best)):

```yaml
auth:
  entra:
    clientId: "${ENTRA_CLIENT_ID}"
    tenantId: "${ENTRA_TENANT_ID}"

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

## Auth Flow

1. User obtains an Entra access token client-side (e.g., via [MSAL](https://learn.microsoft.com/entra/msal/) or [`@4pp-io/r`](https://www.npmjs.com/package/@4pp-io/r))
2. `npm login --registry=<url>` sends the Entra JWT as the password
3. Plugin validates the JWT against Entra's JWKS endpoint
4. Verdaccio issues its own HS256 JWT back to the client
5. Subsequent requests use Verdaccio's token — standard npm auth

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
- Group-based access control requires your Entra app registration to emit `groups` or `roles` claims
- `clientId` and `tenantId` are validated as GUIDs at startup to prevent URL injection
- Token payloads exceeding 8KB are rejected before JWT parsing
- Rotating the Verdaccio `secret` invalidates all existing client tokens (forces re-login)

## License

MIT
