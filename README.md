# verdaccio-entra

Microsoft Entra ID (Azure AD) auth plugin for [Verdaccio](https://verdaccio.org/) — validates access tokens via JWKS.

## Features

- Validates Entra ID access tokens using JWKS (RS256)
- Supports both v1.0 (`sts.windows.net`) and v2.0 (`login.microsoftonline.com`) token issuers
- Group and role-based access control from JWT claims
- Environment variable resolution in config (`${ENV_VAR}`)
- Uses Verdaccio's native login flow — no custom middleware needed
- Includes Docker setup with `runServer` API (not deprecated CLI)

## Install

```bash
npm install verdaccio-entra
```

## Configuration

Add to your Verdaccio `config.yaml`:

```yaml
auth:
  entra:
    clientId: "${ENTRA_CLIENT_ID}"
    tenantId: "${ENTRA_TENANT_ID}"

security:
  api:
    jwt:
      sign:
        expiresIn: 30d
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

## License

MIT
