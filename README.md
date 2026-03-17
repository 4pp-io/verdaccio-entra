# verdaccio-entra

Microsoft Entra ID (Azure AD) auth plugin for [Verdaccio](https://verdaccio.org/) — validates access tokens via JWKS.

## Features

- Validates Entra ID access tokens (RS256) with automatic JWKS key caching and rotation via [jose](https://github.com/panva/jose)
- Sovereign cloud support (US Government, China) via configurable `authority`
- Username enforcement — npm login username must match Entra identity
- Group and role-based access control from JWT claims
- Environment variable override for all config values
- Pre-flight config validation CLI: `npx verdaccio-entra-check --client-id <guid> --tenant-id <guid>`

## Install

```bash
npm install verdaccio-entra
```

Requires Node.js >= 22 and Verdaccio 6.x.

## Configuration

Add to your Verdaccio `config.yaml`:

```yaml
auth:
  entra:
    clientId: "your-client-id" # or ENTRA_CLIENT_ID env var
    tenantId: "your-tenant-id" # or ENTRA_TENANT_ID env var
```

### Environment Variables

All config values can be overridden via environment variables (takes precedence over config.yaml):

| Env Variable                    | Config Key              | Default                             | Description                     |
| ------------------------------- | ----------------------- | ----------------------------------- | ------------------------------- |
| `ENTRA_CLIENT_ID`               | `clientId`              | —                                   | Application (client) ID         |
| `ENTRA_TENANT_ID`               | `tenantId`              | —                                   | Directory (tenant) ID           |
| `ENTRA_AUDIENCE`                | `audience`              | `api://{clientId}`                  | Expected token audience         |
| `ENTRA_AUTHORITY`               | `authority`             | `https://login.microsoftonline.com` | Entra authority URL             |
| `ENTRA_FAIL_CLOSED`             | `failClosed`            | `false`                             | Kill process on config error    |
| `ENTRA_ALLOW_GROUP_OVERAGE`     | `allowGroupOverage`     | `false`                             | Allow auth when >200 groups     |
| `ENTRA_MAX_TOKEN_BYTES`         | `maxTokenBytes`         | `256000`                            | Max token size before rejecting |
| `ENTRA_CLOCK_TOLERANCE_SECONDS` | `clockToleranceSeconds` | `300`                               | Clock skew tolerance (seconds)  |

Set `NODE_USE_ENV_PROXY=1` to enable `HTTPS_PROXY` support for JWKS fetching. See [Node.js proxy docs](https://nodejs.org/en/learn/http/enterprise-network-configuration).

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

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for security considerations, including fail-closed mode, username mutability, and group overage handling.

## License

MIT
