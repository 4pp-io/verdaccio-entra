# Threat Model — verdaccio-entra

## Asset Inventory

| Asset                  | Sensitivity | Location                      |
| ---------------------- | ----------- | ----------------------------- |
| Private npm packages   | High        | Verdaccio storage             |
| Entra ID access tokens | High        | In-flight only (never stored) |
| Verdaccio JWT secret   | High        | config.yaml / env             |
| Verdaccio-issued JWTs  | Medium      | Client `.npmrc`               |

## Trust Boundaries

```
Entra ID (IdP)          Plugin (JWT validation)         Verdaccio (authz)
   │                           │                              │
   │  access token (RS256)     │  groups[]                    │
   ├──────────────────────────►├─────────────────────────────►│
   │                           │                              │
   │                           │  Verdaccio JWT (HS256)       │
   │                           │◄─────────────────────────────┤
```

## STRIDE Analysis

### Spoofing — Severity: Critical

- **Threat**: Forged JWT presented as password
- **Mitigation**: RS256 signature verification via JWKS endpoint; `kid` header validated against Entra's published keys
- **Residual risk**: Low — requires compromise of Entra's signing keys (Microsoft's responsibility)

### Tampering — Severity: Critical

- **Threat**: Modified claims (groups, audience, issuer)
- **Mitigation**: JWT signature covers all claims; any modification invalidates the signature
- **Residual risk**: None for signed tokens

### Repudiation — Severity: Medium

- **Threat**: User denies performing authentication
- **Mitigation**: Verdaccio logs auth events at info level with UPN; plugin logs via structured logger
- **Residual risk**: Medium — logs are local to container; no centralized audit trail unless forwarded to SIEM

### Information Disclosure — Severity: Low

- **Threat**: Error messages leaking internal config (tenant ID, client ID, paths)
- **Mitigation**: Error messages reference config concepts (audience, issuer) but not raw secrets; JWKS endpoint URL is public information
- **Residual risk**: Low — tenant ID appears in error messages (it's not secret but is PII-adjacent)

### Denial of Service — Severity: Medium

- **Threat**: Oversized token payloads; JWKS endpoint flooding
- **Mitigation**: 256KB token size guard (configurable via maxTokenBytes); JWKS client caches keys for 10 minutes
- **Residual risk**: Medium — JWKS endpoint unavailability blocks new logins (existing Verdaccio JWTs continue to work); rate limiting is the reverse proxy's responsibility

### Elevation of Privilege — Severity: High

- **Threat**: Manipulated group/role claims to gain unauthorized access
- **Mitigation**: Groups/roles are signed claims — cannot be modified without invalidating the token signature
- **Residual risk**: Low — overly broad Entra group assignments (organizational process issue, not plugin issue)

## Input Validation Summary

| Input              | Validation                                                                  |
| ------------------ | --------------------------------------------------------------------------- |
| `clientId` config  | Must be valid GUID                                                          |
| `tenantId` config  | Must be valid GUID                                                          |
| JWT password field | Max 256000 bytes (configurable), must decode as JWT, must have `kid` header |
| JWT signature      | RS256 only, verified against JWKS endpoint                                  |
| JWT claims         | Issuer must match tenant, audience must match `api://{clientId}`            |

## Residual Risks

1. **Verdaccio HS256 secret**: Shared secret must be ≥32 characters. If leaked, rotate and restart.
2. **No token revocation**: Compromised Verdaccio tokens remain valid until expiry (7d default).
3. **JWKS availability**: If Entra's JWKS endpoint is unreachable, new logins fail. Existing sessions continue.
4. **Username mutability**: See [SECURITY.md](SECURITY.md#username-mutability).
