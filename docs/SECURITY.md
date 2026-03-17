# Security Considerations

## Fail-closed mode

If `clientId` or `tenantId` are invalid, the plugin throws from its constructor and Verdaccio silently skips it (falling back to other auth plugins like htpasswd). Set `failClosed: true` (or `ENTRA_FAIL_CLOSED=true`) to kill the process instead. Use this in production when Entra is your only auth plugin.

## Username mutability

Verdaccio derives package ownership from the `npm login` username. This plugin validates it against the token's `preferred_username`, `upn`, or `email` claim. Microsoft considers these claims mutable — if a user's UPN changes, previously published packages retain the old username in metadata. This is cosmetic, not a security issue: access control uses immutable group claims.

## Group overage

When a user belongs to >200 groups, Entra omits the `groups` claim entirely. By default the plugin rejects authentication to prevent silent authorization failures. Set `allowGroupOverage: true` if you don't use group-based ACLs.

## App Roles vs Groups

Entra `groups` claims contain opaque GUIDs. [App Roles](https://learn.microsoft.com/entra/identity-platform/howto-add-app-roles-in-apps) emit human-readable strings in the `roles` claim (e.g., `Package.Publisher`). Both are supported — the plugin merges `groups` and `roles` into the array returned to Verdaccio.

## Other

- Deploy behind a reverse proxy with TLS termination and rate limiting
- Verdaccio's JWT `secret` must be at least 32 characters
- `clientId` and `tenantId` are validated as GUIDs at startup to prevent URL injection
- Tokens exceeding `maxTokenBytes` (default: 256KB) are rejected before JWT parsing
- JWKS keys are cached with a 30-second cooldown between refetches (jose default)
- Rotating the Verdaccio `secret` invalidates all existing client tokens

This plugin follows Microsoft SDL principles: threat-modeled ([threat-model.md](threat-model.md)), input-validated, no custom crypto, dependency scanning in CI. See [incident-response.md](incident-response.md) for runbooks.
