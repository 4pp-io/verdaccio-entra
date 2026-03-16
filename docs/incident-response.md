# Incident Response Procedures

## Rotate Verdaccio JWT Secret

If the Verdaccio JWT signing secret is compromised, all issued tokens must be invalidated.

1. Generate a new secret (**must be at least 32 characters** — used as AES-256 key for `createCipheriv`)
2. Update `config.yaml` (or the `VERDACCIO_SECRET` env var)
3. Restart the Verdaccio container
4. All existing client tokens become invalid — users must run `npm login` again

## Force All Users to Re-Authenticate

Same procedure as rotating the JWT secret — changing the secret invalidates all outstanding tokens.

## Block a Specific User

Verdaccio does not support per-user token revocation. Options:

1. **Remove the user from Entra groups** — they retain their Verdaccio JWT until it expires, but on next login they won't get the required groups
2. **Shorten JWT lifetime** — reduce `security.api.jwt.sign.expiresIn` and restart to limit the window
3. **Rotate the secret** (nuclear option) — invalidates all tokens, forcing everyone to re-authenticate

## Suspected Token Compromise

1. Identify the compromised user's UPN from Verdaccio logs
2. Revoke sessions in Entra ID (Microsoft Entra admin center > Users > Revoke sessions)
3. If the Verdaccio JWT was compromised (not the Entra token), rotate the Verdaccio secret
4. Review Verdaccio audit logs for unauthorized publish/unpublish operations

## Security Contact

Report security vulnerabilities via the repository's security policy or contact the maintainer directly.
