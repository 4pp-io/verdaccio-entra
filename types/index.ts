/**
 * Per-plugin config passed by Verdaccio's plugin loader.
 *
 * Verdaccio reads `auth.entra` from config.yaml and passes ONLY that
 * subtree as the first constructor argument. It does NOT pass the full
 * Verdaccio Config object — that is available via `appOptions.config`.
 *
 * Reference: verdaccio/packages/loaders/src/plugin-async-loader.ts
 * (executePlugin passes pluginConfig, not Config)
 *
 * This deliberately does NOT extend @verdaccio/types Config — matching
 * the pattern used by Verdaccio's own plugins (htpasswd, auth-memory).
 */
export interface EntraConfig {
  clientId: string;
  tenantId: string;
  /**
   * Maximum token size in bytes before rejecting without parsing.
   * Entra tokens with many group claims can reach 16-20KB, but the
   * Microsoft.IdentityModel default is 256KB.
   * Default: 256000 (256KB).
   * @see https://learn.microsoft.com/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters.defaultmaximumtokensizeinbytes
   */
  maxTokenBytes?: number;
  /**
   * Optional Entra authority URL. Defaults to Azure Public cloud.
   * Set this for sovereign/national clouds:
   *   - US Government: https://login.microsoftonline.us
   *   - China (21Vianet): https://login.partner.microsoftonline.cn
   *   - Public (default): https://login.microsoftonline.com
   *
   * The plugin computes deterministic JWKS and issuer URIs from the
   * authority and tenantId (no runtime OIDC discovery needed).
   *
   * @see https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud
   */
  authority?: string;
  /**
   * Expected token audience. Defaults to `api://{clientId}`.
   * Override for organizations using custom Application ID URIs
   * (e.g., `https://auth.company.com` or a naked client ID GUID).
   * Can also be set via ENTRA_AUDIENCE env var.
   */
  audience?: string;
  /**
   * Kill the Verdaccio process if the plugin fails to initialize.
   * Default: false (plugin is skipped, Verdaccio falls back to other auth plugins).
   *
   * Set to true in production when this is your only auth plugin.
   * Verdaccio's plugin loader silently skips failed plugins and falls
   * back to htpasswd — without failClosed, a config typo means your
   * registry boots with no Entra auth.
   */
  failClosed?: boolean;
  /**
   * Allow authentication when Entra group overage occurs (>200 groups).
   * Default: false (authentication is rejected with a clear error).
   *
   * When a user belongs to >200 groups, Entra omits the groups claim
   * entirely. With this set to false, the plugin rejects authentication
   * to prevent silent authorization failures. Set to true only if you
   * do not use group-based package ACLs.
   */
  allowGroupOverage?: boolean;
  /**
   * Clock skew tolerance for JWT verification (seconds).
   * Accommodates minor clock drift between the Entra token issuer and
   * this server. Default: 300 (5 minutes).
   * @see https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
   */
  clockToleranceSeconds?: number;
}

import * as v from "valibot";

/**
 * Schema for the Entra ID token claims this plugin inspects.
 * Uses looseObject so additional JWT claims (iat, nbf, azp, etc.) pass through.
 * The type `EntraTokenPayload` is derived from this schema — no manual sync needed.
 *
 * Note: iss, aud, and exp are NOT validated here — jose's jwtVerify already
 * enforces those before the payload reaches this schema. Duplicating that
 * validation would reject valid tokens (e.g. aud can be string | string[]).
 */
export const EntraTokenPayloadSchema = v.looseObject({
  oid: v.optional(v.string()),
  sub: v.optional(v.string()),
  preferred_username: v.optional(v.string()),
  upn: v.optional(v.string()),
  email: v.optional(v.string()),
  groups: v.optional(v.array(v.string())),
  roles: v.optional(v.array(v.string())),
  hasgroups: v.optional(v.boolean()),
  _claim_names: v.optional(v.looseObject({})),
});

/** Claims used by the plugin from a validated Entra ID access token. */
export type EntraTokenPayload = v.InferOutput<typeof EntraTokenPayloadSchema>;
