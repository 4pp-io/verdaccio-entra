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
	 * Entra tokens with many group claims can reach 16-20KB.
	 * Default: 16384 (16KB).
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
}

/** Claims used by the plugin from a validated Entra ID access token. */
export interface EntraTokenPayload {
	oid?: string;
	sub?: string;
	preferred_username?: string;
	upn?: string;
	email?: string;
	groups?: string[];
	roles?: string[];
	iss?: string;
	aud?: string;
	exp?: number;
	[key: string]: unknown;
}
