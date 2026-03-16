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
	 * The plugin appends /{tenantId}/v2.0/.well-known/openid-configuration
	 * to discover the JWKS endpoint and valid issuers dynamically.
	 *
	 * @see https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud
	 */
	authority?: string;
}

/**
 * Verdaccio's PackageAccess type doesn't include `unpublish` even though
 * config.yaml supports it. This intersection adds it properly instead of
 * casting through `unknown`.
 *
 * @see https://verdaccio.org/docs/best#remove-proxy-to-increase-security-at-private-packages
 */
export type PackageAccessWithUnpublish = import("@verdaccio/types").PackageAccess & {
	unpublish?: string[];
};

/** Claims used by the plugin from a validated Entra ID access token. */
export interface EntraTokenPayload {
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
