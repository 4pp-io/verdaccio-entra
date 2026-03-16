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
}

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
