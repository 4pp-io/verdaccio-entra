import { errorUtils, pluginUtils } from "@verdaccio/core";
import type { Logger } from "@verdaccio/types";
import debugCore from "debug";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

import type { EntraConfig, EntraTokenPayload } from "../types/index";
import { enrichVerifyError } from "./diagnostics";

const { Plugin } = pluginUtils;

const debug = debugCore("verdaccio:plugin:entra");

/** @see https://learn.microsoft.com/windows/win32/msi/guid */
export const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Default max token size. Entra tokens with many groups can reach 16-20KB. */
export const DEFAULT_MAX_TOKEN_BYTES = 16_384;
export const AUDIENCE_PREFIX = "api://";

/**
 * Default Azure Public cloud authority.
 * Override with `authority` config for sovereign clouds.
 * @see https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud
 */
export const DEFAULT_AUTHORITY = "https://login.microsoftonline.com";

/**
 * Known Entra issuer URL patterns (used by diagnostics and check-config).
 * The plugin itself resolves issuers dynamically via OIDC discovery.
 */
export const ISSUERS = {
	v1: (tenantId: string, authority = DEFAULT_AUTHORITY): string =>
		`${authority.replace("login.microsoftonline.com", "sts.windows.net")}/${tenantId}/`,
	v2: (tenantId: string, authority = DEFAULT_AUTHORITY): string =>
		`${authority}/${tenantId}/v2.0`,
} as const;

/** Thrown when the JWKS endpoint is unreachable — a service error, not a credential failure. */
class JwksServiceError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "JwksServiceError";
	}
}

/** Validate that a config value is a valid GUID (prevents URL injection into JWKS endpoint) */
function assertGuid(value: string, label: string): void {
	if (!value || !GUID_RE.test(value)) {
		throw new Error(
			`Invalid ${label}: expected a GUID (e.g. "aaaabbbb-0000-cccc-1111-dddd2222eeee"), ` +
				`got "${value ? value.slice(0, 36) : "(empty)"}". ` +
				`Check your Verdaccio config or ${label === "tenantId" ? "ENTRA_TENANT_ID" : "ENTRA_CLIENT_ID"} env var.`,
		);
	}
}

/** OIDC discovery response shape (subset we need) */
interface OidcDiscovery {
	issuer: string;
	jwks_uri: string;
}

/**
 * Fetch OIDC discovery document.
 *
 * Uses native fetch() — proxy support is handled by Node 22.21+'s
 * built-in NODE_USE_ENV_PROXY=1 which covers both fetch() and https.request().
 * No custom proxy code needed in the plugin.
 *
 * @see https://nodejs.org/en/learn/http/enterprise-network-configuration
 * @see https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud
 */
async function discoverOidc(authority: string, tenantId: string): Promise<OidcDiscovery> {
	const url = `${authority}/${tenantId}/v2.0/.well-known/openid-configuration`;
	const res = await fetch(url);
	if (!res.ok) {
		throw new Error(
			`OIDC discovery failed: HTTP ${res.status} from ${url}. ` +
				"Verify your tenantId and authority are correct.",
		);
	}
	return res.json() as Promise<OidcDiscovery>;
}

/**
 * Verdaccio auth plugin that validates Entra ID (Azure AD) access tokens
 * using Verdaccio's **native login flow**.
 *
 * This plugin is strictly an AuthN (authentication/identity) plugin.
 * It does NOT implement authorization hooks (allow_access, allow_publish, etc.)
 * — Verdaccio's core handles authorization natively using the groups returned
 * by `authenticate`.
 *
 * ## Proxy support
 * Set `NODE_USE_ENV_PROXY=1` to enable proxy support for both OIDC discovery
 * (fetch) and JWKS key fetching (https.request via jwks-rsa). This is a
 * Node 22.21+ built-in that covers all HTTP clients without plugin code.
 * @see https://nodejs.org/en/learn/http/enterprise-network-configuration
 *
 * @see https://verdaccio.org/docs/plugin-auth — IPluginAuth<T> interface
 * @see https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud
 */
export default class EntraPlugin extends Plugin<EntraConfig> implements pluginUtils.Auth<EntraConfig> {
	private _logger: Logger;
	private _jwks: jwksClient.JwksClient | undefined;
	private _issuer: string | undefined;
	private _entraConfig: EntraConfig;
	private _audience: string;
	private _maxTokenBytes: number;
	private _ready: Promise<void>;
	private _discoveryFailed = false;

	public constructor(config: EntraConfig, appOptions: pluginUtils.PluginOptions) {
		super(config, appOptions);
		const clientId = process.env["ENTRA_CLIENT_ID"] ?? config.clientId;
		const tenantId = process.env["ENTRA_TENANT_ID"] ?? config.tenantId;
		const authority = process.env["ENTRA_AUTHORITY"] ?? config.authority ?? DEFAULT_AUTHORITY;
		assertGuid(clientId, "clientId");
		assertGuid(tenantId, "tenantId");
		this._entraConfig = { ...config, clientId, tenantId, authority };
		this._audience = process.env["ENTRA_AUDIENCE"] ?? config.audience ?? `${AUDIENCE_PREFIX}${clientId}`;
		this._maxTokenBytes = config.maxTokenBytes ?? DEFAULT_MAX_TOKEN_BYTES;
		this._logger = appOptions.logger;

		this._ready = this._initWithRetry(authority, tenantId);

		debug("EntraPlugin initializing for tenant %s, authority %s, audience %s", tenantId, authority, this._audience);
	}

	/**
	 * Authenticate: validate the Entra JWT passed as the password field.
	 *
	 * Enforces that the npm login username matches the Entra identity in the
	 * token (preferred_username / upn / email). This prevents audit log
	 * spoofing where a valid user could claim a different username in the
	 * registry's package metadata.
	 *
	 * @see https://verdaccio.org/docs/plugin-auth — authenticate callback
	 */
	public authenticate(user: string, password: string, cb: pluginUtils.AuthCallback): void {
		debug("Authenticating user: %s", user);
		if (password.length > this._maxTokenBytes) {
			cb(null, false);
			return;
		}
		this._validateToken(password)
			.then((payload) => {
				const upn = payload.preferred_username ?? payload.upn ?? payload.email;
				if (!upn) {
					this._logger.error({ user }, "Token has no identity claim (preferred_username, upn, email)");
					cb(null, false);
					return;
				}

				// Enforce username matches the Entra identity — prevents audit log spoofing.
				if (user.toLowerCase() !== upn.toLowerCase()) {
					this._logger.warn(
						{ provided: user, actual: upn },
						"Username mismatch: npm login username '@{provided}' does not match Entra identity '@{actual}'",
					);
					cb(errorUtils.getUnauthorized(
						`Username "${user}" does not match Entra identity "${upn}". ` +
							"Use your Entra email/UPN as the npm login username.",
					));
					return;
				}

				const groups = this._extractGroups(payload);
				this._logger.info({ user: upn }, "User @{user} authenticated via Entra ID");
				debug("User %s authenticated, groups: %o", upn, groups);
				cb(null, groups);
			})
			.catch((err) => {
				const msg = err instanceof Error ? err.message : String(err);
				this._logger.warn({ user, err: msg }, "Entra auth failed for @{user}: @{err}");
				debug("Authentication failed for %s: %s", user, msg);
				if (this._isServiceError(err)) {
					cb(errorUtils.getInternalError(msg));
				} else {
					cb(null, false);
				}
			});
	}

	// --- Internals ---

	/**
	 * Initialize OIDC discovery with retry on failure.
	 * Retries up to 3 times with exponential backoff (1s, 2s, 4s).
	 * If all retries fail, sets _discoveryFailed so the next authenticate
	 * call re-triggers discovery (self-healing).
	 */
	private async _initWithRetry(authority: string, tenantId: string, maxRetries = 3): Promise<void> {
		for (let attempt = 1; attempt <= maxRetries; attempt++) {
			try {
				const discovery = await discoverOidc(authority, tenantId);
				this._issuer = discovery.issuer;
				this._jwks = jwksClient({
					jwksUri: discovery.jwks_uri,
					cache: true,
					cacheMaxAge: 600_000, // 10 min
					rateLimit: true, // Prevent kid-spoofing DoS
					jwksRequestsPerMinute: 10,
				});
				this._discoveryFailed = false;
				this._logger.info(
					{ issuer: discovery.issuer, jwks: discovery.jwks_uri },
					"OIDC discovery succeeded — issuer: @{issuer}",
				);
				debug("EntraPlugin ready — issuer: %s, jwks: %s", discovery.issuer, discovery.jwks_uri);
				return;
			} catch (err) {
				const msg = err instanceof Error ? err.message : String(err);
				this._logger.error(
					{ err: msg, attempt, maxRetries },
					"OIDC discovery failed (attempt @{attempt}/@{maxRetries}): @{err}",
				);
				debug("OIDC discovery attempt %d/%d failed: %s", attempt, maxRetries, msg);
				if (attempt < maxRetries) {
					const delay = 1000 * Math.pow(2, attempt - 1);
					await new Promise((r) => setTimeout(r, delay));
				}
			}
		}
		this._discoveryFailed = true;
		this._logger.error(
			{ authority, tenantId },
			"OIDC discovery failed after all retries — will retry on next auth attempt. " +
				"Check authority (@{authority}) and tenantId (@{tenantId}).",
		);
	}

	/**
	 * Validate an Entra ID JWT: decode → fetch JWKS key → verify signature + claims.
	 */
	private async _validateToken(token: string): Promise<EntraTokenPayload> {
		// Self-healing: if previous discovery failed, re-trigger
		if (this._discoveryFailed) {
			const { authority, tenantId } = this._entraConfig;
			this._ready = this._initWithRetry(authority ?? DEFAULT_AUTHORITY, tenantId);
		}

		await this._ready;
		if (!this._jwks || !this._issuer) {
			throw new JwksServiceError(
				"Plugin not ready — OIDC discovery has not completed. " +
					"Check the authority URL and tenant ID.",
			);
		}

		const decoded = jwt.decode(token, { complete: true });
		if (!decoded || typeof decoded === "string") {
			throw new Error(
				"Invalid token format — password must be a valid Entra ID JWT. " +
					"Run: npm login --registry=<url> with your Entra access token as the password.",
			);
		}

		const kid = decoded.header.kid;
		if (!kid) {
			throw new Error(
				"Token missing kid header — not a valid Entra ID JWT. " +
					"Ensure you are passing an access token, not a refresh token or id token.",
			);
		}

		let key: jwksClient.SigningKey;
		try {
			key = await this._jwks.getSigningKey(kid);
		} catch (jwksErr) {
			const msg = jwksErr instanceof Error ? jwksErr.message : String(jwksErr);
			throw new JwksServiceError(
				`Failed to fetch signing key from Entra ID JWKS endpoint (kid: ${kid}): ${msg}. ` +
					"This may indicate the token was not issued by the expected Entra tenant.",
			);
		}

		return new Promise((resolve, reject) => {
			jwt.verify(
				token,
				key.getPublicKey(),
				{
					algorithms: ["RS256"],
					issuer: this._issuer,
					audience: this._audience,
				},
				(err, payload) => {
					if (err) {
						const enriched = enrichVerifyError(err, token, this._entraConfig);
						return reject(new Error(enriched));
					}
					resolve(payload as EntraTokenPayload);
				},
			);
		});
	}

	private _extractGroups(payload: EntraTokenPayload): string[] {
		return ["$authenticated", ...this._extractStringArray(payload.groups), ...this._extractStringArray(payload.roles)];
	}

	private _extractStringArray(value: unknown): string[] {
		if (!Array.isArray(value)) return [];
		return value.filter((item): item is string => typeof item === "string");
	}

	private _isServiceError(err: unknown): boolean {
		return err instanceof JwksServiceError;
	}
}
