import { errorUtils, pluginUtils } from "@verdaccio/core";
import type { Logger } from "@verdaccio/types";
import debugCore from "debug";
import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from "jose";
import type { JWTPayload, JWTVerifyGetKey } from "jose";

import type { EntraConfig, EntraTokenPayload } from "../types/index";
import { enrichJoseError } from "./diagnostics";

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

/**
 * Resolve plugin configuration from YAML config and environment variables.
 *
 * Verdaccio does NOT interpolate `${VAR}` in plugin config blocks — only a
 * hardcoded whitelist (http_proxy, https_proxy, no_proxy, VERDACCIO_STORAGE_PATH).
 * This function explicitly resolves env overrides so the constructor stays pure.
 *
 * Precedence: env var > config.yaml value > default.
 *
 * @see https://www.verdaccio.org/docs/env/
 */
export function resolveConfig(
	config: EntraConfig,
	env: Record<string, string | undefined> = process.env,
): { clientId: string; tenantId: string; authority: string; audience: string } {
	const clientId = env["ENTRA_CLIENT_ID"] ?? config.clientId;
	const tenantId = env["ENTRA_TENANT_ID"] ?? config.tenantId;
	const authority = env["ENTRA_AUTHORITY"] ?? config.authority ?? DEFAULT_AUTHORITY;
	const audience = env["ENTRA_AUDIENCE"] ?? config.audience ?? `${AUDIENCE_PREFIX}${clientId}`;
	assertGuid(clientId, "clientId");
	assertGuid(tenantId, "tenantId");
	return { clientId, tenantId, authority, audience };
}

/** OIDC discovery response shape (subset we need) */
export interface OidcDiscovery {
	issuer: string;
	jwks_uri: string;
}

/**
 * Warn if proxy env vars are set but Node won't use them.
 *
 * Node's native fetch ignores HTTP_PROXY/HTTPS_PROXY unless
 * NODE_USE_ENV_PROXY=1 is set (stable since Node v21.7.0/v20.13.0).
 * jose's createRemoteJWKSet also uses fetch internally, so both
 * OIDC discovery and JWKS fetching are affected.
 *
 * @see https://nodejs.org/en/learn/http/enterprise-network-configuration
 */
export function warnIfProxyMisconfigured(
	logger: Logger,
	env: Record<string, string | undefined> = process.env,
): void {
	const hasProxy = env["HTTPS_PROXY"] || env["HTTP_PROXY"] || env["https_proxy"] || env["http_proxy"];
	const hasFlag = env["NODE_USE_ENV_PROXY"];
	if (hasProxy && !hasFlag) {
		logger.error(
			{},
			"HTTPS_PROXY or HTTP_PROXY is set but NODE_USE_ENV_PROXY is not. " +
				"Node's native fetch (used for OIDC discovery and JWKS fetching) will IGNORE your proxy. " +
				"Set NODE_USE_ENV_PROXY=1 in your container/environment to enable proxy support. " +
				"See https://nodejs.org/en/learn/http/enterprise-network-configuration",
		);
	}
}

/**
 * Fetch OIDC discovery document.
 * Proxy support via NODE_USE_ENV_PROXY=1 (Node 20.13+/21.7+).
 * @see https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud
 */
export async function discoverOidc(authority: string, tenantId: string): Promise<OidcDiscovery> {
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
 * Uses the `jose` library (Web Crypto, zero deps) for JWT verification
 * with `createRemoteJWKSet` handling JWKS caching, key rotation, and
 * rate-limited refetching automatically.
 *
 * This plugin is strictly AuthN. Verdaccio handles AuthZ natively from
 * the groups returned by `authenticate`.
 *
 * @see https://verdaccio.org/docs/plugin-auth
 * @see https://github.com/panva/jose
 */
export default class EntraPlugin extends Plugin<EntraConfig> implements pluginUtils.Auth<EntraConfig> {
	private _logger: Logger;
	private _jwks: JWTVerifyGetKey | undefined;
	private _issuer: string | undefined;
	private _entraConfig: EntraConfig;
	private _audience: string;
	private _maxTokenBytes: number;
	/** Shared discovery promise. Null when failed — next auth attempt creates a fresh one. */
	private _discovery: Promise<void> | null;
	private _discoveryRetries: number;

	public constructor(config: EntraConfig, appOptions: pluginUtils.PluginOptions) {
		super(config, appOptions);
		const resolved = resolveConfig(config);
		this._entraConfig = { ...config, clientId: resolved.clientId, tenantId: resolved.tenantId, authority: resolved.authority };
		this._audience = resolved.audience;
		this._maxTokenBytes = config.maxTokenBytes ?? DEFAULT_MAX_TOKEN_BYTES;
		this._discoveryRetries = config.discoveryRetries ?? 3;
		this._logger = appOptions.logger;

		warnIfProxyMisconfigured(this._logger);
		this._discovery = this._discover();

		debug("EntraPlugin initializing for tenant %s, authority %s, audience %s", resolved.tenantId, resolved.authority, this._audience);
	}

	/**
	 * Authenticate: validate the Entra JWT passed as the password field.
	 *
	 * Enforces that the npm login username matches the Entra identity in the
	 * token (preferred_username / upn / email). This prevents audit log
	 * spoofing where a valid user could claim a different username in the
	 * registry's package metadata.
	 */
	public authenticate(user: string, password: string, cb: pluginUtils.AuthCallback): void {
		debug("Authenticating user: %s", user);
		if (password.length > this._maxTokenBytes) {
			cb(null, false);
			return;
		}
		(async () => {
			const payload = await this._validateToken(password);
			const upn = payload.preferred_username ?? payload.upn ?? payload.email;
			if (!upn) {
				this._logger.error({ user }, "Token has no identity claim (preferred_username, upn, email)");
				cb(null, false);
				return;
			}

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
		})().catch((err) => {
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
	 * Run OIDC discovery with exponential backoff retry.
	 * On success, sets _issuer and _jwks. On failure, nullifies _discovery
	 * so the next auth attempt creates a fresh promise (no thundering herd —
	 * concurrent callers share the same promise until it settles).
	 *
	 * jose's createRemoteJWKSet handles JWKS caching, key rotation,
	 * rate limiting, and kid matching automatically after this.
	 */
	private _discover(): Promise<void> {
		const { authority = DEFAULT_AUTHORITY, tenantId } = this._entraConfig;
		const maxRetries = this._discoveryRetries;

		const attempt = async (): Promise<void> => {
			for (let i = 1; i <= maxRetries; i++) {
				try {
					const discovery = await discoverOidc(authority, tenantId);
					this._issuer = discovery.issuer;
					this._jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
					this._logger.info(
						{ issuer: discovery.issuer, jwks: discovery.jwks_uri },
						"OIDC discovery succeeded — issuer: @{issuer}",
					);
					debug("EntraPlugin ready — issuer: %s, jwks: %s", discovery.issuer, discovery.jwks_uri);
					return;
				} catch (err) {
					const msg = err instanceof Error ? err.message : String(err);
					this._logger.error(
						{ err: msg, attempt: i, maxRetries },
						"OIDC discovery failed (attempt @{attempt}/@{maxRetries}): @{err}",
					);
					debug("OIDC discovery attempt %d/%d failed: %s", i, maxRetries, msg);
					if (i < maxRetries) {
						await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, i - 1)));
					}
				}
			}
			// All retries exhausted — null out so next auth attempt retries
			this._discovery = null;
			this._logger.error(
				{ authority, tenantId },
				"OIDC discovery failed after all retries — will retry on next auth attempt. " +
					"Check authority (@{authority}) and tenantId (@{tenantId}).",
			);
		};

		return attempt();
	}

	/**
	 * Validate an Entra ID JWT using jose.
	 *
	 * jose.jwtVerify does signature verification AND claim validation
	 * (exp, nbf, aud, iss) in a single atomic call using Web Crypto.
	 * createRemoteJWKSet handles JWKS fetching, caching, and key rotation.
	 */
	private async _validateToken(token: string): Promise<EntraTokenPayload> {
		// Lazy re-discovery: if previous attempt failed (_discovery is null),
		// create a fresh promise. Concurrent callers share the same promise.
		if (!this._discovery) {
			this._discovery = this._discover();
		}

		await this._discovery;
		if (!this._jwks || !this._issuer) {
			throw new DiscoveryError(
				"Plugin not ready — OIDC discovery has not completed. " +
					"Check the authority URL and tenant ID.",
			);
		}

		try {
			const { payload } = await jwtVerify(token, this._jwks, {
				algorithms: ["RS256"],
				issuer: this._issuer,
				audience: this._audience,
			});
			return payload as EntraTokenPayload;
		} catch (err) {
			if (err instanceof joseErrors.JWKSNoMatchingKey) {
				throw new DiscoveryError(
					`No matching signing key found for this token. ` +
						"This may indicate the token was not issued by the expected Entra tenant.",
				);
			}
			// Enrich with diagnostics (swap detection, friendly messages) — post-verify only
			throw new Error(enrichJoseError(err, token, this._entraConfig));
		}
	}

	private _extractGroups(payload: JWTPayload): string[] {
		return ["$authenticated", ...this._extractStringArray(payload["groups"]), ...this._extractStringArray(payload["roles"])];
	}

	private _extractStringArray(value: unknown): string[] {
		if (!Array.isArray(value)) return [];
		return value.filter((item): item is string => typeof item === "string");
	}

	private _isServiceError(err: unknown): boolean {
		return err instanceof DiscoveryError;
	}
}

/** Thrown when OIDC discovery or JWKS key resolution fails — a service error. */
class DiscoveryError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "DiscoveryError";
	}
}
