import { errorUtils, pluginUtils } from "@verdaccio/core";
import type { Logger, PackageAccess, RemoteUser } from "@verdaccio/types";
import debugCore from "debug";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

import type { EntraConfig, EntraTokenPayload, PackageAccessWithUnpublish } from "../types/index";
import { enrichVerifyError } from "./diagnostics";

const { Plugin } = pluginUtils;

const debug = debugCore("verdaccio:plugin:entra");

/** @see https://learn.microsoft.com/windows/win32/msi/guid */
export const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const MAX_TOKEN_BYTES = 8192;
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
 * Fetch OIDC discovery document to dynamically resolve JWKS endpoint and issuer.
 * This supports all sovereign/national clouds without hardcoding endpoints.
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
 * ## How it works (per Verdaccio Plugin Auth docs):
 * @see https://verdaccio.org/docs/plugin-auth — IPluginAuth<T> interface
 * @see https://verdaccio.org/docs/configuration — security.api.jwt config
 *
 * 1. User obtains an Entra access-token client-side (MSAL / WAM broker).
 * 2. `npm login --registry=<url>` sends username + Entra JWT as password.
 * 3. `authenticate(user, password, cb)` validates the Entra JWT via JWKS
 *    and returns `cb(null, groups)` on success.
 * 4. **Verdaccio issues its own JWT** (signed with its `secret`) to npm.
 * 5. npm stores Verdaccio's token in `.npmrc`.
 * 6. Subsequent requests carry Verdaccio's JWT — Verdaccio validates it
 *    internally and populates `req.remote_user`. No middleware needed.
 *
 * ### Sovereign cloud support
 * Set `authority` in config to use national clouds:
 * ```yaml
 * auth:
 *   entra:
 *     clientId: "..."
 *     tenantId: "..."
 *     authority: "https://login.microsoftonline.us"  # US Government
 * ```
 * The plugin uses OIDC discovery to resolve the JWKS endpoint and issuer
 * dynamically, so it works with any Entra-compatible authority.
 * @see https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud
 */
export default class EntraPlugin extends Plugin<EntraConfig> implements pluginUtils.Auth<EntraConfig> {
	private _logger: Logger;
	private _jwks: jwksClient.JwksClient | undefined;
	private _issuer: string | undefined;
	private _entraConfig: EntraConfig;
	private _ready: Promise<void>;

	public constructor(config: EntraConfig, appOptions: pluginUtils.PluginOptions) {
		super(config, appOptions);
		const clientId = process.env["ENTRA_CLIENT_ID"] ?? config.clientId;
		const tenantId = process.env["ENTRA_TENANT_ID"] ?? config.tenantId;
		const authority = process.env["ENTRA_AUTHORITY"] ?? config.authority ?? DEFAULT_AUTHORITY;
		assertGuid(clientId, "clientId");
		assertGuid(tenantId, "tenantId");
		this._entraConfig = { ...config, clientId, tenantId, authority };
		this._logger = appOptions.logger;

		// OIDC discovery resolves jwks_uri and issuer dynamically.
		// This supports all sovereign clouds without hardcoded endpoints.
		this._ready = discoverOidc(authority, tenantId)
			.then((discovery) => {
				this._issuer = discovery.issuer;
				this._jwks = jwksClient({
					jwksUri: discovery.jwks_uri,
					cache: true,
					cacheMaxAge: 600_000, // 10 min
					rateLimit: true, // Prevent kid-spoofing DoS
					jwksRequestsPerMinute: 10,
				});
				debug("EntraPlugin ready — issuer: %s, jwks: %s", discovery.issuer, discovery.jwks_uri);
			})
			.catch((err) => {
				const msg = err instanceof Error ? err.message : String(err);
				this._logger.error({ err: msg }, "OIDC discovery failed: @{err}");
				debug("OIDC discovery failed: %s", msg);
				// Plugin will reject all auth attempts until discovery succeeds
			});

		debug("EntraPlugin initializing for tenant %s, authority %s", tenantId, authority);
	}

	/**
	 * Authenticate: validate the Entra JWT passed as the password field.
	 *
	 * Called by Verdaccio during `npm login`.
	 * On success, returns groups via `cb(null, groups)`.
	 * Verdaccio then issues its own JWT to the client.
	 *
	 * @see https://verdaccio.org/docs/plugin-auth — authenticate callback
	 */
	public authenticate(user: string, password: string, cb: pluginUtils.AuthCallback): void {
		debug("Authenticating user: %s", user);
		if (password.length > MAX_TOKEN_BYTES) {
			cb(null, false);
			return;
		}
		this._validateToken(password)
			.then((payload) => {
				const upn = payload.preferred_username ?? payload.upn ?? payload.email ?? user;
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

	/**
	 * Allow access if user is in an allowed group (or access is open).
	 *
	 * Verdaccio populates `user` from its own JWT — no middleware needed.
	 * @see https://verdaccio.org/docs/plugin-auth — allow_access callback
	 */
	public allow_access(user: RemoteUser, pkg: PackageAccess, cb: pluginUtils.AccessCallback): void {
		debug("allow_access for %s to %o", user?.name, pkg?.access);
		const required = pkg?.access ?? ["$authenticated"];

		if (required.includes("$all") || required.includes("$anonymous")) {
			debug("%s granted access ($all/$anonymous)", user?.name);
			cb(null, true);
			return;
		}

		if (this._matchGroups(user, required)) {
			debug("%s granted access via group match", user?.name);
			cb(null, true);
			return;
		}

		this._logger.warn({ user: user?.name }, "Access denied for @{user}");
		cb(errorUtils.getForbidden("access denied"), false);
	}

	/**
	 * Allow publish if user is in an allowed group.
	 *
	 * @see https://verdaccio.org/docs/plugin-auth — allow_publish callback
	 */
	public allow_publish(user: RemoteUser, pkg: PackageAccess, cb: pluginUtils.AuthAccessCallback): void {
		debug("allow_publish for %s, publish list: %o", user?.name, pkg?.publish);
		const required = pkg?.publish ?? ["$authenticated"];

		if (this._matchGroups(user, required)) {
			debug("%s granted publish via group match", user?.name);
			cb(null, true);
			return;
		}

		const err = errorUtils.getForbidden("not allowed to publish package");
		this._logger.error({ user: user?.name }, "@{user} not allowed to publish");
		debug("%s not allowed to publish: %s", user?.name, err.message);
		cb(err);
	}

	/**
	 * Allow unpublish if user is in an allowed group.
	 *
	 * @see https://verdaccio.org/docs/plugin-auth#allow_access-allow_publish-or-allow_unpublish-callback
	 */
	public allow_unpublish(user: RemoteUser, pkg: PackageAccess, cb: pluginUtils.AuthAccessCallback): void {
		const extended = pkg as PackageAccessWithUnpublish;
		debug("allow_unpublish for %s, unpublish list: %o", user?.name, extended.unpublish);
		const required = extended.unpublish ?? pkg?.publish ?? ["$authenticated"];

		if (this._matchGroups(user, required)) {
			debug("%s granted unpublish via group match", user?.name);
			cb(null, true);
			return;
		}

		const err = errorUtils.getForbidden("not allowed to unpublish package");
		this._logger.error({ user: user?.name }, "@{user} not allowed to unpublish");
		debug("%s not allowed to unpublish: %s", user?.name, err.message);
		cb(err);
	}

	// --- Internals ---

	/**
	 * Validate an Entra ID JWT: decode → fetch JWKS key → verify signature + claims.
	 *
	 * The cryptographic boundary is jwt.verify — ALL claim validation (exp, aud, iss)
	 * is delegated to the library AFTER signature verification. No unverified claim
	 * inspection occurs before the signature is checked.
	 */
	private async _validateToken(token: string): Promise<EntraTokenPayload> {
		// Wait for OIDC discovery to complete
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

		// Signature verification + claim validation in one step.
		// jwt.verify checks exp, aud, iss, nbf, and algorithms natively.
		return new Promise((resolve, reject) => {
			jwt.verify(
				token,
				key.getPublicKey(),
				{
					algorithms: ["RS256"],
					issuer: this._issuer,
					audience: `${AUDIENCE_PREFIX}${this._entraConfig.clientId}`,
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

	/**
	 * Distinguish service errors (JWKS endpoint down, discovery failed)
	 * from credential failures (expired token, wrong audience).
	 * @see https://verdaccio.org/docs/plugin-auth#if-the-authentication-produce-an-error
	 */
	private _isServiceError(err: unknown): boolean {
		return err instanceof JwksServiceError;
	}

	private _matchGroups(user: RemoteUser, required: string[]): boolean {
		if (required.includes("$all") || required.includes("$anonymous")) return true;
		if (!user.name) return false;
		const userGroups = new Set(user.groups ?? []);
		return required.some((g) => userGroups.has(g));
	}
}
