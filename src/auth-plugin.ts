import { errorUtils, pluginUtils } from "@verdaccio/core";
import type { Logger, PackageAccess, RemoteUser } from "@verdaccio/types";
import debugCore from "debug";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

import type { EntraConfig, EntraTokenPayload } from "../types/index";

const { Plugin } = pluginUtils;

const debug = debugCore("verdaccio:plugin:entra");

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_TOKEN_BYTES = 8192;

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
			`Invalid ${label}: expected a GUID (e.g. "00000000-0000-0000-0000-000000000000"), ` +
				`got "${value ? value.slice(0, 36) : "(empty)"}". ` +
				`Check your Verdaccio config or ${label === "tenantId" ? "ENTRA_TENANT_ID" : "ENTRA_CLIENT_ID"} env var.`,
		);
	}
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
 * ### Why no apiJWTmiddleware?
 * The previous implementation bypassed Verdaccio's login flow by writing
 * the raw Entra JWT directly as the auth token. Verdaccio couldn't
 * decrypt it (it didn't issue it), so apiJWTmiddleware was needed to
 * intercept every request. With the native flow, Verdaccio manages its
 * own token lifecycle — authenticate once, then Verdaccio handles the rest.
 *
 * ### Required Verdaccio config (config.yaml):
 * ```yaml
 * security:
 *   api:
 *     jwt:
 *       sign:
 *         expiresIn: 7d   # fintech default; adjust per your policy
 * ```
 */
export default class EntraPlugin extends Plugin<EntraConfig> implements pluginUtils.Auth<EntraConfig> {
	private _logger: Logger;
	private _jwks: jwksClient.JwksClient;
	private _issuers: [string, ...string[]];
	private _entraConfig: EntraConfig;

	public constructor(config: EntraConfig, appOptions: pluginUtils.PluginOptions) {
		super(config, appOptions);
		// Env vars take precedence over config.yaml values.
		// Verdaccio does NOT resolve ${VAR} patterns in plugin config —
		// so we read env vars directly rather than hand-rolling interpolation.
		const clientId = process.env["ENTRA_CLIENT_ID"] ?? config.clientId;
		const tenantId = process.env["ENTRA_TENANT_ID"] ?? config.tenantId;
		assertGuid(clientId, "clientId");
		assertGuid(tenantId, "tenantId");
		this._entraConfig = { ...config, clientId, tenantId };
		this._logger = appOptions.logger;
		// Accept both v1.0 (access tokens) and v2.0 (id tokens) issuers
		this._issuers = [`https://sts.windows.net/${tenantId}/`, `https://login.microsoftonline.com/${tenantId}/v2.0`] as [
			string,
			...string[],
		];
		this._jwks = jwksClient({
			jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
			cache: true,
			cacheMaxAge: 600_000, // 10 min
		});
		debug("EntraPlugin initialized for tenant %s, clientId %s", tenantId, clientId);
	}

	/**
	 * Authenticate: validate the Entra JWT passed as the password field.
	 *
	 * Called by Verdaccio during `npm login` / `npm adduser`.
	 * On success, returns groups via `cb(null, groups)`.
	 * Verdaccio then issues its own JWT to the client.
	 *
	 * @see https://verdaccio.org/docs/plugin-auth — authenticate callback
	 */
	public authenticate(user: string, password: string, cb: pluginUtils.AuthCallback): void {
		debug("Authenticating user: %s", user);
		if (password.length > MAX_TOKEN_BYTES) {
			// Not a valid Entra token — let next auth plugin try
			// @see https://verdaccio.org/docs/plugin-auth#if-the-authentication-fails
			cb(null, false);
			return;
		}
		this._validateToken(password)
			.then((payload) => {
				const upn = payload.preferred_username ?? payload.upn ?? payload.email ?? user;
				const groups = this._extractGroups(payload);
				this._logger.info({ user: upn }, "User @{user} authenticated via Entra ID");
				debug("User %s authenticated, groups: %o", upn, groups);
				// Per docs: cb(null, groups) signals success — Verdaccio issues its own token
				cb(null, groups);
			})
			.catch((err) => {
				const msg = err instanceof Error ? err.message : String(err);
				this._logger.warn({ user, err: msg }, "Entra auth failed for @{user}: @{err}");
				debug("Authentication failed for %s: %s", user, msg);
				if (this._isServiceError(err)) {
					// JWKS endpoint unreachable — service error, stop plugin chain
					// @see https://verdaccio.org/docs/plugin-auth#if-the-authentication-produce-an-error
					cb(errorUtils.getInternalError(msg));
				} else {
					// Wrong credentials (expired, bad audience, not a JWT, etc.) — let next plugin try
					// @see https://verdaccio.org/docs/plugin-auth#if-the-authentication-fails
					cb(null, false);
				}
			});
	}

	/**
	 * adduser: called by `npm login` / `npm adduser`.
	 *
	 * Validates the Entra token and signals success via `cb(null, true)`.
	 * Verdaccio then calls `authenticate` and issues its own JWT.
	 *
	 * @see https://verdaccio.org/docs/plugin-auth — adduser callback
	 */
	public adduser(user: string, password: string, cb: pluginUtils.AuthUserCallback): void {
		debug("adduser called for: %s", user);
		if (password.length > MAX_TOKEN_BYTES) {
			cb(null, false);
			return;
		}
		this._validateToken(password)
			.then(() => {
				this._logger.info({ user }, "User @{user} added via Entra ID");
				debug("adduser success for %s", user);
				// Per docs: cb(null, true) signals success
				// @see https://verdaccio.org/docs/plugin-auth#if-adduser-success
				cb(null, true);
			})
			.catch((err) => {
				const msg = err instanceof Error ? err.message : String(err);
				this._logger.warn({ user, err: msg }, "Entra adduser failed for @{user}: @{err}");
				debug("adduser failed for %s: %s", user, msg);
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
		const pkgAny = pkg as unknown as Record<string, unknown>;
		debug("allow_unpublish for %s, unpublish list: %o", user?.name, pkgAny?.unpublish);
		const required = (pkgAny?.unpublish as string[] | undefined) ?? pkg?.publish ?? ["$authenticated"];

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

	private async _validateToken(token: string): Promise<EntraTokenPayload> {
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
		const publicKey = key.getPublicKey();

		return new Promise((resolve, reject) => {
			jwt.verify(
				token,
				publicKey,
				{
					algorithms: ["RS256"],
					issuer: this._issuers,
					audience: `api://${this._entraConfig.clientId}`,
				},
				(err, payload) => {
					if (err) {
						return reject(this._mapJwtError(err));
					}
					resolve(payload as EntraTokenPayload);
				},
			);
		});
	}

	private _mapJwtError(err: jwt.VerifyErrors): Error {
		const name = err.name;
		if (name === "TokenExpiredError") {
			return new Error("Entra ID token has expired. Obtain a fresh access token via MSAL and run npm login again.");
		}
		if (name === "JsonWebTokenError" && err.message.includes("audience")) {
			return new Error(
				`Token audience mismatch — expected api://${this._entraConfig.clientId}. ` +
					"Ensure the MSAL scope matches the Verdaccio app registration.",
			);
		}
		if (name === "JsonWebTokenError" && err.message.includes("issuer")) {
			return new Error(
				"Token issuer mismatch — token was issued by a different Entra tenant. " +
					`Expected tenant: ${this._entraConfig.tenantId}.`,
			);
		}
		return new Error(`Entra token validation failed: ${err.message}`);
	}

	private _extractGroups(payload: EntraTokenPayload): string[] {
		return ["$authenticated", ...this._extractStringArray(payload.groups), ...this._extractStringArray(payload.roles)];
	}

	private _extractStringArray(value: unknown): string[] {
		if (!Array.isArray(value)) return [];
		return value.filter((item): item is string => typeof item === "string");
	}

	/**
	 * Distinguish service errors (JWKS endpoint down) from credential failures
	 * (expired token, wrong audience). Service errors stop the plugin chain;
	 * credential failures let the next plugin try.
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
