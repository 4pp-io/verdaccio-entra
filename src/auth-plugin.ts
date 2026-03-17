import { errorUtils, pluginUtils } from "@verdaccio/core";
import type { Logger } from "@verdaccio/types";
import debugCore from "debug";
import { createRemoteJWKSet, jwtVerify } from "jose";
import type { JWTPayload, JWTVerifyGetKey } from "jose";

import type { EntraConfig, EntraTokenPayload } from "../types/index";
import { enrichJoseError } from "./diagnostics";

const { Plugin } = pluginUtils;

const debug = debugCore("verdaccio:plugin:entra");

/** @see https://learn.microsoft.com/windows/win32/msi/guid */
export const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/**
 * Default max token size: 256,000 bytes (decimal), matching the
 * Microsoft.IdentityModel default `TokenValidationParameters.DefaultMaximumTokenSizeInBytes`.
 * Note: this is 256,000 bytes, not 256 KiB (262,144).
 * @see https://learn.microsoft.com/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters.defaultmaximumtokensizeinbytes
 */
export const DEFAULT_MAX_TOKEN_BYTES = 256_000;
export const AUDIENCE_PREFIX = "api://";

/**
 * Clock skew tolerance for JWT verification (seconds).
 * Accommodates minor clock drift between token issuer and this server.
 * @see https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
 */
export const DEFAULT_CLOCK_TOLERANCE_SECONDS = 300;

/**
 * Default Azure Public cloud authority.
 * Override with `authority` config for sovereign clouds.
 * @see https://learn.microsoft.com/entra/identity-platform/authentication-national-cloud
 */
export const DEFAULT_AUTHORITY = "https://login.microsoftonline.com";

/**
 * Entra v2 issuer and JWKS URI patterns.
 *
 * For a given tenantId and authority, these are 100% deterministic —
 * the plugin computes them directly instead of fetching the OIDC
 * discovery document at runtime. jose's createRemoteJWKSet handles
 * all JWKS key fetching, caching, rotation, and retries.
 *
 * check-config.ts has its own discoverOidc() for pre-flight validation
 * (confirming the endpoint is reachable and the issuer matches).
 *
 * @see https://learn.microsoft.com/entra/identity-platform/v2-protocols-oidc
 */
export const ISSUERS = {
	v2: (tenantId: string, authority = DEFAULT_AUTHORITY): string =>
		`${authority}/${tenantId}/v2.0`,
} as const;

/** Deterministic JWKS URI for Entra v2 endpoints. */
export function jwksUri(tenantId: string, authority = DEFAULT_AUTHORITY): string {
	return `${authority}/${tenantId}/discovery/v2.0/keys`;
}

/**
 * Runtime shape guard for the Entra token payload after jose signature verification.
 * Validates that identity and group claims — if present — have the expected types.
 * Catches unexpected Microsoft token shape changes that a bare type assertion would hide.
 */
function assertEntraPayload(payload: JWTPayload): EntraTokenPayload {
	const optStr: (keyof EntraTokenPayload)[] = ["preferred_username", "upn", "email", "oid", "sub"];
	for (const key of optStr) {
		if (key in payload && typeof payload[key] !== "string") {
			throw new Error(`Unexpected token shape: claim "${key}" is ${typeof payload[key]}, expected string`);
		}
	}
	const optArr: (keyof EntraTokenPayload)[] = ["groups", "roles"];
	for (const key of optArr) {
		if (key in payload && !Array.isArray(payload[key])) {
			throw new Error(`Unexpected token shape: claim "${key}" is ${typeof payload[key]}, expected array`);
		}
	}
	return payload as EntraTokenPayload;
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
	logger?: Logger,
): { clientId: string; tenantId: string; authority: string; audience: string } {
	const clientId = env["ENTRA_CLIENT_ID"] ?? config.clientId;
	const tenantId = env["ENTRA_TENANT_ID"] ?? config.tenantId;
	const authority = env["ENTRA_AUTHORITY"] ?? config.authority ?? DEFAULT_AUTHORITY;
	const audience = env["ENTRA_AUDIENCE"] ?? config.audience ?? `${AUDIENCE_PREFIX}${clientId}`;

	if (logger) {
		const overrides = [
			env["ENTRA_CLIENT_ID"] && "clientId",
			env["ENTRA_TENANT_ID"] && "tenantId",
			env["ENTRA_AUTHORITY"] && "authority",
			env["ENTRA_AUDIENCE"] && "audience",
		].filter(Boolean);
		if (overrides.length > 0) {
			logger.info({ overrides: overrides.join(", ") }, "entra: config fields overridden by env vars: @{overrides}");
		}
	}

	assertGuid(clientId, "clientId");
	assertGuid(tenantId, "tenantId");
	return { clientId, tenantId, authority, audience };
}

/**
 * Warn if proxy env vars are set but Node won't use them.
 *
 * Node's native fetch ignores HTTP_PROXY/HTTPS_PROXY unless
 * NODE_USE_ENV_PROXY=1 is set (stable since Node v21.7.0/v20.13.0).
 * jose's createRemoteJWKSet also uses fetch internally for
 * JWKS key fetching.
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
		logger.warn(
			{ proxy: hasProxy, fix: "set NODE_USE_ENV_PROXY=1" },
			"entra: proxy env vars detected but Node will ignore them without NODE_USE_ENV_PROXY=1",
		);
	}
}

/**
 * Verdaccio auth plugin that validates Entra ID (Azure AD) access tokens
 * using Verdaccio's **native login flow**.
 *
 * Uses the `jose` library (Web Crypto, zero deps) for JWT verification
 * with `createRemoteJWKSet` handling JWKS caching, key rotation, and
 * cooldown-gated refetching (30s default) automatically.
 *
 * This plugin is strictly AuthN. Verdaccio handles AuthZ natively from
 * the groups returned by `authenticate`.
 *
 * @see https://verdaccio.org/docs/plugin-auth
 * @see https://github.com/panva/jose
 */
export default class EntraPlugin extends Plugin<EntraConfig> implements pluginUtils.Auth<EntraConfig> {
	private _logger: Logger;
	private _jwks: JWTVerifyGetKey;
	private _issuer: string;
	private _entraConfig: EntraConfig;
	private _audience: string;
	private _maxTokenBytes: number;
	private _allowGroupOverage: boolean;

	public constructor(config: EntraConfig, appOptions: pluginUtils.PluginOptions) {
		super(config, appOptions);
		this._logger = appOptions.logger;

		let resolved: ReturnType<typeof resolveConfig>;
		try {
			resolved = resolveConfig(config, process.env, this._logger);
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			const envFailClosed = process.env["ENTRA_FAIL_CLOSED"];
			const failClosed = envFailClosed !== undefined ? envFailClosed === "true" : (config.failClosed ?? false);

			// ADVERSARIAL ORACLE NOTE:
			// Verdaccio's plugin-async-loader.js blindly catches ALL constructor exceptions
			// (Error, TypeError, strings, etc.) using a generic catch block, logs a warning,
			// and cheerfully boots up the registry without this plugin. This is a massive "fail open"
			// security risk. Using process.exit(1) here is self-defense against a framework that
			// actively sabotages the security perimeter.
			if (failClosed) {
				this._logger.error(
					{ err: msg, failClosed: true },
					"entra: init failed with failClosed=true, killing process — @{err}",
				);
				process.exit(1);
			}
			this._logger.error(
				{ err: msg, failClosed: false },
				"entra: init failed, plugin will be skipped (set failClosed:true to abort) — @{err}",
			);
			throw new Error("verdaccio-entra: " + msg, { cause: err });
		}

		this._entraConfig = { ...config, clientId: resolved.clientId, tenantId: resolved.tenantId, authority: resolved.authority };
		this._audience = resolved.audience;
		this._maxTokenBytes = config.maxTokenBytes ?? DEFAULT_MAX_TOKEN_BYTES;
		const envAllowOverage = process.env["ENTRA_ALLOW_GROUP_OVERAGE"];
		this._allowGroupOverage = envAllowOverage !== undefined ? envAllowOverage === "true" : (config.allowGroupOverage ?? false);

		// Issuer and JWKS URI are deterministic for Entra v2 endpoints.
		// jose handles all JWKS key fetching, caching, rotation, and retries.
		this._issuer = ISSUERS.v2(resolved.tenantId, resolved.authority);
		this._jwks = createRemoteJWKSet(new URL(jwksUri(resolved.tenantId, resolved.authority)));

		warnIfProxyMisconfigured(this._logger);

		this._logger.info(
			{ issuer: this._issuer, audience: this._audience, jwks: jwksUri(resolved.tenantId, resolved.authority) },
			"entra: plugin loaded — issuer=@{issuer} audience=@{audience}",
		);
		debug("plugin loaded — issuer: %s, audience: %s, jwks: %s", this._issuer, this._audience, jwksUri(resolved.tenantId, resolved.authority));
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
		if (Buffer.byteLength(password) > this._maxTokenBytes) {
			cb(null, false);
			return;
		}
		(async () => {
			const payload = await this._validateToken(password);
			const upn = payload.preferred_username ?? payload.upn ?? payload.email;
			if (!upn) {
				this._logger.warn({ user }, "entra: auth rejected — token has no identity claim (preferred_username/upn/email)");
				cb(null, false);
				return;
			}

			if (user.toLowerCase() !== upn.toLowerCase()) {
				this._logger.warn(
					{ npmUser: user, entraUser: upn },
					"entra: auth rejected — npm username @{npmUser} does not match token identity @{entraUser}",
				);
				cb(errorUtils.getUnauthorized(
					`Username "${user}" does not match Entra identity "${upn}". ` +
						"Use your Entra email/UPN as the npm login username.",
				));
				return;
			}

			const groups = this._extractGroups(payload);
			this._logger.info({ user: upn, groups: groups.length }, "entra: auth ok user=@{user} groups=@{groups}");
			debug("auth ok user=%s groups=%o", upn, groups);
			cb(null, groups);
		})().catch((err: unknown) => {
			const msg = err instanceof Error ? err.message : String(err);
			this._logger.warn({ user, err: msg }, "entra: auth failed user=@{user} — @{err}");
			debug("auth failed user=%s err=%s", user, msg);
			cb(null, false);
		});
	}

	// --- Internals ---

	/**
	 * Validate an Entra ID JWT using jose.
	 *
	 * jose.jwtVerify does signature verification AND claim validation
	 * (exp, nbf, aud, iss) in a single atomic call using Web Crypto.
	 * createRemoteJWKSet handles JWKS fetching, caching, and key rotation.
	 */
	private async _validateToken(token: string): Promise<EntraTokenPayload> {
		try {
			const { payload } = await jwtVerify(token, this._jwks, {
				// Entra ID always signs access tokens using RS256
				// @see https://learn.microsoft.com/entra/identity-platform/access-tokens#validate-tokens
				algorithms: ["RS256"],
				issuer: this._issuer,
				audience: this._audience,
				clockTolerance: DEFAULT_CLOCK_TOLERANCE_SECONDS, // @see DEFAULT_CLOCK_TOLERANCE_SECONDS
			});
			return assertEntraPayload(payload);
		} catch (err) {
			// Enrich with diagnostics (swap detection, friendly messages) — post-verify only
			throw new Error(enrichJoseError(err, token, this._entraConfig));
		}
	}

	private _extractGroups(payload: EntraTokenPayload): string[] {
		const groups = [
			"$authenticated",
			...this._extractStringArray(payload.groups),
			...this._extractStringArray(payload.roles),
		];

		// Entra omits the groups claim when user has >200 group memberships.
		// Instead it sets _claim_names.groups + _claim_sources with a Graph API URL.
		// This plugin is AuthN-only and cannot call Graph.
		// @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
		const claimNames = payload["_claim_names"];
		const hasClaimNamesGroupOverage =
			claimNames &&
			typeof claimNames === "object" &&
			!Array.isArray(claimNames) &&
			"groups" in (claimNames as Record<string, unknown>);

		const hasLegacyGroupOverage =
			payload["hasgroups"] === true && payload.groups === undefined;

		if (hasClaimNamesGroupOverage || hasLegacyGroupOverage) {
			const user = payload.preferred_username ?? payload.upn ?? "unknown";
			this._logger.warn(
				{ user, overage: true, allowGroupOverage: this._allowGroupOverage },
				"entra: group overage for @{user} — token has >200 groups, groups claim omitted by Entra",
			);
			if (!this._allowGroupOverage) {
				throw new Error(
					"Group overage: Entra omitted the groups claim for this user (>200 groups). " +
						"Authentication rejected to prevent silent authorization failure. " +
						"Set allowGroupOverage: true in config if you do not use group-based ACLs.",
				);
			}
		}

		return groups;
	}

	private _extractStringArray(value: unknown): string[] {
		if (!Array.isArray(value)) return [];
		return value.filter((item): item is string => typeof item === "string");
	}
}
