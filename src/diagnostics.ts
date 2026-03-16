/**
 * Diagnostic utilities for verdaccio-entra.
 *
 * These are developer experience (DX) helpers — they exist to help operators
 * debug misconfigured deployments. They are NOT part of the security boundary.
 *
 * Used by:
 *   - scripts/check-config.ts (pre-flight validation)
 *   - auth-plugin.ts catch block (log enrichment only — never in auth decisions)
 *
 * @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
 */

import jwt from "jsonwebtoken";
import { AUDIENCE_PREFIX } from "./auth-plugin";
import type { EntraConfig, EntraTokenPayload } from "../types/index";

/**
 * Detect if clientId and tenantId are swapped by inspecting token claims.
 *
 * Entra access tokens contain:
 *   - `aud`: the audience — should match `api://{clientId}`
 *   - `tid`: the tenant ID GUID
 *
 * If `tid` matches the configured clientId, or `aud` contains the configured
 * tenantId, the user likely swapped the two values.
 *
 * Returns a human-readable hint string, or undefined if no swap detected.
 */
export function detectSwappedIds(token: string, config: EntraConfig): string | undefined {
	const decoded = jwt.decode(token);
	if (!decoded || typeof decoded === "string") return undefined;
	const claims = decoded as EntraTokenPayload;

	const tid = typeof claims["tid"] === "string" ? (claims["tid"] as string) : undefined;
	const { clientId, tenantId } = config;

	if (tid && tid.toLowerCase() === clientId.toLowerCase()) {
		return `It looks like clientId and tenantId may be swapped — the token's tid claim (${tid}) matches your configured clientId. ` +
			"Check ENTRA_CLIENT_ID and ENTRA_TENANT_ID.";
	}
	if (claims.aud && claims.aud.toLowerCase().includes(tenantId.toLowerCase())) {
		return `It looks like clientId and tenantId may be swapped — the token's audience (${claims.aud}) contains your configured tenantId. ` +
			"Check ENTRA_CLIENT_ID and ENTRA_TENANT_ID.";
	}
	return undefined;
}

/**
 * Enrich a jwt.verify error with a diagnostic hint by peeking at claims.
 * Called AFTER signature verification fails — never on untrusted data
 * for auth decisions, only for log messages.
 */
export function enrichVerifyError(err: jwt.VerifyErrors, token: string, config: EntraConfig): string {
	const hint = detectSwappedIds(token, config);
	const base = err.message;

	if (err.name === "TokenExpiredError") {
		return "Entra ID token has expired. Obtain a fresh access token via MSAL and run npm login again.";
	}
	if (err.name === "NotBeforeError") {
		return "Entra ID token is not yet valid (nbf claim is in the future). Check server clock sync.";
	}
	if (base.includes("audience")) {
		return `Token audience mismatch — expected ${AUDIENCE_PREFIX}${config.clientId}. ` +
			(hint ?? "Ensure the MSAL scope matches the Verdaccio app registration.");
	}
	if (base.includes("issuer")) {
		return `Token issuer mismatch — expected tenant ${config.tenantId}. ` +
			(hint ?? "Ensure the token was issued by the correct Entra tenant.");
	}
	return `Entra token validation failed: ${base}`;
}
