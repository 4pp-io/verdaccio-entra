/**
 * Diagnostic utilities for verdaccio-entra.
 *
 * DX helpers that run ONLY post-verification for log enrichment.
 * Never used in auth decisions.
 *
 * @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
 */

import { decodeJwt, errors as joseErrors } from "jose";
import { AUDIENCE_PREFIX } from "./auth-plugin";
import type { EntraConfig } from "../types/index";

/**
 * Detect if clientId and tenantId are swapped by inspecting token claims.
 * Returns a human-readable hint string, or undefined if no swap detected.
 */
export function detectSwappedIds(token: string, config: EntraConfig): string | undefined {
	try {
		const claims = decodeJwt(token);
		const tid = typeof claims["tid"] === "string" ? claims["tid"] : undefined;
		const { clientId, tenantId } = config;

		if (tid && tid.toLowerCase() === clientId.toLowerCase()) {
			return `It looks like clientId and tenantId may be swapped — the token's tid claim (${tid}) matches your configured clientId. ` +
				"Check ENTRA_CLIENT_ID and ENTRA_TENANT_ID.";
		}
		if (claims.aud && typeof claims.aud === "string" && claims.aud.toLowerCase().includes(tenantId.toLowerCase())) {
			return `It looks like clientId and tenantId may be swapped — the token's audience (${claims.aud}) contains your configured tenantId. ` +
				"Check ENTRA_CLIENT_ID and ENTRA_TENANT_ID.";
		}
	} catch {
		// diagnostic: error recorded — token may not be decodable, that's fine
	}
	return undefined;
}

/**
 * Enrich a jose error with a diagnostic hint.
 * Called AFTER jwtVerify fails — uses jose's typed error codes, not string matching.
 *
 * @see https://github.com/panva/jose/blob/main/docs/util/errors
 */
export function enrichJoseError(err: unknown, token: string, config: EntraConfig): string {
	const hint = detectSwappedIds(token, config);

	if (err instanceof joseErrors.JWTExpired) {
		return "Entra ID token has expired. Obtain a fresh access token via MSAL and run npm login again.";
	}
	if (err instanceof joseErrors.JWTClaimValidationFailed) {
		if (err.claim === "aud") {
			return `Token audience mismatch — expected ${AUDIENCE_PREFIX}${config.clientId}. ` +
				(hint ?? "Ensure the MSAL scope matches the Verdaccio app registration.");
		}
		if (err.claim === "iss") {
			return `Token issuer mismatch — expected tenant ${config.tenantId}. ` +
				(hint ?? "Ensure the token was issued by the correct Entra tenant.");
		}
		if (err.claim === "nbf") {
			return "Entra ID token is not yet valid (nbf claim is in the future). Check server clock sync.";
		}
		return `Token claim validation failed: ${err.claim} — ${err.message}`;
	}
	if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
		return "JWT signature verification failed — the token may have been tampered with or signed by an unexpected key.";
	}

	const msg = err instanceof Error ? err.message : String(err);
	return `Entra token validation failed: ${msg}`;
}
