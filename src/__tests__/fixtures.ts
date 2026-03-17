/**
 * Shared test constants and realistic Entra v2.0 token fixtures.
 *
 * Claims mirror the actual Microsoft Entra ID v2.0 access token schema.
 * @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
 * @see https://learn.microsoft.com/entra/identity-platform/optional-claims-reference
 *
 * Uses Microsoft Learn documentation placeholder GUIDs.
 * @see https://learn.microsoft.com/entra/identity-platform/reference-app-manifest
 */

import { AUDIENCE_PREFIX, ISSUERS } from "../auth-plugin";

// ---------------------------------------------------------------------------
// Identity constants
// ---------------------------------------------------------------------------

/** Microsoft Learn placeholder tenant ID */
export const TEST_TENANT = "aaaabbbb-0000-cccc-1111-dddd2222eeee";

/** Microsoft Learn placeholder client (application) ID */
export const TEST_CLIENT = "00001111-aaaa-2222-bbbb-3333cccc4444";

/** Microsoft's own public tenant — always has a valid JWKS endpoint */
export const MICROSOFT_TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47";

/** JWKS key ID used in test RSA key pair */
export const TEST_KID = "test-kid-001";

/** Immutable object ID for the test user (oid claim) */
export const TEST_USER_OID = "00000000-0000-0000-0000-000000000001";

/** Pairwise subject identifier for the test user (sub claim) */
export const TEST_USER_SUB = "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ";

/** Client app ID of the requesting application (azp claim) */
export const TEST_AZP = "22223333-bbbb-4444-cccc-5555dddd6666";

// ---------------------------------------------------------------------------
// Realistic Entra v2.0 access token claims factory
// ---------------------------------------------------------------------------

/**
 * Build a realistic Entra v2.0 access token payload.
 *
 * Includes all standard claims that Entra emits for a v2.0 access token
 * (per Microsoft Learn docs), so tests exercise the plugin against a
 * representative token shape rather than a minimal stub.
 *
 * Claims set by jose's SignJWT helpers (iat, exp, nbf) are omitted here
 * since they're added by the signToken() helper in each test file.
 *
 * @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference#payload-claims
 */
export function entraV2Claims(overrides?: Record<string, unknown>): Record<string, unknown> {
	return {
		// --- Required v2.0 claims ---
		aud: `${AUDIENCE_PREFIX}${TEST_CLIENT}`,
		iss: ISSUERS.v2(TEST_TENANT),
		tid: TEST_TENANT,
		oid: TEST_USER_OID,
		sub: TEST_USER_SUB,
		ver: "2.0",

		// --- Client application identity (v2.0) ---
		azp: TEST_AZP,
		azpacr: "0", // public client

		// --- User identity claims ---
		preferred_username: "user@contoso.com",
		name: "Test User",

		// --- Authorization claims ---
		scp: "access_as_user",
		groups: ["developers"],
		roles: ["registry-admin"],

		// --- Session / internal (opaque — plugin should ignore) ---
		uti: "AbCdEf123456",
		aio: "ASQy/4TAAAAA",
		rh: "0.AAAA",

		...overrides,
	};
}
