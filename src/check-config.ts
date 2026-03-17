/**
 * Config validation logic — pure functions, no side effects.
 *
 * Uses the same discoverOidc function as the plugin — no duplicated
 * network logic. Changes to how the plugin resolves authorities are
 * automatically reflected here.
 *
 * Used by:
 *   - scripts/check-config.ts (CLI wrapper)
 *   - src/__tests__/check-config.test.ts (unit tests, no subprocess needed)
 */

import { GUID_RE, AUDIENCE_PREFIX, ISSUERS, DEFAULT_AUTHORITY, discoverOidc } from "./auth-plugin";
import type { OidcDiscovery } from "./auth-plugin";

export interface CheckResult {
	label: string;
	ok: boolean;
	detail: string;
}

export interface CheckConfigInput {
	clientId: string;
	tenantId: string;
	/** Entra authority URL — defaults to Azure Public cloud */
	authority?: string;
}

/**
 * Run all config validation checks and return results.
 * Pure async function — no console.log, no process.exit.
 */
export async function runChecks(input: CheckConfigInput): Promise<CheckResult[]> {
	const results: CheckResult[] = [];
	const { clientId, tenantId, authority = DEFAULT_AUTHORITY } = input;

	const check = (label: string, ok: boolean, detail: string): void => {
		results.push({ label, ok, detail });
	};

	// --- 1. Validate GUIDs ---
	check(
		"Client ID is set",
		clientId.length > 0,
		"Provide via --client-id flag or ENTRA_CLIENT_ID env var. " +
			"Find it at: Entra admin center > App registrations > [your app] > Overview > Application (client) ID.",
	);

	check(
		"Tenant ID is set",
		tenantId.length > 0,
		"Provide via --tenant-id flag or ENTRA_TENANT_ID env var. " +
			"Find it at: Entra admin center > App registrations > [your app] > Overview > Directory (tenant) ID.",
	);

	check(
		"Client ID is a valid GUID",
		GUID_RE.test(clientId),
		`Got "${clientId}". ` +
			"The Application (client) ID is a GUID like aaaabbbb-0000-cccc-1111-dddd2222eeee.",
	);

	check(
		"Tenant ID is a valid GUID",
		GUID_RE.test(tenantId),
		`Got "${tenantId}". ` +
			"The Directory (tenant) ID is a GUID like aaaabbbb-0000-cccc-1111-dddd2222eeee.",
	);

	// --- 2. Detect swapped/identical IDs ---
	if (GUID_RE.test(clientId) && GUID_RE.test(tenantId)) {
		check(
			"Client ID and Tenant ID are different",
			clientId.toLowerCase() !== tenantId.toLowerCase(),
			"They're identical — you probably pasted the same GUID twice. " +
				"clientId = Application (client) ID, tenantId = Directory (tenant) ID. " +
				"These are two different fields on the app registration Overview page.",
		);
	}

	// --- 3. OIDC discovery (uses the same function as the plugin) ---
	if (GUID_RE.test(tenantId)) {
		let discovery: OidcDiscovery | undefined;
		try {
			discovery = await discoverOidc(authority, tenantId);
			check("OIDC discovery is reachable", true, "");

			const expectedIssuer = ISSUERS.v2(tenantId, authority);
			check(
				"Issuer matches tenant ID",
				discovery.issuer === expectedIssuer,
				`Expected issuer "${expectedIssuer}", got "${discovery.issuer ?? "(missing)"}". ` +
					"This may indicate the tenant ID is wrong or you're hitting the wrong authority.",
			);

			check(
				"JWKS URI discovered",
				discovery.jwks_uri.length > 0,
				"OIDC discovery returned an empty jwks_uri.",
			);
		} catch (err) {
			// diagnostic: error recorded in results — caller decides exit code
			check(
				"OIDC discovery is reachable",
				false,
				`${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}

	return results;
}

/** Compute the expected audience URI for display */
export function expectedAudience(clientId: string): string {
	return `${AUDIENCE_PREFIX}${clientId}`;
}

/** Count failures in results */
export function countFailures(results: CheckResult[]): number {
	return results.filter((r) => !r.ok).length;
}
