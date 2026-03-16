/**
 * Config validation logic — pure functions, no side effects.
 *
 * Used by:
 *   - scripts/check-config.ts (CLI wrapper)
 *   - src/__tests__/check-config.test.ts (unit tests, no subprocess needed)
 */

import { GUID_RE, AUDIENCE_PREFIX, ISSUERS } from "./auth-plugin";

export interface CheckResult {
	label: string;
	ok: boolean;
	detail: string;
}

export interface CheckConfigInput {
	clientId: string;
	tenantId: string;
	/** Override fetch for testing */
	fetcher?: typeof fetch;
}

/**
 * Run all config validation checks and return results.
 * Pure async function — no console.log, no process.exit.
 */
export async function runChecks(input: CheckConfigInput): Promise<CheckResult[]> {
	const results: CheckResult[] = [];
	const { clientId, tenantId, fetcher = fetch } = input;

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

	// --- 3. Check JWKS endpoint ---
	if (GUID_RE.test(tenantId)) {
		const jwksUrl = `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`;
		try {
			const res = await fetcher(jwksUrl);
			check(
				"JWKS endpoint is reachable",
				res.ok,
				`HTTP ${res.status} from ${jwksUrl}. This usually means the tenant ID is wrong.`,
			);
			if (res.ok) {
				const body = (await res.json()) as { keys?: unknown[] };
				check(
					"JWKS endpoint returns signing keys",
					Array.isArray(body.keys) && body.keys.length > 0,
					`No keys found at ${jwksUrl}. The tenant may not have any app registrations.`,
				);
			}
		} catch (err) {
			check(
				"JWKS endpoint is reachable",
				false,
				`Network error fetching ${jwksUrl}: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}

	// --- 4. Check OpenID Connect discovery ---
	if (GUID_RE.test(tenantId)) {
		const oidcUrl = `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`;
		try {
			const res = await fetcher(oidcUrl);
			check(
				"OpenID Connect discovery is reachable",
				res.ok,
				`HTTP ${res.status} from ${oidcUrl}. Verify the tenant ID is correct.`,
			);
			if (res.ok) {
				const body = (await res.json()) as { issuer?: string };
				const expectedIssuer = ISSUERS.v2(tenantId);
				check(
					"Issuer matches tenant ID",
					body.issuer === expectedIssuer,
					`Expected issuer "${expectedIssuer}", got "${body.issuer ?? "(missing)"}". ` +
						"This may indicate the tenant ID is wrong or you're hitting the wrong authority.",
				);
			}
		} catch (err) {
			check(
				"OpenID Connect discovery is reachable",
				false,
				`Network error: ${err instanceof Error ? err.message : String(err)}`,
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
