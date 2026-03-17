/**
 * Config validation logic — no console.log or process.exit; performs network I/O via fetch.
 *
 * Used by:
 *   - src/cli.ts (CLI wrapper)
 *   - src/__tests__/check-config.test.ts (unit tests, no subprocess needed)
 */

import { GUID_RE, AUDIENCE_PREFIX, jwksUri, DEFAULT_AUTHORITY } from "./auth-plugin";

/**
 * Fetch the hardcoded JWKS URI to verify reachability.
 * Proxy support via NODE_USE_ENV_PROXY=1 (Node 20.13+/21.7+).
 */
export async function verifyJwksEndpoint(authority: string, tenantId: string): Promise<boolean> {
	const url = jwksUri(tenantId, authority);
	const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
	if (!res.ok) {
		throw new Error(
			`JWKS endpoint unreachable: HTTP ${res.status} from ${url}. ` +
				"Verify your tenantId and authority are correct.",
		);
	}
	const data = (await res.json()) as unknown;
	if (!data || typeof data !== "object") {
		throw new Error(
			`JWKS endpoint returned invalid data: expected an object with a non-empty 'keys' array from ${url}.`,
		);
	}
	const keys = (data as Record<string, unknown>).keys;
	if (!Array.isArray(keys) || keys.length === 0 || keys.some((k) => !k || typeof k !== "object")) {
		throw new Error(
			`JWKS endpoint returned invalid data: expected an object with a non-empty 'keys' array of key objects from ${url}.`,
		);
	}
	return true;
}

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

	// --- 3. JWKS endpoint validation (matching production behavior) ---
	if (GUID_RE.test(tenantId)) {
		try {
			await verifyJwksEndpoint(authority, tenantId);
			check("JWKS endpoint is reachable and returns keys", true, "");
		} catch (err) {
			// diagnostic: error recorded in results — caller decides exit code
			check(
				"JWKS endpoint is reachable and returns keys",
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
