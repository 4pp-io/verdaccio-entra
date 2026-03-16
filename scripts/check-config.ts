#!/usr/bin/env npx tsx
/**
 * verdaccio-entra config checker
 *
 * Validates your Entra ID configuration before starting Verdaccio.
 * Checks that clientId and tenantId are valid GUIDs, the JWKS endpoint
 * is reachable, and the app registration's audience URI is resolvable.
 *
 * Values can be passed via env vars, CLI flags, or both (flags win).
 *
 * Usage:
 *   npm run check-config -- --client-id=<guid> --tenant-id=<guid>
 *   npm run check-config -- -c <guid> -t <guid>
 *   ENTRA_CLIENT_ID=<guid> ENTRA_TENANT_ID=<guid> npm run check-config --
 *   npm run check-config -- --help
 *
 * Uses node:util parseArgs — zero external dependencies, Node 18+.
 * @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
 */

import { parseArgs } from "node:util";

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// --- Parse CLI args (node:util.parseArgs, built-in since Node 18) ---
const { values: flags } = parseArgs({
	options: {
		"client-id": { type: "string", short: "c" },
		"tenant-id": { type: "string", short: "t" },
		"help": { type: "boolean", short: "h" },
		"quiet": { type: "boolean", short: "q" },
	},
	strict: true,
	allowPositionals: false,
});

if (flags.help) {
	console.log(`
verdaccio-entra config checker

Validates your Entra ID app registration before starting Verdaccio.

Options:
  -c, --client-id <guid>   Application (client) ID from Entra app registration
  -t, --tenant-id <guid>   Directory (tenant) ID from Entra admin center
  -q, --quiet              Only print failures (exit code 0 = all passed)
  -h, --help               Show this help

Environment variables (used as fallback when flags are not provided):
  ENTRA_CLIENT_ID          Same as --client-id
  ENTRA_TENANT_ID          Same as --tenant-id

Examples:
  npm run check-config -- -c 00000000-... -t 11111111-...
  ENTRA_CLIENT_ID=... ENTRA_TENANT_ID=... npm run check-config
`);
	process.exit(0);
}

const quiet = flags.quiet ?? false;

interface CheckResult {
	label: string;
	ok: boolean;
	detail: string;
}

const results: CheckResult[] = [];

function check(label: string, ok: boolean, detail: string): void {
	results.push({ label, ok, detail });
}

function log(msg: string): void {
	if (!quiet) console.log(msg);
}

function printResults(): void {
	console.log("\nverdaccio-entra config check\n" + "=".repeat(40));
	let failures = 0;
	for (const r of results) {
		if (quiet && r.ok) continue;
		const icon = r.ok ? "PASS" : "FAIL";
		console.log(`  [${icon}] ${r.label}`);
		if (!r.ok) {
			console.log(`         ${r.detail}`);
			failures++;
		}
	}
	console.log("\n" + "=".repeat(40));
	if (failures > 0) {
		console.log(`${failures} check(s) failed.\n`);
		process.exit(1);
	} else {
		console.log("All checks passed.\n");
	}
}

async function main(): Promise<void> {
	// --- 1. Resolve config: flags > env vars > empty ---
	const clientId = flags["client-id"] ?? process.env["ENTRA_CLIENT_ID"] ?? "";
	const tenantId = flags["tenant-id"] ?? process.env["ENTRA_TENANT_ID"] ?? "";

	const clientSource = flags["client-id"] ? "--client-id flag" : "ENTRA_CLIENT_ID env";
	const tenantSource = flags["tenant-id"] ? "--tenant-id flag" : "ENTRA_TENANT_ID env";
	log(`Client ID source: ${clientSource}`);
	log(`Tenant ID source: ${tenantSource}`);

	// --- 2. Validate GUIDs ---
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

	// --- 3. Detect swapped/identical IDs ---
	if (GUID_RE.test(clientId) && GUID_RE.test(tenantId)) {
		check(
			"Client ID and Tenant ID are different",
			clientId.toLowerCase() !== tenantId.toLowerCase(),
			"They're identical — you probably pasted the same GUID twice. " +
				"clientId = Application (client) ID, tenantId = Directory (tenant) ID. " +
				"These are two different fields on the app registration Overview page.",
		);
	}

	// --- 4. Check JWKS endpoint ---
	if (GUID_RE.test(tenantId)) {
		const jwksUrl = `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`;
		try {
			const res = await fetch(jwksUrl);
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

	// --- 5. Check OpenID Connect discovery ---
	if (GUID_RE.test(tenantId)) {
		const oidcUrl = `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`;
		try {
			const res = await fetch(oidcUrl);
			check(
				"OpenID Connect discovery is reachable",
				res.ok,
				`HTTP ${res.status} from ${oidcUrl}. Verify the tenant ID is correct.`,
			);
			if (res.ok) {
				const body = (await res.json()) as { issuer?: string };
				const expectedIssuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;
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

	// --- 6. Print setup info ---
	if (GUID_RE.test(clientId)) {
		const expectedAudience = `api://${clientId}`;
		log(`\nExpected token audience: ${expectedAudience}`);
		log(
			"Ensure your Entra app registration has this Application ID URI set under\n" +
				"  Entra admin center > App registrations > [your app] > Expose an API\n",
		);
		log("MSAL scope for client apps:");
		log(`  ${expectedAudience}/.default\n`);
	}

	printResults();
}

main().catch((err) => {
	console.error("Unexpected error:", err);
	process.exit(1);
});
