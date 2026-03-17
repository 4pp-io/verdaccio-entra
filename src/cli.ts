#!/usr/bin/env node
/**
 * verdaccio-entra config checker (CLI)
 *
 * Thin CLI around src/check-config.ts — all logic is in the importable module.
 *
 * Usage:
 *   npx verdaccio-entra-check --client-id=<guid> --tenant-id=<guid>
 *   npx verdaccio-entra-check -c <guid> -t <guid>
 *   ENTRA_CLIENT_ID=<guid> ENTRA_TENANT_ID=<guid> npx verdaccio-entra-check
 *   npx verdaccio-entra-check --help
 */

import { parseArgs } from "node:util";
import { GUID_RE } from "./auth-plugin";
import { runChecks, expectedAudience, countFailures } from "./check-config";

const { values: flags } = parseArgs({
  options: {
    "client-id": { type: "string", short: "c" },
    "tenant-id": { type: "string", short: "t" },
    help: { type: "boolean", short: "h" },
    quiet: { type: "boolean", short: "q" },
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
  npx verdaccio-entra-check -c 00000000-... -t 11111111-...
  ENTRA_CLIENT_ID=... ENTRA_TENANT_ID=... npx verdaccio-entra-check
`);
  process.exit(0);
}

const quiet = flags.quiet ?? false;
const clientId = flags["client-id"] ?? process.env["ENTRA_CLIENT_ID"] ?? "";
const tenantId = flags["tenant-id"] ?? process.env["ENTRA_TENANT_ID"] ?? "";

if (!quiet) {
  console.log(
    `Client ID source: ${flags["client-id"] ? "--client-id flag" : "ENTRA_CLIENT_ID env"}`,
  );
  console.log(
    `Tenant ID source: ${flags["tenant-id"] ? "--tenant-id flag" : "ENTRA_TENANT_ID env"}`,
  );
}

if (!quiet && GUID_RE.test(clientId)) {
  const aud = expectedAudience(clientId);
  console.log(`\nExpected token audience: ${aud}`);
  console.log("Ensure your Entra app registration has this Application ID URI set under");
  console.log("  Entra admin center > App registrations > [your app] > Expose an API\n");
  console.log("MSAL scope for client apps:");
  console.log(`  ${aud}/.default\n`);
}

runChecks({ clientId, tenantId })
  .then((results) => {
    console.log("\nverdaccio-entra config check\n" + "=".repeat(40));
    for (const r of results) {
      if (quiet && r.ok) continue;
      console.log(`  [${r.ok ? "PASS" : "FAIL"}] ${r.label}`);
      if (!r.ok) console.log(`         ${r.detail}`);
    }
    console.log("\n" + "=".repeat(40));
    const failures = countFailures(results);
    if (failures > 0) {
      console.log(`${failures} check(s) failed.\n`);
      process.exit(1);
    } else {
      console.log("All checks passed.\n");
    }
  })
  .catch((err: unknown) => {
    console.error("Unexpected error:", err);
    process.exit(1);
  });
