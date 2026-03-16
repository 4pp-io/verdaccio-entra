import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execSync } from "node:child_process";
import path from "node:path";
import { TEST_TENANT, TEST_CLIENT, MICROSOFT_TENANT } from "./fixtures";

const scriptPath = path.resolve(__dirname, "../../scripts/check-config.ts").replace(/\\/g, "/");

function run(args: string[] = [], env: Record<string, string> = {}): { stdout: string; exitCode: number } {
	const cmd = `tsx "${scriptPath}" ${args.join(" ")}`;
	try {
		const stdout = execSync(cmd, {
			env: { ...process.env, ...env },
			timeout: 30_000,
			shell: "bash",
		}).toString("utf-8");
		return { stdout: String(stdout), exitCode: 0 };
	} catch (err) {
		const e = err as { stdout?: Buffer | string; stderr?: Buffer | string; status?: number };
		return { stdout: String(e.stdout ?? "") + String(e.stderr ?? ""), exitCode: e.status ?? 1 };
	}
}

describe("check-config script", () => {
	const savedClientId = process.env["ENTRA_CLIENT_ID"];
	const savedTenantId = process.env["ENTRA_TENANT_ID"];

	beforeEach(() => {
		delete process.env["ENTRA_CLIENT_ID"];
		delete process.env["ENTRA_TENANT_ID"];
	});

	afterEach(() => {
		if (savedClientId) process.env["ENTRA_CLIENT_ID"] = savedClientId;
		if (savedTenantId) process.env["ENTRA_TENANT_ID"] = savedTenantId;
	});

	it("--help exits 0 and shows usage", () => {
		const { stdout, exitCode } = run(["--help"]);
		expect(exitCode).toBe(0);
		expect(stdout).toContain("--client-id");
		expect(stdout).toContain("--tenant-id");
		expect(stdout).toContain("ENTRA_CLIENT_ID");
	});

	it("fails when no IDs provided", () => {
		const { stdout, exitCode } = run([], { ENTRA_CLIENT_ID: "", ENTRA_TENANT_ID: "" });
		expect(exitCode).toBe(1);
		expect(stdout).toContain("[FAIL] Client ID is set");
		expect(stdout).toContain("[FAIL] Tenant ID is set");
	});

	it("fails on non-GUID client ID", () => {
		const { stdout, exitCode } = run(["--client-id", "not-a-guid", "--tenant-id", TEST_TENANT]);
		expect(exitCode).toBe(1);
		expect(stdout).toContain("[FAIL] Client ID is a valid GUID");
		expect(stdout).toContain("not-a-guid");
	});

	it("fails on non-GUID tenant ID", () => {
		const { stdout, exitCode } = run(["--client-id", TEST_CLIENT, "--tenant-id", "bad"]);
		expect(exitCode).toBe(1);
		expect(stdout).toContain("[FAIL] Tenant ID is a valid GUID");
	});

	it("detects identical client and tenant IDs", () => {
		const { stdout, exitCode } = run(["--client-id", TEST_TENANT, "--tenant-id", TEST_TENANT]);
		expect(exitCode).toBe(1);
		expect(stdout).toContain("[FAIL] Client ID and Tenant ID are different");
		expect(stdout).toContain("pasted the same GUID twice");
	});

	it("reads from env vars as fallback", () => {
		const { stdout, exitCode } = run([], {
			ENTRA_CLIENT_ID: "not-guid",
			ENTRA_TENANT_ID: "also-not-guid",
		});
		expect(exitCode).toBe(1);
		expect(stdout).toContain("ENTRA_CLIENT_ID env");
		expect(stdout).toContain("ENTRA_TENANT_ID env");
	});

	it("flags override env vars", () => {
		const { stdout } = run(
			["--client-id", "not-a-guid"],
			{ ENTRA_CLIENT_ID: TEST_CLIENT },
		);
		expect(stdout).toContain("--client-id flag");
		expect(stdout).toContain("not-a-guid");
	});

	it("--quiet suppresses passing checks", () => {
		const { stdout, exitCode } = run(["--quiet", "--client-id", TEST_TENANT, "--tenant-id", TEST_TENANT]);
		expect(exitCode).toBe(1);
		expect(stdout).not.toContain("[PASS]");
		expect(stdout).toContain("[FAIL]");
	});

	// --- Network tests: require ENTRA_TEST_TENANT_ID env var ---

	it("validates JWKS endpoint with Microsoft's public tenant", () => {
		const { stdout, exitCode } = run([
			"--client-id", TEST_CLIENT,
			"--tenant-id", MICROSOFT_TENANT,
		]);
		expect(exitCode).toBe(0);
		expect(stdout).toContain("[PASS] JWKS endpoint is reachable");
		expect(stdout).toContain("[PASS] JWKS endpoint returns signing keys");
		expect(stdout).toContain("[PASS] Issuer matches tenant ID");
		expect(stdout).toContain("All checks passed");
	});

	it("detects invalid tenant via JWKS endpoint failure", () => {
		const { stdout, exitCode } = run([
			"--client-id", TEST_CLIENT,
			"--tenant-id", "99999999-9999-9999-9999-999999999999",
		]);
		expect(exitCode).toBe(1);
		expect(stdout).toContain("[FAIL] JWKS endpoint is reachable");
		expect(stdout).toContain("tenant ID is wrong");
	});
});
