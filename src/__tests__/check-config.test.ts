import { describe, it, expect, vi, beforeEach } from "vitest";
import { TEST_TENANT, TEST_CLIENT } from "./fixtures";
import { ISSUERS } from "../auth-plugin";
import { runChecks, countFailures, expectedAudience } from "../check-config";
import type { CheckConfigInput } from "../check-config";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function setDiscoverySuccess(issuer?: string): void {
	mockFetch.mockResolvedValue({
		ok: true,
		json: () => Promise.resolve({
			issuer: issuer ?? ISSUERS.v2(TEST_TENANT),
			jwks_uri: `https://login.microsoftonline.com/${TEST_TENANT}/discovery/v2.0/keys`,
		}),
	});
}

function setDiscoveryFailure(): void {
	mockFetch.mockResolvedValue({ ok: false, status: 400 });
}

function input(overrides?: Partial<CheckConfigInput>): CheckConfigInput {
	return {
		clientId: TEST_CLIENT,
		tenantId: TEST_TENANT,
		...overrides,
	};
}

beforeEach(() => {
	setDiscoverySuccess();
});

describe("runChecks", () => {
	it("passes all checks with valid config", async () => {
		const results = await runChecks(input());
		const failures = countFailures(results);
		expect(failures).toBe(0);
		expect(results.some((r) => r.label === "Client ID is set" && r.ok)).toBe(true);
		expect(results.some((r) => r.label === "OIDC discovery is reachable" && r.ok)).toBe(true);
		expect(results.some((r) => r.label === "Issuer matches tenant ID" && r.ok)).toBe(true);
		expect(results.some((r) => r.label === "JWKS URI discovered" && r.ok)).toBe(true);
	});

	it("fails when client ID is empty", async () => {
		const results = await runChecks(input({ clientId: "" }));
		expect(results.some((r) => r.label === "Client ID is set" && !r.ok)).toBe(true);
	});

	it("fails when tenant ID is empty", async () => {
		const results = await runChecks(input({ tenantId: "" }));
		expect(results.some((r) => r.label === "Tenant ID is set" && !r.ok)).toBe(true);
	});

	it("fails on non-GUID client ID", async () => {
		const results = await runChecks(input({ clientId: "not-a-guid" }));
		const fail = results.find((r) => r.label === "Client ID is a valid GUID");
		expect(fail?.ok).toBe(false);
		expect(fail?.detail).toContain("not-a-guid");
	});

	it("fails on non-GUID tenant ID", async () => {
		const results = await runChecks(input({ tenantId: "bad" }));
		const fail = results.find((r) => r.label === "Tenant ID is a valid GUID");
		expect(fail?.ok).toBe(false);
	});

	it("detects identical client and tenant IDs", async () => {
		const results = await runChecks(input({ clientId: TEST_TENANT, tenantId: TEST_TENANT }));
		const fail = results.find((r) => r.label === "Client ID and Tenant ID are different");
		expect(fail?.ok).toBe(false);
		expect(fail?.detail).toContain("pasted the same GUID twice");
	});

	it("skips identity check when IDs are not GUIDs", async () => {
		const results = await runChecks(input({ clientId: "bad", tenantId: "bad" }));
		expect(results.find((r) => r.label === "Client ID and Tenant ID are different")).toBeUndefined();
	});

	it("detects OIDC discovery failure", async () => {
		setDiscoveryFailure();
		const results = await runChecks(input());
		const fail = results.find((r) => r.label === "OIDC discovery is reachable");
		expect(fail?.ok).toBe(false);
	});

	it("detects issuer mismatch", async () => {
		setDiscoverySuccess("https://wrong-issuer.example.com/v2.0");
		const results = await runChecks(input());
		const fail = results.find((r) => r.label === "Issuer matches tenant ID");
		expect(fail?.ok).toBe(false);
		expect(fail?.detail).toContain("wrong-issuer");
	});

	it("handles network error gracefully", async () => {
		mockFetch.mockRejectedValue(new Error("ENOTFOUND"));
		const results = await runChecks(input());
		const fail = results.find((r) => r.label === "OIDC discovery is reachable");
		expect(fail?.ok).toBe(false);
		expect(fail?.detail).toContain("ENOTFOUND");
	});

	it("skips network checks when tenant is not a valid GUID", async () => {
		const results = await runChecks(input({ tenantId: "not-guid" }));
		expect(results.find((r) => r.label === "OIDC discovery is reachable")).toBeUndefined();
	});
});

describe("helpers", () => {
	it("expectedAudience returns api:// prefixed client ID", () => {
		expect(expectedAudience(TEST_CLIENT)).toBe(`api://${TEST_CLIENT}`);
	});

	it("countFailures counts only failed results", () => {
		expect(countFailures([
			{ label: "a", ok: true, detail: "" },
			{ label: "b", ok: false, detail: "fail" },
			{ label: "c", ok: false, detail: "fail" },
		])).toBe(2);
	});
});
