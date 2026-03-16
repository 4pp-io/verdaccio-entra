import { describe, it, expect, vi } from "vitest";
import { TEST_TENANT, TEST_CLIENT } from "./fixtures";
import { ISSUERS } from "../auth-plugin";
import { runChecks, countFailures, expectedAudience } from "../check-config";
import type { CheckConfigInput } from "../check-config";

/** Mock fetcher that simulates successful OIDC/JWKS responses */
function mockFetcher(issuer: string): typeof fetch {
	return vi.fn().mockImplementation((url: string) => {
		if (url.includes("openid-configuration")) {
			return Promise.resolve({
				ok: true,
				json: () => Promise.resolve({ issuer }),
			});
		}
		if (url.includes("discovery/v2.0/keys")) {
			return Promise.resolve({
				ok: true,
				json: () => Promise.resolve({ keys: [{ kid: "test" }] }),
			});
		}
		return Promise.resolve({ ok: false, status: 404 });
	}) as unknown as typeof fetch;
}

/** Mock fetcher that simulates network failures */
function failingFetcher(): typeof fetch {
	return vi.fn().mockImplementation(() => {
		return Promise.resolve({ ok: false, status: 400 });
	}) as unknown as typeof fetch;
}

function input(overrides?: Partial<CheckConfigInput>): CheckConfigInput {
	return {
		clientId: TEST_CLIENT,
		tenantId: TEST_TENANT,
		fetcher: mockFetcher(ISSUERS.v2(TEST_TENANT)),
		...overrides,
	};
}

describe("runChecks", () => {
	it("passes all checks with valid config", async () => {
		const results = await runChecks(input());
		const failures = countFailures(results);
		expect(failures).toBe(0);
		expect(results.some((r) => r.label === "Client ID is set" && r.ok)).toBe(true);
		expect(results.some((r) => r.label === "Tenant ID is set" && r.ok)).toBe(true);
		expect(results.some((r) => r.label === "Client ID is a valid GUID" && r.ok)).toBe(true);
		expect(results.some((r) => r.label === "Tenant ID is a valid GUID" && r.ok)).toBe(true);
		expect(results.some((r) => r.label === "JWKS endpoint is reachable" && r.ok)).toBe(true);
		expect(results.some((r) => r.label === "Issuer matches tenant ID" && r.ok)).toBe(true);
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

	it("detects JWKS endpoint failure", async () => {
		const results = await runChecks(input({ fetcher: failingFetcher() }));
		const fail = results.find((r) => r.label === "JWKS endpoint is reachable");
		expect(fail?.ok).toBe(false);
		expect(fail?.detail).toContain("tenant ID is wrong");
	});

	it("detects OIDC discovery failure", async () => {
		const results = await runChecks(input({ fetcher: failingFetcher() }));
		const fail = results.find((r) => r.label === "OpenID Connect discovery is reachable");
		expect(fail?.ok).toBe(false);
	});

	it("detects issuer mismatch", async () => {
		const results = await runChecks(input({
			fetcher: mockFetcher("https://wrong-issuer.example.com/v2.0"),
		}));
		const fail = results.find((r) => r.label === "Issuer matches tenant ID");
		expect(fail?.ok).toBe(false);
		expect(fail?.detail).toContain("wrong-issuer");
	});

	it("handles JWKS network error gracefully", async () => {
		const results = await runChecks(input({
			fetcher: vi.fn().mockRejectedValue(new Error("ENOTFOUND")) as unknown as typeof fetch,
		}));
		const jwksFail = results.find((r) => r.label === "JWKS endpoint is reachable");
		expect(jwksFail?.ok).toBe(false);
		expect(jwksFail?.detail).toContain("ENOTFOUND");
		const oidcFail = results.find((r) => r.label === "OpenID Connect discovery is reachable");
		expect(oidcFail?.ok).toBe(false);
		expect(oidcFail?.detail).toContain("ENOTFOUND");
	});

	it("handles missing issuer in OIDC response", async () => {
		const results = await runChecks(input({
			fetcher: vi.fn().mockImplementation(() =>
				Promise.resolve({ ok: true, json: () => Promise.resolve({ keys: [{ kid: "x" }] }) }),
			) as unknown as typeof fetch,
		}));
		const fail = results.find((r) => r.label === "Issuer matches tenant ID");
		expect(fail?.ok).toBe(false);
		expect(fail?.detail).toContain("(missing)");
	});

	it("skips network checks when tenant is not a valid GUID", async () => {
		const results = await runChecks(input({ tenantId: "not-guid" }));
		expect(results.find((r) => r.label === "JWKS endpoint is reachable")).toBeUndefined();
		expect(results.find((r) => r.label === "OpenID Connect discovery is reachable")).toBeUndefined();
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
