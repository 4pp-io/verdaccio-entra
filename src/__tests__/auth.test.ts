import { describe, it, expect, vi, beforeAll, beforeEach } from "vitest";
import type { MockInstance } from "vitest";

import { SignJWT, exportJWK, generateKeyPair } from "jose";

import { TEST_TENANT, TEST_CLIENT, TEST_KID, entraV2Claims } from "./fixtures";
import { DEFAULT_MAX_TOKEN_BYTES, AUDIENCE_PREFIX, resolveConfig, warnIfProxyMisconfigured } from "../auth-plugin";

let privateKey: CryptoKey;
let publicJwk: Record<string, unknown>;

beforeAll(async () => {
	const pair = await generateKeyPair("RS256");
	privateKey = pair.privateKey;
	publicJwk = { ...(await exportJWK(pair.publicKey)), kid: TEST_KID, use: "sig", alg: "RS256" };
});

// --- Mock fetch: serves JWKS endpoint for jose's createRemoteJWKSet ---
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function setFetchSuccess(): void {
	mockFetch.mockImplementation((input: string | URL | Request) => {
		const url = String(input);
		if (url.includes("discovery/v2.0/keys")) {
			return Promise.resolve({
				ok: true,
				status: 200,
				json: () => Promise.resolve({ keys: [publicJwk] }),
				headers: new Headers({ "content-type": "application/json" }),
			});
		}
		return Promise.resolve({ ok: false, status: 404 });
	});
}

setFetchSuccess();

async function signToken(
	claims: Record<string, unknown>,
	options?: { expiresIn?: string; kid?: string; alg?: string },
): Promise<string> {
	const builder = new SignJWT(claims)
		.setProtectedHeader({ alg: options?.alg ?? "RS256", kid: options?.kid ?? TEST_KID })
		.setIssuedAt();
	if (options?.expiresIn !== "none") {
		builder.setExpirationTime(options?.expiresIn ?? "1h");
	}
	return builder.sign(privateKey);
}

import EntraPlugin from "../auth-plugin";

function createPlugin(configOverrides?: Record<string, unknown>): EntraPlugin {
	return new EntraPlugin(
		{ clientId: TEST_CLIENT, tenantId: TEST_TENANT, ...configOverrides } as never,
		{
			logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), trace: vi.fn(), child: vi.fn(), http: vi.fn() },
			config: {},
		} as never,
	);
}

function authenticateAsync(plugin: EntraPlugin, user: string, password: string): Promise<string[] | false> {
	return new Promise((resolve, reject) => {
		plugin.authenticate(user, password, (err, groups) => {
			if (err) reject(err);
			else resolve(groups as string[] | false);
		});
	});
}

// ---- Tests ----

describe("EntraPlugin constructor", () => {
	it("creates successfully with valid GUIDs", () => {
		expect(() => createPlugin()).not.toThrow();
	});

	it("throws on invalid clientId (default: plugin skipped)", () => {
		expect(() => createPlugin({ clientId: "not-a-guid" })).toThrow(/verdaccio-entra/);
	});

	it("throws on invalid tenantId (default: plugin skipped)", () => {
		expect(() => createPlugin({ tenantId: "not-a-guid" })).toThrow(/verdaccio-entra/);
	});

	it("throws on empty clientId", () => {
		expect(() => createPlugin({ clientId: "" })).toThrow(/verdaccio-entra/);
	});

	it("calls process.exit(1) when failClosed is true", () => {
		const exitSpy: MockInstance = vi.spyOn(process, "exit").mockImplementation((() => {
			throw new Error("process.exit called");
		}) as never);
		try {
			expect(() => createPlugin({ clientId: "not-a-guid", failClosed: true })).toThrow(/process\.exit/);
			expect(exitSpy).toHaveBeenCalledWith(1);
		} finally {
			exitSpy.mockRestore();
		}
	});

	it("env vars override config values", () => {
		process.env.ENTRA_CLIENT_ID = TEST_CLIENT;
		process.env.ENTRA_TENANT_ID = TEST_TENANT;
		try {
			expect(() => createPlugin({ clientId: "placeholder", tenantId: "placeholder" })).not.toThrow();
		} finally {
			delete process.env.ENTRA_CLIENT_ID;
			delete process.env.ENTRA_TENANT_ID;
		}
	});
});

describe("resolveConfig", () => {
	it("returns config values when no env vars are set", () => {
		const result = resolveConfig(
			{ clientId: TEST_CLIENT, tenantId: TEST_TENANT },
			{},
		);
		expect(result.clientId).toBe(TEST_CLIENT);
		expect(result.tenantId).toBe(TEST_TENANT);
		expect(result.authority).toBe("https://login.microsoftonline.com");
		expect(result.audience).toBe(`${AUDIENCE_PREFIX}${TEST_CLIENT}`);
	});

	it("env vars take precedence over config values", () => {
		const result = resolveConfig(
			{ clientId: "00000000-0000-0000-0000-000000000000", tenantId: "00000000-0000-0000-0000-000000000000" },
			{ ENTRA_CLIENT_ID: TEST_CLIENT, ENTRA_TENANT_ID: TEST_TENANT },
		);
		expect(result.clientId).toBe(TEST_CLIENT);
		expect(result.tenantId).toBe(TEST_TENANT);
	});

	it("env audience overrides config and default", () => {
		const result = resolveConfig(
			{ clientId: TEST_CLIENT, tenantId: TEST_TENANT, audience: "api://from-config" },
			{ ENTRA_AUDIENCE: "api://from-env" },
		);
		expect(result.audience).toBe("api://from-env");
	});

	it("env authority overrides config", () => {
		const result = resolveConfig(
			{ clientId: TEST_CLIENT, tenantId: TEST_TENANT, authority: "https://from-config" },
			{ ENTRA_AUTHORITY: "https://login.microsoftonline.us" },
		);
		expect(result.authority).toBe("https://login.microsoftonline.us");
	});

	it("throws on invalid clientId from env", () => {
		expect(() => resolveConfig(
			{ clientId: TEST_CLIENT, tenantId: TEST_TENANT },
			{ ENTRA_CLIENT_ID: "not-a-guid" },
		)).toThrow(/Invalid clientId/);
	});

	it("is testable without mutating process.env", () => {
		// The whole point: env dict is injectable
		const env = { ENTRA_CLIENT_ID: TEST_CLIENT, ENTRA_TENANT_ID: TEST_TENANT };
		const result = resolveConfig({ clientId: "", tenantId: "" }, env);
		expect(result.clientId).toBe(TEST_CLIENT);
	});
});

describe("warnIfProxyMisconfigured", () => {
	it("warns when HTTPS_PROXY is set without NODE_USE_ENV_PROXY", () => {
		const error = vi.fn();
		const logger = { info: vi.fn(), warn: vi.fn(), error, debug: vi.fn(), trace: vi.fn(), child: vi.fn(), http: vi.fn() } as never;
		warnIfProxyMisconfigured(logger, { HTTPS_PROXY: "http://proxy:8080" });
		expect(error).toHaveBeenCalledOnce();
		expect(error.mock.calls[0]?.[1]).toMatch(/NODE_USE_ENV_PROXY/);
	});

	it("does not warn when NODE_USE_ENV_PROXY is set", () => {
		const error = vi.fn();
		const logger = { info: vi.fn(), warn: vi.fn(), error, debug: vi.fn(), trace: vi.fn(), child: vi.fn(), http: vi.fn() } as never;
		warnIfProxyMisconfigured(logger, { HTTPS_PROXY: "http://proxy:8080", NODE_USE_ENV_PROXY: "1" });
		expect(error).not.toHaveBeenCalled();
	});

	it("does not warn when no proxy vars are set", () => {
		const error = vi.fn();
		const logger = { info: vi.fn(), warn: vi.fn(), error, debug: vi.fn(), trace: vi.fn(), child: vi.fn(), http: vi.fn() } as never;
		warnIfProxyMisconfigured(logger, {});
		expect(error).not.toHaveBeenCalled();
	});
});

describe("authenticate", () => {
	let plugin: EntraPlugin;
	beforeEach(() => {
		setFetchSuccess();
		plugin = createPlugin();
	});

	it("succeeds when username matches token identity", async () => {
		const token = await signToken(entraV2Claims());
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).toContain("$authenticated");
		expect(groups).toContain("developers");
		expect(groups).toContain("registry-admin");
	});

	it("succeeds case-insensitively", async () => {
		const token = await signToken(entraV2Claims({ preferred_username: "Alice@Contoso.com" }));
		const groups = await authenticateAsync(plugin, "alice@contoso.com", token);
		expect(groups).toContain("$authenticated");
	});

	it("rejects when npm username does not match token identity (anti-spoofing)", async () => {
		const token = await signToken(entraV2Claims({ preferred_username: "bob@contoso.com" }));
		await expect(authenticateAsync(plugin, "alice@contoso.com", token))
			.rejects.toThrow(/does not match Entra identity/);
	});

	it("returns false when token has no identity claim", async () => {
		const token = await signToken(entraV2Claims({ preferred_username: undefined, upn: undefined, email: undefined }));
		const result = await authenticateAsync(plugin, "anyone", token);
		expect(result).toBe(false);
	});

	it("returns false for expired token", async () => {
		// Needs to be >5 minutes expired due to clockTolerance
		const token = await signToken(entraV2Claims(), { expiresIn: "-6m" });
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("returns false for token that is not yet valid (nbf in the future)", async () => {
		// Needs to be >5 minutes in the future due to clockTolerance
		const nbfInFuture = Math.floor(Date.now() / 1000) + 360; // 6 minutes from now
		const token = await signToken(entraV2Claims({ nbf: nbfInFuture }));
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("returns false for wrong audience", async () => {
		const token = await signToken(entraV2Claims({ aud: "api://wrong" }));
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("returns false for wrong issuer", async () => {
		const token = await signToken(entraV2Claims({ iss: "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0" }));
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("returns false for unknown kid (no matching JWKS key)", async () => {
		const token = await signToken(entraV2Claims(), { kid: "unknown-kid" });
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("returns false for non-JWT string", async () => {
		const result = await authenticateAsync(plugin, "user@contoso.com", "not-a-jwt");
		expect(result).toBe(false);
	});

	it("returns false for oversized token", async () => {
		const result = await authenticateAsync(plugin, "user@contoso.com", "x".repeat(DEFAULT_MAX_TOKEN_BYTES + 1));
		expect(result).toBe(false);
	});

	it("returns false for tampered signature", async () => {
		const token = await signToken(entraV2Claims());
		const parts = token.split(".");
		const result = await authenticateAsync(plugin, "user@contoso.com", [parts[0], parts[1], "badsig"].join("."));
		expect(result).toBe(false);
	});

	it("merges groups and roles claims", async () => {
		const token = await signToken(entraV2Claims({ groups: ["a", "b"], roles: ["x"] }));
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).toEqual(["$authenticated", "a", "b", "x"]);
	});

	it("handles missing groups/roles gracefully", async () => {
		const token = await signToken(entraV2Claims({ groups: undefined, roles: undefined }));
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).toEqual(["$authenticated"]);
	});

	it("rejects on group overage by default (>200 groups)", async () => {
		const token = await signToken(entraV2Claims({
			groups: undefined,
			roles: ["registry-admin"],
			_claim_names: { groups: "src1" },
			_claim_sources: { src1: { endpoint: "https://graph.microsoft.com/v1.0/users/me/transitiveMemberOf" } },
		}));
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("allows group overage when allowGroupOverage is true", async () => {
		const overagePlugin = createPlugin({ allowGroupOverage: true });
		const token = await signToken(entraV2Claims({
			groups: undefined,
			roles: ["registry-admin"],
			_claim_names: { groups: "src1" },
			_claim_sources: { src1: { endpoint: "https://graph.microsoft.com/v1.0/users/me/transitiveMemberOf" } },
		}));
		const groups = await authenticateAsync(overagePlugin, "user@contoso.com", token);
		expect(groups).toEqual(["$authenticated", "registry-admin"]);
	});

	// --- Real-world Entra token variations ---
	// @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference

	it("ignores non-string items in groups array (defensive against malformed tokens)", async () => {
		const token = await signToken(entraV2Claims({ groups: ["valid-group", 123, null, true, "another-group"] }));
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).toEqual(expect.arrayContaining(["$authenticated", "valid-group", "another-group"]));
		expect(groups).toHaveLength(4); // $authenticated + valid-group + another-group + registry-admin
	});

	it("handles wids claim (directory roles) without leaking them into groups", async () => {
		// Entra emits wids (directory role template IDs) alongside groups.
		// The plugin should only extract groups and roles, not wids.
		const token = await signToken(entraV2Claims({
			wids: ["62e90394-69f5-4237-9190-012177145e10"], // Global Administrator template ID
		}));
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).not.toContain("62e90394-69f5-4237-9190-012177145e10");
		expect(groups).toContain("$authenticated");
	});

	it("authenticates with email fallback when preferred_username and upn are absent", async () => {
		// Guest accounts often only have the email claim
		const token = await signToken(entraV2Claims({
			preferred_username: undefined,
			upn: undefined,
			email: "guest@external.com",
			name: "External Guest",
		}));
		const groups = await authenticateAsync(plugin, "guest@external.com", token);
		expect(groups).toContain("$authenticated");
	});

	it("succeeds with groups as GUIDs (real Entra group object IDs)", async () => {
		// Real Entra tokens emit groups as opaque GUIDs, not friendly names
		const token = await signToken(entraV2Claims({
			groups: [
				"b1c2d3e4-f5a6-7890-abcd-ef1234567890",
				"a0b1c2d3-e4f5-6789-0abc-def123456789",
			],
		}));
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).toContain("b1c2d3e4-f5a6-7890-abcd-ef1234567890");
		expect(groups).toContain("a0b1c2d3-e4f5-6789-0abc-def123456789");
	});

	it("rejects hasgroups=true with overage by default (no groups array, just the flag)", async () => {
		const token = await signToken(entraV2Claims({
			groups: undefined,
			hasgroups: true,
		}));
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("handles app-only token (client_credentials flow — no user claims)", async () => {
		// Client credential tokens have azp/azpacr but no preferred_username/upn/email.
		// The plugin should return false (no identity claim to match).
		const token = await signToken(entraV2Claims({
			preferred_username: undefined,
			upn: undefined,
			email: undefined,
			name: undefined,
			sub: TEST_CLIENT, // In client_credentials, sub = app's oid
			scp: undefined,
			roles: ["Application.ReadWrite"],
		}));
		const result = await authenticateAsync(plugin, "service-account", token);
		expect(result).toBe(false);
	});
});
