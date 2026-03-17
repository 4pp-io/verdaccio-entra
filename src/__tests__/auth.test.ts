import { describe, it, expect, vi, beforeAll, beforeEach } from "vitest";

import { SignJWT, exportJWK, generateKeyPair } from "jose";

import { TEST_TENANT, TEST_CLIENT, TEST_KID } from "./fixtures";
import { DEFAULT_MAX_TOKEN_BYTES, AUDIENCE_PREFIX, ISSUERS } from "../auth-plugin";

let privateKey: CryptoKey;
let publicJwk: Record<string, unknown>;

const DISCOVERED_ISSUER = ISSUERS.v2(TEST_TENANT);
const DISCOVERED_JWKS_URI = `https://login.microsoftonline.com/${TEST_TENANT}/discovery/v2.0/keys`;

beforeAll(async () => {
	const pair = await generateKeyPair("RS256");
	privateKey = pair.privateKey;
	publicJwk = { ...(await exportJWK(pair.publicKey)), kid: TEST_KID, use: "sig", alg: "RS256" };
});

// --- Mock fetch: serves both OIDC discovery AND JWKS endpoints ---
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function setFetchSuccess(): void {
	mockFetch.mockImplementation((input: string | URL | Request) => {
		const url = String(input);
		if (url.includes("openid-configuration")) {
			return Promise.resolve({
				ok: true,
				json: () => Promise.resolve({ issuer: DISCOVERED_ISSUER, jwks_uri: DISCOVERED_JWKS_URI }),
			});
		}
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

function validClaims(overrides?: Record<string, unknown>): Record<string, unknown> {
	return {
		preferred_username: "user@contoso.com",
		iss: DISCOVERED_ISSUER,
		aud: `${AUDIENCE_PREFIX}${TEST_CLIENT}`,
		groups: ["developers"],
		roles: ["registry-admin"],
		...overrides,
	};
}

import EntraPlugin from "../auth-plugin";

function createPlugin(configOverrides?: Record<string, unknown>): EntraPlugin {
	return new EntraPlugin(
		{ clientId: TEST_CLIENT, tenantId: TEST_TENANT, discoveryRetries: 1, ...configOverrides } as never,
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

	it("throws on invalid clientId", () => {
		expect(() => createPlugin({ clientId: "not-a-guid" })).toThrow(/Invalid clientId/);
	});

	it("throws on invalid tenantId", () => {
		expect(() => createPlugin({ tenantId: "not-a-guid" })).toThrow(/Invalid tenantId/);
	});

	it("throws on empty clientId", () => {
		expect(() => createPlugin({ clientId: "" })).toThrow(/Invalid clientId/);
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

describe("OIDC discovery failure", () => {
	it("rejects auth when discovery fails", async () => {
		mockFetch.mockResolvedValue({ ok: false, status: 400 });
		const plugin = createPlugin({ discoveryRetries: 1 });
		await (plugin as unknown as Record<string, Promise<void>>)["_ready"];

		const token = await signToken(validClaims());
		await expect(authenticateAsync(plugin, "user@contoso.com", token)).rejects.toThrow(/OIDC discovery|not ready/i);

		setFetchSuccess();
	});
});

describe("authenticate", () => {
	let plugin: EntraPlugin;
	beforeEach(async () => {
		setFetchSuccess();
		plugin = createPlugin();
		await (plugin as unknown as Record<string, Promise<void>>)["_ready"];
	});

	it("succeeds when username matches token identity", async () => {
		const token = await signToken(validClaims());
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).toContain("$authenticated");
		expect(groups).toContain("developers");
		expect(groups).toContain("registry-admin");
	});

	it("succeeds case-insensitively", async () => {
		const token = await signToken(validClaims({ preferred_username: "Alice@Contoso.com" }));
		const groups = await authenticateAsync(plugin, "alice@contoso.com", token);
		expect(groups).toContain("$authenticated");
	});

	it("rejects when npm username does not match token identity (anti-spoofing)", async () => {
		const token = await signToken(validClaims({ preferred_username: "bob@contoso.com" }));
		await expect(authenticateAsync(plugin, "alice@contoso.com", token))
			.rejects.toThrow(/does not match Entra identity/);
	});

	it("returns false when token has no identity claim", async () => {
		const token = await signToken(validClaims({ preferred_username: undefined, upn: undefined, email: undefined }));
		const result = await authenticateAsync(plugin, "anyone", token);
		expect(result).toBe(false);
	});

	it("returns false for expired token", async () => {
		const token = await signToken(validClaims(), { expiresIn: "-1s" });
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("returns false for wrong audience", async () => {
		const token = await signToken(validClaims({ aud: "api://wrong" }));
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("returns false for wrong issuer", async () => {
		const token = await signToken(validClaims({ iss: ISSUERS.v1("99999999-9999-9999-9999-999999999999") }));
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("returns error for unknown kid (no matching JWKS key)", async () => {
		const token = await signToken(validClaims(), { kid: "unknown-kid" });
		await expect(authenticateAsync(plugin, "user@contoso.com", token)).rejects.toThrow(/matching.*key/i);
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
		const token = await signToken(validClaims());
		const parts = token.split(".");
		const result = await authenticateAsync(plugin, "user@contoso.com", [parts[0], parts[1], "badsig"].join("."));
		expect(result).toBe(false);
	});

	it("merges groups and roles claims", async () => {
		const token = await signToken(validClaims({ groups: ["a", "b"], roles: ["x"] }));
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).toEqual(["$authenticated", "a", "b", "x"]);
	});

	it("handles missing groups/roles gracefully", async () => {
		const token = await signToken(validClaims({ groups: undefined, roles: undefined }));
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).toEqual(["$authenticated"]);
	});
});
