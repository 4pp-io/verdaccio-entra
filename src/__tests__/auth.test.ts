import { describe, it, expect, vi, beforeAll, beforeEach } from "vitest";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { TEST_TENANT, TEST_CLIENT, TEST_KID } from "./fixtures";
import { DEFAULT_MAX_TOKEN_BYTES, AUDIENCE_PREFIX, ISSUERS } from "../auth-plugin";

let privateKey: string;
let publicKey: string;

const DISCOVERED_ISSUER = ISSUERS.v2(TEST_TENANT);

beforeAll(() => {
	const pair = crypto.generateKeyPairSync("rsa", {
		modulusLength: 2048,
		publicKeyEncoding: { type: "spki", format: "pem" },
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
	});
	privateKey = pair.privateKey;
	publicKey = pair.publicKey;
});

// --- Mock fetch for OIDC discovery (plain globalThis.fetch) ---
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function setFetchSuccess(): void {
	mockFetch.mockResolvedValue({
		ok: true,
		json: () => Promise.resolve({
			issuer: DISCOVERED_ISSUER,
			jwks_uri: `https://login.microsoftonline.com/${TEST_TENANT}/discovery/v2.0/keys`,
		}),
	});
}

// Default: successful OIDC discovery
setFetchSuccess();

// --- Mock jwks-rsa ---
vi.mock("jwks-rsa", () => ({
	default: () => ({
		getSigningKey: vi.fn().mockImplementation((kid: string) => {
			if (kid === TEST_KID) {
				return Promise.resolve({ getPublicKey: () => publicKey });
			}
			return Promise.reject(new Error(`Failed to fetch signing key: Unknown kid: ${kid}`));
		}),
	}),
}));

function signToken(
	payload: Record<string, unknown>,
	options?: { expiresIn?: string | number; kid?: string },
): string {
	return jwt.sign(payload, privateKey, {
		algorithm: "RS256",
		header: { alg: "RS256", kid: options?.kid ?? TEST_KID },
		expiresIn: options?.expiresIn ?? "1h",
	} as jwt.SignOptions);
}

function validPayload(overrides?: Record<string, unknown>): Record<string, unknown> {
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

		// discoveryRetries: 1 = single attempt, no backoff delay
		const plugin = createPlugin({ discoveryRetries: 1 });
		// Wait for the single discovery attempt to complete
		// eslint-disable-next-line -- accessing private for test
		await (plugin as unknown as Record<string, Promise<void>>)["_ready"];

		const token = signToken(validPayload());
		await expect(authenticateAsync(plugin, "user@contoso.com", token)).rejects.toThrow(/OIDC discovery|not ready/i);

		setFetchSuccess();
	});
});

describe("authenticate", () => {
	let plugin: EntraPlugin;
	beforeEach(async () => {
		setFetchSuccess();
		plugin = createPlugin();
		// Let async OIDC discovery settle (mock resolves instantly)
		await new Promise<void>((r) => { queueMicrotask(() => r()); });
		await new Promise<void>((r) => { queueMicrotask(() => r()); });
	});

	it("succeeds when username matches token identity", async () => {
		const token = signToken(validPayload());
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).toContain("$authenticated");
		expect(groups).toContain("developers");
		expect(groups).toContain("registry-admin");
	});

	it("succeeds case-insensitively", async () => {
		const token = signToken(validPayload({ preferred_username: "Alice@Contoso.com" }));
		const groups = await authenticateAsync(plugin, "alice@contoso.com", token);
		expect(groups).toContain("$authenticated");
	});

	it("rejects when npm username does not match token identity (anti-spoofing)", async () => {
		const token = signToken(validPayload({ preferred_username: "bob@contoso.com" }));
		await expect(authenticateAsync(plugin, "alice@contoso.com", token))
			.rejects.toThrow(/does not match Entra identity/);
	});

	it("returns false when token has no identity claim", async () => {
		const token = signToken(validPayload({ preferred_username: undefined, upn: undefined, email: undefined }));
		const result = await authenticateAsync(plugin, "anyone", token);
		expect(result).toBe(false);
	});

	it("returns false for expired token", async () => {
		const token = signToken(validPayload(), { expiresIn: "-1s" });
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("returns false for wrong audience", async () => {
		const token = signToken(validPayload({ aud: "api://wrong" }));
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("returns false for wrong issuer", async () => {
		const token = signToken(validPayload({ iss: ISSUERS.v1("99999999-9999-9999-9999-999999999999") }));
		const result = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(result).toBe(false);
	});

	it("returns error for unknown kid (JWKS service failure)", async () => {
		const token = signToken(validPayload(), { kid: "unknown-kid" });
		await expect(authenticateAsync(plugin, "user@contoso.com", token)).rejects.toThrow(/signing key/i);
	});

	it("returns false for non-JWT string", async () => {
		const result = await authenticateAsync(plugin, "user@contoso.com", "not-a-jwt");
		expect(result).toBe(false);
	});

	it("returns false for missing kid header", async () => {
		const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
		const payload = Buffer.from(JSON.stringify(validPayload())).toString("base64url");
		const result = await authenticateAsync(plugin, "user@contoso.com", `${header}.${payload}.fakesig`);
		expect(result).toBe(false);
	});

	it("returns false for oversized token", async () => {
		const result = await authenticateAsync(plugin, "user@contoso.com", "x".repeat(DEFAULT_MAX_TOKEN_BYTES + 1));
		expect(result).toBe(false);
	});

	it("returns false for tampered signature", async () => {
		const token = signToken(validPayload());
		const parts = token.split(".");
		const result = await authenticateAsync(plugin, "user@contoso.com", [parts[0], parts[1], "bad"].join("."));
		expect(result).toBe(false);
	});

	it("merges groups and roles claims", async () => {
		const token = signToken(validPayload({ groups: ["a", "b"], roles: ["x"] }));
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).toEqual(["$authenticated", "a", "b", "x"]);
	});

	it("handles missing groups/roles gracefully", async () => {
		const token = signToken(validPayload({ groups: undefined, roles: undefined }));
		const groups = await authenticateAsync(plugin, "user@contoso.com", token);
		expect(groups).toEqual(["$authenticated"]);
	});
});
