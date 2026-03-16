import { describe, it, expect, vi, beforeAll, beforeEach } from "vitest";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";

// --- Test RSA key pair (generated once for all tests) ---
let privateKey: string;
let publicKey: string;

const TEST_TENANT = "11111111-1111-1111-1111-111111111111";
const TEST_CLIENT = "22222222-2222-2222-2222-222222222222";
const TEST_KID = "test-kid-001";

beforeAll(() => {
	const pair = crypto.generateKeyPairSync("rsa", {
		modulusLength: 2048,
		publicKeyEncoding: { type: "spki", format: "pem" },
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
	});
	privateKey = pair.privateKey;
	publicKey = pair.publicKey;
});

// --- Mock jwks-rsa to return our test public key ---
vi.mock("jwks-rsa", () => {
	return {
		default: () => ({
			getSigningKey: vi.fn().mockImplementation((kid: string) => {
				if (kid === TEST_KID) {
					return Promise.resolve({ getPublicKey: () => publicKey });
				}
				return Promise.reject(new Error(`Failed to fetch signing key: Unknown kid: ${kid}`));
			}),
		}),
	};
});

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
		iss: `https://sts.windows.net/${TEST_TENANT}/`,
		aud: `api://${TEST_CLIENT}`,
		groups: ["developers"],
		roles: ["registry-admin"],
		...overrides,
	};
}

// --- Import plugin after mocks are set up ---
import EntraPlugin from "../auth-plugin";

function createPlugin(configOverrides?: Record<string, unknown>): EntraPlugin {
	const config = {
		clientId: TEST_CLIENT,
		tenantId: TEST_TENANT,
		...configOverrides,
	} as never;
	const appOptions = {
		logger: {
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
			debug: vi.fn(),
			trace: vi.fn(),
			child: vi.fn(),
			http: vi.fn(),
		},
		config: {},
	} as never;
	return new EntraPlugin(config, appOptions);
}

/**
 * Promisify authenticate — resolves with groups on success, resolves with
 * false on credential failure, rejects on service error.
 * Matches Verdaccio callback contract:
 * @see https://verdaccio.org/docs/plugin-auth#authentication-callback
 */
function authenticateAsync(
	plugin: EntraPlugin,
	user: string,
	password: string,
): Promise<string[] | false> {
	return new Promise((resolve, reject) => {
		plugin.authenticate(user, password, (err, groups) => {
			if (err) reject(err);
			else resolve(groups as string[] | false);
		});
	});
}

function adduserAsync(
	plugin: EntraPlugin,
	user: string,
	password: string,
): Promise<boolean | string | false> {
	return new Promise((resolve, reject) => {
		plugin.adduser(user, password, (err, result) => {
			if (err) reject(err);
			else resolve(result as boolean | string | false);
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

	it("resolves env vars in config", () => {
		process.env.TEST_ENTRA_CLIENT = TEST_CLIENT;
		process.env.TEST_ENTRA_TENANT = TEST_TENANT;
		try {
			expect(() =>
				createPlugin({
					clientId: "${TEST_ENTRA_CLIENT}",
					tenantId: "${TEST_ENTRA_TENANT}",
				}),
			).not.toThrow();
		} finally {
			delete process.env.TEST_ENTRA_CLIENT;
			delete process.env.TEST_ENTRA_TENANT;
		}
	});

	it("throws when env var resolves to non-GUID", () => {
		process.env.TEST_BAD_ID = "bad-value";
		try {
			expect(() =>
				createPlugin({ clientId: "${TEST_BAD_ID}" }),
			).toThrow(/Invalid clientId/);
		} finally {
			delete process.env.TEST_BAD_ID;
		}
	});
});

describe("authenticate", () => {
	let plugin: EntraPlugin;
	beforeEach(() => {
		plugin = createPlugin();
	});

	it("succeeds with a valid token and returns groups", async () => {
		const token = signToken(validPayload());
		const groups = await authenticateAsync(plugin, "testuser", token);
		expect(groups).toContain("$authenticated");
		expect(groups).toContain("developers");
		expect(groups).toContain("registry-admin");
	});

	it("extracts preferred_username from token", async () => {
		const token = signToken(validPayload({ preferred_username: "alice@contoso.com" }));
		const groups = await authenticateAsync(plugin, "testuser", token);
		expect(groups).toContain("$authenticated");
	});

	// Credential failures return false (not error) — allows plugin chaining
	// @see https://verdaccio.org/docs/plugin-auth#if-the-authentication-fails

	it("returns false for expired token (credential failure)", async () => {
		const token = signToken(validPayload(), { expiresIn: "-1s" });
		const result = await authenticateAsync(plugin, "testuser", token);
		expect(result).toBe(false);
	});

	it("returns false for wrong audience (credential failure)", async () => {
		const token = signToken(validPayload({ aud: "api://wrong-client-id" }));
		const result = await authenticateAsync(plugin, "testuser", token);
		expect(result).toBe(false);
	});

	it("returns false for wrong issuer (credential failure)", async () => {
		const token = signToken(
			validPayload({ iss: "https://sts.windows.net/99999999-9999-9999-9999-999999999999/" }),
		);
		const result = await authenticateAsync(plugin, "testuser", token);
		expect(result).toBe(false);
	});

	// Service errors (JWKS endpoint down) return error — stops plugin chain
	// @see https://verdaccio.org/docs/plugin-auth#if-the-authentication-produce-an-error

	it("returns error for unknown kid (JWKS service failure)", async () => {
		const token = signToken(validPayload(), { kid: "unknown-kid" });
		await expect(authenticateAsync(plugin, "testuser", token)).rejects.toThrow(/signing key/i);
	});

	it("returns false for non-JWT string (credential failure)", async () => {
		const result = await authenticateAsync(plugin, "testuser", "not-a-jwt");
		expect(result).toBe(false);
	});

	it("returns false for token missing kid header (credential failure)", async () => {
		const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
		const payload = Buffer.from(JSON.stringify(validPayload())).toString("base64url");
		const token = `${header}.${payload}.fakesig`;
		const result = await authenticateAsync(plugin, "testuser", token);
		expect(result).toBe(false);
	});

	it("returns false for token exceeding max size (credential failure)", async () => {
		const oversized = "x".repeat(8193);
		const result = await authenticateAsync(plugin, "testuser", oversized);
		expect(result).toBe(false);
	});

	it("accepts v2.0 issuer", async () => {
		const token = signToken(
			validPayload({ iss: `https://login.microsoftonline.com/${TEST_TENANT}/v2.0` }),
		);
		const groups = await authenticateAsync(plugin, "testuser", token);
		expect(groups).toContain("$authenticated");
	});

	it("merges groups and roles claims", async () => {
		const token = signToken(
			validPayload({
				groups: ["group-a", "group-b"],
				roles: ["role-x"],
			}),
		);
		const groups = await authenticateAsync(plugin, "testuser", token);
		expect(groups).toEqual(["$authenticated", "group-a", "group-b", "role-x"]);
	});

	it("returns false for generic JWT error (e.g. NotBeforeError)", async () => {
		// Sign with nbf in the future to trigger NotBeforeError
		const token = signToken(validPayload(), { expiresIn: "1h" });
		// Manually craft a token with nbf far in the future
		const decoded = jwt.decode(token, { complete: true });
		if (!decoded || typeof decoded === "string") throw new Error("test setup: failed to decode token");
		const payload = { ...decoded.payload as Record<string, unknown>, nbf: Math.floor(Date.now() / 1000) + 99999 };
		const futureToken = jwt.sign(payload, privateKey, {
			algorithm: "RS256",
			header: { alg: "RS256", kid: TEST_KID },
		} as jwt.SignOptions);
		const result = await authenticateAsync(plugin, "testuser", futureToken);
		expect(result).toBe(false);
	});

	it("handles missing groups/roles gracefully", async () => {
		const token = signToken(
			validPayload({ groups: undefined, roles: undefined }),
		);
		const groups = await authenticateAsync(plugin, "testuser", token);
		expect(groups).toEqual(["$authenticated"]);
	});
});

describe("adduser", () => {
	let plugin: EntraPlugin;
	beforeEach(() => {
		plugin = createPlugin();
	});

	it("succeeds with valid token", async () => {
		const token = signToken(validPayload());
		const result = await adduserAsync(plugin, "testuser", token);
		expect(result).toBe(true);
	});

	it("returns false for invalid token (credential failure)", async () => {
		const result = await adduserAsync(plugin, "testuser", "bad");
		expect(result).toBe(false);
	});

	it("returns false for oversized token (credential failure)", async () => {
		const result = await adduserAsync(plugin, "testuser", "x".repeat(8193));
		expect(result).toBe(false);
	});

	it("returns error for unknown kid (JWKS service failure)", async () => {
		const token = signToken(validPayload(), { kid: "unknown-kid" });
		await expect(adduserAsync(plugin, "testuser", token)).rejects.toThrow(/signing key/i);
	});
});
