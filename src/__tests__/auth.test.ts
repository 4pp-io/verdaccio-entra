import { describe, it, expect, vi, beforeAll, beforeEach } from "vitest";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { TEST_TENANT, TEST_CLIENT, TEST_KID } from "./fixtures";
import { MAX_TOKEN_BYTES, AUDIENCE_PREFIX, ISSUERS } from "../auth-plugin";

// --- Test RSA key pair (generated once for all tests) ---
let privateKey: string;
let publicKey: string;

// The issuer that OIDC discovery returns
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

// --- Mock fetch for OIDC discovery ---
vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
	ok: true,
	json: () => Promise.resolve({
		issuer: DISCOVERED_ISSUER,
		jwks_uri: `https://login.microsoftonline.com/${TEST_TENANT}/discovery/v2.0/keys`,
	}),
}));

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
		iss: DISCOVERED_ISSUER,
		aud: `${AUDIENCE_PREFIX}${TEST_CLIENT}`,
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
			expect(() =>
				createPlugin({
					clientId: "placeholder",
					tenantId: "placeholder",
				}),
			).not.toThrow();
		} finally {
			delete process.env.ENTRA_CLIENT_ID;
			delete process.env.ENTRA_TENANT_ID;
		}
	});
});

describe("OIDC discovery failure", () => {
	it("returns service error when discovery fails", async () => {
		// Override fetch to simulate discovery failure
		const originalFetch = globalThis.fetch;
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
			ok: false,
			status: 400,
		}));
		const plugin = createPlugin();
		const token = signToken(validPayload());
		// Discovery fails → plugin not ready → service error
		await expect(authenticateAsync(plugin, "testuser", token)).rejects.toThrow(/OIDC discovery|not ready/i);
		// Restore
		vi.stubGlobal("fetch", originalFetch);
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
		// Use ISSUERS.v1 with a wrong tenant to exercise both issuer formats
		const token = signToken(
			validPayload({ iss: ISSUERS.v1("99999999-9999-9999-9999-999999999999") }),
		);
		const result = await authenticateAsync(plugin, "testuser", token);
		expect(result).toBe(false);
	});

	// Swapped ID detection — provides actionable hints when clientId/tenantId are swapped
	// @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference

	it("detects swapped IDs when tid matches configured clientId", async () => {
		const token = signToken(validPayload({
			tid: TEST_CLIENT,
			aud: `${AUDIENCE_PREFIX}${TEST_TENANT}`,
			iss: `https://sts.windows.net/${TEST_CLIENT}/`,
		}));
		const result = await authenticateAsync(plugin, "testuser", token);
		expect(result).toBe(false);
	});

	it("detects swapped IDs when aud contains configured tenantId", async () => {
		const token = signToken(validPayload({
			aud: `${AUDIENCE_PREFIX}${TEST_TENANT}`,
			iss: "https://sts.windows.net/99999999-9999-9999-9999-999999999999/",
		}));
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
		const oversized = "x".repeat(MAX_TOKEN_BYTES + 1);
		const result = await authenticateAsync(plugin, "testuser", oversized);
		expect(result).toBe(false);
	});

	it("returns false for generic JsonWebTokenError (e.g. invalid signature)", async () => {
		const token = signToken(validPayload());
		const parts = token.split(".");
		const tampered = [parts[0], parts[1], "invalidsignature"].join(".");
		const result = await authenticateAsync(plugin, "testuser", tampered);
		expect(result).toBe(false);
	});

	it("returns false for generic JWT error (e.g. NotBeforeError)", async () => {
		const token = signToken(validPayload(), { expiresIn: "1h" });
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

	it("handles audience mismatch without tid/aud claims gracefully", async () => {
		const token = signToken({
			iss: DISCOVERED_ISSUER,
			preferred_username: "user@contoso.com",
		});
		const result = await authenticateAsync(plugin, "testuser", token);
		expect(result).toBe(false);
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

	it("handles missing groups/roles gracefully", async () => {
		const token = signToken(
			validPayload({ groups: undefined, roles: undefined }),
		);
		const groups = await authenticateAsync(plugin, "testuser", token);
		expect(groups).toEqual(["$authenticated"]);
	});
});
