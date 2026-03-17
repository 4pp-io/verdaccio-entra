import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import type { MockInstance } from "vitest";
import type { Logger } from "@verdaccio/types";
import type { pluginUtils } from "@verdaccio/core";

import { SignJWT, exportJWK, generateKeyPair } from "jose";

import type { EntraConfig } from "../../types/index";
import { TEST_TENANT, TEST_CLIENT, TEST_KID, entraV2Claims } from "./fixtures";
import {
  DEFAULT_MAX_TOKEN_BYTES,
  AUDIENCE_PREFIX,
  resolveConfig,
  warnIfProxyMisconfigured,
} from "../auth-plugin";

let privateKey: CryptoKey;
let publicJwk: Record<string, unknown>;

// --- Mock fetch: serves JWKS endpoint for jose's createRemoteJWKSet ---
const originalFetch = globalThis.fetch;
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

beforeAll(async () => {
  const pair = await generateKeyPair("RS256");
  privateKey = pair.privateKey;
  publicJwk = { ...(await exportJWK(pair.publicKey)), kid: TEST_KID, use: "sig", alg: "RS256" };
  setFetchSuccess();
});

afterAll(() => {
  vi.stubGlobal("fetch", originalFetch);
});

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

function mockLogger(): Logger {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
    child: vi.fn(),
    http: vi.fn(),
  };
}

function createPlugin(configOverrides?: Partial<EntraConfig>): EntraPlugin {
  return new EntraPlugin({ clientId: TEST_CLIENT, tenantId: TEST_TENANT, ...configOverrides }, {
    logger: mockLogger(),
    config: {},
  } as pluginUtils.PluginOptions);
}

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
    }) as () => never);
    try {
      expect(() => createPlugin({ clientId: "not-a-guid", failClosed: true })).toThrow(
        /process\.exit/,
      );
      expect(exitSpy).toHaveBeenCalledWith(1);
    } finally {
      exitSpy.mockRestore();
    }
  });

  it("env vars override config values", () => {
    process.env.ENTRA_CLIENT_ID = TEST_CLIENT;
    process.env.ENTRA_TENANT_ID = TEST_TENANT;
    try {
      expect(() =>
        createPlugin({ clientId: "placeholder", tenantId: "placeholder" }),
      ).not.toThrow();
    } finally {
      delete process.env.ENTRA_CLIENT_ID;
      delete process.env.ENTRA_TENANT_ID;
    }
  });

  it("ENTRA_FAIL_CLOSED env var overrides config.failClosed", () => {
    process.env.ENTRA_FAIL_CLOSED = "true";
    const exitSpy: MockInstance = vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("process.exit called");
    }) as () => never);
    try {
      // Config says failClosed: false, but env var says true — env wins
      expect(() => createPlugin({ clientId: "not-a-guid", failClosed: false })).toThrow(
        /process\.exit/,
      );
      expect(exitSpy).toHaveBeenCalledWith(1);
    } finally {
      exitSpy.mockRestore();
      delete process.env.ENTRA_FAIL_CLOSED;
    }
  });

  it("ENTRA_ALLOW_GROUP_OVERAGE env var overrides config.allowGroupOverage", async () => {
    process.env.ENTRA_ALLOW_GROUP_OVERAGE = "true";
    try {
      // Config says allowGroupOverage: false (default), but env var says true
      const envPlugin = createPlugin({ allowGroupOverage: false });
      const token = await signToken(
        entraV2Claims({
          groups: undefined,
          roles: ["registry-admin"],
          _claim_names: { groups: "src1" },
          _claim_sources: {
            src1: { endpoint: "https://graph.microsoft.com/v1.0/users/me/transitiveMemberOf" },
          },
        }),
      );
      const groups = await authenticateAsync(envPlugin, "user@contoso.com", token);
      // Should allow overage because env var overrides config
      expect(groups).toEqual(["$authenticated", "registry-admin"]);
    } finally {
      delete process.env.ENTRA_ALLOW_GROUP_OVERAGE;
    }
  });
});

describe("resolveConfig", () => {
  it("returns config values when no env vars are set", () => {
    const result = resolveConfig({ clientId: TEST_CLIENT, tenantId: TEST_TENANT }, {});
    expect(result.clientId).toBe(TEST_CLIENT);
    expect(result.tenantId).toBe(TEST_TENANT);
    expect(result.authority).toBe("https://login.microsoftonline.com");
    expect(result.audience).toBe(`${AUDIENCE_PREFIX}${TEST_CLIENT}`);
  });

  it("env vars take precedence over config values", () => {
    const result = resolveConfig(
      {
        clientId: "00000000-0000-0000-0000-000000000000",
        tenantId: "00000000-0000-0000-0000-000000000000",
      },
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
    expect(() =>
      resolveConfig(
        { clientId: TEST_CLIENT, tenantId: TEST_TENANT },
        { ENTRA_CLIENT_ID: "not-a-guid" },
      ),
    ).toThrow(/Invalid clientId/);
  });

  it("is testable without mutating process.env", () => {
    // The whole point: env dict is injectable
    const env = { ENTRA_CLIENT_ID: TEST_CLIENT, ENTRA_TENANT_ID: TEST_TENANT };
    const result = resolveConfig({ clientId: "", tenantId: "" }, env);
    expect(result.clientId).toBe(TEST_CLIENT);
  });

  it("resolves all boolean and numeric env overrides", () => {
    const result = resolveConfig(
      { clientId: TEST_CLIENT, tenantId: TEST_TENANT },
      {
        ENTRA_FAIL_CLOSED: "true",
        ENTRA_ALLOW_GROUP_OVERAGE: "true",
        ENTRA_MAX_TOKEN_BYTES: "1024",
        ENTRA_CLOCK_TOLERANCE_SECONDS: "60",
      },
    );
    expect(result.failClosed).toBe(true);
    expect(result.allowGroupOverage).toBe(true);
    expect(result.maxTokenBytes).toBe(1024);
    expect(result.clockToleranceSeconds).toBe(60);
  });

  it("falls back to config defaults when env vars are absent", () => {
    const result = resolveConfig(
      {
        clientId: TEST_CLIENT,
        tenantId: TEST_TENANT,
        failClosed: true,
        allowGroupOverage: true,
        maxTokenBytes: 512,
        clockToleranceSeconds: 10,
      },
      {},
    );
    expect(result.failClosed).toBe(true);
    expect(result.allowGroupOverage).toBe(true);
    expect(result.maxTokenBytes).toBe(512);
    expect(result.clockToleranceSeconds).toBe(10);
  });

  it("ignores non-numeric ENTRA_MAX_TOKEN_BYTES (falls back to config/default)", () => {
    const result = resolveConfig(
      { clientId: TEST_CLIENT, tenantId: TEST_TENANT },
      { ENTRA_MAX_TOKEN_BYTES: "not-a-number" },
    );
    expect(result.maxTokenBytes).toBe(256_000); // DEFAULT_MAX_TOKEN_BYTES
  });

  it("ignores negative ENTRA_MAX_TOKEN_BYTES", () => {
    const result = resolveConfig(
      { clientId: TEST_CLIENT, tenantId: TEST_TENANT },
      { ENTRA_MAX_TOKEN_BYTES: "-1" },
    );
    expect(result.maxTokenBytes).toBe(256_000);
  });

  it("ignores non-integer ENTRA_CLOCK_TOLERANCE_SECONDS", () => {
    const result = resolveConfig(
      { clientId: TEST_CLIENT, tenantId: TEST_TENANT },
      { ENTRA_CLOCK_TOLERANCE_SECONDS: "3.5" },
    );
    expect(result.clockToleranceSeconds).toBe(300);
  });

  it("envBool is case-insensitive and ignores invalid values", () => {
    const result = resolveConfig(
      { clientId: TEST_CLIENT, tenantId: TEST_TENANT },
      { ENTRA_FAIL_CLOSED: "TRUE", ENTRA_ALLOW_GROUP_OVERAGE: "yes" },
    );
    expect(result.failClosed).toBe(true); // "TRUE" works
    expect(result.allowGroupOverage).toBe(false); // "yes" is invalid, falls through to default
  });
});

describe("warnIfProxyMisconfigured", () => {
  it("warns when HTTPS_PROXY is set without NODE_USE_ENV_PROXY", () => {
    const warn = vi.fn();
    const logger: Logger = { ...mockLogger(), warn };
    warnIfProxyMisconfigured(logger, { HTTPS_PROXY: "http://proxy:8080" });
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0]?.[1]).toMatch(/NODE_USE_ENV_PROXY/);
  });

  it("does not warn when NODE_USE_ENV_PROXY is set", () => {
    const warn = vi.fn();
    const logger: Logger = { ...mockLogger(), warn };
    warnIfProxyMisconfigured(logger, { HTTPS_PROXY: "http://proxy:8080", NODE_USE_ENV_PROXY: "1" });
    expect(warn).not.toHaveBeenCalled();
  });

  it("does not warn when no proxy vars are set", () => {
    const warn = vi.fn();
    const logger: Logger = { ...mockLogger(), warn };
    warnIfProxyMisconfigured(logger, {});
    expect(warn).not.toHaveBeenCalled();
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
    await expect(authenticateAsync(plugin, "alice@contoso.com", token)).rejects.toThrow(
      /does not match Entra identity/,
    );
  });

  it("returns false when token has no identity claim", async () => {
    const token = await signToken(
      entraV2Claims({ preferred_username: undefined, upn: undefined, email: undefined }),
    );
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
    const token = await signToken(
      entraV2Claims({
        iss: "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0",
      }),
    );
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
    const result = await authenticateAsync(
      plugin,
      "user@contoso.com",
      "x".repeat(DEFAULT_MAX_TOKEN_BYTES + 1),
    );
    expect(result).toBe(false);
  });

  it("returns false for tampered signature", async () => {
    const token = await signToken(entraV2Claims());
    const parts = token.split(".");
    const result = await authenticateAsync(
      plugin,
      "user@contoso.com",
      [parts[0], parts[1], "badsig"].join("."),
    );
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
    const token = await signToken(
      entraV2Claims({
        groups: undefined,
        roles: ["registry-admin"],
        _claim_names: { groups: "src1" },
        _claim_sources: {
          src1: { endpoint: "https://graph.microsoft.com/v1.0/users/me/transitiveMemberOf" },
        },
      }),
    );
    const result = await authenticateAsync(plugin, "user@contoso.com", token);
    expect(result).toBe(false);
  });

  it("allows group overage when allowGroupOverage is true", async () => {
    const overagePlugin = createPlugin({ allowGroupOverage: true });
    const token = await signToken(
      entraV2Claims({
        groups: undefined,
        roles: ["registry-admin"],
        _claim_names: { groups: "src1" },
        _claim_sources: {
          src1: { endpoint: "https://graph.microsoft.com/v1.0/users/me/transitiveMemberOf" },
        },
      }),
    );
    const groups = await authenticateAsync(overagePlugin, "user@contoso.com", token);
    expect(groups).toEqual(["$authenticated", "registry-admin"]);
  });

  // --- Real-world Entra token variations ---
  // @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference

  it("rejects token with non-string items in groups array (violates Entra contract)", async () => {
    // Entra documents groups as "JSON array of GUIDs" — always strings.
    // @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
    const token = await signToken(
      entraV2Claims({ groups: ["valid-group", 123, null, true, "another-group"] }),
    );
    const result = await authenticateAsync(plugin, "user@contoso.com", token);
    expect(result).toBe(false);
  });

  it("handles wids claim (directory roles) without leaking them into groups", async () => {
    // Entra emits wids (directory role template IDs) alongside groups.
    // The plugin should only extract groups and roles, not wids.
    const token = await signToken(
      entraV2Claims({
        wids: ["62e90394-69f5-4237-9190-012177145e10"], // Global Administrator template ID
      }),
    );
    const groups = await authenticateAsync(plugin, "user@contoso.com", token);
    expect(groups).not.toContain("62e90394-69f5-4237-9190-012177145e10");
    expect(groups).toContain("$authenticated");
  });

  it("authenticates with email fallback when preferred_username and upn are absent", async () => {
    // Guest accounts often only have the email claim
    const token = await signToken(
      entraV2Claims({
        preferred_username: undefined,
        upn: undefined,
        email: "guest@external.com",
        name: "External Guest",
      }),
    );
    const groups = await authenticateAsync(plugin, "guest@external.com", token);
    expect(groups).toContain("$authenticated");
  });

  it("succeeds with groups as GUIDs (real Entra group object IDs)", async () => {
    // Real Entra tokens emit groups as opaque GUIDs, not friendly names
    const token = await signToken(
      entraV2Claims({
        groups: ["b1c2d3e4-f5a6-7890-abcd-ef1234567890", "a0b1c2d3-e4f5-6789-0abc-def123456789"],
      }),
    );
    const groups = await authenticateAsync(plugin, "user@contoso.com", token);
    expect(groups).toContain("b1c2d3e4-f5a6-7890-abcd-ef1234567890");
    expect(groups).toContain("a0b1c2d3-e4f5-6789-0abc-def123456789");
  });

  it("rejects hasgroups=true with overage by default (no groups array, just the flag)", async () => {
    const token = await signToken(
      entraV2Claims({
        groups: undefined,
        hasgroups: true,
      }),
    );
    const result = await authenticateAsync(plugin, "user@contoso.com", token);
    expect(result).toBe(false);
  });

  it("overage warning falls back to upn when preferred_username is absent", async () => {
    // Service accounts / B2B guests may have upn but not preferred_username
    const token = await signToken(
      entraV2Claims({
        preferred_username: undefined,
        upn: "svc-account@contoso.com",
        email: undefined,
        groups: undefined,
        _claim_names: { groups: "src1" },
        _claim_sources: {
          src1: { endpoint: "https://graph.microsoft.com/v1.0/users/me/transitiveMemberOf" },
        },
      }),
    );
    const result = await authenticateAsync(plugin, "svc-account@contoso.com", token);
    // Should reject (overage, default config) — but exercises the upn fallback in the warning
    expect(result).toBe(false);
  });

  it("overage warning uses 'unknown' when no identity claims are present", async () => {
    // Edge case: overage token with no username claims at all
    const overagePlugin = createPlugin({ allowGroupOverage: true });
    const token = await signToken(
      entraV2Claims({
        preferred_username: undefined,
        upn: undefined,
        email: undefined,
        groups: undefined,
        _claim_names: { groups: "src1" },
        _claim_sources: {
          src1: { endpoint: "https://graph.microsoft.com/v1.0/users/me/transitiveMemberOf" },
        },
      }),
    );
    // allowGroupOverage=true so it doesn't throw, but there's no identity claim
    // so authenticate() itself returns false (no upn to match)
    const result = await authenticateAsync(overagePlugin, "anyone", token);
    expect(result).toBe(false);
  });

  // --- Shape guard: assertEntraPayload catches wrong claim types ---

  it("rejects token where preferred_username is not a string", async () => {
    const token = await signToken(entraV2Claims({ preferred_username: 12345 }));
    const result = await authenticateAsync(plugin, "user@contoso.com", token);
    expect(result).toBe(false);
  });

  it("rejects token where groups is not an array", async () => {
    const token = await signToken(entraV2Claims({ groups: "not-an-array" }));
    const result = await authenticateAsync(plugin, "user@contoso.com", token);
    expect(result).toBe(false);
  });

  it("rejects token where roles is a string instead of array", async () => {
    const token = await signToken(entraV2Claims({ roles: "admin" }));
    const result = await authenticateAsync(plugin, "user@contoso.com", token);
    expect(result).toBe(false);
  });

  it("rejects token where email is a number", async () => {
    const token = await signToken(
      entraV2Claims({
        preferred_username: undefined,
        upn: undefined,
        email: 999,
      }),
    );
    const result = await authenticateAsync(plugin, "user@contoso.com", token);
    expect(result).toBe(false);
  });

  it("rejects token where upn is not a string", async () => {
    // upn is documented as String
    // @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
    const token = await signToken(entraV2Claims({ preferred_username: undefined, upn: 42 }));
    const result = await authenticateAsync(plugin, "user@contoso.com", token);
    expect(result).toBe(false);
  });

  it("rejects token with non-string items in roles array", async () => {
    // roles is documented as "Array of strings"
    // @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
    const token = await signToken(entraV2Claims({ roles: ["admin", 123, null] }));
    const result = await authenticateAsync(plugin, "user@contoso.com", token);
    expect(result).toBe(false);
  });

  it("handles app-only token (client_credentials flow — no user claims)", async () => {
    // Client credential tokens have azp/azpacr but no preferred_username/upn/email.
    // The plugin should return false (no identity claim to match).
    const token = await signToken(
      entraV2Claims({
        preferred_username: undefined,
        upn: undefined,
        email: undefined,
        name: undefined,
        sub: TEST_CLIENT, // In client_credentials, sub = app's oid
        scp: undefined,
        roles: ["Application.ReadWrite"],
      }),
    );
    const result = await authenticateAsync(plugin, "service-account", token);
    expect(result).toBe(false);
  });
});
