/**
 * End-to-end test: real Verdaccio + real plugin + mock JWKS server.
 *
 * Uses Testcontainers (GenericContainer, not Compose) for full log visibility.
 * Two containers on a shared network:
 *   - mock-jwks: generates RSA keys, serves JWKS, writes private key to /shared
 *   - verdaccio: runs the plugin with ENTRA_AUTHORITY pointing at mock-jwks
 *
 * withLogConsumer streams container output in real-time so failures are visible.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { GenericContainer, Network, Wait } from "testcontainers";
import type { StartedTestContainer, StartedNetwork } from "testcontainers";
import { importJWK, SignJWT } from "jose";

const TEST_CLIENT = "11112222-3333-4444-5555-666677778888";
const TEST_TENANT = "aaaabbbb-0000-cccc-1111-dddd2222eeee";
const TEST_USER = "e2e-user@contoso.com";
const TEST_USER_OID = "00000000-0000-0000-0000-000000000001";
const TEST_USER_SUB = "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ";
const TEST_AZP = "22223333-bbbb-4444-cccc-5555dddd6666";

/**
 * Build a realistic Entra v2.0 access token payload for e2e tests.
 * Authority is dynamic (mock server URL), so iss must be overridden per-call.
 * @see https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
 */
function e2eClaims(
  authority: string,
  overrides?: Record<string, unknown>,
): Record<string, unknown> {
  return {
    aud: `api://${TEST_CLIENT}`,
    iss: `${authority}/${TEST_TENANT}/v2.0`,
    tid: TEST_TENANT,
    oid: TEST_USER_OID,
    sub: TEST_USER_SUB,
    ver: "2.0",
    azp: TEST_AZP,
    azpacr: "0",
    preferred_username: TEST_USER,
    name: "E2E Test User",
    scp: "access_as_user",
    groups: ["developers"],
    roles: ["registry-admin"],
    uti: "AbCdEf123456",
    aio: "ASQy/4TAAAAA",
    rh: "0.AAAA",
    ...overrides,
  };
}

let network: StartedNetwork;
let mockJwks: StartedTestContainer;
let verdaccio: StartedTestContainer;
let verdaccioUrl: string;

function logConsumer(prefix: string) {
  return (stream: NodeJS.ReadableStream) => {
    stream.on("data", (line: string) => console.log(`[${prefix}] ${line.trimEnd()}`));
    stream.on("err", (line: string) => console.error(`[${prefix}] ${line.trimEnd()}`));
  };
}

describe("e2e: Verdaccio + Entra plugin", () => {
  beforeAll(async () => {
    network = await new Network().start();

    // Build mock JWKS image
    const mockJwksImage = await GenericContainer.fromDockerfile(
      "./",
      "scripts/mock-jwks.Dockerfile",
    )
      .withCache(true)
      .build();

    // Build Verdaccio plugin image
    const verdaccioImage = await GenericContainer.fromDockerfile("./", "Dockerfile")
      .withCache(true)
      .build();

    // Start mock JWKS server
    mockJwks = await mockJwksImage
      .withNetwork(network)
      .withNetworkAliases("mock-jwks")
      .withExposedPorts(9877)
      .withLogConsumer(logConsumer("mock-jwks"))
      .withWaitStrategy(Wait.forLogMessage("Mock JWKS server listening"))
      .withStartupTimeout(60_000)
      .start();

    // Start Verdaccio with the plugin
    // Use HTTP health check instead of log message matching — log strings
    // change during refactors and cause silent 90-second timeout failures.
    verdaccio = await verdaccioImage
      .withNetwork(network)
      .withExposedPorts(4873)
      .withEnvironment({
        ENTRA_CLIENT_ID: TEST_CLIENT,
        ENTRA_TENANT_ID: TEST_TENANT,
        ENTRA_AUTHORITY: "http://mock-jwks:9877",
      })
      .withLogConsumer(logConsumer("verdaccio"))
      .withWaitStrategy(Wait.forHttp("/-/ping", 4873, { abortOnContainerExit: true }))
      .withStartupTimeout(60_000)
      .start();

    const port = verdaccio.getMappedPort(4873);
    verdaccioUrl = `http://${verdaccio.getHost()}:${port}`;
  }, 90_000);

  afterAll(async () => {
    await verdaccio?.stop().catch(() => {});
    await mockJwks?.stop().catch(() => {});
    await network?.stop().catch(() => {});
  });

  it("authenticates with a valid Entra token and receives groups", async () => {
    // Fetch the private key from the mock server's test endpoint
    const mockJwksHost = mockJwks.getHost();
    const mockJwksPort = mockJwks.getMappedPort(9877);
    const keysRes = await fetch(`http://${mockJwksHost}:${mockJwksPort}/_test/keys.json`);
    const { privateJwk, kid } = await keysRes.json();
    const privateKey = await importJWK(privateJwk, "RS256");

    const authority = "http://mock-jwks:9877";
    const token = await new SignJWT(e2eClaims(authority))
      .setProtectedHeader({ alg: "RS256", kid })
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);

    const res = await fetch(`${verdaccioUrl}/-/user/org.couchdb.user:${TEST_USER}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: TEST_USER, password: token }),
    });

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.ok).toContain(TEST_USER);
    expect(body.token).toBeTruthy();
  });

  it("rejects an invalid token", async () => {
    const res = await fetch(`${verdaccioUrl}/-/user/org.couchdb.user:attacker`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "attacker", password: "not-a-jwt" }),
    });

    expect([401, 403, 409]).toContain(res.status);
  });

  it("rejects group overage token (>200 groups, allowGroupOverage=false by default)", async () => {
    const mockJwksHost = mockJwks.getHost();
    const mockJwksPort = mockJwks.getMappedPort(9877);
    const keysRes = await fetch(`http://${mockJwksHost}:${mockJwksPort}/_test/keys.json`);
    const { privateJwk, kid } = await keysRes.json();
    const privateKey = await importJWK(privateJwk, "RS256");

    const authority = "http://mock-jwks:9877";
    const token = await new SignJWT(
      e2eClaims(authority, {
        groups: undefined,
        _claim_names: { groups: "src1" },
        _claim_sources: {
          src1: { endpoint: "https://graph.microsoft.com/v1.0/users/me/transitiveMemberOf" },
        },
      }),
    )
      .setProtectedHeader({ alg: "RS256", kid })
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);

    const res = await fetch(`${verdaccioUrl}/-/user/org.couchdb.user:${TEST_USER}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: TEST_USER, password: token }),
    });

    // Plugin rejects — Verdaccio returns 401 or 409 (depends on version)
    expect([401, 403, 409]).toContain(res.status);
  });

  it("rejects username mismatch (anti-spoofing)", async () => {
    const mockJwksHost = mockJwks.getHost();
    const mockJwksPort = mockJwks.getMappedPort(9877);
    const keysRes = await fetch(`http://${mockJwksHost}:${mockJwksPort}/_test/keys.json`);
    const { privateJwk, kid } = await keysRes.json();
    const privateKey = await importJWK(privateJwk, "RS256");

    const authority = "http://mock-jwks:9877";
    const token = await new SignJWT(
      e2eClaims(authority, {
        preferred_username: "real-user@contoso.com",
      }),
    )
      .setProtectedHeader({ alg: "RS256", kid })
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);

    const res = await fetch(`${verdaccioUrl}/-/user/org.couchdb.user:spoofed-user@contoso.com`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "spoofed-user@contoso.com", password: token }),
    });

    expect(res.status).toBe(401);
  });
});

describe("e2e: failClosed behavior", () => {
  it(
    "default (failClosed=false): Verdaccio boots with invalid config (plugin skipped)",
    { timeout: 90_000 },
    async () => {
      const image = await GenericContainer.fromDockerfile("./", "Dockerfile")
        .withCache(true)
        .build();

      const container = await image
        .withExposedPorts(4873)
        .withEnvironment({
          ENTRA_CLIENT_ID: "not-a-guid",
          ENTRA_TENANT_ID: "also-not-a-guid",
        })
        .withLogConsumer(logConsumer("failClosed=false"))
        .withWaitStrategy(Wait.forLogMessage("http address"))
        .withStartupTimeout(60_000)
        .start();

      try {
        const port = container.getMappedPort(4873);
        const res = await fetch(`http://${container.getHost()}:${port}/-/ping`);
        expect(res.ok).toBe(true);
      } finally {
        await container.stop().catch(() => {});
      }
    },
  );

  it("failClosed=true: Verdaccio crashes with invalid config", { timeout: 90_000 }, async () => {
    const image = await GenericContainer.fromDockerfile("./", "Dockerfile").withCache(true).build();

    // Wait.forOneShotStartup() expects exit code 0.
    // process.exit(1) exits non-zero, so start() rejects immediately.
    await expect(
      image
        .withEnvironment({
          ENTRA_CLIENT_ID: "not-a-guid",
          ENTRA_TENANT_ID: "also-not-a-guid",
          ENTRA_FAIL_CLOSED: "true",
        })
        .withLogConsumer(logConsumer("failClosed=true"))
        .withWaitStrategy(Wait.forOneShotStartup())
        .withStartupTimeout(60_000)
        .start(),
    ).rejects.toThrow();
  });
});
