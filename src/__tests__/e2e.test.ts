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
		const mockJwksImage = await GenericContainer.fromDockerfile("./", "scripts/mock-jwks.Dockerfile").build();

		// Build Verdaccio plugin image
		const verdaccioImage = await GenericContainer.fromDockerfile("./", "Dockerfile").build();

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
		verdaccio = await verdaccioImage
			.withNetwork(network)
			.withExposedPorts(4873)
			.withEnvironment({
				ENTRA_CLIENT_ID: TEST_CLIENT,
				ENTRA_TENANT_ID: TEST_TENANT,
				ENTRA_AUTHORITY: "http://mock-jwks:9877",
			})
			.withLogConsumer(logConsumer("verdaccio"))
			.withWaitStrategy(Wait.forLogMessage("EntraPlugin ready"))
			.withStartupTimeout(60_000)
			.start();

		const port = verdaccio.getMappedPort(4873);
		verdaccioUrl = `http://${verdaccio.getHost()}:${port}`;

		// Wait for HTTP ready
		const start = Date.now();
		while (Date.now() - start < 15_000) {
			try {
				const res = await fetch(`${verdaccioUrl}/-/ping`);
				if (res.ok) break;
			} catch { /* retry */ }
			await new Promise((r) => setTimeout(r, 500));
		}
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
		const token = await new SignJWT({
			preferred_username: TEST_USER,
			iss: `${authority}/${TEST_TENANT}/v2.0`,
			aud: `api://${TEST_CLIENT}`,
			groups: ["developers"],
			roles: ["registry-admin"],
		})
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

	it("rejects username mismatch (anti-spoofing)", async () => {
		const mockJwksHost = mockJwks.getHost();
		const mockJwksPort = mockJwks.getMappedPort(9877);
		const keysRes = await fetch(`http://${mockJwksHost}:${mockJwksPort}/_test/keys.json`);
		const { privateJwk, kid } = await keysRes.json();
		const privateKey = await importJWK(privateJwk, "RS256");

		const authority = "http://mock-jwks:9877";
		const token = await new SignJWT({
			preferred_username: "real-user@contoso.com",
			iss: `${authority}/${TEST_TENANT}/v2.0`,
			aud: `api://${TEST_CLIENT}`,
		})
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
