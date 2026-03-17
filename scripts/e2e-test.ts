#!/usr/bin/env tsx
/**
 * Offline end-to-end test for verdaccio-entra.
 *
 * Runs entirely locally — no Azure tenant needed.
 *
 * 1. Generates an RSA key pair
 * 2. Starts a mock JWKS server on the host
 * 3. Builds and runs Verdaccio in Docker with the plugin pointing at the mock
 * 4. Signs a JWT with valid Entra-like claims
 * 5. Hits Verdaccio's npm login API with the token
 * 6. Asserts authentication succeeds
 */

import { createServer } from "node:http";
import { execSync } from "node:child_process";
import { generateKeyPair, exportJWK, SignJWT } from "jose";

const TEST_TENANT = "aaaabbbb-0000-cccc-1111-dddd2222eeee";
const TEST_CLIENT = "11112222-3333-4444-5555-666677778888";
const TEST_KID = "e2e-test-key";
const TEST_USER = "e2e-user@contoso.com";
const MOCK_PORT = 49877;
const VERDACCIO_PORT = 49873;
// Podman uses host.containers.internal; Docker uses host.docker.internal
const HOST_GATEWAY = "host.containers.internal";

async function main(): Promise<void> {
	console.log("\n=== verdaccio-entra e2e test ===\n");

	// 1. Generate RSA key pair
	console.log("1. Generating RSA key pair...");
	const { privateKey, publicKey } = await generateKeyPair("RS256");
	const publicJwk = { ...(await exportJWK(publicKey)), kid: TEST_KID, use: "sig", alg: "RS256" };

	// 2. Start mock JWKS server
	console.log("2. Starting mock JWKS server on port %d...", MOCK_PORT);
	const jwksResponse = JSON.stringify({ keys: [publicJwk] });
	const authority = `http://${HOST_GATEWAY}:${MOCK_PORT}`;
	const expectedIssuer = `${authority}/${TEST_TENANT}/v2.0`;
	const expectedAudience = `api://${TEST_CLIENT}`;

	const server = createServer((req, res) => {
		const url = req.url ?? "";
		console.log("   JWKS server: %s %s", req.method, url);
		if (url.includes("discovery/v2.0/keys")) {
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(jwksResponse);
		} else {
			res.writeHead(404);
			res.end("not found");
		}
	});

	await new Promise<void>((resolve) => server.listen(MOCK_PORT, resolve));
	console.log("   Mock JWKS server listening on 0.0.0.0:%d", MOCK_PORT);

	try {
		// 3. Sign a JWT
		console.log("3. Signing JWT for %s...", TEST_USER);
		const token = await new SignJWT({
			preferred_username: TEST_USER,
			iss: expectedIssuer,
			aud: expectedAudience,
			groups: ["developers"],
			roles: ["registry-admin"],
		})
			.setProtectedHeader({ alg: "RS256", kid: TEST_KID })
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(privateKey);

		console.log("   Token signed (%d chars)", token.length);

		// 4. Start Verdaccio in Docker
		console.log("4. Starting Verdaccio in Docker...");
		try {
			execSync("docker stop verdaccio-e2e 2>/dev/null", { stdio: "ignore" });
		} catch { /* ignore */ }
		try {
			execSync("docker rm verdaccio-e2e 2>/dev/null", { stdio: "ignore" });
		} catch { /* ignore */ }

		execSync(
			`docker run -d --name verdaccio-e2e ` +
			`-p ${VERDACCIO_PORT}:4873 ` +
			`-e ENTRA_CLIENT_ID=${TEST_CLIENT} ` +
			`-e ENTRA_TENANT_ID=${TEST_TENANT} ` +
			`-e "ENTRA_AUTHORITY=${authority}" ` +
			`verdaccio-entra-test`,
			{ stdio: "inherit" },
		);

		// Wait for Verdaccio to be ready
		console.log("   Waiting for Verdaccio to start...");
		await waitForHttp(`http://localhost:${VERDACCIO_PORT}/-/ping`, 15000);
		console.log("   Verdaccio is up!");

		// 5. Hit the login API
		console.log("5. Authenticating against Verdaccio...");
		const loginUrl = `http://localhost:${VERDACCIO_PORT}/-/user/org.couchdb.user:${TEST_USER}`;
		const res = await fetch(loginUrl, {
			method: "PUT",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				name: TEST_USER,
				password: token,
			}),
		});

		const body = await res.text();
		console.log("   Response: %d %s", res.status, body.slice(0, 200));

		// 6. Assert
		if (res.status === 201 || res.status === 200) {
			const json = JSON.parse(body);
			if (json.token || json.ok) {
				console.log("\n   *** E2E TEST PASSED ***\n");
				console.log("   User: %s", TEST_USER);
				console.log("   Groups: [developers, registry-admin]");
				console.log("   Verdaccio issued token: %s", json.token ? "yes" : "ok response");
			} else {
				console.error("\n   *** E2E TEST FAILED — unexpected response body ***\n", body);
				process.exit(1);
			}
		} else {
			console.error("\n   *** E2E TEST FAILED — HTTP %d ***\n", res.status);
			console.error("   Body:", body);
			// Dump Verdaccio logs for debugging
			try {
				const logs = execSync("docker logs verdaccio-e2e 2>&1", { encoding: "utf-8" });
				console.error("\n   --- Verdaccio logs ---\n%s", logs);
			} catch { /* ignore */ }
			process.exit(1);
		}
	} finally {
		server.close();
		try {
			execSync("docker stop verdaccio-e2e 2>/dev/null", { stdio: "ignore" });
		} catch { /* ignore */ }
	}
}

async function waitForHttp(url: string, timeoutMs: number): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			const res = await fetch(url);
			if (res.ok) return;
		} catch { /* retry */ }
		await new Promise((r) => setTimeout(r, 500));
	}
	throw new Error(`Timeout waiting for ${url}`);
}

main().catch((err) => {
	console.error("E2E test error:", err);
	process.exit(1);
});
