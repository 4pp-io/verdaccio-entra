/**
 * Standalone mock JWKS server for e2e testing.
 *
 * 1. Generates an RSA key pair
 * 2. Exposes the private key (JWK) + test metadata at http://0.0.0.0:9877/_test/keys.json
 *    so the test runner can sign tokens
 * 3. Serves JWKS on http://0.0.0.0:9877/{tenantId}/discovery/v2.0/keys
 */

import { createServer } from "node:http";
import { generateKeyPair, exportJWK } from "jose";

const PORT = 9877;
const KID = "e2e-test-key";

async function main() {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const publicJwk = { ...(await exportJWK(publicKey)), kid: KID, use: "sig", alg: "RS256" };
  const privateJwk = { ...(await exportJWK(privateKey)), kid: KID, alg: "RS256" };
  const jwksJson = JSON.stringify({ keys: [publicJwk] });

  const keysJson = JSON.stringify({ privateJwk, kid: KID });

  const server = createServer((req, res) => {
    const safeUrl = (req.url ?? "").replace(/[\x00-\x1F\x7F]/g, "");
    console.log("%s %s", req.method, safeUrl);
    if (req.url?.includes("discovery/v2.0/keys")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(jwksJson);
    } else if (req.url === "/_test/keys.json") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(keysJson);
    } else {
      res.writeHead(404);
      res.end("not found");
    }
  });

  server.listen(PORT, "0.0.0.0", () => {
    console.log("Mock JWKS server listening on :%d", PORT);
  });
}

main().catch((err) => {
  console.error("Failed to start mock JWKS server:", err);
  process.exit(1);
});
