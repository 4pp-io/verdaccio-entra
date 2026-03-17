import { describe, it, expect, beforeAll } from "vitest";
import { SignJWT, generateKeyPair, errors as joseErrors } from "jose";
import { TEST_TENANT, TEST_CLIENT } from "./fixtures";
import { detectSwappedIds, enrichJoseError } from "../diagnostics";
import type { EntraConfig } from "../../types/index";

let privateKey: CryptoKey;

const config: EntraConfig = { clientId: TEST_CLIENT, tenantId: TEST_TENANT };

beforeAll(async () => {
	const pair = await generateKeyPair("RS256");
	privateKey = pair.privateKey;
});

async function sign(claims: Record<string, unknown>): Promise<string> {
	return new SignJWT(claims)
		.setProtectedHeader({ alg: "RS256" })
		.setExpirationTime("1h")
		.sign(privateKey);
}

describe("detectSwappedIds", () => {
	it("returns undefined when IDs are correct", async () => {
		const token = await sign({ tid: TEST_TENANT, aud: `api://${TEST_CLIENT}` });
		expect(detectSwappedIds(token, config)).toBeUndefined();
	});

	it("detects when tid matches clientId (swapped)", async () => {
		const token = await sign({ tid: TEST_CLIENT, aud: `api://${TEST_TENANT}` });
		const hint = detectSwappedIds(token, config);
		expect(hint).toContain("swapped");
	});

	it("detects when aud contains tenantId (swapped)", async () => {
		const token = await sign({ tid: "99999999-9999-9999-9999-999999999999", aud: `api://${TEST_TENANT}` });
		const hint = detectSwappedIds(token, config);
		expect(hint).toContain("swapped");
	});

	it("returns undefined for non-JWT string", () => {
		expect(detectSwappedIds("garbage", config)).toBeUndefined();
	});
});

describe("enrichJoseError", () => {
	it("enriches JWTExpired", async () => {
		const err = new joseErrors.JWTExpired("token expired", { exp: 0 });
		const msg = enrichJoseError(err, await sign({}), config);
		expect(msg).toContain("expired");
	});

	it("enriches audience claim failure", async () => {
		const err = new joseErrors.JWTClaimValidationFailed("bad aud", {}, "aud", "check_failed");
		const msg = enrichJoseError(err, await sign({}), config);
		expect(msg).toContain("audience mismatch");
	});

	it("enriches issuer claim failure", async () => {
		const err = new joseErrors.JWTClaimValidationFailed("bad iss", {}, "iss", "check_failed");
		const msg = enrichJoseError(err, await sign({}), config);
		expect(msg).toContain("issuer mismatch");
	});

	it("enriches nbf claim failure", async () => {
		const err = new joseErrors.JWTClaimValidationFailed("not before", {}, "nbf", "check_failed");
		const msg = enrichJoseError(err, await sign({}), config);
		expect(msg).toContain("not yet valid");
	});

	it("enriches signature verification failure", async () => {
		const err = new joseErrors.JWSSignatureVerificationFailed();
		const msg = enrichJoseError(err, await sign({}), config);
		expect(msg).toContain("signature verification failed");
	});

	it("returns generic message for unknown errors", async () => {
		const err = new Error("something weird");
		const msg = enrichJoseError(err, await sign({}), config);
		expect(msg).toContain("something weird");
	});

	it("includes swap hint when IDs are swapped", async () => {
		const err = new joseErrors.JWTClaimValidationFailed("bad aud", {}, "aud", "check_failed");
		const token = await sign({ tid: TEST_CLIENT, aud: `api://${TEST_TENANT}` });
		const msg = enrichJoseError(err, token, config);
		expect(msg).toContain("swapped");
	});
});
