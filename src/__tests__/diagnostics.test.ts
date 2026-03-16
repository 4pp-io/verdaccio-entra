import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { TEST_TENANT, TEST_CLIENT } from "./fixtures";
import { detectSwappedIds, enrichVerifyError } from "../diagnostics";
import type { EntraConfig } from "../../types/index";

const { privateKey } = crypto.generateKeyPairSync("rsa", {
	modulusLength: 2048,
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const config: EntraConfig = { clientId: TEST_CLIENT, tenantId: TEST_TENANT };

function sign(claims: Record<string, unknown>): string {
	return jwt.sign(claims, privateKey, { algorithm: "RS256" } as jwt.SignOptions);
}

describe("detectSwappedIds", () => {
	it("returns undefined when IDs are correct", () => {
		const token = sign({ tid: TEST_TENANT, aud: `api://${TEST_CLIENT}` });
		expect(detectSwappedIds(token, config)).toBeUndefined();
	});

	it("detects when tid matches clientId (swapped)", () => {
		const token = sign({ tid: TEST_CLIENT, aud: `api://${TEST_TENANT}` });
		const hint = detectSwappedIds(token, config);
		expect(hint).toContain("swapped");
		expect(hint).toContain(TEST_CLIENT);
	});

	it("detects when aud contains tenantId (swapped)", () => {
		const token = sign({ tid: "99999999-9999-9999-9999-999999999999", aud: `api://${TEST_TENANT}` });
		const hint = detectSwappedIds(token, config);
		expect(hint).toContain("swapped");
		expect(hint).toContain(TEST_TENANT);
	});

	it("returns undefined for non-JWT string", () => {
		expect(detectSwappedIds("garbage", config)).toBeUndefined();
	});
});

describe("enrichVerifyError", () => {
	it("enriches TokenExpiredError", () => {
		const err = Object.assign(new Error("jwt expired"), { name: "TokenExpiredError" }) as jwt.VerifyErrors;
		const msg = enrichVerifyError(err, sign({}), config);
		expect(msg).toContain("expired");
	});

	it("enriches NotBeforeError", () => {
		const err = Object.assign(new Error("jwt not active"), { name: "NotBeforeError" }) as jwt.VerifyErrors;
		const msg = enrichVerifyError(err, sign({}), config);
		expect(msg).toContain("not yet valid");
	});

	it("enriches audience mismatch", () => {
		const err = Object.assign(new Error("jwt audience invalid"), { name: "JsonWebTokenError" }) as jwt.VerifyErrors;
		const msg = enrichVerifyError(err, sign({}), config);
		expect(msg).toContain("audience mismatch");
	});

	it("enriches issuer mismatch", () => {
		const err = Object.assign(new Error("jwt issuer invalid"), { name: "JsonWebTokenError" }) as jwt.VerifyErrors;
		const msg = enrichVerifyError(err, sign({}), config);
		expect(msg).toContain("issuer mismatch");
	});

	it("returns generic message for unknown errors", () => {
		const err = Object.assign(new Error("something else"), { name: "JsonWebTokenError" }) as jwt.VerifyErrors;
		const msg = enrichVerifyError(err, sign({}), config);
		expect(msg).toContain("something else");
	});

	it("includes swap hint when IDs are swapped", () => {
		const err = Object.assign(new Error("jwt audience invalid"), { name: "JsonWebTokenError" }) as jwt.VerifyErrors;
		const token = sign({ tid: TEST_CLIENT, aud: `api://${TEST_TENANT}` });
		const msg = enrichVerifyError(err, token, config);
		expect(msg).toContain("swapped");
	});
});
