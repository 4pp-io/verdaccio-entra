import { describe, it, expect, vi, afterAll, beforeEach, afterEach } from "vitest";
import { TEST_TENANT, TEST_CLIENT } from "./fixtures";
import { runChecks, countFailures, expectedAudience } from "../check-config";
import type { CheckConfigInput } from "../check-config";

const originalFetch = globalThis.fetch;
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

afterAll(() => {
  vi.stubGlobal("fetch", originalFetch);
});

afterEach(() => {
  vi.useRealTimers();
});

function setJwksSuccess(): void {
  mockFetch.mockResolvedValue({
    ok: true,
    json: () =>
      Promise.resolve({
        keys: [{ kid: "test-key", kty: "RSA" }],
      }),
  });
}

function setJwksFailure(): void {
  mockFetch.mockResolvedValue({ ok: false, status: 400 });
}

function setJwksInvalidShape(): void {
  mockFetch.mockResolvedValue({
    ok: true,
    json: () =>
      Promise.resolve({
        keys: "not-an-array",
      }),
  });
}

function input(overrides?: Partial<CheckConfigInput>): CheckConfigInput {
  return {
    clientId: TEST_CLIENT,
    tenantId: TEST_TENANT,
    ...overrides,
  };
}

beforeEach(() => {
  mockFetch.mockReset();
  setJwksSuccess();
});

describe("runChecks", () => {
  it("passes all checks with valid config", async () => {
    const results = await runChecks(input());
    const failures = countFailures(results);
    expect(failures).toBe(0);
    expect(results.some((r) => r.label === "Client ID is set" && r.ok)).toBe(true);
    expect(
      results.some((r) => r.label === "JWKS endpoint is reachable and returns keys" && r.ok),
    ).toBe(true);
  });

  it("fails when client ID is empty", async () => {
    const results = await runChecks(input({ clientId: "" }));
    expect(results.some((r) => r.label === "Client ID is set" && !r.ok)).toBe(true);
  });

  it("fails when tenant ID is empty", async () => {
    const results = await runChecks(input({ tenantId: "" }));
    expect(results.some((r) => r.label === "Tenant ID is set" && !r.ok)).toBe(true);
  });

  it("fails on non-GUID client ID", async () => {
    const results = await runChecks(input({ clientId: "not-a-guid" }));
    const fail = results.find((r) => r.label === "Client ID is a valid GUID");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("not-a-guid");
  });

  it("fails on non-GUID tenant ID", async () => {
    const results = await runChecks(input({ tenantId: "bad" }));
    const fail = results.find((r) => r.label === "Tenant ID is a valid GUID");
    expect(fail?.ok).toBe(false);
  });

  it("detects identical client and tenant IDs", async () => {
    const results = await runChecks(input({ clientId: TEST_TENANT, tenantId: TEST_TENANT }));
    const fail = results.find((r) => r.label === "Client ID and Tenant ID are different");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("pasted the same GUID twice");
  });

  it("skips identity check when IDs are not GUIDs", async () => {
    const results = await runChecks(input({ clientId: "bad", tenantId: "bad" }));
    expect(
      results.find((r) => r.label === "Client ID and Tenant ID are different"),
    ).toBeUndefined();
  });

  it("detects JWKS endpoint failure", async () => {
    setJwksFailure();
    const results = await runChecks(input());
    const fail = results.find((r) => r.label === "JWKS endpoint is reachable and returns keys");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("JWKS endpoint unreachable: HTTP 400");
  });

  it("detects invalid JWKS shape", async () => {
    setJwksInvalidShape();
    const results = await runChecks(input());
    const fail = results.find((r) => r.label === "JWKS endpoint is reachable and returns keys");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("invalid data");
  });

  it("detects null JWKS response", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(null),
    });
    const results = await runChecks(input());
    const fail = results.find((r) => r.label === "JWKS endpoint is reachable and returns keys");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("invalid data");
  });

  it("detects empty JWKS keys array", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ keys: [] }),
    });
    const results = await runChecks(input());
    const fail = results.find((r) => r.label === "JWKS endpoint is reachable and returns keys");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("invalid data");
  });

  it("detects JWKS keys array with invalid objects", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ keys: ["string-not-object"] }),
    });
    const results = await runChecks(input());
    const fail = results.find((r) => r.label === "JWKS endpoint is reachable and returns keys");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("invalid data");
  });

  it("detects JWKS keys that are arrays instead of objects", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ keys: [["not", "an", "object"]] }),
    });
    const results = await runChecks(input());
    const fail = results.find((r) => r.label === "JWKS endpoint is reachable and returns keys");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("invalid data");
  });

  it("detects JWKS keys missing kty field", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ keys: [{ kid: "test-key" }] }),
    });
    const results = await runChecks(input());
    const fail = results.find((r) => r.label === "JWKS endpoint is reachable and returns keys");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("invalid data");
  });

  it("handles network error gracefully", async () => {
    mockFetch.mockRejectedValue(new Error("ENOTFOUND"));
    const results = await runChecks(input());
    const fail = results.find((r) => r.label === "JWKS endpoint is reachable and returns keys");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("ENOTFOUND");
  });

  it("skips network checks when tenant is not a valid GUID", async () => {
    const results = await runChecks(input({ tenantId: "not-guid" }));
    expect(
      results.find((r) => r.label === "JWKS endpoint is reachable and returns keys"),
    ).toBeUndefined();
  });
});

describe("retry behavior", () => {
  it("retries on 5xx then succeeds", async () => {
    vi.useFakeTimers();
    mockFetch
      .mockResolvedValueOnce({ ok: false, status: 503, headers: new Headers() })
      .mockResolvedValueOnce({ ok: false, status: 502, headers: new Headers() })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: "k", kty: "RSA" }] }),
      });
    const promise = runChecks(input());
    await vi.runAllTimersAsync();
    const results = await promise;
    expect(results.find((r) => r.label === "JWKS endpoint is reachable and returns keys")?.ok).toBe(
      true,
    );
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it("retries on network error (TypeError) then succeeds", async () => {
    vi.useFakeTimers();
    mockFetch.mockRejectedValueOnce(new TypeError("fetch failed")).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ keys: [{ kid: "k", kty: "RSA" }] }),
    });
    const promise = runChecks(input());
    await vi.runAllTimersAsync();
    const results = await promise;
    expect(results.find((r) => r.label === "JWKS endpoint is reachable and returns keys")?.ok).toBe(
      true,
    );
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("retries on timeout (DOMException) then succeeds", async () => {
    vi.useFakeTimers();
    const timeoutErr = new DOMException("The operation was aborted", "TimeoutError");
    mockFetch.mockRejectedValueOnce(timeoutErr).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ keys: [{ kid: "k", kty: "RSA" }] }),
    });
    const promise = runChecks(input());
    await vi.runAllTimersAsync();
    const results = await promise;
    expect(results.find((r) => r.label === "JWKS endpoint is reachable and returns keys")?.ok).toBe(
      true,
    );
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("does not retry on 4xx (config error)", async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 404, headers: new Headers() });
    const results = await runChecks(input());
    const fail = results.find((r) => r.label === "JWKS endpoint is reachable and returns keys");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("HTTP 404");
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("gives up after max attempts on persistent 5xx", async () => {
    vi.useFakeTimers();
    const headers = new Headers();
    mockFetch
      .mockResolvedValueOnce({ ok: false, status: 500, headers })
      .mockResolvedValueOnce({ ok: false, status: 500, headers })
      .mockResolvedValueOnce({ ok: false, status: 500, headers });
    const promise = runChecks(input());
    await vi.runAllTimersAsync();
    const results = await promise;
    const fail = results.find((r) => r.label === "JWKS endpoint is reachable and returns keys");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("HTTP 500");
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it("respects Retry-After header on 429", async () => {
    vi.useFakeTimers();
    const headers429 = new Headers({ "Retry-After": "1" });
    mockFetch
      .mockResolvedValueOnce({ ok: false, status: 429, headers: headers429 })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ keys: [{ kid: "k", kty: "RSA" }] }),
      });
    const promise = runChecks(input());
    await vi.runAllTimersAsync();
    const results = await promise;
    expect(results.find((r) => r.label === "JWKS endpoint is reachable and returns keys")?.ok).toBe(
      true,
    );
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("throws on non-transient error without retry", async () => {
    const err = new Error("unexpected");
    mockFetch.mockRejectedValueOnce(err);
    const results = await runChecks(input());
    const fail = results.find((r) => r.label === "JWKS endpoint is reachable and returns keys");
    expect(fail?.ok).toBe(false);
    expect(fail?.detail).toContain("unexpected");
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

describe("helpers", () => {
  it("expectedAudience returns api:// prefixed client ID", () => {
    expect(expectedAudience(TEST_CLIENT)).toBe(`api://${TEST_CLIENT}`);
  });

  it("countFailures counts only failed results", () => {
    expect(
      countFailures([
        { label: "a", ok: true, detail: "" },
        { label: "b", ok: false, detail: "fail" },
        { label: "c", ok: false, detail: "fail" },
      ]),
    ).toBe(2);
  });
});
