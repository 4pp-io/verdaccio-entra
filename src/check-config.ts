/**
 * Config validation logic — no console.log or process.exit; performs network I/O via fetch.
 *
 * Used by:
 *   - src/cli.ts (CLI wrapper)
 *   - src/__tests__/check-config.test.ts (unit tests, no subprocess needed)
 */

import { GUID_RE, AUDIENCE_PREFIX, jwksUri, DEFAULT_AUTHORITY } from "./auth-plugin";

/** Per-attempt timeout (ms) for JWKS fetch. */
const JWKS_TIMEOUT_MS = 10_000;
/** Maximum number of fetch attempts before giving up. */
const JWKS_MAX_ATTEMPTS = 3;
/** Base delay (ms) for exponential back-off between retries. */
const JWKS_BACKOFF_BASE_MS = 1_000;

/** Returns true if the error is a timeout or network failure worth retrying. */
function isTransient(err: unknown): boolean {
  if (err instanceof DOMException && err.name === "TimeoutError") return true;
  if (err instanceof TypeError) return true; // fetch network errors
  return false;
}

/** Delay for `ms` milliseconds. */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch with retry + exponential back-off.
 *
 * Retries on:
 *   - Timeout / network errors (transient)
 *   - HTTP 429 (respects Retry-After header per Microsoft resilience guidance)
 *   - HTTP 5xx (server errors)
 *
 * Does NOT retry 4xx (except 429) — those indicate a real config problem.
 */
async function fetchWithRetry(url: string): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt < JWKS_MAX_ATTEMPTS; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(JWKS_TIMEOUT_MS) });

      if (res.status === 429 || res.status >= 500) {
        if (attempt < JWKS_MAX_ATTEMPTS - 1) {
          const retryAfter = res.headers.get("Retry-After");
          const waitMs = retryAfter
            ? Math.min(Number(retryAfter) * 1_000, 30_000)
            : JWKS_BACKOFF_BASE_MS * 2 ** attempt;
          await delay(waitMs);
          continue;
        }
      }

      return res;
    } catch (err) {
      lastError = err;
      if (attempt < JWKS_MAX_ATTEMPTS - 1 && isTransient(err)) {
        await delay(JWKS_BACKOFF_BASE_MS * 2 ** attempt);
        continue;
      }
      throw err;
    }
  }
  /* istanbul ignore next -- loop always returns or throws */
  throw lastError;
}

/**
 * Fetch the JWKS URI to verify reachability.
 * Retries transient failures with exponential back-off.
 * Proxy support via NODE_USE_ENV_PROXY=1 (Node 20.13+/21.7+).
 */
async function verifyJwksEndpoint(authority: string, tenantId: string): Promise<boolean> {
  const url = jwksUri(tenantId, authority);
  const res = await fetchWithRetry(url);
  if (!res.ok) {
    throw new Error(
      `JWKS endpoint unreachable: HTTP ${res.status} from ${url}. ` +
        "Verify your tenantId and authority are correct.",
    );
  }
  const data = (await res.json()) as unknown;
  if (!data || typeof data !== "object") {
    throw new Error(
      `JWKS endpoint returned invalid data: expected an object with a non-empty 'keys' array from ${url}.`,
    );
  }
  const keys = (data as Record<string, unknown>).keys;
  if (
    !Array.isArray(keys) ||
    keys.length === 0 ||
    keys.some(
      (k) =>
        !k ||
        typeof k !== "object" ||
        Array.isArray(k) ||
        typeof (k as Record<string, unknown>)["kty"] !== "string",
    )
  ) {
    throw new Error(
      `JWKS endpoint returned invalid data: expected an object with a non-empty 'keys' array of key objects from ${url}.`,
    );
  }
  return true;
}

interface CheckResult {
  label: string;
  ok: boolean;
  detail: string;
}

export interface CheckConfigInput {
  clientId: string;
  tenantId: string;
  /** Entra authority URL — defaults to Azure Public cloud */
  authority?: string;
}

/**
 * Run all config validation checks and return results.
 * Pure async function — no console.log, no process.exit.
 */
export async function runChecks(input: CheckConfigInput): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const { clientId, tenantId, authority = DEFAULT_AUTHORITY } = input;

  const check = (label: string, ok: boolean, detail: string): void => {
    results.push({ label, ok, detail });
  };

  // --- 1. Validate GUIDs ---
  check(
    "Client ID is set",
    clientId.length > 0,
    "Provide via --client-id flag or ENTRA_CLIENT_ID env var. " +
      "Find it at: Entra admin center > App registrations > [your app] > Overview > Application (client) ID.",
  );

  check(
    "Tenant ID is set",
    tenantId.length > 0,
    "Provide via --tenant-id flag or ENTRA_TENANT_ID env var. " +
      "Find it at: Entra admin center > App registrations > [your app] > Overview > Directory (tenant) ID.",
  );

  check(
    "Client ID is a valid GUID",
    GUID_RE.test(clientId),
    `Got "${clientId}". ` +
      "The Application (client) ID is a GUID like aaaabbbb-0000-cccc-1111-dddd2222eeee.",
  );

  check(
    "Tenant ID is a valid GUID",
    GUID_RE.test(tenantId),
    `Got "${tenantId}". ` +
      "The Directory (tenant) ID is a GUID like aaaabbbb-0000-cccc-1111-dddd2222eeee.",
  );

  // --- 2. Detect swapped/identical IDs ---
  if (GUID_RE.test(clientId) && GUID_RE.test(tenantId)) {
    check(
      "Client ID and Tenant ID are different",
      clientId.toLowerCase() !== tenantId.toLowerCase(),
      "They're identical — you probably pasted the same GUID twice. " +
        "clientId = Application (client) ID, tenantId = Directory (tenant) ID. " +
        "These are two different fields on the app registration Overview page.",
    );
  }

  // --- 3. JWKS endpoint validation (matching production behavior) ---
  if (GUID_RE.test(tenantId)) {
    try {
      await verifyJwksEndpoint(authority, tenantId);
      check("JWKS endpoint is reachable and returns keys", true, "");
    } catch (err) {
      // diagnostic: error recorded in results — caller decides exit code
      check(
        "JWKS endpoint is reachable and returns keys",
        false,
        `${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  return results;
}

/** Compute the expected audience URI for display */
export function expectedAudience(clientId: string): string {
  return `${AUDIENCE_PREFIX}${clientId}`;
}

/** Count failures in results */
export function countFailures(results: CheckResult[]): number {
  return results.filter((r) => !r.ok).length;
}
