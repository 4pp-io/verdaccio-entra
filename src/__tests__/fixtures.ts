/**
 * Shared test constants — single source of truth for all test files.
 *
 * Uses Microsoft Learn documentation placeholder GUIDs.
 * @see https://learn.microsoft.com/entra/identity-platform/reference-app-manifest
 */

/** Microsoft Learn placeholder tenant ID */
export const TEST_TENANT = "aaaabbbb-0000-cccc-1111-dddd2222eeee";

/** Microsoft Learn placeholder client (application) ID */
export const TEST_CLIENT = "00001111-aaaa-2222-bbbb-3333cccc4444";

/** Microsoft's own public tenant — always has a valid JWKS endpoint */
export const MICROSOFT_TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47";

/** JWKS key ID used in test RSA key pair */
export const TEST_KID = "test-kid-001";
