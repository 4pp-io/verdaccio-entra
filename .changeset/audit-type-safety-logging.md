---
"@4pp-io/verdaccio-entra": patch
---

### Type safety and logging improvements

- Banned `as never` type assertions in tests via ESLint rule; replaced with properly typed mocks
- Added runtime shape guard (`assertEntraPayload`) after JWT verification to catch unexpected token claim types
- Rewrote all log messages with consistent `entra:` prefix, structured merge objects, and correct severity levels
- Fixed global fetch stub lifecycle in tests (save/restore via afterAll)
