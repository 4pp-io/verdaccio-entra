---
"@4pp-io/verdaccio-entra": patch
---

Add Prettier for consistent formatting across the codebase. Normalize all files to 2-space indentation, enforce LF line endings via .gitattributes, and add a format check to CI. The changesets version script now auto-formats so the Version Packages PR stays clean.
