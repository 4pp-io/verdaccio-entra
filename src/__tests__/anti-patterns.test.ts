/**
 * Anti-pattern tests — enforce architectural invariants via source scanning.
 *
 * These tests grep the actual source files to prevent regressions on
 * patterns that linters can't easily catch.
 */

import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";

const srcDir = path.resolve(__dirname, "..");

function readSource(filename: string): string {
	return fs.readFileSync(path.join(srcDir, filename), "utf-8");
}

function sourceFiles(): string[] {
	return fs.readdirSync(srcDir)
		.filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
		.filter((f) => !f.startsWith("__"));
}

describe("anti-patterns", () => {
	it("source files never use bare global fetch — must use undici or injected fetcher", () => {
		// Bare fetch() bypasses HTTP_PROXY/HTTPS_PROXY on Node 22.
		// All network calls must go through undici's fetch (with proxy dispatcher)
		// or an injected fetcher parameter.
		//
		// Allowed:
		//   import { fetch as undiciFetch } from "undici"  ← proxy-aware
		//   fetcher = fetch  ← parameter default in check-config (injected in tests)
		//   typeof fetch     ← type annotation only
		//
		// Banned:
		//   await fetch(url)          ← bare global fetch, no proxy
		//   const res = fetch(url)    ← same
		//
		// The regex matches `fetch(` that is NOT preceded by a word character
		// (to avoid matching `undiciFetch(` or `mockFetch(` or `fetcher(`).
		const bareCallPattern = /(?<!\w)fetch\s*\(/g;
		const allowedContexts = [
			"typeof fetch",      // Type annotations
			"fetcher = fetch",   // Default parameter (injected in prod, mocked in tests)
			"as undiciFetch",    // Import alias
			"fetch as",          // Import alias
		];

		for (const file of sourceFiles()) {
			const content = readSource(file);
			const lines = content.split("\n");
			for (let i = 0; i < lines.length; i++) {
				const line = lines[i] ?? "";
				if (!bareCallPattern.test(line)) continue;
				// Reset lastIndex for stateful regex
				bareCallPattern.lastIndex = 0;

				const isAllowed = allowedContexts.some((ctx) => line.includes(ctx));
				if (!isAllowed) {
					throw new Error(
						`${file}:${i + 1} uses bare global fetch() which bypasses HTTP_PROXY. ` +
							"Use undici's fetch with the scoped proxy agent, or accept a fetcher parameter.\n" +
							`  Line: ${line.trim()}`,
					);
				}
			}
		}
	});

	it("source files never use setGlobalDispatcher — proxy must be scoped", () => {
		for (const file of sourceFiles()) {
			const content = readSource(file);
			expect(content).not.toContain("setGlobalDispatcher");
		}
	});

	it("source files never implement allow_access/allow_publish/allow_unpublish — Verdaccio handles authz", () => {
		// These are AuthZ hooks that Verdaccio handles natively from the groups
		// returned by authenticate(). Implementing them in an AuthN plugin breaks
		// user-level package access controls.
		const bannedMethods = ["allow_access", "allow_publish", "allow_unpublish"];
		for (const file of sourceFiles()) {
			const content = readSource(file);
			for (const method of bannedMethods) {
				const methodPattern = new RegExp(`\\b${method}\\s*\\(`, "g");
				if (methodPattern.test(content)) {
					throw new Error(
						`${file} implements ${method}() — this is an AuthZ hook that Verdaccio handles natively. ` +
							"The plugin should only implement authenticate() and return groups.",
					);
				}
			}
		}
	});

	it("source files never mutate process.env", () => {
		for (const file of sourceFiles()) {
			const content = readSource(file);
			if (/process\.env\s*\[.*\]\s*=/.test(content)) {
				throw new Error(
					`${file} mutates process.env — plugins must not modify the host process environment.`,
				);
			}
		}
	});
});
