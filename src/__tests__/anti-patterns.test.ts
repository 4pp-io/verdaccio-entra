/**
 * Anti-pattern tests — enforce architectural invariants via source scanning.
 *
 * These are guardrails, not unit tests. They grep source files to catch
 * patterns that slip past linters and type-checkers. Organized by the
 * principle being protected, not the specific bug that introduced them.
 */

import { describe, it } from "vitest";
import fs from "node:fs";
import path from "node:path";

const srcDir = path.resolve(__dirname, "..");

function sourceFiles(): string[] {
	return fs.readdirSync(srcDir)
		.filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
		.filter((f) => !f.startsWith("__"));
}

function forEachSourceLine(cb: (file: string, line: string, lineNum: number) => void): void {
	for (const file of sourceFiles()) {
		const lines = fs.readFileSync(path.join(srcDir, file), "utf-8").split("\n");
		for (let i = 0; i < lines.length; i++) {
			cb(file, lines[i] ?? "", i + 1);
		}
	}
}

function fail(file: string, line: number, rule: string, detail: string): never {
	throw new Error(`${file}:${line} — ${rule}\n  ${detail}`);
}

// === Principle: Plugins are guests in the host process ===

describe("process isolation", () => {
	it("no global state mutation (setGlobalDispatcher, global assignments)", () => {
		forEachSourceLine((file, line, num) => {
			if (/setGlobalDispatcher|globalThis\.\w+\s*=/.test(line) && !line.trim().startsWith("//")) {
				fail(file, num, "no global mutation", line.trim());
			}
		});
	});

	it("no process.env writes", () => {
		forEachSourceLine((file, line, num) => {
			if (/process\.env\s*\[.*\]\s*=/.test(line)) {
				fail(file, num, "no env mutation", line.trim());
			}
		});
	});

	it("no console output — use the host framework's structured logger", () => {
		forEachSourceLine((file, line, num) => {
			if (/\bconsole\.(log|warn|error|info|debug)\s*\(/.test(line) && !line.trim().startsWith("//")) {
				fail(file, num, "no console — use this._logger", line.trim());
			}
		});
	});
});

// === Principle: Proxy support via NODE_USE_ENV_PROXY, not custom code ===

describe("proxy safety", () => {
	it("no undici imports — proxy is handled by NODE_USE_ENV_PROXY=1", () => {
		// Node 22.21+ has built-in proxy support for both fetch() and https.request().
		// No custom proxy agents, dispatchers, or undici imports needed.
		forEachSourceLine((file, line, num) => {
			if (/from\s+["']undici["']|require\s*\(\s*["']undici["']\s*\)/.test(line)) {
				fail(file, num, "no undici — use NODE_USE_ENV_PROXY=1 for proxy support", line.trim());
			}
		});
	});
});

// === Principle: Respect framework boundaries ===

describe("framework compliance", () => {
	it("authenticate enforces username matches token identity — no spoofing", () => {
		// The `user` arg from npm login is attacker-controlled. The plugin must
		// verify it matches the Entra identity before passing it to Verdaccio,
		// otherwise package metadata can be spoofed.
		const content = fs.readFileSync(path.join(srcDir, "auth-plugin.ts"), "utf-8");
		const hasUsernameCheck = /user\.toLowerCase\(\)\s*!==\s*upn\.toLowerCase\(\)/.test(content);
		if (!hasUsernameCheck) {
			throw new Error(
				"auth-plugin.ts does not enforce username === token identity. " +
					"npm login allows arbitrary usernames — the plugin must verify the match.",
			);
		}
	});

	it("no authorization hooks — the host framework handles authz from authenticate() groups", () => {
		const banned = ["allow_access", "allow_publish", "allow_unpublish", "adduser"];
		forEachSourceLine((file, line, num) => {
			for (const method of banned) {
				if (new RegExp(`\\b${method}\\s*\\(`).test(line)) {
					fail(file, num, `no ${method}() — framework handles this natively`, line.trim());
				}
			}
		});
	});
});

// === Principle: Cryptographic boundaries are sacred ===

describe("cryptographic hygiene", () => {
	it("no string-matching on dependency error messages for control flow", () => {
		// diagnostics.ts is exempt — it enriches logs post-verification, not auth decisions
		const exemptFiles = new Set(["diagnostics.ts"]);
		forEachSourceLine((file, line, num) => {
			if (exemptFiles.has(file)) return;
			if (/err\.message\.includes\(/.test(line)) {
				fail(file, num, "no error string matching — use typed errors or error.name", line.trim());
			}
		});
	});
});

// === Principle: Type safety has no escape hatches ===

describe("type safety", () => {
	it("no double-casting through unknown (as unknown as)", () => {
		forEachSourceLine((file, line, num) => {
			if (/as unknown as/.test(line)) {
				fail(file, num, "no double-cast — use intersection types or proper generics", line.trim());
			}
		});
	});
});

// === Principle: No hardcoded environment assumptions ===

describe("portability", () => {
	it("no hardcoded cloud provider URLs outside of exported defaults", () => {
		const urlPattern = /login\.microsoftonline\.(com|us|cn)|sts\.windows\.net/;
		const allowedContexts = ["export const", "DEFAULT_AUTHORITY", ".replace("];

		forEachSourceLine((file, line, num) => {
			if (!urlPattern.test(line)) return;
			if (allowedContexts.some((ctx) => line.includes(ctx))) return;
			if (line.trim().startsWith("//") || line.trim().startsWith("*")) return;
			fail(file, num, "no hardcoded authority URLs — use configurable defaults", line.trim());
		});
	});

	it("no hardcoded absolute filesystem paths", () => {
		forEachSourceLine((file, line, num) => {
			if (line.trim().startsWith("//") || line.trim().startsWith("*")) return;
			if (/["'`]\/usr\/|["'`]\/opt\/|["'`]\/verdaccio\/|["'`][A-Z]:\\/.test(line)) {
				fail(file, num, "no absolute paths — use relative paths or config", line.trim());
			}
		});
	});
});

// === Principle: Errors are never silently swallowed ===

describe("error handling", () => {
	it("catch blocks always escalate or are explicitly marked as diagnostic", () => {
		// Security-critical code (auth-plugin) must escalate: throw, reject, cb(error), or logger.error.
		// Diagnostic code (check-config, diagnostics) may record-and-continue IF the catch block
		// contains the marker comment "diagnostic: error recorded in results" to prove intent.
		//
		// This prevents silent swallowing while allowing diagnostic tools to
		// collect multiple failures in a single run.
		const escalationPattern = /throw\b|reject\(|cb\(|this\._logger\.error/;
		const diagnosticMarker = /diagnostic: error recorded/;

		for (const file of sourceFiles()) {
			const content = fs.readFileSync(path.join(srcDir, file), "utf-8");
			const catchBlocks = content.match(/catch\s*\([^)]*\)\s*\{[^}]*\}/gs) ?? [];
			for (const block of catchBlocks) {
				const escalates = escalationPattern.test(block);
				const markedDiagnostic = diagnosticMarker.test(block);
				if (!escalates && !markedDiagnostic) {
					throw new Error(
						`${file} has a catch block that neither escalates nor is marked diagnostic:\n  ${block.slice(0, 200)}`,
					);
				}
			}
		}
	});
});
