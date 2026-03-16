import { describe, it, expect, vi } from "vitest";
import type { PackageAccess, RemoteUser } from "@verdaccio/types";
import { TEST_TENANT, TEST_CLIENT } from "./fixtures";
import { ISSUERS } from "../auth-plugin";

// Mock fetch for OIDC discovery
vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
	ok: true,
	json: () => Promise.resolve({
		issuer: ISSUERS.v2(TEST_TENANT),
		jwks_uri: `https://login.microsoftonline.com/${TEST_TENANT}/discovery/v2.0/keys`,
	}),
}));

// Mock jwks-rsa (required before importing the plugin)
vi.mock("jwks-rsa", () => ({
	default: () => ({
		getSigningKey: vi.fn(),
	}),
}));

import EntraPlugin from "../auth-plugin";

function createPlugin(): EntraPlugin {
	return new EntraPlugin(
		{ clientId: TEST_CLIENT, tenantId: TEST_TENANT } as never,
		{
			logger: {
				info: vi.fn(),
				warn: vi.fn(),
				error: vi.fn(),
				debug: vi.fn(),
				trace: vi.fn(),
				child: vi.fn(),
				http: vi.fn(),
			},
			config: {},
		} as never,
	);
}

function makeUser(name: string, groups: string[]): RemoteUser {
	return { name, groups, real_groups: groups } as RemoteUser;
}

function makePkg(access?: string[], publish?: string[], unpublish?: string[]): PackageAccess {
	return { access, publish, unpublish } as unknown as PackageAccess;
}

function allowAccessAsync(
	plugin: EntraPlugin,
	user: RemoteUser,
	pkg: PackageAccess,
): Promise<boolean> {
	return new Promise((resolve, reject) => {
		plugin.allow_access(user, pkg, (err, allowed) => {
			if (err) reject(err);
			else resolve(allowed as boolean);
		});
	});
}

function allowPublishAsync(
	plugin: EntraPlugin,
	user: RemoteUser,
	pkg: PackageAccess,
): Promise<boolean> {
	return new Promise((resolve, reject) => {
		plugin.allow_publish(user, pkg, (err, allowed) => {
			if (err) reject(err);
			else resolve(allowed as boolean);
		});
	});
}

describe("allow_access", () => {
	const plugin = createPlugin();

	it("grants access when user group matches required", async () => {
		const user = makeUser("alice", ["$authenticated", "developers"]);
		const pkg = makePkg(["developers"]);
		expect(await allowAccessAsync(plugin, user, pkg)).toBe(true);
	});

	it("grants access for $all", async () => {
		const user = makeUser("anonymous", []);
		const pkg = makePkg(["$all"]);
		expect(await allowAccessAsync(plugin, user, pkg)).toBe(true);
	});

	it("grants access for $anonymous", async () => {
		const user = makeUser("anonymous", []);
		const pkg = makePkg(["$anonymous"]);
		expect(await allowAccessAsync(plugin, user, pkg)).toBe(true);
	});

	it("grants access when $authenticated matches", async () => {
		const user = makeUser("alice", ["$authenticated"]);
		const pkg = makePkg(["$authenticated"]);
		expect(await allowAccessAsync(plugin, user, pkg)).toBe(true);
	});

	it("denies access when no group matches", async () => {
		const user = makeUser("alice", ["$authenticated"]);
		const pkg = makePkg(["admins"]);
		await expect(allowAccessAsync(plugin, user, pkg)).rejects.toThrow(/access denied/i);
	});

	it("denies access for user with no name", async () => {
		const user = makeUser("", ["$authenticated"]);
		const pkg = makePkg(["$authenticated"]);
		await expect(allowAccessAsync(plugin, user, pkg)).rejects.toThrow(/access denied/i);
	});

	it("defaults to $authenticated when access list is undefined", async () => {
		const user = makeUser("alice", ["$authenticated"]);
		const pkg = makePkg(undefined);
		expect(await allowAccessAsync(plugin, user, pkg)).toBe(true);
	});
});

describe("allow_publish", () => {
	const plugin = createPlugin();

	it("grants publish when user group matches", async () => {
		const user = makeUser("alice", ["$authenticated", "publishers"]);
		const pkg = makePkg(undefined, ["publishers"]);
		expect(await allowPublishAsync(plugin, user, pkg)).toBe(true);
	});

	it("denies publish when no group matches", async () => {
		const user = makeUser("alice", ["$authenticated"]);
		const pkg = makePkg(undefined, ["admins"]);
		await expect(allowPublishAsync(plugin, user, pkg)).rejects.toThrow(/not allowed to publish/i);
	});

	it("defaults to $authenticated when publish list is undefined", async () => {
		const user = makeUser("alice", ["$authenticated"]);
		const pkg = makePkg(undefined, undefined);
		expect(await allowPublishAsync(plugin, user, pkg)).toBe(true);
	});

	it("denies publish for user with no name", async () => {
		const user = makeUser("", ["$authenticated"]);
		const pkg = makePkg(undefined, ["$authenticated"]);
		await expect(allowPublishAsync(plugin, user, pkg)).rejects.toThrow(/not allowed to publish/i);
	});
});

function allowUnpublishAsync(
	plugin: EntraPlugin,
	user: RemoteUser,
	pkg: PackageAccess,
): Promise<boolean> {
	return new Promise((resolve, reject) => {
		plugin.allow_unpublish(user, pkg, (err, allowed) => {
			if (err) reject(err);
			else resolve(allowed as boolean);
		});
	});
}

describe("allow_unpublish", () => {
	const plugin = createPlugin();

	it("grants unpublish when user group matches unpublish list", async () => {
		const user = makeUser("alice", ["$authenticated", "admins"]);
		const pkg = makePkg(undefined, undefined, ["admins"]);
		expect(await allowUnpublishAsync(plugin, user, pkg)).toBe(true);
	});

	it("falls back to publish list when unpublish is undefined", async () => {
		const user = makeUser("alice", ["$authenticated", "publishers"]);
		const pkg = makePkg(undefined, ["publishers"], undefined);
		expect(await allowUnpublishAsync(plugin, user, pkg)).toBe(true);
	});

	it("falls back to $authenticated when both are undefined", async () => {
		const user = makeUser("alice", ["$authenticated"]);
		const pkg = makePkg(undefined, undefined, undefined);
		expect(await allowUnpublishAsync(plugin, user, pkg)).toBe(true);
	});

	it("grants unpublish for $all", async () => {
		const user = makeUser("anonymous", []);
		const pkg = makePkg(undefined, undefined, ["$all"]);
		expect(await allowUnpublishAsync(plugin, user, pkg)).toBe(true);
	});

	it("grants unpublish for $anonymous", async () => {
		const user = makeUser("anonymous", []);
		const pkg = makePkg(undefined, undefined, ["$anonymous"]);
		expect(await allowUnpublishAsync(plugin, user, pkg)).toBe(true);
	});

	it("denies unpublish when no group matches", async () => {
		const user = makeUser("alice", ["$authenticated"]);
		const pkg = makePkg(undefined, undefined, ["admins"]);
		await expect(allowUnpublishAsync(plugin, user, pkg)).rejects.toThrow(/not allowed to unpublish/i);
	});

	it("denies unpublish for user with no name", async () => {
		const user = makeUser("", ["$authenticated"]);
		const pkg = makePkg(undefined, undefined, ["$authenticated"]);
		await expect(allowUnpublishAsync(plugin, user, pkg)).rejects.toThrow(/not allowed to unpublish/i);
	});
});
