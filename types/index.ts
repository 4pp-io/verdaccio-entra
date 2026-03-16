import type { Config } from "@verdaccio/types";

export interface EntraConfig extends Config {
	clientId: string;
	tenantId: string;
	allowedGroups?: string[];
}
