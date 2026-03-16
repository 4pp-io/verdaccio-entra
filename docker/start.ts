/**
 * Start Verdaccio using the v6 runServer API.
 *
 * The `verdaccio` CLI binary uses a deprecated startup method that logs:
 *   "warn --- This is a deprecated method, please use runServer instead"
 *
 * @see https://verdaccio.org/docs/programmatically — runServer (v5.11.0+)
 * @see https://github.com/verdaccio/verdaccio/blob/master/website/versioned_docs/version-6.x/programmatically.md
 */
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { runServer } = require("/usr/local/lib/node_modules/verdaccio") as {
	runServer: (configPath: string) => Promise<import("http").Server & { listen: (port: number, host: string, cb: () => void) => void }>;
};

const configPath: string = process.env.VERDACCIO_CONFIG || "/verdaccio/conf/config.yaml";
const port: number = parseInt(process.env.VERDACCIO_PORT || "4873", 10);

runServer(configPath)
	.then((app: { listen: (port: number, host: string, cb: () => void) => void }) => {
		app.listen(port, "0.0.0.0", () => {
			console.log(`verdaccio running on http://0.0.0.0:${port}/`);
		});
	})
	.catch((err: unknown) => {
		console.error("Failed to start verdaccio:", err);
		process.exit(1);
	});
