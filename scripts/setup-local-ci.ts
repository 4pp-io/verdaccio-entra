import { execSync } from "node:child_process";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const VERSION = "v3.14.0";
const REPO = "ChristopherHX/runner.server";

interface GitHubAsset {
  name: string;
  digest: string;
}

function getAssetName(): string {
  const platform = os.platform();
  const arch = os.arch();

  if (platform === "win32") {
    return arch === "arm64" ? "runner.server-win-arm64.zip" : "runner.server-win-x64.zip";
  }
  if (platform === "darwin") {
    return arch === "arm64" ? "runner.server-osx-arm64.tar.gz" : "runner.server-osx-x64.tar.gz";
  }
  return arch === "arm64" ? "runner.server-linux-arm64.tar.gz" : "runner.server-linux-x64.tar.gz";
}

function verifyChecksum(archivePath: string, expectedDigest: string): void {
  process.stdout.write("Verifying file integrity... ");
  const fileBuffer = fs.readFileSync(archivePath);
  const hash = crypto.createHash("sha256");
  hash.update(fileBuffer);
  const actualDigest = hash.digest("hex");

  if (actualDigest !== expectedDigest) {
    console.log("[FAIL]");
    throw new Error(`Checksum mismatch. Expected: ${expectedDigest}, Actual: ${actualDigest}`);
  }
  console.log("[PASS]");
}

function extractArchive(
  assetName: string,
  archivePath: string,
  binDir: string,
  platform: string,
): void {
  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir);
  }

  console.log(`Extracting to ${binDir}...`);
  if (assetName.endsWith(".zip")) {
    if (platform === "win32") {
      execSync(
        `powershell -NoProfile -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${binDir}' -Force"`,
        { stdio: "inherit" },
      );
    } else {
      execSync(`unzip -o "${archivePath}" -d "${binDir}"`, { stdio: "inherit" });
    }
  } else {
    execSync(`tar -xzf "${archivePath}" -C "${binDir}"`, { stdio: "inherit" });
  }
}

/**
 * Type guard to validate the structure of the GitHub release asset metadata.
 */
function isGitHubAsset(obj: unknown): obj is GitHubAsset {
  if (typeof obj !== "object" || obj === null) {
    return false;
  }
  const record = obj as Record<string, unknown>;
  return typeof record["name"] === "string" && typeof record["digest"] === "string";
}

function setup(): void {
  const platform = os.platform();
  const assetName = getAssetName();
  const binDir = path.join(process.cwd(), "bin");
  const archivePath = path.join(process.cwd(), assetName);

  console.log("Local CI Setup");
  console.log("========================================");
  console.log(`Platform: ${platform} (${os.arch()})`);
  console.log(`Target:   ${REPO}@${VERSION}`);
  console.log("========================================");

  try {
    process.stdout.write("Validating release metadata... ");
    const metadataStr = execSync(`gh release view ${VERSION} --repo ${REPO} --json assets`, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });

    const metadata = JSON.parse(metadataStr) as unknown;
    if (
      !metadata ||
      typeof metadata !== "object" ||
      !("assets" in (metadata as Record<string, unknown>))
    ) {
      console.log("[FAIL]");
      throw new Error("Invalid metadata payload received from GitHub API.");
    }

    const assets = (metadata as Record<string, unknown>)["assets"];
    if (!Array.isArray(assets)) {
      console.log("[FAIL]");
      throw new Error("Invalid assets array in GitHub API response.");
    }

    const assetMetadata = assets.find((a: unknown) => {
      return isGitHubAsset(a) && a.name === assetName;
    });

    if (!assetMetadata || !isGitHubAsset(assetMetadata)) {
      console.log("[FAIL]");
      throw new Error(
        `Failed to find cryptographic digest for ${assetName} in official release metadata.`,
      );
    }

    const expectedDigest = assetMetadata.digest.replace("sha256:", "");
    console.log("[PASS]");
    console.log(`Expected SHA256: ${expectedDigest}`);

    console.log(`Downloading ${assetName}...`);
    execSync(`gh release download ${VERSION} --repo ${REPO} --pattern "${assetName}" --clobber`, {
      stdio: "inherit",
    });

    verifyChecksum(archivePath, expectedDigest);

    extractArchive(assetName, archivePath, binDir, platform);

    fs.unlinkSync(archivePath);
    console.log("========================================");
    console.log("Local CI environment successfully attested and installed.");
    const clientName = platform === "win32" ? "Runner.Client.exe" : "Runner.Client";
    console.log(`Execution command: ./bin/${clientName}`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("\nSetup failed:", msg);
    process.exit(1);
  }
}

setup();
