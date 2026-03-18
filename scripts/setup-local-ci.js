const { execSync } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');

const platform = os.platform();
const arch = os.arch();

let assetName = '';

if (platform === 'win32') {
  assetName = arch === 'arm64' ? 'runner.server-win-arm64.zip' : 'runner.server-win-x64.zip';
} else if (platform === 'darwin') {
  assetName = arch === 'arm64' ? 'runner.server-osx-arm64.tar.gz' : 'runner.server-osx-x64.tar.gz';
} else {
  assetName = arch === 'arm64' ? 'runner.server-linux-arm64.tar.gz' : 'runner.server-linux-x64.tar.gz';
}

const binDir = path.join(process.cwd(), 'bin');
const archivePath = path.join(process.cwd(), assetName);

console.log(`Detected platform: ${platform} (${arch})`);
console.log(`Downloading ${assetName}...`);

try {
  // Use gh to download the specific asset
  execSync(`gh release download --repo ChristopherHX/runner.server --pattern "${assetName}" --clobber`, { stdio: 'inherit' });

  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir);
  }

  console.log(`Extracting ${assetName} to ./bin...`);
  if (assetName.endsWith('.zip')) {
    if (platform === 'win32') {
      execSync(`powershell -NoProfile -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${binDir}' -Force"`, { stdio: 'inherit' });
    } else {
      execSync(`unzip -o "${archivePath}" -d "${binDir}"`, { stdio: 'inherit' });
    }
  } else {
    execSync(`tar -xzf "${archivePath}" -C "${binDir}"`, { stdio: 'inherit' });
  }

  // Cleanup the archive
  fs.unlinkSync(archivePath);

  console.log('\n✅ Local CI tools successfully set up in ./bin/');
  const clientName = platform === 'win32' ? 'Runner.Client.exe' : 'Runner.Client';
  console.log(`You can now run: ./bin/${clientName}`);

} catch (err) {
  console.error('\n❌ Setup failed:', err.message);
  process.exit(1);
}
