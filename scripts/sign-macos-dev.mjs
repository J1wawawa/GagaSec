// Sign the complete development bundle after resources are copied. Signing only
// the executable leaves no bundle resource seal. This is ad-hoc, not notarization.
import { spawnSync } from 'node:child_process';
import path from 'node:path';

if (process.platform !== 'darwin')
  throw Error('macOS development signing requires macOS.');
const target = process.env.CARGO_TARGET_DIR
  ? path.resolve('src-tauri', process.env.CARGO_TARGET_DIR)
  : path.resolve('src-tauri/target');
const requested = process.argv.slice(2).filter((arg) => arg !== '--release');
const profile = process.argv.includes('--release') ? 'release' : 'debug';
const bundle = requested[0]
  ? path.resolve(requested[0])
  : path.join(target, `${profile}/bundle/macos/嘎嘎安全助手.app`);
for (const args of [
  ['--force', '--deep', '--sign', '-', bundle],
  ['--verify', '--deep', '--strict', '--verbose=2', bundle],
]) {
  const result = spawnSync('/usr/bin/codesign', args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
