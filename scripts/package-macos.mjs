// Create a drag-to-Applications DMG without scripting Finder or requesting
// Automation permission. The signed app is copied intact; no post-sign edits.
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  existsSync,
  symlinkSync,
  rmSync,
  readFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
if (process.platform !== 'darwin') throw Error('DMG packaging requires macOS.');
const target = process.env.CARGO_TARGET_DIR
  ? path.resolve('src-tauri', process.env.CARGO_TARGET_DIR)
  : path.resolve('src-tauri/target');
const bundle = path.join(target, 'release/bundle/macos/嘎嘎安全助手.app');
const version = JSON.parse(readFileSync('package.json', 'utf8')).version;
const output = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.join(
      target,
      `release/bundle/macos/gaga-${version}-${process.arch}.dmg`,
    );
if (existsSync(output))
  throw Error(`Refusing to replace an existing installer: ${output}`);
const run = (command, args) => {
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw Error(`${command} exited ${result.status}`);
};
const staging = mkdtempSync(path.join(tmpdir(), 'gaga-installer-'));
try {
  run('/usr/bin/codesign', ['--verify', '--deep', '--strict', bundle]);
  run('/usr/bin/ditto', [bundle, path.join(staging, '嘎嘎安全助手.app')]);
  symlinkSync('/Applications', path.join(staging, 'Applications'));
  run('/usr/bin/hdiutil', [
    'create',
    '-volname',
    '嘎嘎安全助手',
    '-srcfolder',
    staging,
    '-format',
    'UDZO',
    output,
  ]);
  run('/usr/bin/hdiutil', ['verify', output]);
} finally {
  rmSync(staging, { recursive: true, force: true });
}
