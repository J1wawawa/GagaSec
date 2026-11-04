// Navigation acceptance in the real Tauri WebView and an isolated SQLite store.
import assert from 'node:assert/strict';
import {launchNative} from './native-app.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
const binary = process.argv[2];
if (!binary || !path.isAbsolute(binary)) throw Error('Pass an absolute debug app executable');
// Optional accumulated-data fixture must have the explicit synthetic marker.
// Never run this automation against an unmarked user workspace.
const root = process.argv[3] || await fs.mkdtemp(path.join(os.tmpdir(), 'gaga-navigation-native-'));
if (process.argv[3]) {
  const marker = JSON.parse(await fs.readFile(path.join(root, 'storage-fixture.json'), 'utf8'));
  assert.equal(marker.syntheticStorageFixture, true);
}
await fs.rm(path.join(root, 'native-ui-verification.json'), {force: true});
const app = await launchNative(binary, ['--navigation-ui', root]);
let output = '';
for (const stream of [app.stdout, app.stderr]) stream.on('data', (chunk) => output += chunk);
try {
  let result;
  for (let i = 0; i < 2400; i++) {
    try { result = JSON.parse(await fs.readFile(path.join(root, 'native-ui-verification.json'), 'utf8')); break; } catch {}
    if (app.exitCode !== null) throw Error('Native app exited: ' + output.slice(-4000));
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (!result) throw Error('Native navigation timed out: ' + output.slice(-4000));
  await fs.writeFile(path.join(root, 'native-navigation.log'), output);
  assert.deepEqual(result.errors, [], JSON.stringify(result, null, 2));
  console.log(JSON.stringify({...result, root}, null, 2));
} finally {
  await app.stop();
}
