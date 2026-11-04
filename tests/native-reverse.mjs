// Actual official model + isolated Pi acceptance; only inert, synthetic fixtures.
// Copy configuration metadata, never credentials. The source workspace is read-only.
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {launchNative} from './native-app.mjs';

const [binary, metadataRoot, fixtures, resultDir] = process.argv.slice(2);
if (![binary, metadataRoot, fixtures, resultDir].every(p => p && path.isAbsolute(p)))
  throw Error('Usage: node tests/native-reverse.mjs ABS_DEBUG_EXECUTABLE ABS_METADATA_WORKSPACE ABS_INERT_FIXTURES ABS_RESULT_DIR');
const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gaga-pi-official-'));
const readConfig = () => {
  const db = new DatabaseSync(path.join(metadataRoot, 'workspace.sqlite3'), {readOnly: true});
  try { return db.prepare("SELECT value FROM settings WHERE key='ai_config'").get().value; }
  finally { db.close(); }
};
const metadata = readConfig(), config = JSON.parse(metadata);
assert.equal(config.provider, 'deepseek');
assert.equal(config.hasKey, true);
const db = new DatabaseSync(path.join(root, 'workspace.sqlite3'));
db.exec('CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)');
db.prepare("INSERT INTO settings VALUES('ai_config',?)").run(metadata);
db.close();
for (const name of ['inert-source.php', 'inert-x64.elf'])
  await fs.copyFile(path.join(fixtures, name), path.join(root, name));
await fs.mkdir(resultDir, {recursive: true});
for (const phase of ['first', 'reopen']) {
  const file = path.join(root, 'native-ui-verification.json');
  await fs.rm(file, {force: true});
  await fs.writeFile(path.join(root, 'phase.txt'), phase);
  const app = await launchNative(binary, ['--reverse-ui', root]);
  let log = '';
  for (const stream of [app.stdout, app.stderr]) stream.on('data', bytes => log += bytes);
  try {
    let result;
    for (let i = 0; i < 7000; i++) {
      try { result = JSON.parse(await fs.readFile(file, 'utf8')); break; } catch {}
      if (app.exitCode !== null) throw Error('Native client exited: ' + log.slice(-2000));
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!result) throw Error('Native reverse timeout: ' + root);
    assert.deepEqual(result.errors, [], JSON.stringify(result));
    assert.equal(readConfig(), metadata, 'Source configuration remains unchanged');
    const identity = crypto.createHash('sha256').update(await fs.readFile(binary)).digest('hex');
    await fs.writeFile(path.join(resultDir, 'pi-official-' + phase + '.json'), JSON.stringify({...result, root, executableSha256: identity, metadataSourceUnchanged: true, credentialsCopied: false}, null, 2));
    console.log(JSON.stringify({phase, passed: result.passed.length, root}));
  } finally {
    await fs.writeFile(path.join(resultDir, 'pi-official-' + phase + '.log'), log);
    await app.stop();
  }
}
await fs.writeFile(path.join(resultDir, 'pi-official-workspace.txt'), root);
