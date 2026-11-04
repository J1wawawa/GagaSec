// Copies official configuration metadata only; the native app reads the existing Keychain credential.
import assert from 'node:assert/strict';
import {launchNative} from './native-app.mjs';
import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs/promises';
import path from 'node:path';
const [binary, sourceRoot, output] = process.argv.slice(2);
if (![binary, sourceRoot, output].every((p) => p && path.isAbsolute(p))) throw Error('Pass absolute binary, source workspace and output paths');
await fs.mkdir(output, {recursive: true});
const root = await fs.mkdtemp(path.join(output, 'official-native-'));
const source = new DatabaseSync(path.join(sourceRoot, 'workspace.sqlite3'), {readOnly: true});
const config = source.prepare("SELECT value FROM settings WHERE key='ai_config'").get().value;
const cfg = JSON.parse(config);
assert.equal(cfg.endpoint, 'https://api.deepseek.com'); assert.equal(cfg.hasKey, true);
const db = new DatabaseSync(path.join(root, 'workspace.sqlite3'));
db.exec('CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)');
db.prepare("INSERT INTO settings VALUES('ai_config',?)").run(config); db.close();
async function runPhase(name) {
  const file = path.join(root, 'native-ui-verification.json'); await fs.rm(file, {force: true});
  const app = await launchNative(binary, ['--official-ui', root]);
  let log = '';
  for (const stream of [app.stdout, app.stderr]) stream.on('data', (chunk) => log += chunk);
  try {
    let result;
    for (let i = 0; i < 7200; i++) {
      try { result = JSON.parse(await fs.readFile(file, 'utf8')); break; } catch {}
      if (app.exitCode !== null) throw Error('Official client exited: ' + log.slice(-3000));
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await fs.writeFile(path.join(root, name + '.log'), log);
    if (!result) throw Error('Official native timeout');
    await fs.writeFile(path.join(root, name + '.json'), JSON.stringify(result, null, 2));
    assert.deepEqual(result.errors, [], JSON.stringify(result, null, 2));
    return result;
  } finally {
    await app.stop();
  }
}
const first = await runPhase('official-first');
const reopen = await runPhase('official-reopen');
const reopened = new DatabaseSync(path.join(root, 'workspace.sqlite3'), {readOnly: true});
assert.equal(reopened.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
assert.equal(reopened.prepare('SELECT count(*) n FROM ai_reviews').get().n, 3);
assert.equal(reopened.prepare('SELECT count(*) n FROM ai_followups').get().n, 1);
assert.equal(source.prepare("SELECT value FROM settings WHERE key='ai_config'").get().value, config);
source.close(); reopened.close();
const summary = {version: JSON.parse(await fs.readFile(new URL('../package.json',import.meta.url),'utf8')).version, root, first, reopen, metadataSourceUnchanged: true, rawKeyCopied: false, officialRequests: first.requestsAttempted, sqliteIntegrity: 'ok'};
await fs.writeFile(path.join(output, 'official-native.json'), JSON.stringify(summary, null, 2));
console.log(JSON.stringify(summary, null, 2));
