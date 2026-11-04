// Real WebView/Docker/report recovery acceptance. Copies configuration metadata,
// never credentials. The Pi task is cancelled before any official model request.
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { launchNative } from './native-app.mjs';

const [binary, metadataRoot, inertFixtures, resultDir] = process.argv.slice(2);
if (![binary, metadataRoot, inertFixtures, resultDir].every(p => p && path.isAbsolute(p)))
  throw Error('Usage: node tests/native-deep-audit.mjs ABS_DEBUG_EXECUTABLE ABS_METADATA_WORKSPACE ABS_INERT_FIXTURES ABS_RESULT_DIR');
// macOS /var is an alias of /private/var; compare canonical selections consistently.
const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'gaga-final-audit-0.7.1-')));
const source = new DatabaseSync(path.join(metadataRoot, 'workspace.sqlite3'), { readOnly: true });
const metadata = source.prepare("SELECT value FROM settings WHERE key='ai_config'").get().value;
source.close();
const config = JSON.parse(metadata);
assert.equal(config.provider, 'deepseek');
assert.equal(config.hasKey, true);
const db = new DatabaseSync(path.join(root, 'workspace.sqlite3'));
db.exec('CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)');
db.prepare("INSERT INTO settings VALUES('ai_config',?)").run(metadata);
db.close();
await fs.mkdir(resultDir, { recursive: true });
for (const name of ['inert-source.php', 'inert-x64.elf'])
  await fs.copyFile(path.join(inertFixtures, name), path.join(root, name));
let integrityFixture;
async function handleEvidenceIntegrity() {
  if (!integrityFixture) {
    try { await fs.access(path.join(root, 'audit-source-corrupt.request')); } catch { return; }
    const reader = new DatabaseSync(path.join(root, 'workspace.sqlite3'), { readOnly: true });
    const id = reader.prepare('SELECT evidence_id FROM nodes ORDER BY rowid LIMIT 1').get().evidence_id;
    reader.close();
    const file = path.join(root, 'evidence', id);
    integrityFixture = { file, original: await fs.readFile(file), reports: {} };
    for (const format of ['html', 'docx']) integrityFixture.reports[format] = await fs.readFile(path.join(root, 'audit-report.' + format));
    await fs.writeFile(file, Buffer.alloc(integrityFixture.original.length, 88));
    await fs.writeFile(path.join(root, 'audit-source-corrupt.ready'), 'ready');
  }
  if (!integrityFixture.restored) {
    try { await fs.access(path.join(root, 'audit-source-restore.request')); } catch { return; }
    for (const format of ['html', 'docx']) assert.deepEqual(await fs.readFile(path.join(root, 'audit-report.' + format)), integrityFixture.reports[format], 'Failed export changed existing ' + format);
    await fs.writeFile(integrityFixture.file, integrityFixture.original);
    integrityFixture.restored = true;
    await fs.writeFile(path.join(root, 'audit-source-restore.ready'), 'ready');
  }
}
for (const phase of ['first', 'reopen']) {
  const resultFile = path.join(root, 'native-ui-verification.json');
  await fs.rm(resultFile, { force: true });
  await fs.writeFile(path.join(root, 'phase.txt'), phase);
  const app = await launchNative(binary, ['--deep-audit-ui', root]);
  let log = '';
  for (const stream of [app.stdout, app.stderr]) stream.on('data', bytes => log += bytes);
  try {
    let result;
    for (let i = 0; i < 6000; i++) {
      if (phase === 'first') await handleEvidenceIntegrity();
      try { result = JSON.parse(await fs.readFile(resultFile, 'utf8')); break; } catch {}
      if (app.exitCode !== null) throw Error('Native client exited: ' + log.slice(-2000));
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!result) throw Error('Native audit timed out: ' + root);
    await fs.writeFile(path.join(resultDir, 'native-' + phase + '.json'), JSON.stringify({ ...result, root }, null, 2));
    assert.deepEqual(result.errors, [], JSON.stringify(result));
    console.log(JSON.stringify({ phase, passed: result.passed.length, root }));
  } finally {
    await fs.writeFile(path.join(resultDir, 'native-' + phase + '.log'), log);
    await app.stop();
  }
}
await fs.writeFile(path.join(resultDir, 'native-workspace.txt'), root);
