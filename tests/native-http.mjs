// Real Tauri WebView + real Rust / SQLite. No browser IPC mock or external AI.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
const binary = process.argv[2];
if (!binary || !path.isAbsolute(binary))
  throw Error('Pass an absolute debug app executable path');
const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gaga-http-native-'));
const app = spawn(binary, ['--http-ui', root], {
  stdio: ['ignore', 'pipe', 'pipe'],
});
let log = '',
  exit;
app.on('exit', (code, signal) => {
  exit = { code, signal };
});
for (const source of [app.stdout, app.stderr])
  source.on('data', (bytes) => {
    log += bytes;
  });
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let result;
try {
  for (let i = 0; i < 600; i++) {
    try {
      result = JSON.parse(
        await fs.readFile(
          path.join(root, 'native-ui-verification.json'),
          'utf8',
        ),
      );
      break;
    } catch {}
    if (exit)
      throw Error(
        'Native app exited: ' + JSON.stringify(exit) + '\n' + log.slice(-3000),
      );
    await pause(100);
  }
  if (!result) throw Error('Native HTTP test timeout\n' + log.slice(-3000));
  assert.deepEqual(result.errors, [], JSON.stringify(result, null, 2));
} finally {
  app.kill('SIGTERM');
  await fs.writeFile(path.join(root, 'native-process.log'), log);
  if (!exit)
    await new Promise((resolve) => {
      app.once('exit', resolve);
      setTimeout(resolve, 3000);
    });
}
const db = new DatabaseSync(path.join(root, 'workspace.sqlite3'), {
  readOnly: true,
});
const extra = [];
const check = (name, value) => {
  assert.ok(value, name);
  extra.push(name);
};
const evidence = db
  .prepare('SELECT id, case_id AS caseId, sha256, report FROM evidence')
  .all();
check(
  'Reopening real SQLite finds two successful HTTP inputs in separate cases',
  evidence.length === 2 && new Set(evidence.map((e) => e.caseId)).size === 2,
);
for (const e of evidence) {
  const bytes = await fs.readFile(path.join(root, 'evidence', e.id));
  check(
    'Archived pair SHA-256 matches stored original ' + e.id,
    crypto.createHash('sha256').update(bytes).digest('hex') === e.sha256,
  );
  const archived = JSON.parse(bytes.toString('utf8'));
  const report = JSON.parse(e.report);
  check(
    'Persisted request view preserves submitted copy ' + e.id,
    archived.request === report.httpExchanges[0].request.raw,
  );
}
check(
  'Failure leaves no temporary HTTP files',
  (await fs.readdir(path.join(root, 'http-input'))).length === 0,
);
check(
  'Only completed analyses were persisted',
  db
    .prepare('SELECT record FROM analysis_runs')
    .all()
    .map((r) => JSON.parse(r.record))
    .every((r) => r.state === 'completed'),
);
db.close();
const summary = {
  version: JSON.parse(await fs.readFile(new URL('../package.json', import.meta.url), 'utf8')).version,
  root,
  ...result,
  persistenceChecks: extra,
  externalModelTested: false,
  clipboardKeystrokesTested: false,
};
await fs.writeFile(
  path.join(root, 'http-verification.json'),
  JSON.stringify(summary, null, 2),
);
console.log(JSON.stringify(summary, null, 2));
