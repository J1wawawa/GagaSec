// Repeated real macOS launches of the marked accumulated-data workspace.
// This is a short startup soak, not a long-term uptime or kernel capture test.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs/promises';
import path from 'node:path';
import {launchNative} from './native-app.mjs';

const [binary, root, output] = process.argv.slice(2);
assert.equal(process.platform, 'darwin');
assert([binary, root, output].every(p => p && path.isAbsolute(p)));
const fixture = JSON.parse(await fs.readFile(path.join(root, 'storage-fixture.json'), 'utf8'));
assert.equal(fixture.syntheticStorageFixture, true);
await fs.mkdir(output, {recursive: true});
const pause = ms => new Promise(r => setTimeout(r, ms));
const results = [];
for (const method of ['direct', 'launch-services', 'direct', 'launch-services']) {
  const started = Date.now();
  let log = '', app;
  if (method === 'direct') {
    const child = spawn(binary, ['--workspace', root], {stdio: ['ignore', 'pipe', 'pipe']});
    app = {
      pid: child.pid, stdout: child.stdout, stderr: child.stderr,
      diagnostics: () => ({method, clientPid: child.pid, clientAlive: child.exitCode === null && child.signalCode === null,
        launcherPid: child.pid, launcherExitCode: child.exitCode, launcherSignal: child.signalCode}),
      async stop() {
        if (child.exitCode === null && child.signalCode === null) {
          child.kill('SIGTERM');
          await Promise.race([new Promise(r => child.once('exit', r)), pause(5000)]);
        }
      },
    };
  } else app = await launchNative(binary, ['--workspace', root]);
  for (const stream of [app.stdout, app.stderr]) stream.on('data', b => log += b);
  let last = app.diagnostics();
  let checks = 0;
  try {
    // All synthetic assets are disabled and no model configuration is present.
    // Only read-only probes run while the normal desktop and schedulers stay alive.
    for (let i = 0; i < 30; i++) {
      await pause(1000);
      last = app.diagnostics();
      if (!last.clientAlive) break;
      const db = new DatabaseSync(path.join(root, 'workspace.sqlite3'), {readOnly: true});
      assert.equal(db.prepare("SELECT value FROM settings WHERE key='active_case'").get().value, 'c000');
      assert.equal(db.prepare('SELECT count(*) n FROM monitor_assets WHERE enabled=1').get().n, 0);
      assert.equal(db.prepare("SELECT count(*) n FROM settings WHERE key='ai_config'").get().n, 0);
      db.close();
      checks++;
    }
  } finally {
    const record = {method, heldMs: Date.now() - started, aliveBeforeStop: last.clientAlive, probes: checks, terminationBeforeStop: last};
    results.push(record);
    await fs.writeFile(path.join(output, `startup-${results.length}-${method}.log`), log);
    await app.stop();
    record.afterRequestedStop = app.diagnostics();
    await fs.writeFile(path.join(output, 'startup-progress.json'), JSON.stringify(results, null, 2));
  }
}
const db = new DatabaseSync(path.join(root, 'workspace.sqlite3'), {readOnly: true});
assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
assert.equal(db.prepare('PRAGMA foreign_key_check').all().length, 0);
assert.equal(db.prepare('SELECT count(*) n FROM monitor_snapshots').get().n, 100000);
assert.equal(db.prepare('SELECT count(*) n FROM monitor_observations').get().n, 100000);
db.close();
const summary = {version: fixture.version, syntheticFixture: true, results,
  errors: results.filter(r => !r.aliveBeforeStop || r.probes !== 30).map(r => r.method + ' exited during soak'),
  originalExitRootCauseConfirmed: false, longTermUptimeVerified: false, externalModelsCalled: false};
await fs.writeFile(path.join(output, 'mac-startup-soak.json'), JSON.stringify(summary, null, 2));
console.log(JSON.stringify(summary, null, 2));
assert.deepEqual(summary.errors, []);
