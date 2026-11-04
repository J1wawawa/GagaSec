// Real 1 GiB synthetic archive, 1000 unrelated empty archives, WebView/IPC and restart.
// Seeds explicit stress fixtures, not results from the log analyzer or customer data.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { execFileSync } from 'node:child_process';
import { launchNative } from './native-app.mjs';

const [binary, output] = process.argv.slice(2);
if (![binary, output].every(p => p && path.isAbsolute(p))) throw Error('Pass absolute executable and result directory');
await fs.mkdir(output, { recursive: true });
const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'gaga-report-073-')));
await fs.mkdir(path.join(root, 'evidence'));
await fs.mkdir(path.join(root, 'screenshots'));
const bytes = 1024 * 1024 * 1024;
const source = await fs.open(path.join(root, 'evidence/report-large-fixture'), 'wx');
const chunk = Buffer.alloc(1024 * 1024, 65);
const digest = crypto.createHash('sha256');
try {
  for (let i = 0; i < bytes / chunk.length; i++) {
    await source.writeFile(chunk);
    digest.update(chunk);
  }
  await source.sync();
} finally { await source.close(); }
const sha = digest.digest('hex');
const emptySha = crypto.createHash('sha256').digest('hex');
const report = { kind: 'logs', engine: 'J4team synthetic export fixture/1', title: '仅验证报告导出', summary: '合成归档，无真实入侵或日志检测结论。', metrics: [], findings: [], indicators: [], details: [], warnings: ['本案例人工构造，仅验证导出进度、取消、隔离与持久化。'] };
const db = new DatabaseSync(path.join(root, 'workspace.sqlite3'));
db.exec(`CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE cases(id TEXT PRIMARY KEY,title TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE evidence(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),name TEXT NOT NULL,kind TEXT NOT NULL,sha256 TEXT NOT NULL,size INTEGER NOT NULL,created_at TEXT NOT NULL,report TEXT NOT NULL);
CREATE TABLE nodes(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),evidence_id TEXT REFERENCES evidence(id),finding_id TEXT,occurred_at TEXT NOT NULL,recorded_at TEXT NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,actor TEXT NOT NULL,included INTEGER NOT NULL DEFAULT 1);
PRAGMA user_version=1;`);
const at = '2026-10-29T10:00:00+08:00';
for (const id of ['A', 'B']) db.prepare('INSERT INTO cases VALUES(?,?,?)').run(id, '[导出压力] ' + id, at);
db.prepare('INSERT INTO settings VALUES(?,?)').run('active_case', 'A');
const add = db.prepare('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)');
add.run('report-large-fixture', 'A', 'report-large-fixture.log', 'logs', sha, bytes, at, JSON.stringify(report));
db.exec('BEGIN');
for (let i = 0; i < 1000; i++) {
  const id = 'unselected-' + i;
  add.run(id, 'A', 'unselected-canary-' + i, 'logs', emptySha, 0, at, JSON.stringify(report));
  await fs.writeFile(path.join(root, 'evidence', id), '');
}
db.exec('COMMIT');
for (let i = 1; i <= 2; i++) db.prepare('INSERT INTO nodes VALUES(?,?,?,?,?,?,?,?,?,?)').run('node-' + i, 'A', 'report-large-fixture', null, at, at, 'A selected node ' + i, '合成导出压力记录；无真实攻击结论。', 'J4team test', 1);
db.close();
await fs.writeFile(path.join(root, 'cancelled.html'), 'previous-report-canary');
const results = [];
for (const phase of ['first', 'reopen']) {
  const resultFile = path.join(root, 'native-ui-verification.json');
  await fs.rm(resultFile, { force: true });
  await fs.writeFile(path.join(root, 'phase.txt'), phase);
  const app = await launchNative(binary, ['--report-ui', root]);
  let log = '';
  for (const stream of [app.stdout, app.stderr]) stream.on('data', b => log += b);
  try {
    let result;
    for (let i = 0; i < 6000; i++) {
      try { result = JSON.parse(await fs.readFile(resultFile, 'utf8')); break; } catch {}
      if (app.exitCode !== null) throw Error('Native report app exited: ' + log.slice(-1000));
      await new Promise(r => setTimeout(r, 100));
    }
    if (!result) throw Error('Native report timed out: ' + root);
    results.push(result);
    await fs.writeFile(path.join(output, 'report-' + phase + '.json'), JSON.stringify({ ...result, root }, null, 2));
    assert.deepEqual(result.errors, [], JSON.stringify(result));
  } finally {
    await fs.writeFile(path.join(output, 'report-' + phase + '.log'), log);
    await app.stop();
  }
}
const physical = JSON.parse(execFileSync('python3', ['-c', `
import hashlib,json,sqlite3,sys,zipfile,xml.etree.ElementTree as ET
from pathlib import Path
r=Path(sys.argv[1]);checks=[]
def check(name,value):
 assert value,name
 checks.append(name)
db=sqlite3.connect(f'file:{r}/workspace.sqlite3?mode=ro',uri=True)
check('SQLite integrity',db.execute('PRAGMA integrity_check').fetchone()[0]=='ok')
check('SQLite foreign keys',not db.execute('PRAGMA foreign_key_check').fetchall())
check('All 1001 source archives persist',db.execute('SELECT count(*) FROM evidence').fetchone()[0]==1001)
check('Cancelled target unchanged',(r/'cancelled.html').read_bytes()==b'previous-report-canary')
check('No temporary output remains',not list(r.glob('.gaga-*.partial')))
with (r/'evidence/report-large-fixture').open('rb') as f:
 digest=hashlib.sha256()
 for chunk in iter(lambda:f.read(1024*1024),b''):digest.update(chunk)
 h=digest.hexdigest()
check('1 GiB original digest unchanged',h==sys.argv[2] and (r/'evidence/report-large-fixture').stat().st_size==1024**3)
with zipfile.ZipFile(r/'complete.docx') as z:
 check('DOCX integrity',z.testzip() is None)
 for name in z.namelist():
  if name.endswith(('.xml','.rels')):ET.fromstring(z.read(name))
 text=z.read('word/document.xml').decode()
 check('DOCX includes both nodes and source digest',all(s in text for s in ['A selected node 1','A selected node 2',h]))
 check('DOCX excludes unrelated event and sources','[导出压力] B' not in text and 'unselected-canary' not in text)
html=(r/'complete.html').read_text()
check('HTML retains source digest and both nodes',all(s in html for s in ['A selected node 1','A selected node 2',h]))
print(json.dumps({'checks':checks,'errors':[]}))
`, root, sha], { encoding: 'utf8' }));
await fs.writeFile(path.join(output, 'report-physical.json'), JSON.stringify(physical, null, 2));
const summary = { version: results[0].version, root, first: results[0], reopen: results[1], physical, archiveBytes: bytes, sourceSha256: sha, syntheticFixtures: true, realModelsCalled: false };
await fs.writeFile(path.join(output, 'native-report.json'), JSON.stringify(summary, null, 2));
console.log(JSON.stringify({ version: summary.version, first: results[0].passed.length, reopen: results[1].passed.length, physical: physical.checks.length, timings: results[0].timings, root }));
