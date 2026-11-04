import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { launchNative } from './native-app.mjs';
import { nativeWindowCapture } from './native-window.mjs';
const [binary, output] = process.argv.slice(2);
assert(binary && output && path.isAbsolute(binary) && path.isAbsolute(output));
await fs.mkdir(output, { recursive: true });
const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gaga-monitor-native-'));
const captureWindow = await nativeWindowCapture(root);
const addr = Object.values(os.networkInterfaces())
  .flat()
  .find((a) => a?.family === 'IPv4' && !a.internal)?.address;
assert(addr, 'Needs reachable local Docker host IPv4');
const server = http.createServer((req, res) => {
  if (req.url === '/start') {
    res.writeHead(302, { location: '/js' });
    res.end();
    return;
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(
    req.url === '/js'
      ? '<title>跳转中</title><script>location.replace("/final")</script>'
      : '<!doctype html><meta charset="utf-8"><title>自动巡检截图验收</title><body style="background:#fafafa;color:#151515;font:24px sans-serif;padding:70px"><h1>最终页面 · 自动截图</h1><p>HTTP 跳转 → JavaScript 跳转 → 浏览器渲染</p><p>这是一份本地合成验收材料，不代表真实攻击。</p></body>',
  );
});
await new Promise((r) => server.listen(0, '0.0.0.0', r));
const url = `http://${addr}:${server.address().port}/start`;
const results = [];
try {
  for (const phase of ['first', 'reopen']) {
    await fs.rm(path.join(root, 'ui-checkpoints.log'), { force: true });
    await fs.writeFile(
      path.join(root, 'monitor-config.json'),
      JSON.stringify({ phase, url }),
    );
    await fs.rm(path.join(root, 'native-ui-verification.json'), {
      force: true,
    });
    const app = await launchNative(binary, ['--monitor-ui', root]);
    let log = '';
    for (const stream of [app.stdout, app.stderr])
      stream.on('data', (b) => (log += b));
    try {
      let result,
        captured = false;
      for (let i = 0; i < 1600; i++) {
        if (!captured)
          try {
            const checkpoints = await fs.readFile(
              path.join(root, 'ui-checkpoints.log'),
              'utf8',
            );
            if (checkpoints.includes('SCREENSHOT monitor-auto-screenshot')) {
              captureWindow(app.pid, path.join(output, 'monitor-native.png'));
              captured = true;
            }
          } catch (e) {
            if (e.code !== 'ENOENT') throw e;
          }
        try {
          result = JSON.parse(
            await fs.readFile(
              path.join(root, 'native-ui-verification.json'),
              'utf8',
            ),
          );
          break;
        } catch {}
        assert(app.diagnostics().clientAlive, 'Native client exited');
        await new Promise((r) => setTimeout(r, 100));
      }
      assert(result, 'Native monitor timed out');
      await fs.writeFile(
        path.join(output, phase + '.json'),
        JSON.stringify({ ...result, root }, null, 2),
      );
      assert.deepEqual(result.errors, [], JSON.stringify(result));
      results.push(result);
    } finally {
      await app.stop();
      await fs.writeFile(path.join(output, phase + '.log'), log);
    }
  }
  const files = JSON.parse(
    execFileSync(
      'python3',
      [
        '-c',
        `import sys,zipfile,json,sqlite3
from pathlib import Path
p=Path(sys.argv[1]);db=sqlite3.connect(p/'workspace.sqlite3');checks=[]
assert db.execute('pragma integrity_check').fetchone()[0]=='ok'
assert not db.execute('pragma foreign_key_check').fetchall();checks.append('SQLite integrity and FK')
with zipfile.ZipFile(p/'monitor-report.docx') as z:
 assert z.testzip() is None
 assert len([n for n in z.namelist() if n.startswith('word/media/')])==1
 checks.append('DOCX embeds auto screenshot')
assert db.execute('select count(*) from screenshots').fetchone()[0]==1;checks.append('No duplicate screenshots after disabled run')
print(json.dumps(checks))`,
        root,
      ],
      { encoding: 'utf8' },
    ),
  );
  await fs.writeFile(
    path.join(output, 'summary.json'),
    JSON.stringify(
      { root, first: results[0], reopen: results[1], files },
      null,
      2,
    ),
  );
  console.log(
    JSON.stringify({
      root,
      first: results[0].passed.length,
      reopen: results[1].passed.length,
      files: files.length,
    }),
  );
} finally {
  server.close();
}
