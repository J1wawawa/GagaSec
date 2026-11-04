import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { launchNative } from './native-app.mjs';
import { nativeWindowCapture } from './native-window.mjs';
const [binary, output] = process.argv.slice(2);
assert([binary, output].every((p) => p && path.isAbsolute(p)));
await fs.mkdir(output, { recursive: true });
const root = await fs.realpath(
  await fs.mkdtemp(path.join(os.tmpdir(), 'gaga-report-structure-')),
);
const results = [];
const captureWindow =
  process.platform === 'darwin' ? await nativeWindowCapture(root) : null;
for (const phase of ['first', 'reopen']) {
  await fs.writeFile(path.join(root, 'phase.txt'), phase);
  await fs.rm(path.join(root, 'ui-checkpoints.log'), { force: true });
  const resultPath = path.join(root, 'native-ui-verification.json');
  await fs.rm(resultPath, { force: true });
  const captured = new Set();
  const app = await launchNative(binary, ['--report-structure-ui', root]);
  let log = '';
  for (const stream of [app.stdout, app.stderr])
    stream.on('data', (b) => (log += b));
  try {
    let result;
    for (let i = 0; i < 3000; i++) {
      if (captureWindow)
        try {
          const lines = (
            await fs.readFile(path.join(root, 'ui-checkpoints.log'), 'utf8')
          )
            .split('\n')
            .filter((l) => l.startsWith('SCREENSHOT '));
          for (const line of lines)
            if (!captured.has(line)) {
              captureWindow(
                app.pid,
                path.join(output, line.slice(11) + '.png'),
              );
              captured.add(line);
            }
        } catch (e) {
          if (e.code !== 'ENOENT') throw e;
        }

      try {
        result = JSON.parse(await fs.readFile(resultPath, 'utf8'));
        break;
      } catch {}
      if (app.exitCode !== null || !app.diagnostics().clientAlive)
        throw Error('Client exited ' + JSON.stringify(app.diagnostics()));
      await new Promise((r) => setTimeout(r, 100));
    }
    assert(result, 'Flexible report UI timed out');
    results.push(result);
    await fs.writeFile(
      path.join(output, 'structure-' + phase + '.json'),
      JSON.stringify({ ...result, root }, null, 2),
    );
    assert.deepEqual(result.errors, [], JSON.stringify(result));
  } finally {
    await fs.writeFile(path.join(output, 'structure-' + phase + '.log'), log);
    await app.stop();
  }
}
const physical = JSON.parse(
  execFileSync(
    'python3',
    [
      '-c',
      `
import json,sqlite3,sys,zipfile,xml.etree.ElementTree as ET
from pathlib import Path
r=Path(sys.argv[1]);checks=[]
def check(name,ok):
 assert ok,name
 checks.append(name)
db=sqlite3.connect(f'file:{r}/workspace.sqlite3?mode=ro',uri=True)
check('Database integrity/FK',db.execute('PRAGMA integrity_check').fetchone()[0]=='ok' and not db.execute('PRAGMA foreign_key_check').fetchall())
for stem in ['flexible','text-only']:
 with zipfile.ZipFile(r/(stem+'.docx')) as z:
  check(stem+' DOCX ZIP integrity',z.testzip() is None)
  for name in z.namelist():
   if name.endswith(('.xml','.rels')):ET.fromstring(z.read(name))
  text=z.read('word/document.xml').decode()
  if stem=='flexible':
   check('Custom title order and Heading2',text.index('阶段一：初始入侵')<text.index('事件 1：Web 服务器')<text.index('阶段二：横向移动')<text.index('事件 2：数据库') and 'w:val="Heading2"' in text)
   check('Both sub-events have embedded proof images',len([n for n in z.namelist() if n.startswith('word/media/')])==2)
   check('DOCX contains both responsible people','张三' in text and '李四' in text)
  else:check('Text-only DOCX content','无节点报告正文' in text)
 html=(r/(stem+'.html')).read_text()
 check(stem+' HTML content',('1.1 事件 1' in html and html.count('data:image/png;base64,')==2) if stem=='flexible' else '无节点报告正文' in html)
check('No partial export files',not list(r.glob('.gaga-*.partial')))
check('Only one original and screenshot archived',db.execute('SELECT count(*) FROM evidence').fetchone()[0]==1 and db.execute('SELECT count(*) FROM screenshots').fetchone()[0]==1)
print(json.dumps({'checks':checks,'errors':[]}))
`,
      root,
    ],
    { encoding: 'utf8' },
  ),
);
const summary = {
  version: results[0].version,
  root,
  first: results[0],
  reopen: results[1],
  physical,
  syntheticFixtures: true,
  externalModelsCalled: false,
};
await fs.writeFile(
  path.join(output, 'native-report-structure.json'),
  JSON.stringify(summary, null, 2),
);
console.log(
  JSON.stringify({
    version: summary.version,
    first: results[0].passed.length,
    reopen: results[1].passed.length,
    physical: physical.checks.length,
    root,
  }),
);
