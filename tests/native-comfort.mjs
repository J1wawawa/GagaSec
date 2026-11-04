// Real macOS WebView acceptance. The caller supplies an independently captured
// public-page screenshot; all database writes stay in a new temporary workspace.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { deflateRawSync } from 'node:zlib';
import { launchNative } from './native-app.mjs';

const [binary, screenshot] = process.argv.slice(2);
assert(binary && path.isAbsolute(binary), 'Pass an absolute debug executable');
assert(
  screenshot && path.isAbsolute(screenshot),
  'Pass the public-page screenshot',
);
const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gaga-comfort-native-'));
assert.equal(
  process.platform,
  'darwin',
  'This acceptance captures macOS native windows',
);
const windowHelper = path.join(root, 'own-window');
await fs.writeFile(
  windowHelper + '.swift',
  `import CoreGraphics
import Foundation
let pid = Int(CommandLine.arguments[1])!
let rows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as! [[String: Any]]
if let r = rows.first(where: { ($0[kCGWindowOwnerPID as String] as? Int) == pid && ($0[kCGWindowLayer as String] as? Int) == 0 }) {
 print(r[kCGWindowNumber as String]!)
}
`,
);
execFileSync('swiftc', [windowHelper + '.swift', '-o', windowHelper]);
await fs.writeFile(
  path.join(root, 'auth.log'),
  '2026-10-31T10:21:00+08:00 lab sshd[18]: Failed password for invalid user guest from 192.0.2.44 port 40222 ssh2\n2026-10-31T10:22:00+08:00 lab sshd[18]: Accepted publickey for analyst from 192.0.2.44 port 40223 ssh2\n',
);
await fs.writeFile(
  path.join(root, 'inspect.json'),
  JSON.stringify([
    {
      Id: 'inert-fixture',
      Name: '/ui-acceptance',
      Config: { Image: 'fixture', User: '' },
      HostConfig: {
        Privileged: true,
        NetworkMode: 'host',
        PidMode: '',
        Binds: [],
        CapAdd: [],
      },
      Mounts: [],
    },
  ]),
);
await fs.copyFile(
  new URL(
    '../src-tauri/resources/agents/gaga-agent-windows-amd64.exe',
    import.meta.url,
  ),
  path.join(root, 'fixture-agent.exe'),
);
const source =
  '<?php\n// Inert forensic fixture: the analysis engine never executes PHP.\n' +
  Array.from({ length: 24 }, (_, i) => `// source line ${i + 1}`).join('\n') +
  '\necho "static fixture";\n';
const compressed = deflateRawSync(Buffer.from(source)).toString('base64');
await fs.writeFile(
  path.join(root, 'layered.php'),
  `<?php\n$value = gzinflate(base64_decode('${compressed}'));\n// No eval, include or dynamic execution.\n`,
);
await fs.writeFile(
  path.join(root, 'baidu-screenshot.txt'),
  'data:image/png;base64,' + (await fs.readFile(screenshot)).toString('base64'),
);
await fs.mkdir(path.join(root, 'screenshots-ui'));
console.log('Disposable native workspace: ' + root);
const app = await launchNative(binary, ['--comfort-ui', root]);
let output = '',
  seen = new Set();
for (const stream of [app.stdout, app.stderr])
  stream.on('data', (chunk) => (output += chunk));
try {
  let result;
  const start = Date.now();
  while (Date.now() - start < 300000) {
    try {
      const log = await fs.readFile(
        path.join(root, 'ui-checkpoints.log'),
        'utf8',
      );
      for (const line of log
        .split('\n')
        .filter((l) => l.startsWith('SCREENSHOT '))) {
        if (seen.has(line)) continue;
        seen.add(line);
        const id = execFileSync(windowHelper, [String(app.pid)], {
          encoding: 'utf8',
        }).trim();
        if (!/^\d+$/.test(id)) throw Error('Native window was not found');
        execFileSync('/usr/sbin/screencapture', [
          '-x',
          '-o',
          '-l',
          id,
          path.join(root, 'screenshots-ui', line.slice(11) + '.png'),
        ]);
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
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
    if (app.exitCode !== null)
      throw Error('Native client exited: ' + output.slice(-2000));
    await new Promise((r) => setTimeout(r, 120));
  }
  await fs.writeFile(path.join(root, 'native-process.log'), output);
  assert(result, 'Native acceptance timed out');
  console.log(
    JSON.stringify(
      {
        root,
        version: result.version,
        passed: result.passed.length,
        layouts: result.layouts.length,
        screenshots: seen.size,
        errors: result.errors,
        baidu: result.baidu && {
          status: result.baidu.status,
          sha256: result.baidu.sha256,
          title: result.baidu.title,
        },
      },
      null,
      2,
    ),
  );
  assert.deepEqual(result.errors, []);
} finally {
  await app.stop();
}
