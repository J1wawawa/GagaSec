import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, execFileSync } from 'node:child_process';

const checker = fileURLToPath(new URL('./check-source.mjs', import.meta.url));
const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gaga-source-guard-'));
const checks = [];
function scan() {
  const result = spawnSync(process.execPath, [checker, '--root', root], {
    encoding: 'utf8',
  });
  assert.ok([0, 1].includes(result.status), result.stderr);
  return {
    status: result.status,
    value: JSON.parse(result.stdout),
    output: result.stdout,
  };
}
try {
  await fs.writeFile(path.join(root, 'README.md'), 'public source');
  assert.equal(scan().status, 0);
  checks.push('clean source accepted');
  const secret = ['sk', 'SYNTHETIC_CANARY_ONLY_'.repeat(3)].join('-');
  await fs.writeFile(path.join(root, 'accidental.txt'), secret);
  let result = scan();
  assert.equal(result.status, 1);
  assert.ok(!result.output.includes(secret));
  checks.push('credential rejected without printing it');
  await fs.rm(path.join(root, 'accidental.txt'));
  await fs.writeFile(
    path.join(root, 'renamed.bin'),
    Buffer.from('SQLite format 3\0canary'),
  );
  assert.equal(scan().status, 1);
  checks.push('database with changed extension rejected');
  await fs.rm(path.join(root, 'renamed.bin'));
  await fs.writeFile(path.join(root, '.env'), 'local');
  assert.equal(scan().status, 1);
  await fs.rename(path.join(root, '.env'), path.join(root, '.env.example'));
  assert.equal(scan().status, 0);
  checks.push('local environment blocked and clean example accepted');
  const lanIdentity = path.join(root, 'nested/lan-private/identity.json');
  const lanCanary = 'SYNTHETIC_LAN_IDENTITY_DO_NOT_PUBLISH';
  await fs.mkdir(path.dirname(lanIdentity), { recursive: true });
  await fs.writeFile(lanIdentity, JSON.stringify({ key: lanCanary }));
  result = scan();
  assert.equal(result.status, 1);
  assert.ok(
    result.value.problems.some(
      (p) => p.reason === 'lan-private-credentials-or-chat-data',
    ),
  );
  assert.ok(!result.output.includes(lanCanary));
  await fs.rm(path.join(root, 'nested'), { recursive: true });
  assert.equal(scan().status, 0);
  checks.push('LAN private directory blocked without printing credentials');
  await fs.mkdir(path.join(root, 'fixtures/agent-interop'), {
    recursive: true,
  });
  const fixture = path.join(
    root,
    'fixtures/agent-interop/test-only-private.pem',
  );
  await fs.copyFile(
    new URL('../fixtures/agent-interop/test-only-private.pem', import.meta.url),
    fixture,
  );
  assert.equal(scan().status, 0);
  await fs.appendFile(fixture, '\nchanged');
  assert.equal(scan().status, 1);
  checks.push('only exact public fixture key is allowed');
  await fs.rm(fixture);
  execFileSync('git', ['init', '-q', root]);
  await fs.writeFile(
    path.join(root, '.gitignore'),
    '*.sqlite3\nlan-private/\n',
  );
  await fs.writeFile(path.join(root, 'workspace.sqlite3'), 'local data');
  execFileSync('git', ['add', '-f', 'workspace.sqlite3'], { cwd: root });
  result = scan();
  assert.equal(result.value.mode, 'git-tracked');
  assert.equal(result.status, 1);
  checks.push('gitignore cannot hide accidentally tracked workspace');
  await fs.mkdir(path.join(root, 'lan-private'));
  await fs.writeFile(
    path.join(root, 'lan-private/identity.json'),
    JSON.stringify({ key: lanCanary }),
  );
  execFileSync('git', ['add', '-f', 'lan-private/identity.json'], {
    cwd: root,
  });
  result = scan();
  assert.equal(result.status, 1);
  assert.ok(
    result.value.problems.some(
      (p) =>
        p.file === 'lan-private/identity.json' &&
        p.reason === 'lan-private-credentials-or-chat-data',
    ),
  );
  assert.ok(!result.output.includes(lanCanary));
  checks.push('force-tracked LAN identity blocked without printing it');
  await fs.writeFile(
    path.join(root, 'runtime-0.jsonl'),
    '{"message":"PRIVATE_LOG_CANARY"}',
  );
  execFileSync('git', ['add', '-f', 'runtime-0.jsonl'], { cwd: root });
  result = scan();
  assert.ok(
    result.value.problems.some((p) => p.reason === 'private-runtime-log'),
  );
  assert.ok(!result.output.includes('PRIVATE_LOG_CANARY'));
  checks.push('force-tracked runtime log blocked without reading message text');
  process.stdout.write(JSON.stringify({ checks, errors: [] }, null, 2) + '\n');
} finally {
  await fs.rm(root, { recursive: true, force: true });
}
