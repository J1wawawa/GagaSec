// Source-only release guard. Never print matching bytes or read system credentials.
// This catches known mistakes; it is not a complete secret detector or archive DLP.
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const args = process.argv.slice(2);
const rootFlag = args.indexOf('--root');
const root = path.resolve(rootFlag < 0 ? '.' : args[rootFlag + 1]);
const excluded = new Set([
  '.git',
  'node_modules',
  'dist',
  'target',
  'gen',
  '__pycache__',
]);
const publicFixture = 'fixtures/agent-interop/test-only-private.pem';
const fixtureHash =
  'd2604a66e4693e46afb4e5b644dba60757e180e4f5b841898ec0b351c1be5669';
const problems = [];
const report = (file, reason) => problems.push({ file, reason });
let files = [];
let mode;
try {
  // --cached includes accidentally tracked files even when .gitignore excludes them.
  const top = execFileSync('git', ['rev-parse', '--show-toplevel'], {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
  if ((await fs.realpath(top)) !== (await fs.realpath(root)))
    throw Error('Use the project root.');
  files = execFileSync('git', ['ls-files', '--cached', '-z'], {
    cwd: root,
    encoding: 'utf8',
  })
    .split('\0')
    .filter(Boolean);
  mode = 'git-tracked';
} catch {
  mode = 'source-directory';
  async function walk(relative = '') {
    for (const item of await fs.readdir(path.join(root, relative), {
      withFileTypes: true,
    })) {
      const file = path.posix.join(relative, item.name);
      if (item.isDirectory()) {
        if (!excluded.has(item.name) && file !== 'src-tauri/resources/agents')
          await walk(file);
      } else files.push(file);
    }
  }
  await walk();
}

for (const file of files.sort()) {
  // The LAN identity stores binary credentials as base64, not PEM. Reject the
  // entire private-data path, including force-tracked files, without reading it.
  if (file.split('/').includes('lan-private')) {
    report(file, 'lan-private-credentials-or-chat-data');
    continue;
  }
  if (
    file.split('/').includes('runtime-logs') ||
    /^runtime-\d+\.jsonl$/.test(path.posix.basename(file))
  ) {
    report(file, 'private-runtime-log');
    continue;
  }
  const location = path.join(root, file);
  const meta = await fs.lstat(location);
  if (meta.isSymbolicLink() || !meta.isFile()) {
    report(file, 'source-link-or-special-file');
    continue;
  }
  const name = path.posix.basename(file);
  if (file.startsWith('src-tauri/resources/agents/'))
    report(file, 'generated-agent-template');
  if (
    /\.sqlite(?:3)?(?:-|$)|\.(?:db|p12|pfx)$/i.test(name) ||
    name === 'gaga-task.json' ||
    /^workspace-location(?:\.previous)?\.json$/.test(name) ||
    (name.startsWith('.env') && !['.env.example', '.env.sample'].includes(name))
  )
    report(file, 'workspace-or-local-configuration');
  if (meta.size > 32 * 1024 * 1024) {
    report(file, 'oversized-source-file');
    continue;
  }
  const bytes = await fs.readFile(location);
  if (bytes.subarray(0, 16).equals(Buffer.from('SQLite format 3\0')))
    report(file, 'database-content');
  if (/sk-[A-Za-z0-9_-]{24,}/.test(bytes.toString('latin1')))
    report(file, 'possible-api-credential');
  if (
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(
      bytes.toString('latin1'),
    )
  ) {
    const hash = crypto.createHash('sha256').update(bytes).digest('hex');
    if (file !== publicFixture || hash !== fixtureHash)
      report(file, 'private-key-not-public-fixture');
  }
  // The filename is not a blanket exception: replacing that public key is blocked too.
  if (
    file === publicFixture &&
    crypto.createHash('sha256').update(bytes).digest('hex') !== fixtureHash
  )
    report(file, 'public-fixture-changed-review-required');
}
const result = {
  format: 'gaga-source-hygiene/1',
  mode,
  filesChecked: files.length,
  problems,
  matchingContentIncluded: false,
};
process.stdout.write(JSON.stringify(result, null, 2) + '\n');
process.exitCode = problems.length ? 1 : 0;
