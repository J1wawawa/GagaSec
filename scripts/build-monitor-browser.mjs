// Keep the image compatibility label identical to monitor_browser::source_hash.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
const root = new URL('../monitor-browser/', import.meta.url);
const hash = createHash('sha256');
for (const name of [
  'Dockerfile',
  'package.json',
  'package-lock.json',
  'capture.mjs',
]) {
  const bytes = await readFile(new URL(name, root));
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  hash.update(name).update(length).update(bytes);
}
const digest = hash.digest('hex');
const args = process.argv.slice(2);
if (args.length === 1 && args[0] === '--hash-only') {
  console.log(digest);
} else {
  const mirror = args.length ? args[1] : 'official';
  const mirrors = {
    official: 'https://dl-cdn.alpinelinux.org/alpine',
    aliyun: 'https://mirrors.aliyun.com/alpine',
  };
  if (
    (args.length && (args.length !== 2 || args[0] !== '--mirror')) ||
    !mirrors[mirror]
  )
    throw Error(
      'Usage: node scripts/build-monitor-browser.mjs [--mirror official|aliyun]',
    );
  const child = spawn(
    'docker',
    [
      'build',
      '--build-arg',
      `ALPINE_MIRROR=${mirrors[mirror]}`,
      '--build-arg',
      `GAGA_BROWSER_SOURCE_SHA256=${digest}`,
      '-t',
      'gaga-monitor-browser:1',
      fileURLToPath(root),
    ],
    { stdio: 'inherit' },
  );
  child.on('error', (error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
  child.on('exit', (code) => {
    process.exitCode = code ?? 1;
  });
}
