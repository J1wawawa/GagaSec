// Exercise real Chromium with inert local pages. No user workspace or model Key.
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs/promises';
import { spawn } from 'node:child_process';
const output = process.argv[2];
const addr = Object.values(os.networkInterfaces())
  .flat()
  .find((a) => a?.family === 'IPv4' && !a.internal)?.address;
assert(addr, 'Needs reachable local Docker host IPv4');
let seen = [];
const server = http.createServer((req, res) => {
  seen.push(req.url);
  if (req.url === '/disconnect') {
    req.socket.destroy();
    return;
  }
  if (['/start', '/private', '/ipv6', '/loop'].includes(req.url)) {
    res.writeHead(302, {
      location:
        req.url === '/private'
          ? 'http://127.0.0.1/blocked'
          : req.url === '/ipv6'
            ? 'http://[::1]/blocked'
            : req.url === '/loop'
              ? '/loop'
              : '/js',
    });
    res.end();
    return;
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(
    req.url === '/js'
      ? '<title>Entry</title><h1>Entry</h1><script>location.replace("/final")</script>'
      : '<title>Final</title><h1>Final</h1>',
  );
});
await new Promise((r) => server.listen(0, '0.0.0.0', r));
const passed = [];
async function capture(endpoint, follow) {
  seen = [];
  const name = 'gaga-browser-audit-' + crypto.randomUUID();
  const p = spawn('docker', [
    'run',
    '--rm',
    '-i',
    '--pull=never',
    '--name',
    name,
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    '--pids-limit=128',
    '--memory=768m',
    '--cpus=1',
    '--user=1000:1000',
    '--network=bridge',
    '--tmpfs=/tmp:rw,nosuid,nodev,size=256m,mode=1777',
    '--env=HOME=/tmp',
    'gaga-monitor-browser:1',
  ]);
  let stdout = '',
    stderr = '';
  p.stdout.on('data', (v) => (stdout += v));
  p.stderr.on('data', (v) => (stderr += v));
  p.stdin.end(
    JSON.stringify({
      url: `http://${addr}:${server.address().port}${endpoint}`,
      followRedirects: follow,
    }),
  );
  const timeout = setTimeout(() => p.kill('SIGTERM'), 55000);
  try {
    const code = await new Promise((resolve, reject) => {
      p.on('error', reject);
      p.on('close', resolve);
    });
    assert(stdout, stderr);
    return { code, value: JSON.parse(stdout), requests: [...seen] };
  } finally {
    clearTimeout(timeout);
    await new Promise((resolve) => {
      const cleanup = spawn('docker', ['rm', '-f', name], { stdio: 'ignore' });
      cleanup.on('error', resolve);
      cleanup.on('close', resolve);
    });
  }
}
try {
  const followed = await capture('/start', true);
  assert.equal(followed.code, 0, JSON.stringify(followed.value));
  assert(followed.value.finalUrl.endsWith('/final'));
  assert.deepEqual(followed.requests, ['/start', '/js', '/final']);
  passed.push('HTTP and JavaScript redirect hops reach the final page');

  const disabled = await capture('/start', false);
  assert.notEqual(
    disabled.code,
    0,
    JSON.stringify({
      ...disabled,
      value: { ...disabled.value, pngBase64: undefined, dom: undefined },
    }),
  );
  assert.deepEqual(disabled.requests, ['/start']);
  assert.match(disabled.value.error, /跳转被设置/);
  passed.push('Disabled HTTP redirect never requests its destination');

  const script = await capture('/js', false);
  assert.equal(script.code, 0, JSON.stringify(script.value));
  assert.deepEqual(script.requests, ['/js']);
  assert(script.value.finalUrl.endsWith('/js'));
  assert(script.value.pngBase64.length > 100);
  assert(
    script.value.blockedNavigations.some((n) => n.reason === 'follow-disabled'),
  );
  assert(script.value.coverageGaps.length);
  passed.push(
    'Disabled JavaScript navigation captures the entry page with an explicit gap',
  );

  const privateHop = await capture('/private', true);
  assert.notEqual(privateHop.code, 0);
  assert.match(privateHop.value.error, /安全边界/);
  assert.deepEqual(privateHop.requests, ['/private']);
  passed.push('HTTP redirect into a different private host is blocked');

  const ipv6Hop = await capture('/ipv6', true);
  assert.notEqual(ipv6Hop.code, 0);
  assert.match(ipv6Hop.value.error, /安全边界/);
  assert.deepEqual(ipv6Hop.requests, ['/ipv6']);
  passed.push('IPv6 loopback redirect is classified and blocked');

  const failed = await capture('/disconnect', true);
  assert.notEqual(failed.code, 0);
  assert(!failed.value.pngBase64);
  passed.push(
    'Connection failure never archives a Chromium error page as a website screenshot',
  );

  const loop = await capture('/loop', true);
  assert.notEqual(loop.code, 0);
  assert(loop.requests.length <= 8);
  passed.push('HTTP redirect loop is bounded to eight requests');
  if (output)
    await fs.writeFile(
      output,
      JSON.stringify({ passed, errors: [], modelsCalled: false }, null, 2),
    );
  console.log(JSON.stringify({ passed, errors: [] }, null, 2));
} finally {
  server.close();
}
