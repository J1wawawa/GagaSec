import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
const go = process.env.GAGA_GO || 'go';
mkdirSync('src-tauri/resources/agents', { recursive: true });
for (const [os, arch, suffix] of [
  ['linux', 'amd64', ''],
  ['linux', 'arm64', ''],
  ['windows', 'amd64', '.exe'],
]) {
  const result = spawnSync(
    go,
    [
      'build',
      '-trimpath',
      '-ldflags=-s -w',
      '-o',
      `../src-tauri/resources/agents/gaga-agent-${os}-${arch}${suffix}`,
      '.',
    ],
    {
      cwd: 'agent',
      env: { ...process.env, GOOS: os, GOARCH: arch, CGO_ENABLED: '0' },
      stdio: 'inherit',
    },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status || 1);
  console.log(`Built Agent ${os}/${arch}`);
}
