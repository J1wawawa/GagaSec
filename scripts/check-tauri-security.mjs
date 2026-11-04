// Release guard for the desktop trust boundary. This is intentionally a
// source check: it does not read credentials, start the client, or make a
// network request. Runtime behavior remains covered by the Rust security tests.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const readJson = (file) =>
  JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
const fail = (message) => {
  throw new Error(`Tauri security guard: ${message}`);
};

const config = readJson('src-tauri/tauri.conf.json');
const csp = config.app?.security?.csp || '';
if (!csp.includes("default-src 'self'")) fail('CSP must have a self default');
if (!csp.includes("script-src 'self'"))
  fail('CSP must restrict scripts to self');
if (!csp.includes("object-src 'none'")) fail('CSP must disable objects');
if (!csp.includes("frame-src 'none'")) fail('CSP must disable frames');
if (!csp.includes('connect-src ipc: http://ipc.localhost'))
  fail('CSP connect-src must stay on the Tauri IPC bridge');
if (/\b(?:script-src|connect-src|default-src)\s+[^;]*\*/.test(csp))
  fail('CSP must not contain wildcard script/connect/default sources');
const devUrl = new URL(config.build?.devUrl || '');
if (devUrl.protocol !== 'http:' || devUrl.hostname !== '127.0.0.1')
  fail('development URL must be loopback HTTP');

const capabilities = readJson('src-tauri/capabilities/default.json');
const permissions = capabilities.permissions || [];
const forbidden = permissions.filter((permission) =>
  /^(?:shell|process|http|fs):(?:default|allow-all|allow-read|allow-write)/.test(
    permission,
  ),
);
if (forbidden.length)
  fail(`high-risk capabilities enabled: ${forbidden.join(', ')}`);
if (!capabilities.windows?.includes('main'))
  fail('default capability must be scoped to the main window');

const cargo = fs.readFileSync(path.join(root, 'src-tauri/Cargo.toml'), 'utf8');
if (/tauri-plugin-shell|tauri-plugin-http/.test(cargo))
  fail('shell/http plugins require a separate reviewed capability boundary');

const workflow = fs.readFileSync(
  path.join(root, '.github/workflows/build.yml'),
  'utf8',
);
if (!workflow.includes('permissions:\n  contents: read'))
  fail('CI workflow must keep repository permissions read-only');
if (!workflow.includes('npm audit --audit-level=high'))
  fail('CI must run the frontend dependency audit');
if (!workflow.includes('reverse-worker audit --audit-level=high'))
  fail('CI must run the reverse-worker dependency audit');

const providers = readJson('src/ai-providers.json').providers || [];
if (providers.length !== 4)
  fail('only the four approved model providers are allowed');
for (const provider of providers) {
  const endpoint = new URL(provider.endpoint);
  if (endpoint.protocol !== 'https:')
    fail(`model endpoint is not HTTPS: ${provider.id}`);
  if (!provider.models?.length)
    fail(`model provider has no models: ${provider.id}`);
}

console.log(
  JSON.stringify(
    {
      format: 'gaga-tauri-security/1',
      checks: [
        'strict CSP and loopback dev URL',
        'window-scoped low-risk capabilities',
        'no shell/http Tauri plugins',
        'read-only CI permissions and dependency audits',
        'four HTTPS official model providers',
      ],
      errors: [],
    },
    null,
    2,
  ),
);
