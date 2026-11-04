// One disposable browser per snapshot. Input is data on stdin, never code.
import { chromium } from 'playwright-core';
import { lookup } from 'node:dns/promises';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
let input = '';
for await (const chunk of process.stdin) {
  input += chunk;
  if (input.length > 16384) throw Error('采集参数过大');
}
const cfg = JSON.parse(input);
const initial = new URL(cfg.url);
const forbidden = (host) =>
  /^(localhost|metadata\.google\.internal)$/i.test(host) ||
  host === '169.254.169.254';
const privateIp = (ip) =>
  /^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|22[4-9]\.|23\d\.|24\d\.|25[0-5]\.)/.test(
    ip,
  ) ||
  /^(::|fc|fd|fe[89ab]|ff)/i.test(ip) ||
  (ip.includes(':') && ip.startsWith('::ffff:'));
const resolve = async (host) => {
  // WHATWG URL.hostname retains brackets for IPv6 literals; dns.lookup does
  // not accept those brackets. Normalize before classifying/looking it up.
  host = host.replace(/^\[([^\]]+)\]$/, '$1');
  return isIP(host) ? [{ address: host }] : lookup(host, { all: true });
};
const initialPrivate = (await resolve(initial.hostname)).some((a) =>
  privateIp(a.address),
);
const cache = new Map();
async function allowed(raw) {
  const u = new URL(raw);
  if (
    !['http:', 'https:'].includes(u.protocol) ||
    u.username ||
    u.password ||
    forbidden(u.hostname)
  )
    return false;
  if (!cache.has(u.hostname)) cache.set(u.hostname, await resolve(u.hostname));
  const addresses = cache.get(u.hostname);
  if (
    !addresses.length ||
    addresses.some(
      (a) =>
        a.address.startsWith('169.254.') ||
        a.address.toLowerCase().startsWith('fe80:'),
    )
  )
    return false;
  return (
    !addresses.some((a) => privateIp(a.address)) ||
    (initialPrivate && u.hostname === initial.hostname)
  );
}
let browser;
const hardLimit = setTimeout(() => {
  process.stdout.write(JSON.stringify({ error: '浏览器截图超过 40 秒时限' }));
  process.exit(124);
}, 40000);
try {
  if (!(await allowed(initial.href))) throw Error('页面地址不在允许范围');
  browser = await chromium.launch({
    executablePath: '/usr/bin/chromium',
    headless: true,
    args: [
      '--disable-dev-shm-usage',
      '--disable-background-networking',
      '--disable-extensions',
      '--disable-quic',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    ],
  });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 1,
    acceptDownloads: false,
    serviceWorkers: 'block',
    locale: 'zh-CN',
  });
  const page = await context.newPage();
  const navigations = [];
  let requests = 0,
    navCount = 0;
  let pendingNavigation = null;
  const blocked = [];
  await context.route('**/*', async (route) => {
    const request = route.request();
    try {
      const top =
        request.isNavigationRequest() && request.frame() === page.mainFrame();
      let reason = null;
      if (++requests > 240 || !['GET', 'HEAD'].includes(request.method()))
        reason = 'request-limit';
      else if (!(await allowed(request.url()))) reason = 'safety-boundary';
      else if (top && ++navCount > 8) reason = 'navigation-limit';
      else if (top && !cfg.followRedirects && navCount > 1)
        reason = 'follow-disabled';
      if (reason) {
        if (top) blocked.push({ url: request.url(), reason });
        // A 204 navigation keeps the already committed entry document visible.
        // abort() can replace it with Chromium's internal error document.
        return top
          ? await route.fulfill({ status: 204, body: '' })
          : await route.abort();
      }
      // Chromium does not re-run a Playwright route for HTTP redirect hops,
      // even if the first response was fulfilled. Never give it an unchecked
      // Location header. Top-level hops are queued for explicit page.goto;
      // subresources are fetched one validated hop at a time.
      let target = request.url();
      for (let hop = 0; hop < 8; hop++) {
        const response = await route.fetch({
          url: target,
          maxRedirects: 0,
          maxRetries: 0,
          timeout: 12000,
        });
        let next = null;
        try {
          const location = response.headers().location;
          if (response.status() >= 300 && response.status() < 400 && location) {
            next = new URL(location, target).href;
            if (top) {
              navigations.push({
                url: target,
                status: response.status(),
                location: next,
                at: new Date().toISOString(),
              });
              if (!cfg.followRedirects)
                blocked.push({ url: next, reason: 'follow-disabled' });
              else if (!(await allowed(next)))
                blocked.push({ url: next, reason: 'safety-boundary' });
              else pendingNavigation = next;
              return await route.fulfill({ status: 204, body: '' });
            }
          } else {
            await route.fulfill({ response });
            return;
          }
        } finally {
          await response.dispose();
        }
        if (++requests > 240 || !(await allowed(next)))
          return await route.abort();
        target = next;
      }
      await route.abort();
    } catch {
      await route.abort().catch(() => {});
    }
  });
  await context.routeWebSocket('**/*', (socket) => socket.close());
  context.on('page', (popup) => {
    if (popup !== page) popup.close().catch(() => {});
  });
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame() && frame.url() !== 'about:blank')
      navigations.push({ url: frame.url(), at: new Date().toISOString() });
  });
  page.on('response', (response) => {
    if (
      response.request().isNavigationRequest() &&
      response.frame() === page.mainFrame()
    )
      navigations.push({
        url: response.url(),
        status: response.status(),
        location: response.headers().location || null,
        at: new Date().toISOString(),
      });
  });
  let navigationError = null;
  const navigate = async (url) => {
    try {
      await page.goto(url, {
        waitUntil: 'domcontentloaded',
        timeout: 25000,
      });
    } catch (e) {
      // An intercepted HTTP Location intentionally stops this navigation.
      if (!pendingNavigation) navigationError = String(e.message).slice(0, 300);
    }
  };
  await navigate(initial.href);
  const assertCapturable = () => {
    const unsafe = blocked.some((n) => n.reason !== 'follow-disabled');
    if (!/^https?:\/\//i.test(page.url()) || unsafe)
      throw Error(
        blocked.length
          ? '页面跳转被设置或安全边界阻止：' +
              blocked.map((n) => n.url).join(', ')
          : navigationError || '页面未加载',
      );
  };
  let settleUntil = Date.now() + 1600;
  while (Date.now() < settleUntil || pendingNavigation) {
    if (pendingNavigation) {
      const target = pendingNavigation;
      pendingNavigation = null;
      await navigate(target);
      settleUntil = Date.now() + 1600;
    } else {
      await page.waitForTimeout(100);
    }
  }
  assertCapturable();
  const finalUrl = page.url();
  const dom = await page.content();
  if (Buffer.byteLength(dom) > 1024 * 1024) throw Error('渲染 DOM 超过 1 MiB');
  const png = await page.screenshot({
    type: 'png',
    fullPage: false,
    timeout: 8000,
    animations: 'disabled',
  });
  assertCapturable();
  if (page.url() !== finalUrl || pendingNavigation)
    throw Error('截图期间页面继续跳转，请重试');
  if (png.length > 8 * 1024 * 1024) throw Error('截图超过 8 MiB');
  process.stdout.write(
    JSON.stringify({
      finalUrl,
      capturedAt: new Date().toISOString(),
      title: await page.title(),
      navigations,
      blockedNavigations: blocked,
      coverageGaps: blocked.length
        ? ['跟随跳转已关闭；截图仅记录已加载的入口页面，未访问跳转目标。']
        : [],
      navigationError,
      viewport: { width: 1440, height: 900 },
      dom,
      domSha256: createHash('sha256').update(dom).digest('hex'),
      pngBase64: png.toString('base64'),
    }),
  );
} catch (e) {
  process.stdout.write(
    JSON.stringify({ error: String(e.message).slice(0, 1000) }),
  );
  process.exitCode = 1;
} finally {
  clearTimeout(hardLimit);
  await browser?.close();
}
