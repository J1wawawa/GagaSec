// Browser-only layout supplement. No native IPC or backend success is simulated.
import fs from 'node:fs/promises';
import path from 'node:path';
const output = process.argv[2];
if (!output) throw Error('Pass output directory');
await fs.mkdir(output, {recursive: true});
const pages = await (await fetch('http://127.0.0.1:9226/json/list')).json();
const socket = new WebSocket(pages.find((page) => page.type === 'page').webSocketDebuggerUrl);
await new Promise((resolve) => socket.addEventListener('open', resolve, {once: true}));
let sequence = 0;
const pending = new Map(), checks = [], errors = [];
socket.onmessage = (event) => {
  const message = JSON.parse(event.data);
  if (message.id) {
    const task = pending.get(message.id); pending.delete(message.id);
    message.error ? task.reject(Error(message.error.message)) : task.resolve(message.result);
  }
  if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails.exception?.description || message.params.exceptionDetails.text);
};
const call = (method, params = {}) => new Promise((resolve, reject) => {
  const id = ++sequence; pending.set(id, {resolve, reject}); socket.send(JSON.stringify({id, method, params}));
});
const evaluate = async (expression) => {
  const result = await call('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true});
  if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
};
const pause = (ms = 70) => new Promise((resolve) => setTimeout(resolve, ms));
const check = (name, condition) => { if (!condition) throw Error(name); checks.push(name); };
const click = async (selector) => { await evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`); await pause(); };
const theme = async (value) => {
  await evaluate(`(()=>{const s=document.querySelector('[aria-label="主题模式"]');s.value=${JSON.stringify(value)};s.dispatchEvent(new Event('change',{bubbles:true}))})()`);
  await pause();
};
try {
  await call('Runtime.enable'); await call('Page.enable');
  await call('Page.navigate', {url: 'http://127.0.0.1:1420/'}); await pause(800);
  await evaluate(`document.querySelector('.splash-skip')?.click()`);
  for (const [width, height] of [[1320, 860], [1100, 760], [960, 660]]) {
    await call('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile: false});
    for (const mode of ['light', 'dark']) {
      await theme(mode);
      const bounds = await evaluate(`(()=>{const r=document.querySelector('.desktop-commandbar');return [...r.querySelectorAll('button,.brand')].every(e=>{const b=e.getBoundingClientRect();return b.width>0&&b.left>=0&&b.right<=innerWidth})&&r.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth})()`);
      check(`Every top-level entry fits without horizontal scrolling ${width} ${mode}`, bounds);
      await click('[aria-label="全部工具"]');
      check(`All 21 tools discoverable ${width} ${mode}`, await evaluate(`document.querySelectorAll('.tool-results [data-tool]').length===21`));
      const dialog = await evaluate(`(()=>{const p=document.querySelector('.tool-palette'),r=p.getBoundingClientRect(),s=document.querySelector('.tool-results');return r.top>=0&&r.bottom<=innerHeight&&p.scrollWidth<=p.clientWidth&&s.scrollHeight>s.clientHeight&&s.scrollWidth<=s.clientWidth})()`);
      check(`Search dialog uses its own scroll pane within viewport ${width} ${mode}`, dialog);
      if ([1320, 960].includes(width)) {
        const shot = await call('Page.captureScreenshot', {format: 'png'});
        await fs.writeFile(path.join(output, `tools-${width}-${mode}-browser-preview.png`), Buffer.from(shot.data, 'base64'));
      }
      await click('[aria-label="关闭全部工具"]');
      const modules = await evaluate(`Array.from(document.querySelectorAll('.module-navigation .nav-item')).map(b=>b.dataset.module)`);
      for (const module of modules) {
        await evaluate(`(()=>{const m=document.querySelector('.module-navigation [data-module="${module}"]');const group=m.closest('[data-group]').dataset.group;document.querySelector('.primary-navigation [data-group="'+group+'"]').click()})()`);
        await pause(20); await click(`.module-navigation [data-module="${module}"]`);
        check(`Only related tools shown for ${module} ${width} ${mode}`, await evaluate(`document.querySelectorAll('.module-navigation [data-active="true"] .nav-item').length<=4&&document.querySelector('.content-scroll.module-${module}')!==null`));
      }
      await click('.primary-navigation [data-group="http"]');
      if ([1320, 960].includes(width)) {
        const shot = await call('Page.captureScreenshot', {format: 'png'});
        await fs.writeFile(path.join(output, `http-${width}-${mode}-browser-preview.png`), Buffer.from(shot.data, 'base64'));
      }
    }
  }
  await theme('system');
  check('No JavaScript runtime errors', errors.length === 0);
  await fs.writeFile(path.join(output, 'navigation-layout.json'), JSON.stringify({browserPreview: true, checks, errors}, null, 2));
  console.log(JSON.stringify({checks: checks.length, errors, browserPreview: true}));
} finally {
  socket.close();
}
