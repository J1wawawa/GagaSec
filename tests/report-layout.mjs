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
  await call('Page.navigate', {url: 'http://127.0.0.1:1420/'}); await pause(1000);
  await evaluate(`document.querySelector('.splash-skip')?.click()`);
  await click('.primary-navigation [data-group="reports"]');
  await click('[data-action="open-report-editor"]');
  for(const [width,height] of [[1320,860],[1100,760],[960,660]]) {
    await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
    for(const mode of ['light','dark']) {
      await theme(mode);
      for(const section of ['basics','assessment','containment','investigation','attribution','outcome']) {
        await click(`[data-report-section="${section}"]`);
        check(`All six chapter buttons visible ${section} ${width} ${mode}`,await evaluate(`Array.from(document.querySelectorAll('.report-section-nav button')).every(e=>{const r=e.getBoundingClientRect();return r.top>=0&&r.bottom<=innerHeight&&r.right<=innerWidth})`));
        check(`Form has no horizontal overflow ${section} ${width} ${mode}`,await evaluate(`(()=>{const f=document.querySelector('.report-writing');return f.scrollWidth<=f.clientWidth&&document.body.scrollWidth<=innerWidth})()`));
        check(`Editor uses internal scrolling ${section} ${width} ${mode}`,await evaluate(`getComputedStyle(document.querySelector('.report-writing')).overflowY==='auto'`));
        if(['basics','investigation'].includes(section)&&[1320,960].includes(width)) {
          const shot=await call('Page.captureScreenshot',{format:'png'});
          await fs.writeFile(path.join(output,`report-${section}-${width}-${mode}-browser-preview.png`),Buffer.from(shot.data,'base64'));
        }
      }
    }
  }
  await theme('system');
  check('No JavaScript runtime errors',errors.length===0);
  await fs.writeFile(path.join(output,'report-layout.json'),JSON.stringify({browserPreview:true,checks,errors},null,2));
  console.log(JSON.stringify({browserPreview:true,checks:checks.length,errors}));
} finally {
  socket.close();
}
