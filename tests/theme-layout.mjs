// Browser media emulation only. Native manual theme and window checks run separately.
import fs from 'node:fs/promises';
const output=process.argv[2];
const pages=await(await fetch('http://127.0.0.1:9226/json/list')).json();
const ws=new WebSocket(pages.find(p=>p.type==='page').webSocketDebuggerUrl);
await new Promise(r=>ws.addEventListener('open',r,{once:true}));
let id=0;const pending=new Map(),checks=[];
ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result);}};
const call=(method,params={})=>new Promise((resolve,reject)=>{const n=++id;pending.set(n,{resolve,reject});ws.send(JSON.stringify({id:n,method,params}));});
const evaluate=async expression=>{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const check=(name,v)=>{if(!v)throw Error(name);checks.push(name);};
try{
 await call('Page.navigate',{url:'http://127.0.0.1:1420/'});await pause(700);
 await evaluate("document.querySelector('.splash-skip')?.click()");
 const select=async v=>{await evaluate(`(()=>{const s=document.querySelector('[aria-label="主题模式"]');s.value='${v}';s.dispatchEvent(new Event('change',{bubbles:true}));})()`);await pause(60);};
 await select('system');
 for(const theme of ['light','dark','light']){
  await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:theme}]});await pause(80);
  check('System theme responds to media change: '+theme,await evaluate(`document.documentElement.dataset.theme==='${theme}'&&document.documentElement.dataset.themeMode==='system'`));
 }
 await select('dark');await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:'light'}]});await pause(80);
 check('Manual override stays dark while system is light',await evaluate("document.documentElement.dataset.theme==='dark'"));
 await select('system');
 check('Returning to system applies current light preference',await evaluate("document.documentElement.dataset.theme==='light'"));
 await call('Page.reload');await pause(600);await evaluate("document.querySelector('.splash-skip')?.click()");
 check('System preference survives renderer reload',await evaluate("document.querySelector('[aria-label=\"主题模式\"]').value==='system'"));
 await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
 check('Reduced motion disables spinning animation',await evaluate("(()=>{const e=document.createElement('span');e.className='spinning';document.body.append(e);const result=getComputedStyle(e).animationDuration;e.remove();return parseFloat(result)<0.01;})()"));
 await fs.writeFile(output,JSON.stringify({browserMediaEmulation:true,checks,errors:[]},null,2));
 console.log(JSON.stringify({checks:checks.length,errors:[]}));
}finally{await call('Emulation.setEmulatedMedia',{features:[]});ws.close();}
