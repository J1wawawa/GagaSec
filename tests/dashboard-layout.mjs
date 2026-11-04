import fs from 'node:fs/promises';import path from 'node:path';import {DatabaseSync} from 'node:sqlite';
const native=JSON.parse(await fs.readFile(process.argv[2],'utf8'));const output=process.argv[3];await fs.mkdir(output,{recursive:true});
const demo=native.dashboardSnapshots.demo;
const db=new DatabaseSync(path.join(native.root,'workspace.sqlite3'));
const demoId=demo.caseId;
const cases=db.prepare('SELECT id,title,created_at AS createdAt FROM cases').all();
const evidence=db.prepare('SELECT id,case_id AS caseId,name,kind,sha256,size,created_at AS createdAt,report FROM evidence WHERE case_id=?').all(demoId).map(e=>({...e,report:JSON.parse(e.report)}));
const nodes=db.prepare('SELECT id,case_id AS caseId,evidence_id AS evidenceId,finding_id AS findingId,occurred_at AS occurredAt,recorded_at AS recordedAt,title,body,actor,included FROM nodes WHERE case_id=?').all(demoId).map(n=>({...n,included:!!n.included,screenshots:[]}));
const runs=db.prepare('SELECT record FROM analysis_runs WHERE case_id=?').all(demoId).map(r=>JSON.parse(r.record));db.close();
const workspace={cases,activeCase:demoId,evidence,nodes,analysisRuns:runs,aiReviews:[],followups:[],reviewFeedback:[],dataDir:'browser-preview'};
const pages=await(await fetch('http://127.0.0.1:9226/json/list')).json();const ws=new WebSocket(pages.find(p=>p.type==='page').webSocketDebuggerUrl);await new Promise(r=>ws.addEventListener('open',r,{once:true}));let seq=0;const pending=new Map();const errors=[];ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result)}if(m.method==='Runtime.exceptionThrown')errors.push(m.params.exceptionDetails.exception?.description||m.params.exceptionDetails.text)};
const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}))});const evaluate=async expression=>{const r=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value};const pause=ms=>new Promise(r=>setTimeout(r,ms));const checks=[];const check=(label,condition)=>{if(!condition)throw Error(label);checks.push(label)};
await call('Runtime.enable');await call('Page.enable');
const injected=await call('Page.addScriptToEvaluateOnNewDocument',{source:'window.__GAGA_DASHBOARD_FIXTURE__='+JSON.stringify(demo)+';window.__GAGA_WORKSPACE_FIXTURE__='+JSON.stringify(workspace)+';'});
await call('Page.navigate',{url:'http://127.0.0.1:1420/'});await pause(900);await evaluate(`document.querySelector('.splash-skip')?.click()`);await pause(100);
check('Overview shows actual five locally analyzed demo evidence records',await evaluate(`document.querySelector('[data-metric="evidence"] strong').textContent==='5'&&document.querySelector('.dashboard-demo-note').textContent.includes('不代表真实攻击')`));
for(const [width,height] of [[1320,860],[1100,760],[960,660]]){
 await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
 for(const theme of ['light','dark']){
  await evaluate(`(()=>{const e=document.querySelector('[aria-label="主题模式"]');e.value='${theme}';e.dispatchEvent(new Event('change',{bubbles:true}));})()`);await pause(60);
  const bounds=await evaluate(`(()=>{const c=document.querySelector('.content-scroll');return {outer:c.scrollHeight<=c.clientHeight+1&&c.scrollWidth<=c.clientWidth+1,body:document.body.scrollWidth<=innerWidth,cards:Array.from(document.querySelectorAll('.dashboard-card')).every(e=>{const r=e.getBoundingClientRect(),p=c.getBoundingClientRect();return r.bottom<=p.bottom&&r.right<=p.right&&r.height>80}),footer:document.querySelector('.dashboard-footer').getBoundingClientRect().bottom<=c.getBoundingClientRect().bottom+1}})()`);
  check(`Fixed desktop frame ${width}x${height} ${theme}`,Object.values(bounds).every(Boolean));
  for(const tab of ['证据类型','IOC 类型','风险线索']){await evaluate(`Array.from(document.querySelectorAll('[aria-label="数据分布类型"] button')).find(b=>b.textContent===${JSON.stringify(tab)}).click()`);await pause(25);check(`Populated distribution ${tab} ${width} ${theme}`,await evaluate(`document.querySelectorAll('.dashboard-distribution-row').length>0`));}
  if(width===1320){await evaluate(`Array.from(document.querySelectorAll('[aria-label="数据分布类型"] button')).find(b=>b.textContent==='证据类型').click()`);await pause(30);const s=await call('Page.captureScreenshot',{format:'png'});await fs.writeFile(path.join(output,`dashboard-${theme}-preview.png`),Buffer.from(s.data,'base64'));}
 }
}
await call('Emulation.setDeviceMetricsOverride',{width:1320,height:860,deviceScaleFactor:1,mobile:false});
const today=demo.series.at(-1).day;await evaluate(`document.querySelector('.dashboard-chart-day:last-child').click()`);await pause(60);check('Chart date selection is visible and can be cleared',await evaluate(`document.querySelector('.dashboard-chart-day:last-child').getAttribute('aria-pressed')==='true'&&document.querySelector('.dashboard-trend footer').textContent.includes('清除日期筛选')`));await evaluate(`document.querySelector('.dashboard-trend footer button').click()`);
await evaluate(`document.querySelector('[aria-label="查看趋势数据表"]').click()`);await pause(30);check('Exact table values match native snapshot',await evaluate(`(()=>{const rows=Array.from(document.querySelectorAll('.dashboard-chart-table tbody tr'));return rows.length===7&&rows.at(-1).children[1].textContent==='5'&&rows.at(-1).children[2].textContent==='5'})()`));
check('Browser preview remains explicitly labeled',await evaluate(`document.querySelector('.preview-banner').textContent.includes('浏览器界面预览')`));
check('No renderer exceptions',!errors.length);
await fs.writeFile(path.join(output,'dashboard-layout-check.json'),JSON.stringify({checks,errors,browserPreview:true,dataSource:'actual native demo snapshot',sizes:[[1320,860],[1100,760],[960,660]]},null,2));
await call('Page.removeScriptToEvaluateOnNewDocument',{identifier:injected.identifier});ws.close();console.log(JSON.stringify({checks:checks.length,errors}));
