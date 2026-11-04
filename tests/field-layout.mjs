// Browser preview only. Data comes from the completed real native field exercise SQLite.
import fs from 'node:fs/promises';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
const [root,output]=process.argv.slice(2);await fs.mkdir(output,{recursive:true});
const result=JSON.parse(await fs.readFile(path.join(root,'field-verification.json'),'utf8'));
const data=result.dashboard;const db=new DatabaseSync(path.join(root,'workspace.sqlite3'),{readOnly:true});
const cases=db.prepare('SELECT id,title,created_at AS createdAt FROM cases').all();
const evidence=db.prepare('SELECT id,case_id AS caseId,name,kind,sha256,size,created_at AS createdAt,report FROM evidence WHERE case_id=?').all(data.caseId).map(e=>({...e,report:JSON.parse(e.report)}));
const nodes=db.prepare('SELECT id,case_id AS caseId,evidence_id AS evidenceId,finding_id AS findingId,occurred_at AS occurredAt,recorded_at AS recordedAt,title,body,actor,included FROM nodes WHERE case_id=?').all(data.caseId).map(n=>({...n,included:!!n.included,screenshots:[]}));
const runs=db.prepare('SELECT record FROM analysis_runs WHERE case_id=?').all(data.caseId).map(r=>JSON.parse(r.record));db.close();
const workspace={cases,activeCase:data.caseId,evidence,nodes,analysisRuns:runs,aiReviews:[],followups:[],reviewFeedback:[],dataDir:'browser-preview-actual-local-test-data'};
const pages=await(await fetch('http://127.0.0.1:9226/json/list')).json();const ws=new WebSocket(pages.find(p=>p.type==='page').webSocketDebuggerUrl);await new Promise(r=>ws.addEventListener('open',r,{once:true}));let seq=0;const pending=new Map(),errors=[];ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result)}if(m.method==='Runtime.exceptionThrown')errors.push(m.params.exceptionDetails.exception?.description||m.params.exceptionDetails.text)};
const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}))});
const evaluate=async expression=>{const r=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value};const pause=ms=>new Promise(r=>setTimeout(r,ms));const checks=[];const check=(label,value)=>{if(!value)throw Error(label);checks.push(label)};
await call('Runtime.enable');await call('Page.enable');
const injection=await call('Page.addScriptToEvaluateOnNewDocument',{source:'window.__GAGA_DASHBOARD_FIXTURE__='+JSON.stringify(data)+';window.__GAGA_WORKSPACE_FIXTURE__='+JSON.stringify(workspace)+';'});
try{
 await call('Page.navigate',{url:'http://127.0.0.1:1420/'});await pause(900);await evaluate(`document.querySelector('.splash-skip')?.click()`);
 check('Dashboard matches real native field evidence count',await evaluate(`document.querySelector('[data-metric="evidence"] strong').textContent==='${data.counts.evidence}'`));
 check('Dashboard matches real extracted IOC count',await evaluate(`document.querySelector('[data-metric="indicators"] strong').textContent==='${data.counts.indicators}'`));
 for(const [width,height] of [[1320,860],[1100,760],[960,660]]){
  await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
  for(const theme of ['light','dark']){
   await evaluate(`(()=>{const e=document.querySelector('[aria-label="主题模式"]');e.value='${theme}';e.dispatchEvent(new Event('change',{bubbles:true}));})()`);await pause(60);
   check(`Native data dashboard fixed frame ${width} ${theme}`,await evaluate(`(()=>{const c=document.querySelector('.content-scroll');return c.scrollHeight<=c.clientHeight+1&&c.scrollWidth<=c.clientWidth+1&&document.body.scrollWidth<=innerWidth})()`));
   if(width===1320){check(`All five runtime rows fit default desktop ${theme}`,await evaluate(`(()=>{const e=document.querySelector('.dashboard-status-list');return e.scrollHeight<=e.clientHeight+1})()`));const shot=await call('Page.captureScreenshot',{format:'png'});await fs.writeFile(path.join(output,`field-dashboard-${theme}-preview.png`),Buffer.from(shot.data,'base64'));}
  }
 }
 await call('Emulation.setDeviceMetricsOverride',{width:1320,height:860,deviceScaleFactor:1,mobile:false});
 await evaluate(`Array.from(document.querySelectorAll('.nav-item')).find(e=>e.textContent==='日志分析').click()`);await pause(120);
 await evaluate(`Array.from(document.querySelectorAll('.file-row')).find(e=>e.textContent.includes('generated-auth-1GiB.log')).click()`);await pause(100);
 const expected=result.logs.find(l=>l.name.includes('1GiB')).report.metrics.find(m=>m.label==='日志行数').value;
 await evaluate(`Array.from(document.querySelectorAll('.result-tabs button')).find(b=>b.textContent==='发现与举证').click()`);await pause(80);
 check('Large log page displays exact native line count',await evaluate(`document.querySelector('.metrics').textContent.includes('${expected}')`));
 check('Large log page retains scarce late success evidence',await evaluate(`document.querySelector('.finding-table').textContent.includes('SSH 登录成功')`));
 for(const [width,height] of [[1320,860],[960,660]]){
  await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});await pause(70);
  check(`Populated log page stays in fixed desktop ${width}`,await evaluate(`(()=>{const e=document.querySelector('.content-scroll');return e.scrollWidth<=e.clientWidth+1&&document.body.scrollWidth<=innerWidth})()`));
  if(width===1320){const shot=await call('Page.captureScreenshot',{format:'png'});await fs.writeFile(path.join(output,'field-large-log-preview.png'),Buffer.from(shot.data,'base64'));}
 }
 check('Preview explicitly labeled browser-only',await evaluate(`document.querySelector('.preview-banner').textContent.includes('浏览器界面预览')`));check('No renderer exceptions',errors.length===0);
 await fs.writeFile(path.join(output,'field-layout-check.json'),JSON.stringify({checks,errors,browserPreview:true,dataSource:'actual native field-exercise database'},null,2));
 console.log(JSON.stringify({checks:checks.length,errors}));
}finally{await call('Page.removeScriptToEvaluateOnNewDocument',{identifier:injection.identifier});ws.close();}
