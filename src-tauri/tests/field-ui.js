(async()=>{
 const passed=[];const invoke=(name,args={})=>window.__TAURI_INTERNALS__.invoke(name,args);const pause=ms=>new Promise(r=>setTimeout(r,ms));
 const wait=async(fn,label)=>{for(let i=0;i<200;i++){if(await fn())return;await pause(100)}throw Error('Field UI timeout: '+label)};
 const check=(label,value)=>{if(!value)throw Error(label);passed.push(label)};
 const nav=async(text)=>{Array.from(document.querySelectorAll('.nav-item')).find(b=>b.querySelector('span')?.textContent===text).click();await pause(100)};
 const file=async(name)=>{await wait(()=>Array.from(document.querySelectorAll('.file-row')).some(b=>b.textContent.includes(name)),name);Array.from(document.querySelectorAll('.file-row')).find(b=>b.textContent.includes(name)).click();await pause(100)};
 try{
  await wait(()=>document.querySelector('.dashboard-footer')?.textContent.includes('更新于'),'dashboard');document.querySelector('.splash-skip')?.click();
  const w=await invoke('get_workspace');check('Native field workspace is isolated and contains actual test data',w.cases.some(c=>c.id===w.activeCase&&c.title.startsWith('[本机实测]'))&&w.evidence.length===8);
  check('Native dashboard reflects eight archived field evidence records',document.querySelector('[data-metric="evidence"] strong').textContent==='8');
  check('Native dashboard shows real extracted indicators',Number(document.querySelector('[data-metric="indicators"] strong').textContent)>0);
  const e=w.evidence.find(e=>e.name==='generated-auth-1GiB.log');check('Native test opens physically archived GiB input',e.size>1024*1024*1024&&e.sha256.length===64);
  await nav('日志分析');await file(e.name);
  const count=e.report.metrics.find(m=>m.label==='日志行数').value;
  check('Actual native log metrics match full scan line count',document.querySelector('.metrics').textContent.includes(count));
  check('Actual native log process has a completed persisted incident',document.querySelector('.analysis-process').textContent.includes('incident-'));
  const indexed=await invoke('query_log_timeline',{filter:{evidenceId:e.id}});
  check('GiB native timeline uses full derived index and original time',indexed.total>100&&indexed.events[0].at==='2026-10-27T02:33:00.000Z');
  Array.from(document.querySelectorAll('.result-tabs button')).find(b=>b.textContent==='发现与举证').click();await pause(100);
  const success=e.report.findings.find(f=>f.title.includes('SSH 登录成功'));
  const row=Array.from(document.querySelectorAll('.finding-row')).find(b=>b.textContent.includes('SSH 登录成功'));check('Scarce late successful login is visible among sampled findings',Boolean(row));row.click();await pause(100);
  check('Native evidence inspector exposes original line and exact location',document.querySelector('.finding-detail').textContent.includes('Accepted publickey')&&document.querySelector('.finding-detail').textContent.includes(String(success.line)));
  const material=await invoke('preview_ai_material',{evidenceId:e.id});
  check('Actual native AI material includes late successful login and sudo evidence',material.includes('Accepted publickey')&&material.includes('COMMAND=/usr/bin/id')&&material.includes(e.sha256));
  check('Large input becomes bounded AI material',material.length<22000);
  check('Native log viewport stays within the desktop frame',document.documentElement.scrollWidth<=innerWidth&&document.querySelector('.content-scroll').scrollWidth<=document.querySelector('.content-scroll').clientWidth+1);
  await nav('WebShell 分析');await file('disabled-webshell.php');
  check('Native static report includes dynamic-code signatures with source proof',document.querySelector('.finding-table').textContent.includes('动态代码执行'));
  await file('benign.php');check('Native benign PHP control has zero findings',document.querySelector('.metrics').textContent.includes('规则命中0'));
  await nav('告警研判');await file('Agent采集');
  check('Native snapshot displays tool collection failures',document.querySelector('.metrics').textContent.includes('采集错误项3'));
  await nav('事件时间线');check('Native field timeline retains proof and screenshot placeholders',document.querySelectorAll('.timeline-node').length===3&&document.querySelectorAll('.screenshot-placeholder').length===3);
  document.querySelector('.dashboard-primary').click();await pause(100);
  await invoke('record_ui_verification',{result:{passed,native:true,errors:[],externalModelCalled:false,mode:'actual-container-and-GiB-log-workspace'}});
 }catch(error){await invoke('record_ui_verification',{result:{passed,native:true,errors:[String(error),error.stack],mode:'actual-container-and-GiB-log-workspace'}})}
})();
