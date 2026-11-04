// Synthetic archives only. This exercises the shipping WebView/IPC, not a browser mock.
(async () => {
  const invoke=(name,args={})=>window.__TAURI_INTERNALS__.invoke(name,args),passed=[],timings={};
  const pause=(ms=50)=>new Promise(r=>setTimeout(r,ms));
  const wait=async(fn,label)=>{for(let i=0;i<2400;i++){if(await fn())return;await pause();}throw Error('Report acceptance timeout: '+label);};
  const check=(name,ok)=>{if(!ok)throw Error(name);passed.push(name);};
  const jobs=()=>invoke('get_report_exports');
  let root;
  try {
    await wait(()=>document.querySelector('.dashboard-footer')?.textContent.includes('更新于'),'dashboard');
    document.querySelector('.splash-skip')?.click();
    let w=await invoke('get_workspace');root=w.dataDir;
    const a=w.cases.find(c=>c.title==='[导出压力] A'),b=w.cases.find(c=>c.title==='[导出压力] B');
    check('Synthetic fixture contains 1000 unselected archives and two nodes sharing one 1 GiB source',w.evidence.length===1001&&w.nodes.length===2&&w.nodes.every(n=>n.evidenceId==='report-large-fixture'));
    if((await invoke('read_http_text',{path:root+'/phase.txt'})).trim()==='reopen') {
      check('Process-only export history is empty after restart',(await jobs()).length===0);
      check('Completed HTML remains on disk after restart',(await invoke('read_http_text',{path:root+'/complete.html'})).includes('report-large-fixture'));
      await invoke('record_ui_verification',{result:{passed,errors:[],phase:'reopen',realModelCalled:false}});return;
    }
    document.querySelector('[data-group="reports"]').click();await pause(150);
    await wait(()=>[...document.querySelectorAll('button')].some(b=>b.textContent.trim()==='导出报告'),'delivery entry');[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='导出报告').click();await pause();
    const started=performance.now();
    const first=await invoke('start_report_export',{caseId:a.id,path:root+'/cancelled.html',format:'html'});
    await wait(async()=>{const j=(await jobs()).find(j=>j.id===first.id);return j?.phase==='verifying'&&j.verifiedBytes>0;},'real checksum progress');
    let current=(await jobs()).find(j=>j.id===first.id);
    check('Shared source is verified once and checksum reports real intermediate bytes',current.totalBytes===1024*1024*1024&&current.verifiedBytes>0&&current.verifiedBytes<current.totalBytes);
    let duplicateError;try{await invoke('start_report_export',{caseId:a.id,path:root+'/duplicate.html',format:'html'});}catch(e){duplicateError=String(e);}
    check('Second export is rejected while current task is active',duplicateError?.includes('已有报告'));
    await wait(()=>document.querySelector('[aria-label="原始证据校验进度"]')?.value>0,'visible progress');
    check('Native progress bar uses source byte count',document.querySelector('progress').max===1024*1024*1024);
    document.querySelector('[data-group="http"]').click();await pause(100);
    check('Navigation remains usable while export runs',!!document.querySelector('[aria-label="HTTP 请求包"]')&&!!document.querySelector('[data-action="show-report-export"]'));
    const select=document.querySelector('[aria-label="当前事件"]');select.value=b.id;select.dispatchEvent(new Event('change',{bubbles:true}));
    await wait(async()=> (await invoke('get_workspace')).activeCase===b.id,'switch B');
    document.querySelector('[data-action="show-report-export"]').click();
    await wait(()=>document.querySelector('.report-export-panel')?.textContent.includes('另一事件'),'background task in B');
    check('Another incident retains visible source label and cancel control',document.querySelector('.report-export-panel').textContent.includes('[导出压力] A')&&!!document.querySelector('[data-action="cancel-report-export"]'));
    const cancelledAt=performance.now();document.querySelector('[data-action="cancel-report-export"]').click();
    await wait(async()=> (await jobs()).find(j=>j.id===first.id)?.state==='cancelled','cancel final');
    timings.cancelMs=performance.now()-cancelledAt;timings.startToCancelMs=performance.now()-started;
    check('Cancellation preserves previous target bytes',(await invoke('read_http_text',{path:root+'/cancelled.html'}))==='previous-report-canary');
    for(const format of ['html','docx']) {
      const start=performance.now();
      const j=await invoke('start_report_export',{caseId:a.id,path:root+'/complete.'+format,format});
      await wait(async()=>{const r=(await jobs()).find(x=>x.id===j.id);if(r?.state==='failed')throw Error(r.error);return r?.state==='completed';},'complete '+format);
      const completed=(await jobs()).find(x=>x.id===j.id);
      check('Completed '+format+' stays bound to original incident after switching',completed.caseId===a.id&&completed.verifiedBytes===completed.totalBytes&&completed.totalBytes===1024*1024*1024);
      timings[format+'Ms']=performance.now()-start;
    }
    const html=await invoke('read_http_text',{path:root+'/complete.html'});
    check('HTML includes both selected nodes and excludes B and unselected records',html.includes('A selected node 1')&&html.includes('A selected node 2')&&!html.includes('[导出压力] B')&&!html.includes('unselected-canary'));
    check('Export never switches active investigation',(await invoke('get_workspace')).activeCase===b.id);
    const rejected=await invoke('start_report_export',{caseId:a.id,path:root+'/workspace.sqlite3',format:'html'});
    await wait(async()=> (await jobs()).find(j=>j.id===rejected.id)?.state==='failed','protected output refusal');
    check('Database overwrite refusal has an actionable reason',(await jobs()).find(j=>j.id===rejected.id).error.includes('不能用报告覆盖'));
    select.value=a.id;select.dispatchEvent(new Event('change',{bubbles:true}));
    await wait(()=>document.querySelector('.report-export-panel')?.textContent.includes('不能用报告覆盖'),'source incident status');
    check('Failed export is shown separately from completed outputs',document.querySelectorAll('[data-export-state="failed"]').length===1&&document.querySelectorAll('[data-export-state="completed"]').length===1);
    for(const theme of ['light','dark']) {
      const themeSelect=document.querySelector('[aria-label="主题模式"]');themeSelect.value=theme;themeSelect.dispatchEvent(new Event('change',{bubbles:true}));
      await invoke('resize_ui_verification',{width:960,height:660});await pause(150);
      check('Export history fits minimum native window '+theme,document.documentElement.scrollWidth<=innerWidth&&document.querySelector('.report-export-panel').getBoundingClientRect().bottom<innerHeight);
    }
    await invoke('record_ui_verification',{result:{passed,errors:[],phase:'first',timings,realModelCalled:false,samplesExecuted:false,archiveBytes:1024*1024*1024,unselectedArchives:1000}});
  } catch(error) {
    await invoke('record_ui_verification',{result:{passed,errors:[String(error),error.stack],timings,realModelCalled:false}});
  }
})();
