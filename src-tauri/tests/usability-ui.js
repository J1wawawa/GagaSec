// Synthetic evidence only. No model request, key read, sample execution or external target.
(async () => {
 const invoke=(name,args={})=>window.__TAURI_INTERNALS__.invoke(name,args),passed=[];
 const pause=(ms=90)=>new Promise(r=>setTimeout(r,ms));
 const wait=async(fn,label)=>{const start=Date.now();while(Date.now()-start<45000){if(await fn())return;await pause();}throw Error('Usability timeout: '+label);};
 const check=(label,value)=>{if(!value)throw Error(label);passed.push(label);};
 const button=(text,selector='button')=>[...document.querySelectorAll(selector)].find(b=>b.textContent.trim()===text);
 const set=async(el,value)=>{if(!el)throw Error('Missing input');const proto=el instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:el instanceof HTMLSelectElement?HTMLSelectElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(proto,'value').set.call(el,value);el.dispatchEvent(new Event(el instanceof HTMLSelectElement?'change':'input',{bubbles:true}));await pause();};
 const enter=(label,value)=>set(document.querySelector(`[aria-label="${label}"]`),value);
 const route=async(group,module)=>{document.querySelector(`[data-group="${group}"]`).click();await pause();if(module)document.querySelector(`[data-module="${module}"]`).click();await pause();};
 const reports=async()=>{await route('reports');await wait(()=>document.querySelector('[data-action="open-report-editor"]:not(:disabled)'),'report center');document.querySelector('[data-action="open-report-editor"]').click();await pause();};
 const readyReport=()=>wait(()=>document.querySelector('.report-save-status')?.dataset.state==='saved','report saved');
 const capture=async()=>{button('记录这组报文').click();await wait(()=>document.querySelector('[aria-label="快速关联报告章节"]:not([disabled])'),'record directory');};
 const close=()=>document.querySelector('[aria-label="关闭时间线节点窗口"]').click();
 const pixel='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';
 try{
  await wait(()=>document.querySelector('.dashboard-footer')?.textContent.includes('更新于'),'workspace');document.querySelector('.splash-skip')?.click();
  let w=await invoke('get_workspace');const root=w.dataDir,caseId=w.activeCase;
  const phase=(await invoke('read_http_text',{path:root+'/phase.txt'})).trim();
  if(phase==='reopen'){
   const d=await invoke('get_report_draft',{caseId});
   check('Restart preserves nodes, pasted image and chapter references',w.nodes.length===2&&w.nodes[0].screenshots.length+w.nodes[1].screenshots.length===1&&d.steps[0].nodeIds.length===2);
   check('Restart preserves edited report body',d.steps[0].body==='原证据导航前保存的正文');
   await reports();await readyReport();button('报告预览','.report-modebar button').click();await pause();
   check('Restart report renders the saved image',document.querySelectorAll('.report-paper img[src^="data:"]').length===1);
   await invoke('record_ui_verification',{result:{phase,passed,errors:[],realModelCalled:false}});return;
  }
  await route('http');
  await enter('HTTP 请求包','GET /.env HTTP/1.1\r\nHost: example.test\r\n\r\n');
  await enter('HTTP 响应包','HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDB_PASSWORD=synthetic_value\n');
  document.querySelector('.http-composer form').requestSubmit();await wait(()=>!!button('记录这组报文'),'HTTP result');
  w=await invoke('get_workspace');const evidence=w.evidence[0];
  await capture();
  await enter('快速关联报告章节','new');await enter('快速新章节标题','阶段一：Web 排查');
  await set(document.querySelector('.capture-fields .form-row label:last-child input'),'张三');
  const bytes=Uint8Array.from(atob(pixel),c=>c.charCodeAt(0));const file=new File([bytes],'synthetic.png',{type:'image/png'});
  const event=new Event('paste',{bubbles:true,cancelable:true});Object.defineProperty(event,'clipboardData',{value:{files:[file]}});document.querySelector('[aria-label="快速举证截图"]').dispatchEvent(event);
  await wait(()=>document.querySelector('[aria-label="快速截图图注"]'),'paste');await enter('快速截图图注','合成举证图，仅用于操作验收');
  for(const theme of ['light','dark']){
   // Change the actual theme control using a user-equivalent change event.
   await enter('主题模式',theme);await invoke('resize_ui_verification',{width:960,height:660});await pause(180);
   const modal=document.querySelector('.capture-modal'),r=modal.getBoundingClientRect();
   check('Capture fits minimum width in '+theme,r.left>=0&&r.right<=innerWidth+1&&modal.scrollWidth<=modal.clientWidth+1);
   check('Report and screenshot controls remain present in '+theme,!!document.querySelector('.capture-options img')&&!!document.querySelector('.capture-footer .primary'));
  }
  document.querySelector('.capture-footer .primary').click();await wait(()=>!document.querySelector('.capture-modal'),'save capture');
  w=await invoke('get_workspace');let d=await invoke('get_report_draft',{caseId});
  check('Save keeps investigator on the current analysis',!!document.querySelector('.module-http'));
  check('One save commits node, captioned screenshot and report reference',w.nodes.length===1&&w.nodes[0].screenshots[0].caption==='合成举证图，仅用于操作验收'&&d.steps[0].nodeIds[0]===w.nodes[0].id&&d.steps[0].owner==='张三');
  await capture();check('Reopened capture has a fresh empty screenshot slot',!document.querySelector('.capture-options img'));
  await enter('快速关联报告章节',d.steps[0].id);button('保存并打开报告','.capture-footer button').click();await wait(()=>!!document.querySelector('.report-workspace'),'open report');await readyReport();
  w=await invoke('get_workspace');d=await invoke('get_report_draft',{caseId});
  check('Second save links existing chapter without replacing its owner',w.nodes.length===2&&d.steps.length===1&&d.steps[0].owner==='张三'&&d.steps[0].nodeIds.length===2);
  document.querySelector(`[data-report-section="${d.steps[0].id}"]`).click();await pause();await enter('章节正文','原证据导航前保存的正文');
  const details=[...document.querySelectorAll('details')].find(el=>el.querySelector('summary')?.textContent.includes('举证'));if(details)details.open=true;
  button('查看原证据与分析').click();await wait(()=>!!document.querySelector('.module-http'),'source navigation');
  check('Source navigation saves current report body',(await invoke('get_report_draft',{caseId})).steps[0].body==='原证据导航前保存的正文');
  check('Source navigation returns to the referenced HTTP material',document.querySelector('.file-row.selected')?.textContent.includes(evidence.name)&&document.querySelector('.http-reader')?.textContent.includes('/.env'));
  // Ensure a local recovery journal cannot keep a stale report selection enabled.
  await capture();await enter('快速关联报告章节',d.steps[0].id);
  const backupKey=`gaga-report-draft/1/${encodeURIComponent(root)}/${encodeURIComponent(caseId)}`;
  localStorage.setItem(backupKey,JSON.stringify({baseVersion:d.updatedAt,draft:d}));button('刷新章节','.capture-options button').click();
  await wait(()=>document.querySelector('[aria-label="快速关联报告章节"]').disabled,'recovery block');
  check('Pending report recovery clears previous chapter selection',document.querySelector('[aria-label="快速关联报告章节"]').value==='');
  localStorage.removeItem(backupKey);close();await pause();
  for(let i=0;i<25;i++)await invoke('analyze_http_pair',{request:`GET /health?item=${i} HTTP/1.1\r\nHost: example.test\r\n\r\n`,response:'HTTP/1.1 204 No Content\r\n\r\n'});
  // The seeding IPC bypasses React; reopen the case through its real selector.
  await enter('当前事件',caseId);
  await route('investigation','evidence');await wait(()=>document.querySelectorAll('[data-evidence-id]').length===24,'paged evidence');
  check('Evidence collection displays 24 rows per page',document.querySelectorAll('[data-evidence-id]').length===24);
  button('下一页').click();await pause();check('Evidence next page displays remaining originals',document.querySelectorAll('[data-evidence-id]').length===2);
  await enter('搜索本事件证据',evidence.sha256);await pause(250);check('Hash search identifies the original',document.querySelectorAll('[data-evidence-id]').length===1&&!!document.querySelector(`[data-evidence-id="${evidence.id}"]`));
  await enter('搜索本事件证据','');await enter('证据举证筛选','linked');check('Linked filter finds the cited material',document.querySelectorAll('[data-evidence-id]').length===1);
  await enter('证据举证筛选','unlinked');check('Unlinked filter excludes cited material',!document.querySelector(`[data-evidence-id="${evidence.id}"]`));
  document.querySelector('.commandbar-actions [data-module="environment"]').click();await pause();button('检查本机环境').click();await wait(()=>document.querySelector('.platform-page')?.textContent.includes('存储可写：通过')&&!document.querySelector('.platform-page')?.textContent.includes('本机环境检查…'),'environment');
  check('Environment presents local, model, isolation and target readiness',document.querySelectorAll('.setup-item').length===4);
  button('打开模型设置').click();await pause();check('Readiness links directly to official model settings',!!document.querySelector('.module-settings'));
  const job=await invoke('start_report_export',{caseId,path:root+'/usability.docx',format:'docx'});await wait(async()=>{const j=(await invoke('get_report_exports')).find(j=>j.id===job.id);if(j?.state==='failed')throw Error(j.error);return j?.state==='completed';},'DOCX export');
  check('Linked report exports as DOCX',true);
  await invoke('record_ui_verification',{result:{phase,passed,errors:[],realModelCalled:false,rawSampleExecuted:false}});
 }catch(e){await invoke('record_ui_verification',{result:{passed,errors:[String(e)],realModelCalled:false}});}
})();
