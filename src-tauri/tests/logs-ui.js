// Synthetic errors and a previously generated synthetic case PDF only.
(async () => {
 const invoke=(n,a={})=>window.__TAURI_INTERNALS__.invoke(n,a), passed=[];
 const pause=(ms=75)=>new Promise(r=>setTimeout(r,ms));
 const wait=async(fn,label)=>{const start=Date.now();while(Date.now()-start<45000){if(await fn())return;await pause();}throw Error('Log/PDF native timeout: '+label);};
 const check=(n,ok)=>{if(!ok)throw Error(n);passed.push(n);};
 const button=(name,selector='button')=>[...document.querySelectorAll(selector)].find(b=>b.textContent.trim()===name);
 let root;
 try {
  await wait(()=>document.querySelector('.dashboard-footer')?.textContent.includes('更新于'),'dashboard');document.querySelector('.splash-skip')?.click();
  const w=await invoke('get_workspace'); root=w.dataDir;
  const phase=(await invoke('read_http_text',{path:root+'/phase.txt'})).trim();
  if(phase==='reopen'){
   const s=await invoke('get_runtime_logs');
   check('Restart retains report failure and success records',s.entries.some(e=>e.code==='EXPORT_FAILED')&&s.entries.some(e=>e.code==='EXPORT_COMPLETED'));
   const pdf=await invoke('inspect_report_watermark',{path:root+'/flow.pdf'});
   check('PDF remains readable and watermark decrypts after restart',pdf.pdfPages>1&&pdf.verification==='verified_local'&&pdf.watermark.name==='J4team 流转验收');
   await invoke('record_ui_verification',{result:{phase,passed,errors:[],synthetic:true,externalModelCalled:false}});return;
  }
  document.querySelector('[data-group="http"]').click();await pause();
  const enter=(label,value)=>{const el=document.querySelector(`[aria-label="${label}"]`);Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(el,value);el.dispatchEvent(new Event('input',{bubbles:true}));};
  enter('HTTP 请求包','NOT_AN_HTTP_REQUEST SENSITIVE_BODY_CANARY');await pause();document.querySelector('.http-composer form').requestSubmit();
  await wait(()=>document.querySelector('.http-input-error'),'user-visible error');
  await wait(async()=> (await invoke('get_runtime_logs')).entries.some(e=>e.component==='analyze_http_pair'),'central IPC logging');
  let s=await invoke('get_runtime_logs');
  check('Actual UI invocation failure has an ID/time/component in the local journal',s.entries.some(e=>e.component==='analyze_http_pair'&&e.id&&e.time&&e.level==='error'));
  check('IPC arguments and submitted HTTP body are not logged',!JSON.stringify(s).includes('SENSITIVE_BODY_CANARY'));
  await invoke('record_client_error',{component:'synthetic',message:'Authorization: Bearer PRIVATE_LOG_CANARY\napi_key=PRIVATE_LOG_CANARY\nhttps://user:pass@example.test/x?token=PRIVATE_LOG_CANARY'});
  s=await invoke('get_runtime_logs');check('Native log sink redacts common credentials and URLs',!JSON.stringify(s).includes('PRIVATE_LOG_CANARY'));
  setTimeout(()=>{throw Error('synthetic actual frontend exception');},0);
  await wait(async()=> (await invoke('get_runtime_logs')).entries.some(e=>e.component==='frontend'&&e.message.includes('synthetic actual frontend exception')),'frontend error capture');
  check('Actual uncaught frontend exception is persisted',true);
  let d=await invoke('get_report_draft',{caseId:w.activeCase});d.summary='合成报告导出与错误恢复验收';d.title='运行日志与 PDF 流转验收';await invoke('save_report_draft',{caseId:w.activeCase,draft:d});
  const failed=await invoke('start_report_export',{caseId:w.activeCase,path:root+'/missing-directory/report.docx',format:'docx'});
  await wait(async()=> (await invoke('get_report_exports')).some(j=>j.id===failed.id&&j.state==='failed'),'failed export');
  check('Background export failure is journaled with the original task ID',(await invoke('get_runtime_logs')).entries.some(e=>e.code==='EXPORT_FAILED'&&e.contextId===failed.id));
  const okay=await invoke('start_report_export',{caseId:w.activeCase,path:root+'/retry.docx',format:'docx'});
  await wait(async()=> (await invoke('get_report_exports')).some(j=>j.id===okay.id&&j.state==='completed'),'retry export');
  check('Successful retry preserves the earlier failure record',(await invoke('get_runtime_logs')).entries.some(e=>e.code==='EXPORT_FAILED'));
  const next=await invoke('start_report_export',{caseId:w.activeCase,path:root+'/retry-second.docx',format:'docx'});
  await wait(async()=> (await invoke('get_report_exports')).some(j=>j.id===next.id&&j.state==='completed'),'second identical export');
  s=await invoke('get_runtime_logs');
  check('Consecutive successful report tasks retain separate context IDs',[okay.id,next.id].every(id=>s.entries.some(e=>e.code==='EXPORT_COMPLETED'&&e.contextId===id)));
  const input={name:'synthetic protected-output check',target:'test',mode:'snapshot',architecture:'linux-arm64',interface:'any',durationSeconds:60,batchSeconds:5,snaplen:512,includeHttp:false,hours:1,online:false};
  let packageRejected=false;try{await invoke('platform_action',{action:'agentGenerate',args:{caseId:w.activeCase,input,path:root+'/evidence/protected.zip'}});}catch{packageRejected=true;}
  check('Agent output cannot replace archived evidence',packageRejected&&(await invoke('read_http_text',{path:root+'/evidence/protected.zip'}))==='protected evidence canary');
  let caseRejected=false;try{await invoke('platform_action',{action:'agentGenerate',args:{caseId:'missing-synthetic-case',input,path:root+'/missing-case.zip'}});}catch{caseRejected=true;}
  check('Missing Agent case refuses generation before credential access',caseRejected);
  const guarded=await invoke('start_report_export',{caseId:w.activeCase,path:root+'/migration-backups/protected.zip',format:'html'});
  await wait(async()=> (await invoke('get_report_exports')).some(j=>j.id===guarded.id&&j.state==='failed'),'protected migration snapshot');
  check('Report output cannot replace a migration recovery snapshot',(await invoke('read_http_text',{path:root+'/migration-backups/protected.zip'}))==='migration backup canary');
  const before=await invoke('inspect_report_watermark',{path:root+'/input.pdf'});
  const after=await invoke('stamp_report_pdf',{source:root+'/input.pdf',destination:root+'/flow.pdf',name:'J4team 流转验收'});
  check('Real multipage case PDF stays readable and keeps its page count after stamping',before.pdfPages>1&&before.pdfPages===after.pdfPages&&after.verification==='verified_local');
  let rejected=false;try{await invoke('stamp_report_pdf',{source:root+'/bad.pdf',destination:root+'/previous.pdf',name:'synthetic'});}catch{rejected=true;}
  check('Malformed PDF refuses writing and keeps the previous target',rejected&&(await invoke('read_http_text',{path:root+'/previous.pdf'}))==='previous PDF canary');
  check('PDF failure is recorded even when called directly through IPC',(await invoke('get_runtime_logs')).entries.some(e=>e.code==='PDF_STAMP_FAILED'));
  const origin=location.origin;location.assign('https://example.invalid/navigation-audit');await pause(300);
  check('External navigation cannot replace the privileged workbench',location.origin===origin&&!!document.querySelector('.desktop-app')&&(await invoke('get_runtime_logs')).entries.some(e=>e.code==='NAVIGATION_BLOCKED'));
  document.querySelector('[data-module="settings"]').click();await pause();button('运行日志','.settings-navigation button').click();await wait(()=>document.querySelectorAll('.runtime-log-list article').length>0,'journal page');
  const search=document.querySelector('[aria-label="搜索运行日志"]');
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(search,failed.id);search.dispatchEvent(new Event('input',{bubbles:true}));
  await wait(()=>document.querySelectorAll('.runtime-log-list article').length>0&&[...document.querySelectorAll('.runtime-log-list article')].every(e=>e.dataset.contextId===failed.id),'search by task ID');
  check('Runtime log task ID is searchable and visible',document.querySelector('.runtime-log-ids').textContent.includes(failed.id));
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(search,'');search.dispatchEvent(new Event('input',{bubbles:true}));await pause();
  for(const theme of ['light','dark']){
   const select=document.querySelector('[aria-label="主题模式"]');select.value=theme;select.dispatchEvent(new Event('change',{bubbles:true}));await invoke('resize_ui_verification',{width:960,height:660});await pause(150);
   check('Log search, filters and records fit minimum '+theme+' window',document.documentElement.scrollWidth<=innerWidth&&document.querySelector('.runtime-logs').scrollWidth<=document.querySelector('.runtime-logs').clientWidth+1);
  }
  await invoke('export_runtime_logs',{path:root+'/error-index.json'});const index=await invoke('read_http_text',{path:root+'/error-index.json'});
  check('Exported error index omits all message details, paths and credentials',JSON.parse(index).entries.length>0&&!index.includes('message":')&&!index.includes('PRIVATE_LOG_CANARY')&&!index.includes(root));
  let overwriteRejected=false;try{await invoke('export_runtime_logs',{path:root+'/error-index.json'});}catch{overwriteRejected=true;}
  check('Error index refuses overwrite and retains the existing complete file',overwriteRejected&&(await invoke('read_http_text',{path:root+'/error-index.json'}))===index);
  await invoke('resize_ui_verification',{width:1320,height:860});
  await invoke('record_ui_verification',{result:{phase,passed,errors:[],pdfPages:after.pdfPages,synthetic:true,externalModelCalled:false}});
 }catch(e){await invoke('record_ui_verification',{result:{passed,errors:[String(e),e.stack],synthetic:true,externalModelCalled:false}});}
})();
