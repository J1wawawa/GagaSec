// Runs only in the debug acceptance mode, using generated logs and inert PHP.
(async()=>{
 const invoke=(name,args={})=>window.__TAURI_INTERNALS__.invoke(name,args),passed=[];
 const pause=(ms=80)=>new Promise(resolve=>setTimeout(resolve,ms));
 const wait=async(fn,label)=>{const start=Date.now();while(Date.now()-start<90000){const value=await fn();if(value)return value;await pause();}throw Error('Analysis UI timeout: '+label);};
 const check=(label,ok)=>{if(!ok)throw Error(label);passed.push(label);};
 const jobs=()=>invoke('get_local_analysis_jobs',{caseId:null});
 const find=async id=>(await jobs()).find(job=>job.id===id);
 try{
  await wait(()=>document.querySelector('.dashboard-footer')?.textContent.includes('更新于'),'startup');document.querySelector('.splash-skip')?.click();
  const workspace=await invoke('get_workspace'),root=workspace.dataDir,caseId=workspace.activeCase;
  const phase=(await invoke('read_http_text',{path:root+'/phase.txt'})).trim();
  if(phase==='reopen'){
   const saved=await jobs();
   check('Restart retains completed, cancelled and failed analysis histories',saved.some(j=>j.state==='completed')&&saved.some(j=>j.state==='cancelled')&&saved.some(j=>j.state==='failed'));
   check('Restart does not resume completed or cancelled work',saved.every(j=>!['running','cancelling'].includes(j.state)));
   document.querySelector('[data-action="show-local-analysis"]').click();await pause();
   check('Persisted task drawer can be opened after restart',!!document.querySelector('[data-local-analysis]'));
   await invoke('record_ui_verification',{result:{phase,passed,errors:[],synthetic:true,externalModelCalled:false}});return;
  }
  let rejected=false;try{await invoke('start_local_analysis',{caseId:'missing-case',path:root+'/large.log',kind:'logs'});}catch{rejected=true;}
  check('Missing case refuses background analysis before reading input',rejected);
  const task=await invoke('start_local_analysis',{caseId,path:root+'/large.log',kind:'logs'});
  rejected=false;try{await invoke('start_local_analysis',{caseId,path:root+'/large.log',kind:'logs'});}catch{rejected=true;}
  check('Concurrent local scans are bounded',rejected);
  document.querySelector('[data-action="show-local-analysis"]').click();
  const intermediate=await wait(async()=>{const j=await find(task.id);return j.phase==='scanning'&&j.counts.bytes>0&&j.counts.bytes<j.totalBytes&&j.previews.length?j:null;},'actual intermediate log results');
  check('Log counters and findings are visible before scan completes',intermediate.state==='running'&&intermediate.counts.hits>0);
  await wait(()=>document.querySelector('.local-task-previews code'),'actual preview UI');
  check('Live preview renders evidence line and excerpt',document.querySelector('.local-task-previews').textContent.includes('第 ')&&document.querySelector('.local-task-previews code').textContent.length>0);
  document.querySelector('[data-group="http"]').click();await pause();
  check('Can navigate while a scan continues without a global busy lock',!!document.querySelector('.http-composer')&&!!document.querySelector('[data-local-analysis]'));
  const other=await invoke('create_case',{title:'合成并行查看事件'});
  const done=await wait(async()=>{const j=await find(task.id);return j.state==='completed'?j:null;},'log completion');
  check('Task remains in its captured case while active case changes',done.caseId===caseId&&other.activeCase!==caseId);
  check('Completed task has a saved evidence ID, bounded preview and full byte count',!!done.evidenceId&&done.previews.length<=24&&done.counts.bytes===done.totalBytes);
  check('Actual archive, scan, index and commit stages are recorded', ['archiving','scanning','indexing','committing','completed'].every(p=>done.stages.some(s=>s.phase===p)));
  await wait(()=>document.querySelector('[data-action="open-local-result"]'),'result button');document.querySelector('[data-action="open-local-result"]').click();
  await wait(()=>document.querySelector('.log-investigation'),'open result in original case');
  check('Opening a completed result restores its case and log timeline',(await invoke('get_workspace')).activeCase===caseId);
  const cancelled=await invoke('start_local_analysis',{caseId,path:root+'/large.log',kind:'logs'});
  document.querySelector('[data-action="show-local-analysis"]').click();
  await wait(async()=>{const j=await find(cancelled.id);return j.phase==='scanning'&&j.counts.lines>0;},'cancellation during scan');
  await wait(()=>document.querySelector('[data-action="cancel-local-analysis"]'),'stop button');document.querySelector('[data-action="cancel-local-analysis"]').click();
  const stopped=await wait(async()=>{const j=await find(cancelled.id);return j.state==='cancelled'?j:null;},'cancelled terminal');
  check('Actual stop control cancels the scan and never reports completion',stopped.state==='cancelled'&&!stopped.evidenceId);
  check('Cancelled scan adds no complete evidence',(await invoke('get_workspace')).evidence.length===1);
  const missing=await invoke('start_local_analysis',{caseId,path:root+'/missing.log',kind:'logs'});
  const failed=await wait(async()=>{const j=await find(missing.id);return j.state==='failed'?j:null;},'missing file failure');
  check('Failed input records task error and can be diagnosed',(await invoke('get_runtime_logs')).entries.some(e=>e.code==='LOCAL_FAILED'&&e.contextId===failed.id));
  const sample=await invoke('start_local_analysis',{caseId,path:root+'/inert.php',kind:'webshell'});
  const result=await wait(async()=>{const j=await find(sample.id);return j.state==='completed'||j.state==='failed'?j:null;},'isolated WebShell');
  check('Inert WebShell is actually parsed in the Docker isolation workflow',result.state==='completed'&&result.stages.some(s=>s.phase==='isolated')&&!!result.evidenceId);
  check('Static sample findings are available with the task',result.previews.length>0&&result.stages.some(s=>s.phase==='environment'));
  for(const theme of ['light','dark']){
   const select=document.querySelector('[aria-label="主题模式"]');select.value=theme;select.dispatchEvent(new Event('change',{bubbles:true}));
   await invoke('resize_ui_verification',{width:960,height:660});await pause(180);
   check('Task drawer fits minimum '+theme+' desktop window',document.documentElement.scrollWidth<=innerWidth&&document.querySelector('[data-local-analysis]').scrollWidth<=document.querySelector('[data-local-analysis]').clientWidth+1);
  }
  await invoke('resize_ui_verification',{width:1320,height:860});
  await invoke('record_ui_verification',{result:{phase,passed,errors:[],synthetic:true,externalModelCalled:false,realDockerStaticAnalysis:true,realMalwareExecuted:false,logInputBytes:done.totalBytes,logLines:done.counts.lines}});
 }catch(error){await invoke('record_ui_verification',{result:{passed,errors:[String(error),error.stack],synthetic:true,externalModelCalled:false}});}
})();
