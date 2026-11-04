// Native Tauri + isolated Docker + saved DeepSeek credentials. Benign fixtures only.
(async()=>{
 const invoke=(n,args={})=>window.__TAURI_INTERNALS__.invoke(n,args), passed=[];
 const pause=(ms=100)=>new Promise(r=>setTimeout(r,ms));
 const check=(n,v)=>{if(!v)throw Error(n);passed.push(n);};
 const wait=async(fn,n,limit=400)=>{for(let i=0;i<limit;i++){if(await fn())return;await pause();}throw Error('Timeout: '+n);};
 const enter=async(selector,value)=>{const e=document.querySelector(selector);const proto=e instanceof HTMLSelectElement?HTMLSelectElement.prototype:e instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(proto,'value').set.call(e,value);e.dispatchEvent(new Event(e instanceof HTMLSelectElement?'change':'input',{bubbles:true}));await pause(150);};
 const nav=async(module='binary')=>{document.querySelector('.primary-navigation [data-group="samples"]').click();await pause();document.querySelector(`.module-navigation [data-module="${module}"]`).click();await pause();};
 const tab=async(id)=>{document.querySelector(`[data-sample-view="${id}"]`).click();await pause(200);};
 const refresh=async()=>{document.querySelector('[aria-label="当前事件"]').dispatchEvent(new Event('change',{bubbles:true}));await pause(200);};
 const stage=label=>invoke('ui_checkpoint',{label:'Reverse: '+label});
 const button=(sel,text)=>[...document.querySelectorAll(sel)].find(b=>b.textContent.trim()===text);
 try{
  await wait(()=>document.querySelector('.dashboard-footer')?.textContent.includes('更新于'),'database');document.querySelector('.splash-skip')?.click();await pause(200);
  let w=await invoke('get_workspace'),root=w.dataDir;
  const cfg=await invoke('get_ai_config');check('Saved DeepSeek is used without exposing or copying the key',cfg.provider==='deepseek'&&cfg.hasKey);
  const phase=(await invoke('read_http_text',{path:root+'/phase.txt'})).trim();
  await nav();await tab('environment');
  await wait(()=>document.querySelector('.reverse-status-grid')?.textContent.includes('已就绪'),'isolated image');
  check('Environment has its own visible desktop tab',!!document.querySelector('[data-reverse-view="environment"]')&&document.querySelector('.reverse-policy').textContent.includes('不会回退'));
  if(phase==='reopen'){
   await tab('pi');await wait(()=>document.querySelector('.reverse-history')?.textContent.includes('已归档'),'reopened jobs');
   const jobs=await invoke('get_reverse_jobs');check('Reopened jobs retain final text, artifacts and cleanup',jobs.filter(j=>j.state==='completed').length===2&&jobs.filter(j=>j.state==='completed').every(j=>j.content&&j.artifacts.length>=2&&j.cleanupConfirmed));
   check('Reopened cancelled task remains cancelled',jobs.some(j=>j.state==='cancelled'));
   w=await invoke('get_workspace');check('Reopened report links persist',w.nodes.length===2&&w.nodes.every(n=>n.evidenceId&&n.body.includes('SHA-256')));
   [...document.querySelectorAll('.reverse-history button')].find(b=>b.textContent.includes('已归档'))?.click();await pause();
   await invoke('record_ui_verification',{result:{version:'0.7.0',phase,native:true,passed,errors:[]}});return;
  }
  await stage('embedded image build');
  button('.reverse-environment .toolbar-group button','构建 / 更新分析镜像').click();
  await wait(()=>!button('.reverse-environment .toolbar-group button','构建 / 更新分析镜像')?.disabled,'build embedded resources',6000);
  check('Client builds its actual embedded worker and Pi image',!document.querySelector('.reverse-error'));
  await stage('container imports');
  const script=phase==='finish'?w.evidence.find(e=>e.name==='inert-source.php'):await invoke('analyze_file',{path:root+'/inert-source.php',kind:'webshell'});
  const elf=phase==='finish'?w.evidence.find(e=>e.name==='inert-x64.elf'):await invoke('analyze_file',{path:root+'/inert-x64.elf',kind:'binary'});
  if(phase==='finish'){const anti=w.evidence.find(e=>e.name==='anti-markers.php')||await invoke('analyze_file',{path:root+'/anti-markers.php',kind:'webshell'});check('Current shipping worker exposes anti-analysis uncertainty without execution',anti.report.details.some(d=>d.label==='反分析覆盖与线索'&&d.value.includes('未验证')));}
  check('Shipping process receives isolated reports with original hashes',[script,elf].every(e=>e.report.engine==='J4team isolated-static/0.7.0'&&e.report.details.some(d=>d.label==='隔离执行')));
  await refresh();await nav('webshell');await tab('static');check('Imported WebShell remains accessible in static result page',[...document.querySelectorAll('.file-row')].some(e=>e.textContent.includes('inert-source.php')));
  await tab('pi');await wait(()=>document.querySelector('[data-action="start-reverse"]')&&!document.querySelector('[data-action="start-reverse"]').disabled,'Pi start enabled');
  const original=(await invoke('get_workspace')).activeCase;
  for(const e of phase==='finish'?[]:[script,elf]){
   await nav(e.kind==='webshell'?'webshell':'binary');await tab('pi');await wait(()=>document.querySelector('[aria-label="逆向样本"]'),'sample picker');
   await enter('[aria-label="逆向样本"]',e.id);
   await enter('[aria-label="逆向调查问题"]',e.kind==='webshell'?'这是无害静态演练，不能执行样本。先调用 read_metadata，再调用 read_source(startLine=1,count=10)，根据 if(false) 分支判断敏感代码是否可达。最终用中文 400 字以内，包含 SHA-256、行号、事实与局限。':'这是无害 x64 ELF，不能执行样本。依次调用 read_metadata、disassemble(entryOffset=0,count=2)、search_strings(query="GAGA_BENIGN")。最终用中文 400 字以内，核对入口、偏移和 xor/ret，不把静态观察认定为恶意行为。');
   await stage('official Pi '+e.kind);document.querySelector('[data-action="start-reverse"]').click();
   await wait(async()=> (await invoke('get_reverse_jobs')).some(j=>j.evidenceId===e.id&&j.state==='running'),'task started');
   check('Native task receives progress before completion',!!document.querySelector('[data-action="cancel-reverse"]'));
   if(e.kind==='webshell'){
     // Switch while the real request runs: completion must archive to the original case.
     document.querySelector('[aria-label="新建事件"]').click();await pause();await enter('form.modal input','[无害验收] 事件边界对照');document.querySelector('form.modal').requestSubmit();await wait(()=>!document.querySelector('form.modal'),'new case');await pause(200);
     check('Other case cannot see running task or sample',!(await invoke('get_reverse_jobs')).length&&!(await invoke('get_workspace')).evidence.length);
     let denied=false;try{await invoke('start_reverse',{evidenceId:e.id,question:'cross-case denied'});}catch{denied=true;}check('Other case cannot submit original sample',denied);
     await enter('[aria-label="当前事件"]',original);await nav('webshell');await tab('pi');
   }
   await wait(async()=>{const j=(await invoke('get_reverse_jobs')).find(j=>j.evidenceId===e.id);return j&&j.state!=='running';},'official result',3300);
   const j=(await invoke('get_reverse_jobs')).find(j=>j.evidenceId===e.id);if(j.state!=='completed')throw Error('Official '+e.kind+': '+j.error);
   check('Official '+e.kind+' has tool artifacts, model loop and confirmed cleanup',j.artifacts.length>=2&&j.modelRequests>=2&&j.cleanupConfirmed&&j.content.includes(e.sha256));
   await refresh();await nav(e.kind==='webshell'?'webshell':'binary');await tab('pi');
   await wait(()=>document.querySelector('[data-action="record-reverse"]'),'report action');
   button('.reverse-result-pane .tabs button','工具举证').click();await pause();check('Tool artifact hash and preview are visible',!!document.querySelector('.reverse-artifact .hash'));
   document.querySelector('[data-action="record-reverse"]').click();await wait(()=>document.querySelector('form.modal'),'node editor');document.querySelector('form.modal').requestSubmit();await wait(()=>!document.querySelector('form.modal'),'node saved');
   w=await invoke('get_workspace');check('Official '+e.kind+' result joins original case timeline with report evidence',w.nodes.some(n=>n.evidenceId===j.reportEvidenceId&&n.body.includes(e.sha256)));
  }
  await stage('cancel task');await nav();await tab('pi');
  await enter('[aria-label="逆向样本"]',script.id);await wait(()=>!document.querySelector('[data-action="start-reverse"]')?.disabled,'cancel trial ready');document.querySelector('[data-action="start-reverse"]').click();
  await wait(()=>document.querySelector('[data-action="cancel-reverse"]'),'cancel available');document.querySelector('[data-action="cancel-reverse"]').click();
  await wait(async()=> (await invoke('get_reverse_jobs'))[0]?.state==='cancelled','cancel completed',700);
  check('Cancelled task cleans its container and creates no final report',(await invoke('get_reverse_jobs'))[0].cleanupConfirmed&&!(await invoke('get_reverse_jobs'))[0].reportEvidenceId);
  const env=await invoke('reverse_environment');check('No analysis containers are left behind',env.leftovers.length===0);
  await invoke('export_report',{path:root+'/isolated-report.html',format:'html'});await invoke('export_report',{path:root+'/isolated-report.docx',format:'docx'});
  const html=await invoke('read_http_text',{path:root+'/isolated-report.html'});check('Exported report includes both isolated analyses and original hashes',html.includes(script.sha256)&&html.includes(elf.sha256)&&html.includes('AI 隔离逆向'));
  await stage('desktop light dark checks');
  for(const theme of ['light','dark']){
   await enter('[aria-label="主题模式"]',theme);await invoke('resize_ui_verification',{width:960,height:660});await pause(200);
   const r=document.querySelector('.reverse-split').getBoundingClientRect();check(theme+' minimum frame keeps the analysis panes inside the native window',r.width>600&&r.height>250&&r.right<=innerWidth+1&&r.bottom<=innerHeight+1);
   await tab('environment');check(theme+' environment is locally scrollable',document.querySelector('.reverse-environment').clientHeight<=innerHeight);await tab('pi');
  }
  await enter('[aria-label="主题模式"]','system');await invoke('resize_ui_verification',{width:1320,height:860});
  await invoke('record_ui_verification',{result:{version:'0.7.0',phase,native:true,passed,errors:[],realModelCalled:phase!=='finish',historicalRealModelJobs:phase==='finish'?2:0,samplesExecuted:false}});
 }catch(e){await invoke('record_ui_verification',{result:{version:'0.7.0',native:true,passed,errors:[String(e),e.stack]}});}
})();
