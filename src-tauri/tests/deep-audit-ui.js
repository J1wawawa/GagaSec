// 原生验收：无害样本、真实 Docker；取消在读取模型 Key 之前，不调用云 API。
(async () => {
  const invoke=(name,args={})=>window.__TAURI_INTERNALS__.invoke(name,args),passed=[];
  const pause=(ms=100)=>new Promise(r=>setTimeout(r,ms));
  const check=(name,ok)=>{if(!ok)throw Error(name);passed.push(name);};
  const wait=async(fn,label,tries=400)=>{for(let i=0;i<tries;i++){if(await fn())return;await pause();}throw Error('Timeout: '+label+' '+document.querySelector('.reverse-workspace')?.textContent.slice(0,1600));};
  const button=(selector,text)=>[...document.querySelectorAll(selector)].find(e=>e.textContent.trim()===text);
  const nav=async(group,module)=>{document.querySelector(`[data-group="${group}"]`).click();await pause();if(module){document.querySelector(`.module-navigation [data-module="${module}"]`).click();await pause();}if(group==='reports'){await wait(()=>document.querySelector('[data-action="open-report-editor"]:not(:disabled)'),'report center');document.querySelector('[data-action="open-report-editor"]').click();await pause();}};
  const enter=(selector,value)=>{const el=document.querySelector(selector);const proto=el instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:el instanceof HTMLSelectElement?HTMLSelectElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(proto,'value').set.call(el,value);el.dispatchEvent(new Event(el instanceof HTMLSelectElement?'change':'input',{bubbles:true}));};
  const refresh=async()=>{document.querySelector('[aria-label="当前事件"]').dispatchEvent(new Event('change',{bubbles:true}));await pause(200);};
  let root;
  try {
    await wait(()=>document.querySelector('.dashboard-footer')?.textContent.includes('更新于'),'workspace');document.querySelector('.splash-skip')?.click();await pause();
    let w=await invoke('get_workspace');root=w.dataDir;
    const phase=(await invoke('read_http_text',{path:root+'/phase.txt'})).trim();
    if(phase==='reopen') {
      check('AI privacy lock survives application restart',(await invoke('get_ai_privacy')).aiLocked);
      check('Restart never resumes automatic AI after privacy lock',!(await invoke('platform_state')).aiSettings.enabled);
      const jobs=await invoke('get_reverse_jobs');check('Cancelled task remains cancelled with zero model requests',jobs.some(j=>j.state==='cancelled'&&j.modelRequests===0&&j.cleanupConfirmed));
      const draft=await invoke('get_report_draft',{caseId:w.activeCase});check('Recovered report survives application restart',draft.title==='[审计] 恢复草稿标题');
      check('Screenshot and incident node survive restart',w.nodes.length===1&&w.nodes[0].screenshots.length===1);
      await nav('reports');await wait(()=>document.querySelector('[aria-label="报告标题"]')?.value===draft.title,'report restored');
      await invoke('record_ui_verification',{result:{version:'0.7.0',phase,passed,errors:[],realModelCalled:false}});return;
    }
    await nav('collection','agents');
    await wait(()=>button('button','启动 HTTPS 接收'),'collector');
    check('Online receiver requires explicit start and is available with migrated crypto',!button('button','启动 HTTPS 接收').disabled&&document.body.textContent.includes('AWS-LC'));
    document.querySelector('.commandbar-actions [data-module="settings"]').click();await pause();button('.settings-navigation button','功能状态').click();await pause();
    check('Capability matrix distinguishes experiments and unverified external platforms',document.querySelectorAll('[data-feature]').length===11&&document.querySelector('[data-feature="windows-sandbox"]').textContent.includes('待实机验收'));
    button('.settings-navigation button','数据与维护').click();await wait(()=>document.querySelector('.storage-row'),'storage view');
    check('Maintenance has backup restore diagnostics and real storage sizes',document.querySelectorAll('.maintenance-actions button').length===3&&document.querySelector('.maintenance-panel').textContent.includes('本地存储'));
    const storage=await invoke('workspace_maintenance',{operation:'info',path:null,parent:null});
    check('Native storage includes SQLite main WAL and SHM files',storage.databaseBytes===storage.databaseMainBytes+storage.databaseWalBytes+storage.databaseShmBytes&&storage.databaseWalBytes>0);
    check('Maintenance displays WAL breakdown',document.querySelector('.maintenance-panel').textContent.includes('WAL'));
    button('.settings-navigation button','隐私与外发').click();
    await wait(()=>document.querySelector('[data-action="toggle-ai-privacy"]'),'privacy panel');
    check('Privacy page explains cloud sample and local storage boundaries',document.querySelector('.privacy-panel').textContent.includes('CAPE')&&document.querySelector('.privacy-panel').textContent.includes('明文'));
    document.querySelector('[data-action="toggle-ai-privacy"]').click();
    await wait(async()=> (await invoke('get_ai_privacy')).aiLocked,'AI locked');
    await wait(()=>document.querySelector('.ai-privacy-indicator')?.dataset.aiLocked==='true','privacy indicator');
    const expectLocked=async(name,args,label)=>{let error;try{await invoke(name,args);}catch(e){error=String(e);}check(label,error?.includes('AI 外发已锁定'));};
    await expectLocked('test_ai_connection',{revision:(await invoke('get_ai_config')).revision},'Native connection test blocked while AI locked');
    await expectLocked('platform_action',{action:'monitorAiSave',args:{enabled:true,minIntervalSecs:60,maxPerHour:10}},'Native auto AI cannot be enabled while privacy locked');
    await nav('samples','webshell');document.querySelector('[data-sample-view="environment"]').click();
    await wait(()=>button('.reverse-environment button','构建 / 更新分析镜像')&&!button('.reverse-environment button','构建 / 更新分析镜像').disabled,'environment');
    button('.reverse-environment button','构建 / 更新分析镜像').click();
    await pause(200);
    await wait(async()=>{const error=document.querySelector('.reverse-error');if(error)throw Error(error.textContent);return !button('.reverse-environment button','构建 / 更新分析镜像').disabled&&!!(await invoke('reverse_environment')).imageId;},'embedded build',10000);
    check('Client builds and validates its embedded image',!document.querySelector('.reverse-error'));
    const source=await invoke('analyze_file',{path:root+'/inert-source.php',kind:'webshell'});
    const elf=await invoke('analyze_file',{path:root+'/inert-x64.elf',kind:'binary'});
    check('Shipping application uses isolated workers with current engine and original hashes',[source,elf].every(e=>e.sha256.length===64&&e.report.engine==='J4team isolated-static/0.7.0'));
    check('Static Docker analysis remains available with AI privacy lock',(await invoke('get_ai_privacy')).aiLocked);
    await expectLocked('review_with_ai',{evidenceId:source.id,material:'合成静态样本；不发送。',question:'检查隐私锁'},'Native manual AI review blocked before any model request');
    await expectLocked('start_reverse',{evidenceId:source.id,question:'检查隐私锁'},'Native Pi start blocked while AI privacy locked');
    document.querySelector('.commandbar-actions [data-module="settings"]').click();await pause();button('.settings-navigation button','隐私与外发').click();
    await wait(()=>document.querySelector('[data-action="toggle-ai-privacy"]')?.textContent.includes('解锁'),'unlock control');
    document.querySelector('[data-action="toggle-ai-privacy"]').click();
    await wait(async()=> !(await invoke('get_ai_privacy')).aiLocked,'AI unlocked');
    check('Unlock does not resume automatic AI',!(await invoke('platform_state')).aiSettings.enabled);
    await refresh();await nav('samples','webshell');document.querySelector('[data-sample-view="pi"]').click();
    await wait(()=>document.querySelector('[data-action="start-reverse"]')&&!document.querySelector('[data-action="start-reverse"]').disabled,'Pi ready',900);
    document.querySelector('[data-action="start-reverse"]').click();
    // Cancel against the persisted task ID before Docker startup finishes. Waiting for
    // React's periodic job refresh could let Pi reach the credential broker first.
    let queued;
    for(let i=0;i<800;i++){queued=(await invoke('get_reverse_jobs'))[0];if(queued?.state==='running')break;await pause(5);}
    check('Pi task is addressable before cancellation',queued?.state==='running');
    await invoke('cancel_reverse',{id:queued.id});
    await wait(async()=> (await invoke('get_reverse_jobs'))[0]?.state==='cancelled','cancelled',700);
    const job=(await invoke('get_reverse_jobs'))[0];check('Cancel cleans containers before any official request',job.cleanupConfirmed&&job.modelRequests===0&&!job.reportEvidenceId);
    check('Task stores model, sample identity and increasing revision',job.provider==='deepseek'&&job.model&&job.sampleName&&job.revision>=2&&job.configRevision);
    check('Current workspace has no leftover analysis containers',(await invoke('reverse_environment')).leftovers.length===0);
    await invoke('add_node',{title:'[审计] 静态分析举证',body:'无害合成样本；未执行。原始 SHA-256：'+source.sha256,occurredAt:'2026-10-28T10:21:00+08:00',actor:'J4team 本机审计',evidenceId:source.id,findingId:null});
    await refresh();w=await invoke('get_workspace');const incident=w.activeCase;
    await nav('reports');await wait(()=>document.querySelector('[aria-label="报告标题"]')&&!document.querySelector('[aria-label="报告标题"]').disabled,'report ready');
    enter('[aria-label="报告标题"]','[审计] 快速切换保存');
    await nav('logs');await nav('reports');await wait(()=>document.querySelector('[aria-label="报告标题"]')?.value==='[审计] 快速切换保存','late save');
    check('Navigating away immediately preserves edits in original incident',(await invoke('get_report_draft',{caseId:incident})).title==='[审计] 快速切换保存');
    let draft=await invoke('get_report_draft',{caseId:incident});
    const key=`gaga-report-draft/1/${encodeURIComponent(root)}/${encodeURIComponent(incident)}`;
    await nav('logs');localStorage.setItem(key,JSON.stringify({baseVersion:draft.updatedAt,draft:{...draft,title:'[审计] 恢复草稿标题'}}));
    await nav('reports');await wait(()=>document.querySelector('[aria-label="报告标题"]')?.value==='[审计] 恢复草稿标题','journal restore');
    await wait(async()=> (await invoke('get_report_draft',{caseId:incident})).title==='[审计] 恢复草稿标题','recovery save');
    check('Unacknowledged local draft restores and saves to SQLite',localStorage.getItem(key)===null);
    await nav('logs');localStorage.setItem(key,JSON.stringify({baseVersion:'conflicting-version',draft:{...draft,title:'must not silently overwrite'}}));
    await nav('reports');await wait(()=>button('.report-workspace button','使用数据库版本'),'conflict choice');
    check('Conflicting recovery never silently overwrites newer database report',document.querySelector('[aria-label="报告标题"]').value==='[审计] 恢复草稿标题');
    button('.report-workspace button','使用数据库版本').click();
    button('.report-modebar button','节点与截图').click();await pause();
    button('.report-node-card button','粘贴截图').click();await wait(()=>document.querySelector('[aria-label="粘贴截图区域"]'),'paste target');
    const canvas=document.createElement('canvas');canvas.width=80;canvas.height=40;canvas.getContext('2d').fillRect(0,0,80,40);
    const blob=await new Promise(r=>canvas.toBlob(r,'image/png'));const transfer=new DataTransfer();transfer.items.add(new File([blob],'audit-fixture.png',{type:'image/png'}));
    document.querySelector('[aria-label="粘贴截图区域"]').dispatchEvent(new ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:transfer}));
    await wait(()=>document.querySelector('.screenshot-paste img'),'preview');enter('form.modal textarea','审计合成图，验证报告嵌入；不是现场截图。');await pause();document.querySelector('form.modal').requestSubmit();
    await wait(()=>!document.querySelector('form.modal'),'screenshot archived');
    w=await invoke('get_workspace');check('Pasted screenshot is actually archived with caption and digest',w.nodes[0].screenshots[0]?.sha256.length===64&&w.nodes[0].screenshots[0].caption.includes('合成图'));
    await invoke('export_report',{path:root+'/audit-report.html',format:'html'});await invoke('export_report',{path:root+'/audit-report.docx',format:'docx'});
    const html=await invoke('read_http_text',{path:root+'/audit-report.html'});check('Export includes recovered title, original evidence and embedded image',html.includes('[审计] 恢复草稿标题')&&html.includes(source.sha256)&&html.includes('data:image/png;base64,'));
    // The external native runner mutates only this disposable test workspace.
    await invoke('export_diagnostics',{path:root+'/audit-source-corrupt.request'});
    await wait(async()=>{try{return (await invoke('read_http_text',{path:root+'/audit-source-corrupt.ready'})).trim()==='ready';}catch{return false;}},'source corruption ready');
    for(const format of ['html','docx']) {
      let error;try{await invoke('export_report',{path:root+'/audit-report.'+format,format});}catch(e){error=String(e);}
      check(format+' native export rejects modified original evidence',error?.includes('证据')&&error?.includes('校验失败'));
    }
    check('Failed native export preserves existing HTML',html===await invoke('read_http_text',{path:root+'/audit-report.html'}));
    await invoke('export_diagnostics',{path:root+'/audit-source-restore.request'});
    await wait(async()=>{try{return (await invoke('read_http_text',{path:root+'/audit-source-restore.ready'})).trim()==='ready';}catch{return false;}},'source restoration ready');
    await invoke('export_report',{path:root+'/audit-report.docx',format:'docx'});
    check('Native export succeeds again after restoring original bytes',true);
    const parent=root.slice(0,root.lastIndexOf('/'));
    const backup=await invoke('workspace_maintenance',{operation:'backup',path:null,parent});
    const restored=await invoke('workspace_maintenance',{operation:'restore',path:backup.path,parent});
    check('Real evidence and screenshot backup restores into a new workspace',backup.files>=4&&restored.path!==root&&restored.backgroundTasksDisabled&&!restored.credentialsIncluded);
    await invoke('export_diagnostics',{path:root+'/diagnostics.json'});
    const diagnostic=await invoke('read_http_text',{path:root+'/diagnostics.json'});
    check('Allowlist diagnostics exclude incident titles raw evidence and workspace paths',!diagnostic.includes(root)&&!diagnostic.includes('[审计]')&&JSON.parse(diagnostic).privacy.credentialsRead===false);
    await invoke('activate_workspace',{path:restored.path});
    const pointer=JSON.parse(await invoke('read_http_text',{path:root+'/test-app-config/workspace-location.json'}));
    check('Next-start switch is staged without changing the active incident',pointer.path===restored.path&&(await invoke('get_workspace')).activeCase===incident);
    await invoke('activate_workspace',{path:root});
    const previous=JSON.parse(await invoke('read_http_text',{path:root+'/test-app-config/workspace-location.previous.json'}));
    const current=JSON.parse(await invoke('read_http_text',{path:root+'/test-app-config/workspace-location.json'}));
    check('Native second workspace selection preserves previous pointer',previous.path===restored.path&&current.path===root);
    await nav('samples','webshell');document.querySelector('[data-sample-view="pi"]').click();await pause();
    for(const theme of ['light','dark']) {
      enter('[aria-label="主题模式"]',theme);await invoke('resize_ui_verification',{width:960,height:660});await pause(200);
      const pane=document.querySelector('.reverse-split').getBoundingClientRect();check(theme+' analysis layout stays inside minimum native window',pane.right<=innerWidth+1&&pane.bottom<=innerHeight+1&&pane.width>600);
      document.querySelector('.ai-privacy-indicator').click();await wait(()=>{const panel=document.querySelector('[data-settings="privacy"]');return panel&&getComputedStyle(panel).display!=='none';},'privacy visible');
      const privacy=document.querySelector('.privacy-panel').getBoundingClientRect();check(theme+' privacy panel fits minimum native width',privacy.width>300&&privacy.right<=innerWidth+1&&document.documentElement.scrollWidth<=innerWidth);
      await nav('samples','webshell');document.querySelector('[data-sample-view="pi"]').click();await pause();
    }
    await invoke('set_ai_privacy',{settings:{aiLocked:true}});
    await invoke('export_report',{path:root+'/audit-locked-report.html',format:'html'});
    check('Local report export remains available while AI locked',(await invoke('read_http_text',{path:root+'/audit-locked-report.html'})).includes(source.sha256));
    enter('[aria-label="主题模式"]','system');await invoke('resize_ui_verification',{width:1320,height:860});
    await invoke('record_ui_verification',{result:{version:'0.7.0',phase,passed,errors:[],realModelCalled:false,samplesExecuted:false,maintenance:{backup,restored}}});
  } catch(e) { await invoke('record_ui_verification',{result:{version:'0.7.0',passed,errors:[String(e),e.stack],realModelCalled:false}}); }
})();
