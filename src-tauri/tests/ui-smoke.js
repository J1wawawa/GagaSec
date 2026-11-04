(async()=>{
  const passed=[];
  const invoke=(command,args={})=>window.__TAURI_INTERNALS__.invoke(command,args);
  const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
  const wait=async(predicate,label)=>{for(let i=0;i<150;i++){if(predicate())return;await pause(100);}throw Error('Timeout: '+label);};
  const check=(label,value)=>{if(!value)throw Error(label);passed.push(label);};
  const button=(selector,text)=>Array.from(document.querySelectorAll(selector)).find(b=>b.textContent.trim()===text);
  const navigate=async(text)=>{button('.nav-item',text).click();await pause(100);};
  function enter(el,value){const proto=el instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(proto,'value').set.call(el,value);el.dispatchEvent(new Event('input',{bubbles:true}));}
  try {
    await wait(()=>document.querySelector('.nav-item'),'React interface');document.querySelector('.splash-skip')?.click();
    check('Native application starts on the data dashboard',Boolean(document.querySelector('.dashboard-page')));
    await navigate('HTTP 报文分析');
    check('Native HTTP navigation opens editor',Boolean(document.querySelector('[aria-label="HTTP 请求包"]')));
    const req='GET /.env?token=demo-ui-token HTTP/1.1\r\nHost: example.test\r\n\r\n';
    const res='HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDB_PASSWORD=demo-ui-password';
    enter(document.querySelector('[aria-label="HTTP 请求包"]'),req);enter(document.querySelector('[aria-label="HTTP 响应包"]'),res);await pause(100);
    check('Paired input retains both messages',document.querySelector('[aria-label="HTTP 请求包"]').value===req.replace(/\r\n/g,'\n')&&document.querySelector('[aria-label="HTTP 响应包"]').value.includes('demo-ui-password'));
    document.querySelector('.http-composer form').requestSubmit();await wait(()=>document.querySelector('.http-reader'),'native analysis result');
    check('Actual Rust result displays both packets',document.querySelector('.http-reader').textContent.includes('DB_PASSWORD')&&document.querySelector('.http-reader').textContent.includes('GET /.env'));
    check('Related response is explicitly provisional',document.querySelector('.http-assessment').textContent.includes('关联线索')&&document.querySelector('.http-assessment').textContent.includes('待复核'));
    const workspace=await invoke('get_workspace');const evidence=workspace.evidence.find(e=>e.kind==='http');
    check('Pair was archived in real SQLite workspace',Boolean(evidence&&evidence.sha256.length===64&&evidence.report.httpExchanges.length===1));
    const material=await invoke('preview_ai_material',{evidenceId:evidence.id});
    check('AI material includes paired context and hides common credentials',material.includes('请求视图')&&material.includes('响应视图')&&!material.includes('demo-ui-token')&&!material.includes('demo-ui-password'));
    button('.http-finding','响应含敏感配置字段')?.click();
    // The row contains location text, so select the title span when needed.
    if(!document.querySelector('.finding-detail'))Array.from(document.querySelectorAll('.http-finding')).find(b=>b.textContent.includes('响应含敏感配置字段')).click();
    await pause(100);button('.finding-detail button','加入事件').click();await pause(100);
    document.querySelector('.modal form')?.requestSubmit();
    if(document.querySelector('form.modal'))document.querySelector('form.modal').requestSubmit();
    await wait(()=>document.querySelector('.timeline-node'),'timeline node');
    check('HTTP node retains request and response proof',document.querySelector('.timeline-node').textContent.includes('GET /.env')&&document.querySelector('.timeline-node').textContent.includes('DB_PASSWORD'));
    check('HTTP node reserves a screenshot with caption workflow',Boolean(document.querySelector('.screenshot-placeholder')));
    await navigate('HTTP 报文分析');
    await invoke('analyze_example',{kind:'http'});
    const select=document.querySelector('[aria-label="当前事件"]');select.dispatchEvent(new Event('change',{bubbles:true}));
    await wait(()=>Array.from(document.querySelectorAll('.file-row')).some(b=>b.textContent.includes('示例-demo-http.har')),'HAR evidence refresh');
    Array.from(document.querySelectorAll('.file-row')).find(b=>b.textContent.includes('示例-demo-http.har')).click();await pause(150);
    check('HAR displays all three associated exchanges',document.querySelector('[aria-label="HTTP 交互"]').options.length===3);
    const exchanges=document.querySelector('[aria-label="HTTP 交互"]');exchanges.value='http-2';exchanges.dispatchEvent(new Event('change',{bubbles:true}));await pause(100);
    check('Blocked response does not become successful exploitation',document.querySelector('.http-assessment').textContent.includes('不足以确认')&&document.querySelector('.http-assessment').textContent.includes('403'));
    check('Paired result fits actual native window',document.documentElement.scrollWidth<=innerWidth&&document.querySelector('.content-scroll').scrollWidth<=document.querySelector('.content-scroll').clientWidth+1);
    check('Actual local analysis shows persisted process and incident ID',document.querySelector('.analysis-process').textContent.includes('incident-')&&document.querySelector('.analysis-process').textContent.includes('未接入 RAG'));
    await navigate('告警研判');
    enter(document.querySelector('[aria-label="告警原文"]'),'NDR 告警：入侵阶段-敏感路径访问-平时；编码020335；标签 A005_B032；源IP 10.49.185.188；proof 为空；请求与响应未提供。');
    await pause(80);document.querySelector('.alert-composer').requestSubmit();
    await wait(()=>document.querySelector('.ai-start'),'alert analysis ready');
    check('Pasted alert has visible AI entry and honest local process',document.querySelector('.analysis-process').textContent.includes('此次只执行本地检查'));
    const config=await invoke('get_ai_config');
    if(config.model==='local-ui-test-service'){
      button('.ai-start button','开始 AI 研判').click();
      await wait(()=>document.querySelector('[aria-label="AI 发送材料"]'),'AI material preview');
      check('AI preview contains alert source and evidence gap',document.querySelector('[aria-label="AI 发送材料"]').value.includes('proof 为空'));
      document.querySelector('[aria-label="AI 发送材料"]').closest('form').requestSubmit();
      await wait(()=>Array.from(document.querySelectorAll('.process-step.running')).some(e=>e.textContent.includes('模型 API 请求')),'actual request progress');
      check('Actual model request exposes running process',document.querySelector('.model-state').textContent.includes('分析中'));
      await wait(()=>document.querySelector('.assessment-heading'),'structured response');
      const review=(await invoke('get_workspace')).aiReviews[0];
      check('Triage verdict hides model probability and does not confirm success',document.querySelector('.assessment-heading').textContent.includes('未确认')&&!document.querySelector('.assessment-heading').textContent.includes('60%'));
      check('Structured response includes evidence references and missing evidence',Boolean(document.querySelector('.reason-refs button'))&&document.querySelector('.ai-review').textContent.includes('原始会话报文'));
      const prompt=Array.from(document.querySelectorAll('.ai-review details')).find(e=>e.querySelector('summary')?.textContent.includes('查看最终 Prompt'));prompt.open=true;
      const displayedPrompt=JSON.parse(prompt.querySelector('pre').textContent);
      check('Final prompt contains actual persisted messages',displayedPrompt.model===review.model&&review.promptVersion.startsWith('J4team investigation/')&&prompt.textContent.includes(review.promptVersion)&&JSON.stringify(displayedPrompt.messages)===JSON.stringify(review.requestMessages));
      enter(document.querySelector('[aria-label="追问-'+review.id+'"]'),'请给出进一步取证步骤');await pause(80);
      check('Followup typing retains actual complete value',document.querySelector('[aria-label="追问-'+review.id+'"] ').value==='请给出进一步取证步骤');
      document.querySelector('.followup form').requestSubmit();await wait(()=>document.querySelector('.chat-turn'),'followup response');
      check('Real followup returns and is rendered',document.querySelector('.chat-turn').textContent.includes('本地测试服务'));
      button('.feedback-actions button','标记误报').click();await pause(80);
      check('False positive requires written basis',document.querySelector('.error-banner').textContent.includes('依据'));
      enter(document.querySelector('[aria-label="处置备注-'+review.id+'"]'),'已核对变更工单：此次为授权巡检，仍待人工确认。');await pause(80);
      button('.feedback-actions button','分析准确').click();await wait(()=>document.querySelector('.saved-feedback'),'persisted feedback');
      check('Manual disposition is persisted without rewriting AI',(await invoke('get_workspace')).reviewFeedback.length===1&&(await invoke('get_workspace')).aiReviews[0].content===review.content);
      button('.ai-review button','记录研判结论').click();await pause(80);document.querySelector('form.modal').requestSubmit();await wait(()=>document.querySelector('.timeline-node'),'AI timeline');
      check('AI timeline keeps run ID and screenshot placeholder',document.querySelector('.timeline-list').textContent.includes(review.runId)&&Boolean(document.querySelector('.screenshot-placeholder')));
      const docker=await invoke('check_docker');
      if(docker.daemonReady&&docker.runnerImage){
        const dir=(await invoke('get_workspace')).dataDir;
        await invoke('analyze_file',{path:dir+'/native-harmless.sh',kind:'binary'});
        const currentCase=document.querySelector('[aria-label="当前事件"]');currentCase.dispatchEvent(new Event('change',{bubbles:true}));await pause(200);
        await navigate('动态行为分析');await wait(()=>document.querySelector('.sandbox-checks')?.textContent.includes('已安装'),'native Docker preflight');
        check('Native Docker preflight detects engine and observer image',document.querySelector('.sandbox-checks').textContent.includes('已找到'));
        Array.from(document.querySelectorAll('.sandbox-view-tabs button')).find(b=>b.textContent==='新建任务').click();await pause(80);document.querySelector('[aria-label="确认专用隔离环境"]').click();await pause(80);
        // This isolated smoke workspace only contains the fixed harmless shell fixture.
        Array.from(document.querySelectorAll('button')).find(b=>b.textContent.includes('启动临时容器并观察')).click();
        await wait(()=>document.querySelector('.sandbox-job')?.textContent.includes('临时容器已清理'),'native Docker collection and cleanup');
        await wait(()=>document.querySelector('.sandbox-job')?.textContent.includes('已归档'),'native Docker report archive');
        check('Native Docker job retains process file and network trace',document.querySelector('.sandbox-job').textContent.includes('execve(')&&document.querySelector('.sandbox-job').textContent.includes('native-gaga-marker')&&document.querySelector('.sandbox-job').textContent.includes('connect('));
        const labJobs=await invoke('get_sandbox_jobs');
        check('Native Docker report is attached to actual evidence',labJobs.length===1&&labJobs[0].cleanupConfirmed&&Boolean(labJobs[0].reportEvidenceId));
        await wait(()=>Boolean(button('.sandbox-job button','记录到事件时间线')),'dynamic report actions ready');button('.sandbox-job button','记录到事件时间线').click();await pause(80);document.querySelector('form.modal').requestSubmit();await wait(()=>document.querySelector('.timeline-list'),'dynamic timeline');
        check('Dynamic observation becomes a referenced timeline node',document.querySelector('.timeline-list').textContent.includes(labJobs[0].id));
      }
    }
    if(config.model==='local-ui-test-service'){
      const root=(await invoke('get_workspace')).dataDir;
      await invoke('export_report',{path:root+'/workbench-example.docx',format:'docx'});await invoke('export_report',{path:root+'/workbench-example.html',format:'html'});
      check('Workbench report exports real HTTP AI and dynamic nodes',true);
    }
    const dashboardSnapshots=config.model==='local-ui-test-service'?await window.gagaPlatformSmoke(passed):undefined;
    await window.gagaAuditSmoke(passed);
    if(window.gagaAcceptanceSmoke) await window.gagaAcceptanceSmoke(passed);
    await invoke('record_ui_verification',{result:{passed,dashboardSnapshots,native:true,modelTransport:config.model==='local-ui-test-service'?'loopback-test-service':'not-tested',errors:[],evidenceCount:(await invoke('get_workspace')).evidence.length}});
  }catch(error){await invoke('record_ui_verification',{result:{passed,native:true,errors:[String(error),error.stack]}});}
})();
