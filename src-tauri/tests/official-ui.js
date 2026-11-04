// Real native controls, official HTTPS requests, and a fresh synthetic case.
(async () => {
  const invoke = (name, args = {}) => window.__TAURI_INTERNALS__.invoke(name, args);
  const passed = [], stages = [];
  let requestsAttempted = 0;
  const pause = (ms = 100) => new Promise((resolve) => setTimeout(resolve, ms));
  const check = (name, condition) => { if (!condition) throw Error(name); passed.push(name); };
  const wait = async (fn, label, attempts = 200) => {
    for (let i = 0; i < attempts; i++) {
      if (await fn()) return;
      const error = document.querySelector('.error-banner');
      if (error) throw Error(label + ': ' + error.textContent);
      await pause();
    }
    throw Error('Official native timeout: ' + label);
  };
  const button = (selector, text) => [...document.querySelectorAll(selector)].find((b) => b.textContent.trim() === text);
  const enter = async (selector, value) => {
    const el = document.querySelector(selector);
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', {bubbles: true})); await pause();
  };
  const nav = async (group) => { document.querySelector(`.primary-navigation [data-group="${group}"]`).click(); await pause(); };
  const checkpoint = async (label) => { stages.push(label); await invoke('ui_checkpoint', {label: 'Official: ' + label}); };
  const visible = (selector) => {
    const el = document.querySelector(selector); if (!el) return false;
    const r = el.getBoundingClientRect(); return r.height > 0 && r.top >= 0 && r.top < innerHeight - 1;
  };
  async function reviewCurrent(kind) {
    await checkpoint('Review ' + kind + ' starts');
    document.querySelector('.result-actions button.primary').click();
    await wait(() => document.querySelector('[aria-label="AI 发送材料"]'), 'material preview');
    const material = document.querySelector('[aria-label="AI 发送材料"]').value;
    check('Official ' + kind + ' review has evidence hash and bounded material', material.includes('SHA-256') && material.length < 24000);
    await enter('[aria-label="AI 调查问题"]', '这是隔离测试中的合成材料。请仅依据材料判断，逐项引用来源，保留未知项，不能将测试活动认定为真实入侵。');
    requestsAttempted++;
    document.querySelector('[aria-label="AI 发送材料"]').closest('form').requestSubmit();
    await wait(() => document.querySelector('.ai-review') && !document.querySelector('.result-actions button.primary')?.disabled, 'official ' + kind + ' response', 1500);
    const w = await invoke('get_workspace');
    const evidence = w.evidence.find((e) => e.kind === kind);
    const review = w.aiReviews.find((r) => r.evidenceId === evidence.id);
    check('Official ' + kind + ' structured assessment is saved and displayed', review?.endpoint === 'https://api.deepseek.com' && !!review.assessment && !!document.querySelector('.assessment-heading'));
    check('Official ' + kind + ' review retains exact prompt, source and completed process', review.material === material && review.requestMessages.length >= 2 && w.analysisRuns.some((r) => r.id === review.runId && r.state === 'completed'));
    check('Official ' + kind + ' result has consistent visible actions', visible('.result-actions') && visible('.result-tabs'));
    await checkpoint('Review ' + kind + ' saved');
    return review;
  }
  try {
    await wait(() => document.querySelector('.dashboard-footer')?.textContent.includes('更新于'), 'dashboard');
    document.querySelector('.splash-skip')?.click();
    await wait(() => document.querySelector('[aria-label="当前分析模型"]'), 'saved model metadata');
    const cfg = await invoke('get_ai_config');
    check('Existing DeepSeek key is available through system credential service', cfg.provider === 'deepseek' && cfg.endpoint === 'https://api.deepseek.com' && cfg.hasKey);
    let w = await invoke('get_workspace');
    if (w.aiReviews.length === 3) {
      for (const kind of ['http', 'triage', 'logs']) {
        await nav(kind);
        if (document.querySelector('.content-scroll').dataset.editing === 'true') {
          document.querySelector('[data-action="toggle-input"]').click(); await pause();
        }
        const evidence = w.evidence.find((e) => e.kind === kind);
        [...document.querySelectorAll('.file-row')].find((b) => b.textContent.includes(evidence.name)).click(); await pause();
        button('.result-tabs button', 'AI 复核').click();
        await wait(() => document.querySelector('.assessment-heading'), 'reopened ' + kind + ' assessment');
        const review = w.aiReviews.find((r) => r.evidenceId === evidence.id);
        check('Reopened native ' + kind + ' view displays persisted official assessment', document.querySelector('.ai-review').textContent.includes(review.assessment.category));
        if (kind === 'http') check('Reopened HTTP view includes persisted followup', document.querySelectorAll('.chat-turn').length === 1);
      }
      check('Reopen performs no additional official requests', requestsAttempted === 0);
      await invoke('record_ui_verification', {result: {version: '0.6.4', native: true, reopened: true, passed, stages, errors: [], requestsAttempted}});
      return;
    }
    check('Official UI test starts with no imported customer evidence', w.evidence.length === 0 && w.aiReviews.length === 0);
    document.querySelector('[aria-label="新建事件"]').click(); await pause();
    await enter('form.modal input', '[AI实测] 0.6.4 · 合成 HTTP、告警与日志');
    document.querySelector('form.modal').requestSubmit(); await wait(() => !document.querySelector('form.modal'), 'synthetic case');
    document.querySelector('.commandbar-actions [data-module="settings"]').click(); await pause();
    button('.settings-navigation button', '模型连接').click(); await pause();
    await checkpoint('Connection starts'); requestsAttempted++;
    button('.model-actionbar button', '测试连接').click();
    await wait(() => document.querySelector('.connection-test-result'), 'official connection', 600);
    check('Actual official connection succeeds in native settings', document.querySelector('.connection-test-result').dataset.success === 'true');
    await checkpoint('Connection verified');
    await nav('http');
    await enter('[aria-label="HTTP 请求包"]', 'GET /.env HTTP/1.1\nHost: example.test\nX-Gaga-Sample: synthetic\n\n');
    await enter('[aria-label="HTTP 响应包"]', 'HTTP/1.1 200 OK\nContent-Type: text/plain\nX-Gaga-Sample: synthetic\n\nDB_PASSWORD=gaga-synthetic-example');
    document.querySelector('.http-composer form').requestSubmit();
    await wait(() => document.querySelector('.http-reader'), 'local HTTP');
    check('HTTP analysis focuses visible result and collapses input', visible('.http-reader') && !visible('.http-composer'));
    const http = await reviewCurrent('http');
    await checkpoint('Followup starts');
    await enter(`[aria-label="追问-${http.id}"]`, '列出还需要补充的证据，并指出不能据此确认的结论。');
    requestsAttempted++;
    document.querySelector('.followup form').requestSubmit();
    await wait(() => document.querySelector('.chat-turn'), 'official followup', 1500);
    check('Actual native followup is displayed and persisted', (await invoke('get_workspace')).followups.length === 1 && document.querySelector('.chat-turn').textContent.length > 30);
    await checkpoint('Followup saved');
    await nav('triage');
    const alert = '{"sample":"synthetic","device":"NDR","name":"敏感路径访问测试","sourceIp":"192.0.2.42","destinationIp":"198.51.100.10","proof":"未提供原始请求与响应，仅验证软件研判流程"}';
    await enter('[aria-label="告警原文"]', alert);
    document.querySelector('.alert-composer').requestSubmit();
    await wait(() => document.querySelector('.ai-start') && !document.querySelector('.result-actions button')?.disabled, 'local alert');
    check('Alert result is visible without the input competing for space', visible('.result-actions') && !visible('.alert-composer'));
    document.querySelector('[data-action="toggle-input"]').click(); await pause();
    check('Reopening alert input retains exact original draft', document.querySelector('[aria-label="告警原文"]').value === alert && !visible('.analysis-layout'));
    document.querySelector('[data-action="toggle-input"]').click(); await pause();
    await reviewCurrent('triage');
    await nav('logs');
    await invoke('analyze_example',{kind:'logs'});
    document.querySelector('[aria-label="当前事件"]').dispatchEvent(new Event('change',{bubbles:true}));
    await wait(() => document.querySelector('.log-investigation'), 'local sample log');
    check('Log workspace exposes original timeline and stable result actions', visible('.log-event-grid') && visible('.result-actions'));
    await reviewCurrent('logs');
    w = await invoke('get_workspace');
    check('Three official evidence reviews remain isolated in the synthetic case', w.evidence.length === 3 && w.aiReviews.length === 3 && w.followups.length === 1 && w.cases.find((c) => c.id === w.activeCase).title.startsWith('[AI实测]'));
    await invoke('record_ui_verification', {result: {version: '0.6.4', native: true, officialApiTested: true, model: cfg.model, reopened: false, passed, stages, errors: [], requestsAttempted}});
  } catch (error) {
    await invoke('record_ui_verification', {result: {version: '0.6.4', native: true, passed, stages, errors: [String(error), error.stack], requestsAttempted}});
  }
})();
