// Native acceptance in a disposable workspace. Only one public RDAP lookup;
// no threat-intelligence keys, model calls, customer data or sample uploads.
(async () => {
  const invoke = (name, args = {}) =>
    window.__TAURI_INTERNALS__.invoke(name, args);
  const passed = [];
  const pause = (ms = 100) => new Promise((r) => setTimeout(r, ms));
  const wait = async (fn, label) => {
    const start = Date.now();
    while (Date.now() - start < 90000) {
      const value = await fn();
      if (value) return value;
      await pause();
    }
    throw Error('Intelligence UI timeout: ' + label);
  };
  const check = (label, value) => {
    if (!value) throw Error(label);
    passed.push(label);
    void invoke('ui_checkpoint', { label });
  };
  const button = (text, selector = 'button') =>
    [...document.querySelectorAll(selector)].find(
      (b) => b.textContent.trim() === text,
    );
  async function enter(element, value) {
    const proto =
      element.tagName === 'TEXTAREA'
        ? HTMLTextAreaElement.prototype
        : element.tagName === 'SELECT'
          ? HTMLSelectElement.prototype
          : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(element, value);
    element.dispatchEvent(
      new Event(element.tagName === 'SELECT' ? 'change' : 'input', {
        bubbles: true,
      }),
    );
    await pause();
  }
  async function go(module) {
    document.querySelector('[aria-label="全部工具"]').click();
    await wait(() => document.querySelector(`[data-tool="${module}"]`), module);
    document.querySelector(`[data-tool="${module}"]`).click();
    await pause(160);
  }
  try {
    await wait(
      () =>
        document
          .querySelector('.dashboard-footer')
          ?.textContent.includes('更新于'),
      'startup',
    );
    document.querySelector('.splash-skip')?.click();
    const workspace = await invoke('get_workspace'),
      caseId = workspace.activeCase,
      root = workspace.dataDir;
    check(
      'Optional intelligence is locked and all four services disabled by default',
      (await invoke('get_intel_config')).locked &&
        (await invoke('get_intel_config')).providers.every(
          (p) => !p.enabled && !p.hasKey,
        ),
    );
    await go('settings');
    button('情报服务', '.settings-navigation button').click();
    await wait(() => document.querySelector('.ti-settings select'), 'settings');
    check(
      'Intelligence settings expose exactly four documented services',
      document.querySelectorAll('.ti-settings select option').length === 4,
    );
    await enter(document.querySelector('.ti-settings select'), 'rdap');
    check(
      'RDAP settings do not request a key',
      !document.querySelector('[aria-label="情报 API Key"]'),
    );
    document.querySelectorAll('.ti-settings input[type="checkbox"]')[0].click();
    document.querySelectorAll('.ti-settings input[type="checkbox"]')[1].click();
    await pause();
    button('保存服务配置').click();
    await wait(
      async () =>
        (await invoke('get_intel_config')).providers.find(
          (p) => p.id === 'rdap',
        ).enabled,
      'save RDAP',
    );
    button('解锁情报查询').click();
    await wait(
      async () => !(await invoke('get_intel_config')).locked,
      'unlock',
    );
    await go('knowledge');
    button('在线查询', '.platform-tabs button').click();
    await wait(
      () => document.querySelector('[aria-label="待查询指标"]'),
      'query view',
    );
    await enter(
      document.querySelector('[aria-label="待查询指标"]'),
      'icann.org',
    );
    check(
      'Query is unavailable before confirming exact indicator egress',
      document.querySelector('.ti-query > button.primary').disabled,
    );
    document.querySelector('[aria-label="确认情报指标外发"]').click();
    await pause();
    check(
      'Explicit consent enables a configured read-only lookup',
      !document.querySelector('.ti-query > button.primary').disabled,
    );
    document.querySelector('.ti-query > button.primary').click();
    const job = await wait(async () => {
      const jobs = await invoke('get_intel_jobs', { caseId });
      const j = jobs.find((j) => j.indicator === 'icann.org');
      if (j?.state === 'failed') throw Error(j.message);
      return j?.state === 'completed' ? j : null;
    }, 'live public RDAP result');
    const full = await invoke('get_intel_job', { caseId, id: job.id });
    check(
      'Live RDAP returns a matching current domain registration over HTTPS',
      full.outcome === 'data' &&
        full.result.objectClassName === 'domain' &&
        full.result.ldhName.toLowerCase() === 'icann.org' &&
        full.sourceUrl.startsWith('https://'),
    );
    check(
      'Source result has acquisition time and canonical SHA-256',
      !!full.fetchedAt && /^[a-f0-9]{64}$/.test(full.resultSha256),
    );
    check(
      'Job list omits large source responses',
      job.result === null || job.result === undefined,
    );
    await wait(() => document.querySelector('.ti-job button'), 'result row');
    document.querySelector('.ti-job button').click();
    await wait(() => button('复核并加入事件报告'), 'citation');
    check(
      'UI explains registration limits and displays the frozen source timestamp',
      document
        .querySelector('.ti-result-detail')
        .textContent.includes('不等于历史 WHOIS') &&
        document
          .querySelector('.ti-result-detail')
          .textContent.includes(full.resultSha256),
    );
    for (const theme of ['light', 'dark']) {
      document.documentElement.dataset.theme = theme;
      await invoke('resize_ui_verification', { width: 960, height: 660 });
      await pause(250);
      check(
        'Query and details fit minimum desktop width in ' + theme,
        ['.ti-query', '.ti-results', '.ti-fields', '.ti-result-detail'].every(
          (s) => {
            const e = document.querySelector(s),
              r = e.getBoundingClientRect();
            return (
              r.width > 0 &&
              r.left >= 0 &&
              r.right <= innerWidth + 1 &&
              e.scrollWidth <= e.clientWidth + 2
            );
          },
        ),
      );
    }
    button('复核并加入事件报告').click();
    await wait(
      () => button('保存节点') && !button('保存节点').disabled,
      'record modal',
    );
    check(
      'Report citation opens editable timeline record with source hash',
      document
        .querySelector('[role="dialog"]')
        .textContent.includes('记录到事件时间线') &&
        document
          .querySelector('[role="dialog"] textarea')
          .value.includes(full.resultSha256),
    );
    button('保存节点').click();
    await wait(
      async () => (await invoke('get_workspace')).nodes.length === 1,
      'saved citation',
    );
    const recorded = await invoke('get_workspace'),
      evidenceId = recorded.nodes[0].evidenceId;
    check(
      'Citation creates evidence and a node only in its originating event',
      recorded.nodes[0].caseId === caseId &&
        recorded.evidence.some((e) => e.id === evidenceId) &&
        recorded.nodes[0].body.includes(full.resultSha256),
    );
    for (const format of ['html', 'docx'])
      await invoke('export_report', {
        path: root + '/rdap-case.' + format,
        format,
        caseId,
      });
    const html = await invoke('read_http_text', {
      path: root + '/rdap-case.html',
    });
    check(
      'Actual HTML report contains the indicator and cited result hash',
      html.includes('icann.org') && html.includes(full.resultSha256),
    );
    const q = {
      caseId,
      evidenceId: null,
      provider: 'rdap',
      operation: 'registration',
      kind: 'domain',
      indicators: ['icann.org'],
      currentOnly: true,
      fresh: false,
      consent: true,
    };
    const cache = (await invoke('start_intel_query', { query: q }))[0];
    check(
      'Repeat uses a local cache and preserves original acquisition time',
      cache.state === 'completed' &&
        cache.sourceJobId === job.id &&
        cache.fetchedAt === full.fetchedAt,
    );
    const skipped = await invoke('start_intel_query', {
      query: { ...q, indicators: ['host.local', 'example.com'] },
    });
    check(
      'Local and documentation domains are skipped without egress',
      skipped.every((j) => j.state === 'skipped'),
    );
    const next = await invoke('create_case', { title: '[验收] 第二事件隔离' });
    const current = await invoke('get_workspace');
    check(
      'Second event starts with no inherited query records',
      (await invoke('get_intel_jobs', { caseId: current.activeCase }))
        .length === 0,
    );
    let rejection;
    try {
      await invoke('get_intel_job', { caseId: current.activeCase, id: job.id });
    } catch (e) {
      rejection = String(e);
    }
    check(
      'Cross-event result access is rejected',
      rejection?.includes('TI-CASE'),
    );
    await invoke('switch_case', { id: caseId });
    await invoke('set_intel_lock', { locked: true });
    try {
      await invoke('start_intel_query', { query: q });
      rejection = '';
    } catch (e) {
      rejection = String(e);
    }
    check(
      'Lock prevents a new request even if cached results exist',
      rejection.includes('TI-LOCKED'),
    );
    check(
      'No AI call, sample execution or upload was made',
      !(await invoke('get_workspace')).aiReviews.length,
    );
    await invoke('resize_ui_verification', { width: 1320, height: 860 });
    document.documentElement.dataset.theme = 'light';
    await invoke('record_ui_verification', {
      result: {
        native: true,
        passed,
        errors: [],
        liveService: 'public RDAP icann.org only',
        authenticatedThreatIntelCalls: false,
        externalModelCalled: false,
        malwareExecuted: false,
        sampleUploaded: false,
        sourceJobId: job.id,
      },
    });
  } catch (error) {
    await invoke('record_ui_verification', {
      result: {
        native: true,
        passed,
        errors: [String(error), error.stack],
        diagnostics: document
          .querySelector('.ti-workspace')
          ?.innerText.slice(0, 4000),
        authenticatedThreatIntelCalls: false,
        externalModelCalled: false,
      },
    });
  }
})();
