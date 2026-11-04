// Real WebView acceptance with a disposable database, inert samples and one
// public website. No model calls, privileged actions or sample execution.
(async () => {
  const invoke = (name, args = {}) =>
    window.__TAURI_INTERNALS__.invoke(name, args);
  const passed = [],
    layouts = [];
  const pause = (ms = 100) => new Promise((r) => setTimeout(r, ms));
  const wait = async (fn, label) => {
    const started = Date.now();
    while (Date.now() - started < 90000) {
      const value = await fn();
      if (value) return value;
      await pause();
    }
    throw Error('Comfort acceptance timeout: ' + label);
  };
  const check = (label, ok) => {
    if (!ok) throw Error(label);
    passed.push(label);
    void invoke('ui_checkpoint', { label });
  };
  const button = (text, selector = 'button') =>
    [...document.querySelectorAll(selector)].find(
      (e) => e.textContent.trim() === text,
    );
  const enter = async (element, value) => {
    if (!element) throw Error('Missing editable field');
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
  };
  const center = async () => {
    const back = document.querySelector('[aria-label="返回报告中心"]');
    if (back) {
      back.click();
      await wait(
        () =>
          document.querySelector('.report-workspace')?.dataset.view === 'home',
        'return report center',
      );
    }
  };
  const go = async (module) => {
    await center();
    document.querySelector('[aria-label="全部工具"]').click();
    await wait(() => document.querySelector(`[data-tool="${module}"]`), module);
    document.querySelector(`[data-tool="${module}"]`).click();
    await pause(200);
  };
  const capture = async (name) => {
    await invoke('ui_checkpoint', { label: 'SCREENSHOT ' + name });
    await pause(1800);
  };
  const layout = async (module, selectors) => {
    const focusedReport =
      document.querySelector('.report-workspace')?.dataset.view === 'write';
    for (const theme of ['light', 'dark']) {
      if (focusedReport) await center();
      await enter(document.querySelector('[aria-label="主题模式"]'), theme);
      if (focusedReport) {
        document.querySelector('[data-action="open-report-editor"]').click();
        await pause();
      }
      for (const [width, height] of [
        [960, 660],
        [1180, 760],
        [1320, 860],
      ]) {
        await invoke('resize_ui_verification', { width, height });
        await pause(250);
        const row = { module, theme, width, height, panes: {} };
        if (module === 'response-receipt') {
          check(
            `${module} ${theme} ${width}: long receipts use the available writing width`,
            document
              .querySelector('.response-action-editor')
              .getBoundingClientRect().width >= Math.min(900, innerWidth - 60),
          );
        }
        for (const s of selectors) {
          const e = document.querySelector(s);
          if (!e) throw Error('Missing layout target: ' + s);
          const r = e.getBoundingClientRect();
          row.panes[s] = {
            x: r.x,
            y: r.y,
            width: r.width,
            height: r.height,
            bottom: r.bottom,
          };
          if (!(
            r.width > 0 &&
            r.height > 0 &&
            r.left >= 0 &&
            r.right <= innerWidth + 1 &&
            r.top >= 0 &&
            r.bottom <= innerHeight + 2 &&
            e.scrollWidth <= e.clientWidth + 2
          ))
            await capture(module + '-failure');
          check(
            `${module} ${theme} ${width}: ${s} fits window ` +
              JSON.stringify({
                rect: row.panes[s],
                scrollWidth: e.scrollWidth,
                clientWidth: e.clientWidth,
              }),
            r.width > 0 &&
              r.height > 0 &&
              r.left >= 0 &&
              r.right <= innerWidth + 1 &&
              r.top >= 0 &&
              r.bottom <= innerHeight + 2 &&
              e.scrollWidth <= e.clientWidth + 2,
          );
        }
        check(
          `${module} ${theme} ${width}: no document overflow`,
          document.documentElement.scrollWidth <= innerWidth,
        );
        layouts.push(row);
        if (
          (width === 1320 && theme === 'light') ||
          (width === 960 && theme === 'dark')
        )
          await capture(module + '-' + theme + '-' + width);
      }
    }
  };
  try {
    await wait(
      () =>
        document
          .querySelector('.dashboard-footer')
          ?.textContent.includes('更新于'),
      'startup',
    );
    document.querySelector('.splash-skip')?.click();
    const initial = await invoke('get_workspace'),
      root = initial.dataDir,
      caseId = initial.activeCase;
    const log = await invoke('analyze_file', {
      path: root + '/auth.log',
      kind: 'logs',
    });
    check('Log scanner ingests actual fixture', !!log.id);
    await invoke('analyze_file', {
      path: root + '/inspect.json',
      kind: 'containers',
    });
    await go('http');
    await enter(
      document.querySelector('[aria-label="HTTP 请求包"]'),
      'GET /robots.txt HTTP/1.1\r\nHost: example.test\r\nUser-Agent: Gaga-UI-Acceptance\r\n\r\n',
    );
    await enter(
      document.querySelector('[aria-label="HTTP 响应包"]'),
      'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nUser-agent: *\nDisallow: /private/',
    );
    await layout('http-input', [
      '[aria-label="HTTP 请求包"]',
      '[aria-label="HTTP 响应包"]',
    ]);
    const requestSource = document.querySelector('[aria-label="HTTP 请求包"]');
    const originalRequest = requestSource.value;
    document.querySelector('[aria-label="放大编辑 请求包"]').click();
    await wait(
      () => document.querySelector('.text-editor-focus textarea'),
      'expanded packet editor',
    );
    await layout('http-expanded', ['.text-editor-focus']);
    const multilineRequest =
      originalRequest +
      Array.from({ length: 120 }, (_, i) => `evidence-line-${i}`).join('\n');
    await enter(
      document.querySelector('.text-editor-focus textarea'),
      multilineRequest,
    );
    check(
      'Expanded packet input synchronizes long multiline text without submitting analysis',
      requestSource.value === multilineRequest &&
        !document.querySelector('.http-reader'),
    );
    document
      .querySelector('.text-editor-focus textarea')
      .dispatchEvent(
        new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }),
      );
    await wait(
      () => !document.querySelector('.text-editor-focus'),
      'expanded editor close',
    );
    check(
      'Returning from expanded editing retains text and restores the original caret target',
      document.activeElement === requestSource &&
        requestSource.value === multilineRequest,
    );
    await enter(requestSource, originalRequest);
    document.querySelector('.http-composer form').requestSubmit();
    await wait(() => document.querySelector('.http-reader'), 'HTTP result');
    check(
      'Completed analysis gives a non-blocking visible status cue',
      document
        .querySelector('.status-toast')
        ?.textContent.includes('HTTP 联合分析完成'),
    );
    check(
      'HTTP request and response really persist as paired evidence',
      (await invoke('get_workspace')).evidence.some((e) => e.kind === 'http'),
    );
    check(
      'Source library is collapsed by default',
      document.querySelector('.file-pane').hidden,
    );
    document.querySelector('.analysis-files-toggle').click();
    await pause();
    check(
      'Source library can be opened and its file is reachable',
      document.querySelector('.file-row').offsetWidth > 0 &&
        !document.querySelector('.file-pane').hidden,
    );
    document.querySelector('.analysis-files-toggle').click();
    await pause();
    await layout('http-result', ['.result-content']);
    await go('logs');
    await wait(
      () => document.querySelector('.log-investigation'),
      'log timeline',
    );
    await layout('logs', ['.result-content']);
    check(
      'Log AI action remains reachable at every desktop size',
      [...document.querySelectorAll('.investigation-intro button')].some(
        (e) => e.getBoundingClientRect().height > 0,
      ),
    );
    await go('containers');
    await wait(
      () => document.querySelector('.coverage-panel'),
      'container coverage',
    );
    await layout('containers', ['.result-content']);
    await go('triage');
    await enter(
      document.querySelector('[aria-label="告警原文"]'),
      JSON.stringify({
        event: 'sensitive-path',
        source: '192.0.2.44',
        proof: 'Synthetic device label only; no request or response captured.',
      }),
    );
    await layout('triage-input', ['[aria-label="告警原文"]']);
    document.querySelector('.alert-composer').requestSubmit();
    await wait(
      () => document.querySelector('.module-triage .analysis-layout'),
      'alert archived',
    );
    await layout('triage-result', ['.result-content']);
    const job = await invoke('start_local_analysis', {
      caseId,
      path: root + '/layered.php',
      kind: 'webshell',
    });
    await wait(async () => {
      const current = (
        await invoke('get_local_analysis_jobs', { caseId })
      ).find((j) => j.id === job.id);
      if (current?.state === 'failed') throw Error(current.error);
      return current?.state === 'completed';
    }, 'Docker static analysis');
    await go('webshell');
    await wait(() => document.querySelector('.webshell-code'), 'WebShell code');
    document.querySelector('[aria-label="收起分析任务"]')?.click();
    await layout('webshell', ['.webshell-grid', '.webshell-code']);
    check(
      'WebShell source has a useful reading height',
      document.querySelector('.webshell-code').getBoundingClientRect().height >=
        180,
    );
    const binary = await invoke('start_local_analysis', {
      caseId,
      path: root + '/fixture-agent.exe',
      kind: 'binary',
    });
    await wait(async () => {
      const task = (await invoke('get_local_analysis_jobs', { caseId })).find(
        (j) => j.id === binary.id,
      );
      if (task?.state === 'failed') throw Error(task.error);
      return task?.state === 'completed';
    }, 'isolated PE static analysis');
    await go('binary');
    await wait(
      () => document.querySelector('.module-binary .analysis-layout'),
      'binary results',
    );
    await layout('binary', ['.result-content']);
    await go('timeline');
    button('新增处置动作').click();
    await wait(
      () => document.querySelector('[aria-label="动作说明"]'),
      'response form',
    );
    await enter(
      document.querySelector('[aria-label="动作标题"]'),
      '人工填写区验收',
    );
    await enter(
      document.querySelector('[aria-label="动作目标"]'),
      'example.test',
    );
    await enter(document.querySelector('[aria-label="申请人"]'), '验收分析员');
    await enter(
      document.querySelector('[aria-label="动作说明"]'),
      '只记录合成工单，不执行封禁。\n第二行：操作范围与回滚条件。',
    );
    check(
      'Action description has a substantial multi-line writing area',
      document.querySelector('[aria-label="动作说明"]').getBoundingClientRect()
        .height >= 260,
    );
    button('记录处置动作').click();
    await wait(() => button('提交审批'), 'response created');
    button('提交审批').click();
    await wait(() => button('批准'), 'approval');
    button('批准').click();
    await wait(() => button('开始执行'), 'execution');
    button('开始执行').click();
    await wait(() => button('记录成功'), 'completion');
    button('记录成功').click();
    await wait(
      () => document.querySelector('[aria-label="执行回执"]'),
      'receipt form',
    );
    check(
      'Opening the receipt editor does not advance the recorded action',
      (await invoke('get_response_actions', { caseId }))[0].status ===
        'executing',
    );
    await enter(
      document.querySelector('[aria-label="执行回执"]'),
      '合成工单 R-001\n设备确认：规则已登记\n验证：未执行真实封禁。',
    );
    await layout('response-receipt', ['.response-action-editor']);
    button('保存记录').click();
    await wait(
      async () =>
        (await invoke('get_response_actions', { caseId }))[0].receipt?.includes(
          'R-001',
        ),
      'receipt saved',
    );
    await wait(
      () =>
        !document.querySelector('[aria-label="执行回执"]') &&
        button('恢复验证'),
      'receipt dismissed',
    );
    button('恢复验证').click();
    await wait(
      () => document.querySelector('[aria-label="恢复验证结果"]'),
      'verification editor',
    );
    await enter(
      document.querySelector('[aria-label="恢复验证结果"]'),
      '合成验证完成\n观察时间与证据已记录。',
    );
    button('保存记录').click();
    await wait(
      async () =>
        (await invoke('get_response_actions', { caseId }))[0].status ===
        'verified',
      'verification saved',
    );
    await wait(
      () => !document.querySelector('[aria-label="恢复验证结果"]'),
      'verification dismissed',
    );
    check(
      'Multi-line receipt and recovery verification persist through the visible forms',
      (
        await invoke('get_response_actions', { caseId })
      )[0].verification.includes('观察时间'),
    );
    await go('reports');
    await wait(
      () =>
        document.querySelector(
          '[data-action="open-report-editor"]:not(:disabled)',
        ),
      'report center',
    );
    check(
      'Reports open in their own center',
      !!document.querySelector('.report-home') &&
        !document.querySelector('.report-body-editor'),
    );
    await layout('report-center', ['.report-home-intro']);
    document.querySelector('[data-action="open-report-editor"]').click();
    await pause();
    await layout('report-editor', ['.report-writing-layout']);
    check(
      'Report summaries are large by default',
      document.querySelector('[aria-label="事件摘要"]').getBoundingClientRect()
        .height >= 180,
    );
    button('导出报告').click();
    await pause();
    check(
      'HTML, PDF and DOCX are discoverable in a dedicated delivery dialog',
      ['保存 HTML', '打印 / PDF', '导出 DOCX'].every(
        (text) =>
          button(text) ||
          document.querySelector('.report-delivery').textContent.includes(text),
      ),
    );
    document.querySelector('[aria-label="关闭报告导出"]').click();
    await go('lists');
    check(
      'New whitelist and blacklist rules default to global scope',
      [...document.querySelectorAll('select')].some(
        (e) => e.value === 'global',
      ),
    );
    await invoke('platform_action', {
      action: 'ruleAdd',
      args: {
        list: 'allow',
        kind: 'domain',
        value: 'baidu.com',
        scope: 'global',
        expiresAt: '',
        notes: 'Public website monitoring acceptance; no enforcement',
      },
    });
    const second = await invoke('create_case', {
      title: '[验收] 全局规则事件隔离',
    });
    check(
      'Global rules follow an independent event',
      (await invoke('platform_state')).rules.some(
        (r) => r.scope === 'global' && r.value === 'baidu.com',
      ),
    );
    await invoke('switch_case', { id: caseId });
    const assets = await invoke('platform_action', {
      action: 'assetImport',
      args: { text: '百度,https://www.baidu.com/', intervalSecs: 3600 },
    });
    const asset = (await invoke('platform_state')).assets[0];
    if (!asset) throw Error('Baidu asset missing: ' + JSON.stringify(assets));
    await invoke('platform_action', {
      action: 'assetToggle',
      args: { id: asset.id, enabled: false },
    });
    await go('assets');
    await wait(() => button('立即巡检'), 'asset card');
    button('立即巡检').click();
    await wait(
      () => document.querySelector('.asset-screenshot-evidence'),
      'Baidu HTTP capture',
    );
    const page = await invoke('get_monitor_snapshots_page', {
        assetId: asset.id,
        offset: 0,
        limit: 10,
      }),
      snapshot = page.rows[0];
    check(
      'Real Baidu GET has successful status, hash and archived evidence',
      snapshot.status === 200 &&
        /^[a-f0-9]{64}$/.test(snapshot.sha256) &&
        !!snapshot.evidenceId &&
        !snapshot.error,
    );
    const archive = JSON.parse(
      await invoke('read_http_text', {
        path: root + '/evidence/' + snapshot.evidenceId,
      }),
    );
    if (atob(archive.rawHtmlBase64).includes('location.replace'))
      check(
        'Baidu navigation stub is explicitly partial coverage',
        snapshot.coverageGaps.some((g) => g.includes('跳转')),
      );
    button('人工确认此快照为基线').click();
    await wait(
      async () =>
        (await invoke('platform_state')).assets.find((a) => a.id === asset.id)
          .baselineId === snapshot.id,
      'baseline saved',
    );
    await wait(() => !button('立即巡检').disabled, 'inspection idle');
    button('立即巡检').click();
    await wait(
      async () =>
        (
          await invoke('get_monitor_snapshots_page', {
            assetId: asset.id,
            offset: 0,
            limit: 10,
          })
        ).total >= 2,
      'second capture',
    );
    button('历史快照').click();
    await pause(200);
    check(
      'Monitor history renders only the selected snapshot',
      document.querySelectorAll('.asset-screenshot-evidence').length === 1 &&
        document.querySelector('[aria-label="巡检快照"]').options.length >= 2,
    );
    button('补充截图').click();
    await wait(
      () =>
        document.activeElement?.getAttribute('aria-label') === '快速举证截图',
      'screenshot focus',
    );
    const dataUrl = (
      await invoke('read_http_text', { path: root + '/baidu-screenshot.txt' })
    ).trim();
    const bytes = Uint8Array.from(atob(dataUrl.split(',')[1]), (c) =>
        c.charCodeAt(0),
      ),
      transfer = new DataTransfer();
    transfer.items.add(new File([bytes], 'baidu.png', { type: 'image/png' }));
    document.activeElement.dispatchEvent(
      new ClipboardEvent('paste', {
        clipboardData: transfer,
        bubbles: true,
        cancelable: true,
      }),
    );
    await wait(
      () => document.querySelector('[aria-label="快速截图图注"]'),
      'clipboard image preview',
    );
    await enter(
      document.querySelector('[aria-label="快速截图图注"]'),
      '百度独立浏览器截图；采集时间记录于验收目录；仅验证举证链路。',
    );
    button('保存节点').click();
    const recorded = await wait(async () => {
      const w = await invoke('get_workspace');
      return w.nodes.find((n) => n.screenshots.length) ? w : null;
    }, 'screenshot archive');
    check(
      'Pasted screenshot is archived with URL, snapshot and source digest',
      recorded.nodes.some(
        (n) =>
          n.screenshots.length &&
          n.body.includes('https://www.baidu.com/') &&
          n.body.includes('HTML SHA-256'),
      ),
    );
    await go('reports');
    await wait(
      () =>
        document.querySelector(
          '[data-action="open-report-editor"]:not(:disabled)',
        ),
      'report reload',
    );
    for (const format of ['html', 'docx'])
      await invoke('export_report', {
        caseId,
        path: root + '/baidu-evidence.' + format,
        format,
      });
    check(
      'Actual report HTML includes source digest and screenshot',
      (
        await invoke('read_http_text', { path: root + '/baidu-evidence.html' })
      ).includes('data:image/png;base64,'),
    );
    await invoke('resize_ui_verification', { width: 1320, height: 860 });
    await enter(document.querySelector('[aria-label="主题模式"]'), 'light');
    check(
      'Module transitions do not send stale evidence to specialized analysis APIs',
      !(await invoke('get_runtime_logs')).entries.some(
        (entry) => entry.code === 'CLIENT_ERROR',
      ),
    );
    await invoke('record_ui_verification', {
      result: {
        passed,
        layouts,
        errors: [],
        synthetic: true,
        publicWebsite: 'https://www.baidu.com/',
        baidu: snapshot,
        externalModelCalled: false,
        samplesExecuted: false,
        secondCase: second.activeCase,
      },
    });
  } catch (error) {
    await invoke('record_ui_verification', {
      result: {
        passed,
        layouts,
        errors: [String(error), error.stack],
        synthetic: true,
        externalModelCalled: false,
      },
    });
  }
})();
