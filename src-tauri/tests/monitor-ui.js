// Real desktop/web-browser integration with a disposable incident database.
(async () => {
  const invoke = (name, args = {}) =>
    window.__TAURI_INTERNALS__.invoke(name, args);
  const action = (action, args = {}) =>
    invoke('platform_action', { action, args });
  const passed = [];
  const pause = (ms = 100) => new Promise((r) => setTimeout(r, ms));
  const wait = async (fn, label) => {
    const start = Date.now();
    while (Date.now() - start < 110000) {
      const v = await fn();
      if (v) return v;
      await pause();
    }
    throw Error('Monitor timeout: ' + label);
  };
  const check = (label, ok) => {
    if (!ok) throw Error(label);
    passed.push(label);
  };
  const button = (text, sel = 'button') =>
    [...document.querySelectorAll(sel)].find(
      (e) => e.textContent.trim() === text,
    );
  const enter = async (label, value) => {
    const el = document.querySelector(`[aria-label="${label}"]`);
    if (!el) throw Error('Missing ' + label);
    Object.getOwnPropertyDescriptor(
      el instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement.prototype
        : HTMLInputElement.prototype,
      'value',
    ).set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    await pause();
  };
  const go = async (module) => {
    document.querySelector('[aria-label="全部工具"]').click();
    await wait(() => document.querySelector(`[data-tool="${module}"]`), 'tool');
    document.querySelector(`[data-tool="${module}"]`).click();
    await pause();
  };
  const capture = async (name) => {
    await invoke('ui_checkpoint', { label: 'SCREENSHOT ' + name });
    await pause(1800);
  };
  let root;
  try {
    await wait(
      () =>
        document
          .querySelector('.dashboard-footer')
          ?.textContent.includes('更新于'),
      'dashboard',
    );
    document.querySelector('.splash-skip')?.click();
    let workspace = await invoke('get_workspace');
    root = workspace.dataDir;
    const cfg = JSON.parse(
      await invoke('read_http_text', { path: root + '/monitor-config.json' }),
    );
    await go('assets');
    if (cfg.phase === 'reopen') {
      const state = await action('assetSnapshots', {
        id: (await invoke('platform_state')).assets[0].id,
      });
      check(
        'Automatic screenshot and disabled options survive restart',
        state.length === 4 &&
          state.some((s) => s.screenshot) &&
          !(await invoke('platform_state')).assets[0].autoScreenshot,
      );
      const shot = state.find((s) => s.screenshot).screenshot;
      check(
        'Reopened screenshot passes stored hash verification',
        (await invoke('screenshot_data', { id: shot.id })).startsWith(
          'data:image/png;base64,',
        ),
      );
      await invoke('record_ui_verification', {
        result: { passed, errors: [], phase: cfg.phase },
      });
      return;
    }
    check(
      'Dedicated browser environment is ready',
      (await action('browserEnvironment')).ready,
    );
    check(
      'Browser environment preparation works through the native action',
      (await action('browserPrepare', { mirror: 'aliyun' })).ready,
    );
    document
      .querySelector('[role="tab"]')
      .parentNode.querySelectorAll('button')[1]
      .click();
    await pause();
    check(
      'New targets expose independent redirect and screenshot switches',
      document.querySelector('[aria-label="新资产跟随跳转"]').checked &&
        document.querySelector('[aria-label="新资产自动截图"]').checked,
    );
    await enter('资产导入内容', '页面自动采集验收,' + cfg.url);
    button('登记资产', '[data-panel="asset-import"] button').click();
    await wait(
      async () => (await invoke('platform_state')).assets.length === 1,
      'asset import',
    );
    await pause(300);
    let asset = (await invoke('platform_state')).assets[0];
    check(
      'Imported options persist without enabling schedule',
      asset.followRedirects && asset.autoScreenshot && !asset.enabled,
    );
    document.querySelector('[aria-label^="巡检设置 "]').click();
    await wait(
      () => document.querySelector('[aria-label="自动页面截图"]'),
      'asset settings',
    );
    check(
      'Asset settings open as a separate dialog',
      !!document.querySelector('[role="dialog"][aria-label="资产巡检设置"]'),
    );
    await wait(
      () => !document.querySelector('[aria-label="关闭资产巡检设置"]').disabled,
      'settings can close',
    );
    document.querySelector('[aria-label="关闭资产巡检设置"]').click();
    await wait(
      () =>
        !document.querySelector('[aria-label="关闭资产巡检设置"]') &&
        !button('立即巡检').disabled,
      'check ready',
    );
    button('立即巡检').click();
    const first = await wait(async () => {
      const rows = await action('assetSnapshots', { id: asset.id });
      return rows[0];
    }, 'browser capture');
    if (first.screenshotError) throw Error(first.screenshotError);
    await wait(
      () => document.querySelector('.asset-screenshot-evidence .shot'),
      'screenshot figure',
    );
    document
      .querySelector('.asset-screenshot-evidence .shot')
      .scrollIntoView({ block: 'center' });
    await wait(
      () => document.querySelector('.asset-screenshot-evidence img')?.complete,
      'native screenshot preview',
    );
    check(
      'HTTP redirect and browser JavaScript redirect have separate final URLs',
      first.finalUrl.endsWith('/js') &&
        first.browserFinalUrl.endsWith('/final') &&
        first.redirects.length === 1,
    );
    check(
      'Browser records final navigation, DOM digest and real PNG',
      first.browserNavigations.some((n) => n.url.endsWith('/final')) &&
        /^[0-9a-f]{64}$/.test(first.domSha256) &&
        first.screenshot?.size > 1000,
    );
    check(
      'Rendered screenshot appears without manual paste',
      document.querySelector('.asset-screenshot-evidence img').naturalWidth ===
        1440,
    );
    workspace = await invoke('get_workspace');
    check(
      'Automated screenshot has an incident node with source/time/hash',
      workspace.nodes.some(
        (n) =>
          n.evidenceId === first.evidenceId &&
          n.screenshots.length === 1 &&
          n.body.includes('/final') &&
          n.body.includes('HTTP HTML SHA-256'),
      ),
    );
    const raw = JSON.parse(
      await invoke('read_http_text', {
        path: root + '/evidence/' + first.evidenceId,
      }),
    );
    check(
      'Evidence preserves redirect response, rendered DOM and screenshot hash',
      typeof raw.redirectResponses[0].rawHtmlBase64 === 'string' &&
        raw.redirectResponses[0].status === 302 &&
        raw.browser.dom.includes('最终页面') &&
        raw.browser.screenshotSha256 === first.screenshot.sha256,
    );
    check(
      'History payload excludes image/body blobs',
      !JSON.stringify(first).includes('rawHtmlBase64') &&
        !JSON.stringify(first).includes('pngBase64'),
    );
    await capture('monitor-auto-screenshot');
    for (const format of ['html', 'docx'])
      await invoke('export_report', {
        caseId: workspace.activeCase,
        path: root + '/monitor-report.' + format,
        format,
      });
    check(
      'Exported HTML embeds the automatically collected screenshot',
      (
        await invoke('read_http_text', { path: root + '/monitor-report.html' })
      ).includes('data:image/png;base64,'),
    );
    const configure = async (follow, screenshot) => {
      await wait(() => !button('立即巡检').disabled, 'check completed');
      document.querySelector('[aria-label^="巡检设置 "]').click();
      await wait(
        () => document.querySelector('[aria-label="跟随页面跳转"]'),
        'settings',
      );
      for (const [name, enabled] of [
        ['跟随页面跳转', follow],
        ['自动页面截图', screenshot],
      ]) {
        const checkbox = document.querySelector(`[aria-label="${name}"]`);
        if (checkbox.checked !== enabled) checkbox.click();
        await pause();
      }
      button('保存设置').click();
      await wait(
        () => !document.querySelector('[aria-label="关闭资产巡检设置"]'),
        'settings save',
      );
    };
    const inspect = async (count) => {
      await wait(() => !button('立即巡检').disabled, 'check ready');
      button('立即巡检').click();
      const latest = await wait(async () => {
        const rows = await action('assetSnapshots', { id: asset.id });
        return rows.length === count && rows[0];
      }, 'capture ' + count);
      await wait(
        () =>
          document.querySelector('[aria-label="巡检快照"]')?.options.length ===
          count,
        'visible capture history',
      );
      check('Immediate capture preserves ' + count + ' history rows', true);
      return latest;
    };
    await configure(true, false);
    const httpOnly = await inspect(2);
    check(
      'Redirect on / screenshot off keeps HTTP evidence without a browser capture',
      httpOnly.finalUrl.endsWith('/js') &&
        httpOnly.status === 200 &&
        !httpOnly.screenshot &&
        !httpOnly.screenshotError,
    );
    await configure(false, true);
    const blocked = await inspect(3);
    check(
      'Redirect off / screenshot on reports blocked navigation and keeps the original 302 evidence',
      blocked.status === 302 &&
        !blocked.screenshot &&
        blocked.screenshotError.includes('跳转被设置'),
    );
    const blockedRaw = JSON.parse(
      await invoke('read_http_text', {
        path: root + '/evidence/' + blocked.evidenceId,
      }),
    );
    check(
      'Failed browser capture retains HTTP provenance and its explicit coverage gap',
      blockedRaw.redirectResponses[0].status === 302 &&
        blockedRaw.snapshot.coverageGaps.some((gap) =>
          gap.includes('自动截图失败'),
        ),
    );
    await wait(
      () =>
        document
          .querySelector('.asset-screenshot-evidence')
          .textContent.includes('自动截图失败'),
      'visible browser error',
    );
    check('Browser failure is visible in the screenshot panel', true);
    await configure(false, false);
    asset = (await invoke('platform_state')).assets[0];
    check(
      'Both capture switches can be independently disabled',
      !asset.followRedirects && !asset.autoScreenshot,
    );
    const second = await inspect(4);
    check(
      'Disabled redirect remains 302 and screenshot stays absent',
      second.status === 302 && !second.screenshot && !second.screenshotError,
    );
    await invoke('record_ui_verification', {
      result: {
        passed,
        errors: [],
        phase: cfg.phase,
        publicWebsite: false,
        modelsCalled: false,
      },
    });
  } catch (error) {
    await invoke('record_ui_verification', {
      result: { passed, errors: [String(error), error.stack] },
    });
  }
})();
