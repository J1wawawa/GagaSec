(async () => {
  const passed = [];
  const invoke = (name, args = {}) => window.__TAURI_INTERNALS__.invoke(name, args);
  const pause = (ms = 90) => new Promise((resolve) => setTimeout(resolve, ms));
  const wait = async (predicate, label) => {
    for (let i = 0; i < 150; i++) {
      if (await predicate()) return;
      await pause();
    }
    throw Error('Navigation timeout: ' + label);
  };
  const check = (name, value) => {
    if (!value) throw Error(name);
    passed.push(name);
  };
  const top = (label) => [...document.querySelectorAll('.primary-navigation button')]
    .find((button) => button.textContent.trim() === label);
  const chooseTop = async (label) => { top(label).click(); await pause(); };
  const key = (name, extra = {}) => document.activeElement.dispatchEvent(
    new KeyboardEvent('keydown', {key: name, bubbles: true, cancelable: true, ...extra}),
  );
  const enter = async (value) => {
    const input = document.querySelector('[aria-label="搜索工具"]');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
    input.dispatchEvent(new Event('input', {bubbles: true}));
    await pause();
  };
  const visible = (element) => {
    if (!element) return false;
    const r = element.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && r.left >= 0 && r.right <= innerWidth + 1;
  };
  const routes = [
    ['事件调查', ['cases', 'evidence', 'timeline']],
    ['报告', ['reports']],
    ['日志分析', ['logs']],
    ['HTTP', ['http']],
    ['告警研判', ['triage']],
    ['采集排查', ['agents', 'containers']],
    ['样本分析', ['webshell', 'binary', 'sandbox', 'samples']],
    ['持续监控', ['assets', 'flows']],
    ['威胁情报', ['knowledge', 'lists', 'intel']],
  ];
  try {
    await wait(() => document.querySelector('.tool-launcher-button'), 'React ready');
    document.querySelector('.splash-skip')?.click();
    await wait(() => document.querySelector('.dashboard-footer')?.textContent.includes('更新于'), 'SQLite dashboard');
    const initial = await invoke('get_workspace');
    check('Native starts on overview with nine explicit task entries',
      [...document.querySelectorAll('.primary-navigation button')].map((b) => b.textContent.trim()).join('|') ===
      ['总览', ...routes.map(([label]) => label)].join('|'));
    for (const theme of ['light', 'dark']) {
      const select = document.querySelector('[aria-label="主题模式"]');
      select.value = theme; select.dispatchEvent(new Event('change', {bubbles: true}));
      await invoke('resize_ui_verification', {width: 960, height: 660});
      await pause(180);
      check('Every top entry remains visible without overflow at minimum size: ' + theme,
        [...document.querySelectorAll('.primary-navigation button,.commandbar-actions button')].every(visible) &&
        document.querySelector('.desktop-commandbar').scrollWidth <= innerWidth);
      for (const [label, modules] of routes) {
        await chooseTop(label);
        check('Only related tools are exposed: ' + label + ' ' + theme,
          [...document.querySelectorAll('.module-navigation .nav-item')].filter((b) => b.offsetHeight)
            .map((b) => b.dataset.module).join('|') === (modules.length > 1 ? modules.join('|') : ''));
        for (const module of modules) {
          const button = document.querySelector(`.module-navigation [data-module="${module}"]`);
          check('Tool has a visible direct entry: ' + module + ' ' + theme, modules.length === 1 ? visible(top(label)) && document.querySelector('.module-navigation').hidden : visible(button));
          if (modules.length > 1) button.click(); else top(label).click(); await pause();
          check('Native content and active navigation agree: ' + module + ' ' + theme,
            !!document.querySelector('.content-scroll.module-' + module) &&
            button.getAttribute('aria-current') === 'page' && top(label).getAttribute('aria-current') === 'page');
        }
      }
      for (const module of ['environment', 'settings']) {
        document.querySelector(`.commandbar-actions [data-module="${module}"]`).click(); await pause();
        check('Client preference has a direct accessible entry: ' + module + ' ' + theme,
          !!document.querySelector('.content-scroll.module-' + module) &&
          !document.querySelector('.primary-navigation [aria-current="page"]'));
      }
    }
    await chooseTop('样本分析');
    document.querySelector('.module-navigation [data-module="sandbox"]').click(); await pause();
    await chooseTop('日志分析'); await chooseTop('样本分析');
    check('Returning to a task group restores its last tool', !!document.querySelector('.module-sandbox'));
    await chooseTop('HTTP');
    const req = document.querySelector('[aria-label="HTTP 请求包"]');
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(req, 'GET /navigation-test HTTP/1.1\nHost: example.test\n\n');
    req.dispatchEvent(new Event('input', {bubbles: true})); await pause();
    await chooseTop('日志分析'); await chooseTop('HTTP');
    check('Switching the new top-level tools preserves HTTP draft', document.querySelector('[aria-label="HTTP 请求包"]').value.includes('/navigation-test'));
    check('Single-purpose workspace removes duplicate secondary navigation', document.querySelector('.module-navigation').hidden);
    check('HTTP has one compact title row and a large input pane at minimum size', document.querySelector('.analysis-head').getBoundingClientRect().height <= 42 && document.querySelector('[aria-label="HTTP 请求包"]').getBoundingClientRect().height >= 220);
    const help = document.querySelector('.analysis-help summary');help.focus();help.click();await pause();
    check('Analysis limits remain available on demand',document.querySelector('.analysis-help').open && document.querySelector('.analysis-help').textContent.includes('SHA-256'));
    key('Escape');await pause();check('Escape closes inline analysis help',!document.querySelector('.analysis-help').open);
    const trigger = document.querySelector('[aria-label="全部工具"]'); trigger.focus(); trigger.click(); await pause();
    check('Tool search opens above inert background with focused input',
      document.getElementById('root').inert && document.activeElement.getAttribute('aria-label') === '搜索工具');
    check('All twenty-two tool routes including LAN are discoverable without duplication',
      document.querySelectorAll('.tool-results [data-tool]').length === 22 &&
      new Set([...document.querySelectorAll('[data-tool]')].map((b) => b.dataset.tool)).size === 22 &&
      !!document.querySelector('[data-tool="lan"]'));
    check('Tool dialog stays inside minimum native frame',
      visible(document.querySelector('.tool-palette')) &&
      document.querySelector('.tool-palette').getBoundingClientRect().bottom <= innerHeight);
    await enter('DOCKER');
    check('English aliases search across collection and sample tasks',
      ['containers', 'sandbox'].every((module) => document.querySelector(`[data-tool="${module}"]`)));
    await enter('截图');
    check('Evidence workflow is discoverable by screenshot keyword', !!document.querySelector('[data-tool="timeline"]'));
    await enter('definitely-no-such-tool');
    check('Unknown tool query has a clear empty state', !!document.querySelector('.tools-empty') && !document.querySelector('[data-tool]'));
    await enter('eBPF'); key('Enter'); await pause();
    check('Enter opens exact search result and closes the tool dialog', !!document.querySelector('.module-flows') && !document.querySelector('.tool-palette'));
    key('k', {ctrlKey: true}); await pause();
    check('Ctrl K reopens clean search with all routes', document.querySelector('[aria-label="搜索工具"]').value === '' && document.querySelectorAll('[data-tool]').length === 22);
    await enter('样本');
    const oldActive = document.querySelector('[aria-label="搜索工具"]').getAttribute('aria-activedescendant');
    key('ArrowDown'); await pause();
    check('Keyboard navigation changes highlighted search result', document.querySelector('[aria-label="搜索工具"]').getAttribute('aria-activedescendant') !== oldActive);
    key('Escape'); await pause();
    check('Escape restores tool trigger focus and interactive background', !document.querySelector('.tool-palette') && !document.getElementById('root').inert && document.activeElement === trigger);
    document.querySelector('[aria-label="新建事件"]').click(); await pause(); key('k', {metaKey: true}); await pause();
    check('Tool shortcut does not interrupt an existing modal', document.querySelectorAll('[role="dialog"]').length === 1 && !document.querySelector('.tool-palette'));
    key('Escape'); await pause();
    const select = document.querySelector('[aria-label="主题模式"]');select.value = 'system';select.dispatchEvent(new Event('change', {bubbles: true}));
    await invoke('resize_ui_verification', {width: 1320, height: 860});
    const workspace = await invoke('get_workspace');
    check('Navigation test writes no evidence, timeline nodes or AI calls', workspace.evidence.length === initial.evidence.length && workspace.nodes.length === initial.nodes.length && workspace.aiReviews.length === initial.aiReviews.length);
    await invoke('record_ui_verification', {result: {native: true, version: '0.6.5', passed, errors: [], externalModelCalled: false}});
  } catch (error) {
    await invoke('record_ui_verification', {result: {native: true, version: '0.6.5', passed, errors: [String(error), error.stack]}});
  }
})();
