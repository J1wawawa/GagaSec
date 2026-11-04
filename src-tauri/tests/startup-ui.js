// Explicit --startup-ui, synthetic workspaces only. Never opens real credentials.
(async () => {
  const invoke = (name, args = {}) => window.__TAURI_INTERNALS__.invoke(name, args);
  const passed = [], viewportChecks = [], pause = (ms = 65) => new Promise(r => setTimeout(r, ms));
  const wait = async (fn, label) => { const start = Date.now(); while (Date.now() - start < 30000) { if (await fn()) return; await pause(); } throw Error('Startup UI timeout: ' + label); };
  const check = (name, ok) => { if (!ok) throw Error(name); passed.push(name); };
  const button = (text, selector = 'button') => [...document.querySelectorAll(selector)].find(b => b.textContent.trim() === text);
  let phase;
  window.addEventListener('error', event => { void invoke('startup_audit', { result: { phase, complete: true, passed, errors: ['Window error: ' + event.message, event.error?.stack], synthetic: true } }); });
  window.addEventListener('unhandledrejection', event => { void invoke('startup_audit', { result: { phase, complete: true, passed, errors: ['Unhandled rejection: ' + String(event.reason)], synthetic: true } }); });
  try {
    phase = (await invoke('startup_audit', { result: null })).phase;
    await wait(() => document.querySelector('.startup-screen'), 'startup screen');
    if (phase === 'corrupt') {
      await wait(() => document.querySelector('.startup-screen[data-state="failed"]'), 'failed database');
      const state = await invoke('get_startup_state');
      check('Database failure remains visible at its actual stage', state.state === 'failed' && state.steps.some(s => s.id === 'database' && s.state === 'failed') && !!document.querySelector('.startup-error'));
      check('Failed initialization never mounts an empty replacement workspace', !document.querySelector('.desktop-app'));
      document.querySelector('.splash-skip').click(); await pause();
      check('Reducing motion cannot bypass a failed database', !!document.querySelector('.startup-error') && !document.querySelector('.desktop-app'));
      let rejected = false; try { await invoke('get_workspace'); } catch (error) { rejected = String(error).includes('STARTUP-PENDING'); }
      check('Store-dependent IPC rejects before initialization completes', rejected);
    } else {
      await wait(async () => (await invoke('get_startup_state')).steps.some(s => s.id === 'database' && s.state === 'running'), 'real blocked database');
      check('Window and status remain responsive while SQLite is locked', !document.querySelector('.desktop-app') && !!document.querySelector('.startup-screen'));
      document.querySelector('.splash-skip').click(); await pause();
      check('Skipping visual motion does not bypass actual loading', !document.querySelector('.desktop-app') && document.querySelector('.startup-screen').dataset.motion === 'reduced');
      await invoke('startup_audit', { result: { phase, complete: false, checkpoint: 'release-sqlite-lock', passed, errors: [] } });
      await wait(() => document.querySelector('.dashboard-footer')?.textContent.includes('更新于'), 'workspace after lock release');
      await invoke('startup_audit', { result: { phase, complete: false, checkpoint: 'dashboard-mounted', passed, errors: [] } });
      await wait(() => !document.querySelector('.startup-screen'), 'ready screen closes');
      const state = await invoke('get_startup_state');
      check('Backend ready follows all four successful initialization stages', state.state === 'ready' && state.steps.length === 4 && state.steps.every(s => s.state === 'completed'));
      if (phase === 'hidden') {
        check('A genuinely hidden window finishes UI startup without animation frames', document.visibilityState === 'hidden' && !document.querySelector('.desktop-app').inert && !document.querySelector('.startup-screen'));
        await invoke('startup_audit', { result: { phase, complete: true, passed, errors: [], synthetic: true, externalModelCalled: false } }); return;
      }
      document.querySelector('[data-module="settings"]').click(); await pause(); button('外观体验', '.settings-navigation button').click(); await pause();
      await invoke('startup_audit', { result: { phase, complete: false, checkpoint: 'appearance-opened', passed, errors: [] } });
      const theme = async value => { const select = document.querySelector('[aria-label="主题模式"]'); select.value = value; select.dispatchEvent(new Event('change', { bubbles: true })); await pause(); };
      for (const mode of ['light', 'dark']) {
        await theme(mode);
        for (const [width, height] of [[960, 660], [1100, 720], [1320, 860], [1600, 1000]]) {
          await invoke('resize_ui_verification', { width, height }); await pause(100);
          button('重播启动动画').click(); await pause(90);
          const screen = document.querySelector('.startup-screen'), consoleBox = screen.querySelector('.startup-console').getBoundingClientRect();
          check(`Startup fits ${mode} ${width}x${height}`, screen.scrollWidth <= screen.clientWidth && screen.scrollHeight <= screen.clientHeight && consoleBox.right <= innerWidth && consoleBox.bottom <= innerHeight);
          check(`Replay shows actual completed stages ${mode} ${width}`, screen.querySelectorAll('li[data-state="completed"]').length === 6 && screen.textContent.includes('本次启动记录'));
          viewportChecks.push({theme:mode,requested:{width,height},actual:{width:innerWidth,height:innerHeight}});
          screen.querySelector('.splash-skip').click(); await pause();
        }
      }
      check('Replaying animation never reruns database initialization', JSON.stringify((await invoke('get_startup_state')).steps) === JSON.stringify(state.steps));
      // Leave a real native replay for the runner to capture; no fake progress.
      await theme('dark'); await invoke('resize_ui_verification', { width: 1320, height: 860 }); await pause(100);
      button('重播启动动画').click(); await pause(100);
    }
    await invoke('startup_audit', { result: { phase, complete: true, passed, viewportChecks, errors: [], synthetic: true, externalModelCalled: false } });
  } catch (error) {
    await invoke('startup_audit', { result: { phase, complete: true, passed, errors: [String(error), error.stack], uiError: document.querySelector('.startup-error')?.textContent, synthetic: true, externalModelCalled: false } });
  }
})();
