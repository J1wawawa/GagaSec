(async () => {
  const passed = [];
  const invoke = (command, args = {}) =>
    window.__TAURI_INTERNALS__.invoke(command, args);
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const wait = async (predicate, label) => {
    for (let i = 0; i < 150; i++) {
      if (predicate()) return;
      await pause(80);
    }
    throw Error('Timeout: ' + label);
  };
  const check = (name, condition) => {
    if (!condition) throw Error(name);
    passed.push(name);
  };
  const button = (selector, name) =>
    [...document.querySelectorAll(selector)].find(
      (b) => b.textContent.trim() === name,
    );
  const navigate = async (name) => {
    button('.nav-item', name).click();
    await pause(80);
  };
  const enter = async (selector, value) => {
    const el = document.querySelector(selector);
    el.focus();
    const proto =
      el instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement.prototype
        : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    await pause(60);
  };
  const requestSelector = '[aria-label="HTTP 请求包"]';
  const responseSelector = '[aria-label="HTTP 响应包"]';
  const submit = () =>
    document.querySelector('.http-composer form').requestSubmit();
  try {
    await wait(() => document.querySelector('.nav-item'), 'React ready');
    document.querySelector('.splash-skip')?.click();
    await wait(() => !document.querySelector('.splash'), 'splash dismissed');
    await navigate('HTTP 报文分析');
    check(
      'Actual native desktop has an empty editable paired HTTP form',
      !!document.querySelector(requestSelector),
    );
    check('Production HTTP form has no example insertion control', ![...document.querySelectorAll('button')].some(b => /填入测试报文|分析内置/.test(b.textContent)));
    // Deliberately omit the final blank line to exercise copied header-only input.
    const request = 'GET /.env HTTP/1.1\nHost: example.test\nX-Gaga-Sample: synthetic';
    const response = 'HTTP/1.1 200 OK\nContent-Type: text/plain\n\nDB_PASSWORD=gaga-synthetic-example';
    await enter(requestSelector, request);
    await enter(responseSelector, response);
    await enter(responseSelector, 'this is not an HTTP response');
    submit();
    await wait(
      () => document.querySelector('.http-input-error'),
      'actionable response failure',
    );
    check(
      'Invalid response error identifies the correct side inside the editor',
      document
        .querySelector('.http-input-error')
        .textContent.includes('响应包') &&
        document
          .querySelector('.http-input-error')
          .textContent.includes('HTTP/1.1 200 OK'),
    );
    check(
      'Failure preserves both submitted inputs',
      document.querySelector(requestSelector).value === request &&
        document.querySelector(responseSelector).value ===
          'this is not an HTTP response',
    );
    check(
      'Failure creates no evidence or successful process record',
      (await invoke('get_workspace')).evidence.length === 0 &&
        (await invoke('get_workspace')).analysisRuns.length === 0,
    );
    const bounds = document
      .querySelector('.http-input-error')
      .getBoundingClientRect();
    const hit = document.elementFromPoint(
      bounds.x + bounds.width / 2,
      bounds.y + bounds.height / 2,
    );
    check(
      'Error is visible and unobscured in the native view',
      bounds.height > 0 &&
        bounds.bottom < innerHeight &&
        !!hit?.closest('.http-input-error'),
    );
    await enter(responseSelector, response);
    submit();
    await wait(
      () =>
        document.querySelector('.http-reader') &&
        !document.querySelector('.http-input-error'),
      'retry completes',
    );
    let w = await invoke('get_workspace');
    const first = w.evidence.find((e) => e.kind === 'http');
    check(
      'Retry analyzes a header-only request without requiring a final empty line',
      !!first && first.report.httpExchanges[0].request.raw === request,
    );
    check(
      'Real paired result retains response and related findings',
      first.report.httpExchanges[0].response.raw === response &&
        first.report.findings.some((f) => f.title === '响应含敏感配置字段'),
    );
    check(
      'Missing header/body boundary is explicitly reported',
      first.report.warnings.some((s) => s.includes('空行')),
    );
    check(
      'Real completed process is visible and persisted',
      document
        .querySelector('.analysis-process')
        .textContent.includes('已完成') &&
        w.analysisRuns.some(
          (r) => r.evidenceId === first.id && r.state === 'completed',
        ),
    );

    document.querySelector('[data-action="toggle-input"]').click();
    await pause(60);
    await enter(responseSelector, 'bad response after an existing result');
    submit();
    await wait(
      () => document.querySelector('.http-input-error'),
      'failure after existing evidence',
    );
    const retryBounds = document
      .querySelector('.http-input-error')
      .getBoundingClientRect();
    const retryHit = document.elementFromPoint(
      retryBounds.x + retryBounds.width / 2,
      retryBounds.y + retryBounds.height / 2,
    );
    check(
      'Failure is visible above the scrollable editor even with prior analysis results',
      retryBounds.height > 0 &&
        retryBounds.bottom < innerHeight &&
        !!retryHit?.closest('.http-input-error'),
    );
    check(
      'Failed retry leaves the previous evidence intact and creates no duplicate',
      (await invoke('get_workspace')).evidence.length === 1 &&
        (await invoke('get_workspace')).evidence[0].id === first.id,
    );
    await enter(responseSelector, response);

    const a = w.activeCase;
    await navigate('告警研判');
    await enter(
      '[aria-label="告警原文"]',
      'HTTP regression fixture, case A only',
    );
    document.querySelector('[aria-label="新建事件"]').click();
    await pause(80);
    await enter('form.modal input', 'HTTP regression B');
    document.querySelector('form.modal').requestSubmit();
    await wait(() => !document.querySelector('form.modal'), 'new case B');
    const b = (await invoke('get_workspace')).activeCase;
    check(
      'New case has independent alert input',
      b !== a && document.querySelector('[aria-label="告警原文"]').value === '',
    );
    await navigate('HTTP 报文分析');
    check(
      'New case has independent request and response drafts',
      document.querySelector(requestSelector).value === '' &&
        document.querySelector(responseSelector).value === '',
    );
    const switchTo = async (id) => {
      const el = document.querySelector('[aria-label="当前事件"]');
      el.value = id;
      el.dispatchEvent(new Event('change', { bubbles: true }));
      await pause(40);
      await wait(
        () =>
          document.querySelector('[aria-label="当前事件"]').value === id &&
          !document.querySelector('[aria-label="当前事件"]').disabled,
        'case switch',
      );
    };
    await switchTo(a);
    check(
      'Returning to case A restores its own paired draft',
      document.querySelector(requestSelector).value === request &&
        document.querySelector(responseSelector).value === response,
    );
    await navigate('告警研判');
    check(
      'Returning to case A restores its own alert draft',
      document.querySelector('[aria-label="告警原文"]').value ===
        'HTTP regression fixture, case A only',
    );
    await switchTo(b);
    await navigate('HTTP 报文分析');
    await enter(requestSelector, 'GET /.env HTTP/1.1\nHost: example.test');
    submit();
    await wait(
      () => document.querySelector('.http-reader'),
      'request only analysis',
    );
    w = await invoke('get_workspace');
    check(
      'Request-only analysis succeeds in B and keeps impact unknown',
      w.evidence.length === 1 &&
        w.evidence[0].caseId === b &&
        w.evidence[0].report.httpExchanges[0].response === null &&
        w.evidence[0].report.httpExchanges[0].assessment.includes('缺少响应'),
    );
    check(
      'No successful A evidence is transferred into B',
      w.evidence.every((e) => e.caseId === b) &&
        w.evidence.every((e) => e.id !== first.id),
    );
    const material = await invoke('preview_ai_material', {
      evidenceId: w.evidence[0].id,
    });
    check(
      'AI material can be prepared from actual analyzed evidence without cloud calls',
      material.includes('请求') && material.includes('响应'),
    );
    const malformedBefore = w.evidence.length;
    let rejected = false;
    try {
      await invoke('analyze_http_pair', { request: 'broken', response: '' });
    } catch (e) {
      rejected = String(e).includes('请求包');
    }
    check(
      'Malformed input is rejected with request-side detail and no new evidence',
      rejected &&
        (await invoke('get_workspace')).evidence.length === malformedBefore,
    );
    await invoke('record_ui_verification', {
      result: {
        passed,
        native: true,
        externalModelTested: false,
        errors: [],
        evidenceCount: (await invoke('get_workspace')).evidence.length,
      },
    });
  } catch (error) {
    await invoke('record_ui_verification', {
      result: {
        passed,
        native: true,
        externalModelTested: false,
        errors: [String(error), error.stack],
      },
    });
  }
})();
