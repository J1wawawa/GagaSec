// UI enters its own synthetic material; production never offers a sample button.
(async () => {
  const invoke = (name, args = {}) =>
      window.__TAURI_INTERNALS__.invoke(name, args),
    passed = [];
  const pause = (ms = 60) => new Promise((r) => setTimeout(r, ms));
  const wait = async (fn, label) => {
    const start = Date.now();
    while (Date.now() - start < 45000) {
      if (await fn()) return;
      await pause();
    }
    throw Error(
      'Flexible report timeout: ' + label + ' hidden=' + document.hidden,
    );
  };
  const check = (name, ok) => {
    if (!ok) throw Error(name);
    passed.push(name);
  };
  const button = (text, selector = 'button') =>
    [...document.querySelectorAll(selector)].find(
      (b) => b.textContent.trim() === text,
    );
  const enter = async (label, value) => {
    const el = document.querySelector(`[aria-label="${label}"]`);
    if (!el) throw Error('Missing input ' + label);
    Object.getOwnPropertyDescriptor(
      el instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement.prototype
        : HTMLInputElement.prototype,
      'value',
    ).set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    await pause();
  };
  const outline = async () => {
    document.querySelector('[aria-label="打开报告目录"]').click();
    await pause();
  };
  const center = async () => {
    const back = document.querySelector('[aria-label="返回报告中心"]');
    if (back) {
      back.click();
      await wait(
        () =>
          document.querySelector('.report-workspace')?.dataset.view === 'home',
        'report center',
      );
    }
  };
  const choose = async (id) => {
    await outline();
    document.querySelector(`[data-report-section="${id}"]`).click();
    await pause();
  };
  const save = async () => {
    button('保存', '.report-workspace > .page-head button').click();
    await wait(
      () =>
        document.querySelector('.report-save-status')?.dataset.state ===
        'saved',
      'save',
    );
  };
  const reports = async () => {
    await center();
    const id = (await invoke('get_workspace')).activeCase;
    document.querySelector('[data-group="reports"]').click();
    await wait(
      () =>
        document.querySelector('.report-workspace')?.dataset.caseId === id &&
        document.querySelector('.report-save-status')?.dataset.state ===
          'saved',
      'report ready',
    );
    document.querySelector('[data-action="open-report-editor"]')?.click();
    await pause();
  };
  const loadPreviewImages = async () => {
    await wait(
      () => document.querySelector('.report-paper'),
      'preview mounted',
    );
    for (const shot of document.querySelectorAll('.report-paper .shot')) {
      shot.scrollIntoView({ block: 'center' });
      await wait(() => {
        const image = shot.querySelector('img');
        return image?.complete && image.naturalWidth > 0;
      }, 'visible archived image');
    }
  };
  const switchCase = async (id) => {
    await center();
    const select = document.querySelector('[aria-label="当前事件"]');
    if (![...select.options].some((o) => o.value === id))
      select.add(new Option('isolated report case', id));
    select.value = id;
    select.dispatchEvent(new Event('change', { bubbles: true }));
    await wait(
      () =>
        document.querySelector('[aria-label="当前事件"]').value === id &&
        !document.querySelector('.report-save-status[data-state="loading"]'),
      'case switch',
    );
    await pause(150);
  };
  const add = async (title, parent = false) => {
    document
      .querySelector(
        parent
          ? '[aria-label="新增子章节"]'
          : '[data-action="add-report-section"]',
      )
      .click();
    await pause();
    await enter('章节标题', title);
    await outline();
    const id = document.querySelector(
      '.report-section-nav [aria-current="step"]',
    ).dataset.reportSection;
    document.querySelector('[aria-label="关闭报告目录"]').click();
    await pause();
    return id;
  };
  const exportFile = async (caseId, root, name, format) => {
    const job = await invoke('start_report_export', {
      caseId,
      path: root + '/' + name + '.' + format,
      format,
    });
    await wait(async () => {
      const j = (await invoke('get_report_exports')).find(
        (j) => j.id === job.id,
      );
      if (j?.state === 'failed') throw Error(j.error);
      return j?.state === 'completed';
    }, 'export ' + name);
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
    let w = await invoke('get_workspace');
    root = w.dataDir;
    const phase = (
      await invoke('read_http_text', { path: root + '/phase.txt' })
    ).trim();
    check(
      'Overview has no test/demo creation entry',
      ![...document.querySelectorAll('button')].some((b) =>
        /体验演示|打开演示/.test(b.textContent),
      ),
    );
    if (phase === 'reopen') {
      const a = w.cases.find((c) => c.title === '[合成报告验收] A'),
        b = w.cases.find((c) => c.title === '[合成报告验收] B');
      await switchCase(a.id);
      await reports();
      const d = await invoke('get_report_draft', { caseId: a.id });
      check(
        'Custom tree survives restart',
        d.structureVersion === 2 &&
          d.steps.length === 4 &&
          d.steps[1].parentId === d.steps[0].id &&
          d.steps[3].parentId === d.steps[2].id,
      );
      check(
        'Reused evidence links survive restart',
        d.steps[1].nodeIds.length === 1 &&
          d.steps[1].nodeIds[0] === d.steps[3].nodeIds[0],
      );
      button('报告预览', '.report-modebar button').click();
      await pause();
      await loadPreviewImages();
      check(
        'Reopened preview retains both sub-event images',
        document.querySelectorAll('.report-paper img[src^="data:"]').length ===
          2,
      );
      await switchCase(b.id);
      await reports();
      const db = await invoke('get_report_draft', { caseId: b.id });
      check(
        'Second incident preserves independent text-only layout',
        db.steps.length === 1 && db.steps[0].body.includes('无节点报告正文'),
      );
      await invoke('record_ui_verification', {
        result: { passed, errors: [], phase, realModelCalled: false },
      });
      return;
    }
    document.querySelector('[data-group="http"]').click();
    await pause();
    check(
      'HTTP page has no sample insertion controls',
      ![...document.querySelectorAll('button')].some((b) =>
        /填入测试报文|分析内置/.test(b.textContent),
      ),
    );
    await enter('HTTP 请求包', 'GET /health HTTP/1.1\nHost: example.test\n\n');
    await enter('HTTP 响应包', 'HTTP/1.1 200 OK\nContent-Length: 2\n\nok');
    document.querySelector('.http-composer form').requestSubmit();
    await wait(
      async () => (await invoke('get_workspace')).evidence.length === 1,
      'real HTTP input',
    );
    w = await invoke('get_workspace');
    const a = w.activeCase,
      e = w.evidence[0];
    await invoke('update_case', {
      id: a,
      title: '[合成报告验收] A',
      status: 'open',
    });
    w = await invoke('add_node', {
      title: '[合成] HTTP 访问原文',
      body: '仅验证举证复用，不代表入侵。',
      occurredAt: '2026-10-29T10:21:00+08:00',
      actor: 'J4team fixture',
      evidenceId: e.id,
      findingId: null,
    });
    const node = w.nodes[0];
    await invoke('paste_screenshot', {
      nodeId: node.id,
      dataUrl:
        'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
      caption: '合成举证图，不是现场截图',
    });
    await switchCase(a);
    await reports();
    check(
      'Editor owns the entire desktop workspace',
      getComputedStyle(document.querySelector('.desktop-commandbar'))
        .display === 'none' &&
        getComputedStyle(document.querySelector('.app-toolbar')).display ===
          'none' &&
        getComputedStyle(document.querySelector('.status-bar')).display ===
          'none',
    );
    check(
      'Outline is closed by default and正文 uses full width',
      !document.querySelector('.report-section-nav') &&
        document.querySelector('.report-writing').getBoundingClientRect()
          .width >=
          innerWidth - 8,
    );
    await outline();
    check(
      'Report outline opens as a keyboard accessible dialog',
      document
        .querySelector('[role="dialog"][aria-label="报告目录与章节"]')
        ?.contains(document.activeElement),
    );
    document.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }),
    );
    await pause();
    check(
      'Escape closes outline and returns focus to its button',
      !document.querySelector('.report-section-nav') &&
        document.activeElement?.getAttribute('aria-label') === '打开报告目录',
    );
    check(
      'New report starts with an empty editable structure',
      (await invoke('get_report_draft', { caseId: a })).steps.length === 0,
    );
    const phase1 = await add('阶段一：初始入侵');
    await enter('章节正文', '阶段一事实与缺口。');
    const event1 = await add('事件 1：Web 服务器', true);
    await enter('章节正文', 'Web 服务器核查与举证。');
    await enter(event1 + '-负责人', '张三');
    document
      .querySelector(`[aria-label="${event1}-关联节点-${node.id}"]`)
      .click();
    await pause();
    const phase2 = await add('阶段二：横向移动');
    await enter('章节正文', '阶段二覆盖与待核查事项。');
    const event2 = await add('事件 2：数据库', true);
    await enter('章节正文', '数据库关联调查，不推断已成功入侵。');
    await enter(event2 + '-负责人', '李四');
    document
      .querySelector(`[aria-label="${event2}-关联节点-${node.id}"]`)
      .click();
    await save();
    let d = await invoke('get_report_draft', { caseId: a });
    check(
      'Two phases and two sub-events have independent bodies/owners',
      d.steps.length === 4 &&
        d.steps[1].owner === '张三' &&
        d.steps[3].owner === '李四' &&
        d.steps[1].parentId === phase1 &&
        d.steps[3].parentId === phase2,
    );
    check(
      'Same node can be cited by multiple sections',
      d.steps[1].nodeIds[0] === node.id && d.steps[3].nodeIds[0] === node.id,
    );
    await choose(event2);
    let parent = document.querySelector('[aria-label="所属主章节"]');
    parent.value = phase1;
    parent.dispatchEvent(new Event('change', { bubbles: true }));
    await save();
    d = await invoke('get_report_draft', { caseId: a });
    check(
      'Sub-event can change phase without losing proof',
      d.steps.find((s) => s.id === event2).parentId === phase1 &&
        d.steps.find((s) => s.id === event2).nodeIds[0] === node.id,
    );
    parent = document.querySelector('[aria-label="所属主章节"]');
    parent.value = phase2;
    parent.dispatchEvent(new Event('change', { bubbles: true }));
    await save();

    await choose(phase2);
    document.querySelector('[aria-label="上移章节"]').click();
    await save();
    d = await invoke('get_report_draft', { caseId: a });
    check(
      'Moving a phase preserves its subtree and evidence',
      d.steps.map((s) => s.id).join(',') ===
        [phase2, event2, phase1, event1].join(',') &&
        d.steps[1].nodeIds[0] === node.id,
    );
    document.querySelector('[aria-label="下移章节"]').click();
    await save();
    const spare = await add('待删除章节');
    await add('待删除子章节', true);
    await choose(spare);
    document.querySelector('[aria-label="删除章节"]').click();
    await pause();
    check(
      'Deleting a phase asks for confirmation',
      !!document.querySelector('[data-action="confirm-delete-section"]'),
    );
    document.querySelector('[data-action="confirm-delete-section"]').click();
    await save();
    w = await invoke('get_workspace');
    d = await invoke('get_report_draft', { caseId: a });
    check(
      'Deleting subtree preserves original node and image',
      d.steps.length === 4 &&
        w.nodes.length === 1 &&
        w.nodes[0].screenshots.length === 1,
    );
    button('统计与时间胶囊', '.report-modebar button').click();
    await wait(
      () =>
        document.querySelector('.report-insights [data-metric="nodes"] strong')
          ?.textContent === '1',
      'shared insights',
    );
    check(
      'Reused evidence is counted once in native statistics',
      document.querySelector('[data-metric="evidence"] strong').textContent ===
        '1' &&
        document.querySelector('[data-metric="screenshots"] strong')
          .textContent === '1/1',
    );
    check(
      'One capsule retains two chapter links and original evidence action',
      document.querySelectorAll('.insight-capsule').length === 1 &&
        document.querySelectorAll('.insight-section-tags>span').length === 2 &&
        !!button('查看原证据', '.insight-actions button'),
    );
    for (const theme of ['light', 'dark']) {
      await center();
      const select = document.querySelector('[aria-label="主题模式"]');
      select.value = theme;
      select.dispatchEvent(new Event('change', { bubbles: true }));
      await reports();
      await invoke('resize_ui_verification', { width: 960, height: 660 });
      await pause();
      button('统计与时间胶囊', '.report-modebar button').click();
      await pause();
      check(
        'Statistics and capsules fit minimum ' + theme + ' native window',
        document.documentElement.scrollWidth <= innerWidth &&
          document.querySelector('.report-insights-panel').scrollWidth <=
            document.querySelector('.report-insights-panel').clientWidth,
      );
    }
    button('正文编辑', '.report-modebar button').click();
    await pause();
    button('导出报告', '.report-workspace > .page-head button').click();
    await pause();
    button('配置电子水印', '.report-delivery button').click();
    await pause();
    await enter('电子水印名称', '电子水印验收 · 甲');
    document.querySelector('[aria-label="关闭电子水印"]').click();
    await pause();
    document.querySelector('[aria-label="关闭报告导出"]').click();
    await save();
    check(
      'DIY watermark configuration saves to this incident',
      (await invoke('get_report_draft', { caseId: a })).watermark.name ===
        '电子水印验收 · 甲',
    );
    for (const theme of ['light', 'dark']) {
      await center();
      const select = document.querySelector('[aria-label="主题模式"]');
      select.value = theme;
      select.dispatchEvent(new Event('change', { bubbles: true }));
      await reports();
      await choose(event1);
      for (const [width, height] of [
        [960, 660],
        [1180, 760],
        [1320, 860],
      ]) {
        await invoke('resize_ui_verification', { width, height });
        await pause(180);
        check(
          'Full-page editor fits ' + theme + ' ' + width,
          document.documentElement.scrollWidth <= innerWidth &&
            document.querySelector('.report-writing').scrollWidth <=
              document.querySelector('.report-writing').clientWidth + 1 &&
            document.querySelector('.report-writing').getBoundingClientRect()
              .width >=
              innerWidth - 8,
        );
        if (width === 1320) {
          await invoke('ui_checkpoint', {
            label: 'SCREENSHOT report-full-page-' + theme,
          });
          await pause(1600);
        }
      }
    }
    button('报告预览', '.report-modebar button').click();
    await pause();
    await loadPreviewImages();
    check(
      'Preview uses hierarchical headings and real images',
      document
        .querySelector('.report-paper h3')
        ?.textContent.includes('1.1 事件 1') &&
        document.querySelectorAll('.report-paper img[src^="data:"]').length ===
          2,
    );
    await exportFile(a, root, 'flexible', 'html');
    await exportFile(a, root, 'flexible', 'docx');
    check('Custom report HTML/DOCX export completes', true);
    for (const format of ['html', 'docx']) {
      const mark = await invoke('inspect_report_watermark', {
        path: root + '/flexible.' + format,
      });
      check(
        'Encrypted ' + format + ' watermark is queryable through native IPC',
        mark.verification === 'verified_local' &&
          mark.watermark.name === '电子水印验收 · 甲' &&
          !!mark.watermark.createdAt,
      );
    }
    const b = (await invoke('create_case', { title: '[合成报告验收] B' }))
      .activeCase;
    await switchCase(b);
    await reports();
    await outline();
    const template = document.querySelector('[aria-label="插入报告模板"]');
    template.value = 'five';
    template.dispatchEvent(new Event('change', { bubbles: true }));
    await save();
    check(
      'Five-step layout is an optional insertable template',
      (await invoke('get_report_draft', { caseId: b })).steps.length === 5,
    );
    for (let i = 0; i < 5; i++) {
      await outline();
      const row = document.querySelector(
        '.report-section-nav [data-report-section]:not([data-report-section="basics"])',
      );
      row.click();
      await pause();
      document.querySelector('[aria-label="删除章节"]').click();
      await pause();
      document.querySelector('[data-action="confirm-delete-section"]').click();
      await pause();
    }
    await save();
    check(
      'Removing all template chapters stays empty',
      (await invoke('get_report_draft', { caseId: b })).steps.length === 0,
    );
    await add('独立补充说明');
    await enter('章节正文', '无节点报告正文，仅人工编写且未关联举证。');
    await save();
    await exportFile(b, root, 'text-only', 'html');
    await exportFile(b, root, 'text-only', 'docx');
    check(
      'Text-only authored report exports without forced evidence nodes',
      true,
    );
    check(
      'Incident B never changes incident A layout',
      (await invoke('get_report_draft', { caseId: a })).steps.length === 4,
    );
    await invoke('record_ui_verification', {
      result: { passed, errors: [], phase, realModelCalled: false },
    });
  } catch (error) {
    await invoke('record_ui_verification', {
      result: {
        passed,
        errors: [String(error), error.stack],
        realModelCalled: false,
      },
    });
  }
})();
