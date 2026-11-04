// Native acceptance only. Inputs are inert strings, never executed; no real AI.
(async () => {
  const invoke = (name, args = {}) =>
      window.__TAURI_INTERNALS__.invoke(name, args),
    passed = [];
  const pause = (ms = 80) => new Promise((r) => setTimeout(r, ms));
  const wait = async (fn, label) => {
    const start = Date.now();
    while (Date.now() - start < 90000) {
      const value = await fn();
      if (value) return value;
      await pause();
    }
    throw Error('WebShell UI timeout: ' + label);
  };
  const check = (label, ok) => {
    if (!ok) throw Error(label);
    passed.push(label);
  };
  const button = (text, selector = 'button') =>
    [...document.querySelectorAll(selector)].find(
      (b) => b.textContent.trim() === text,
    );
  const save = async () => {
    button('保存', '.report-workspace > .page-head button').click();
    await wait(
      () =>
        document.querySelector('.report-save-status')?.dataset.state ===
        'saved',
      'report save',
    );
  };
  const reports = async () => {
    document.querySelector('[data-group="reports"]').click();
    await wait(
      () =>
        document.querySelector('.report-save-status')?.dataset.state ===
        'saved',
      'report ready',
    );
    document.querySelector('[data-action="open-report-editor"]')?.click();
    await pause();
  };
  const job = async (root, name) => {
    const w = await invoke('get_workspace');
    const j = await invoke('start_local_analysis', {
      caseId: w.activeCase,
      path: root + '/' + name,
      kind: 'webshell',
    });
    return wait(async () => {
      const rows = await invoke('get_local_analysis_jobs', { caseId: null });
      const task = rows.find((row) => row.id === j.id);
      if (task?.state === 'failed') throw Error(task.error);
      return task?.state === 'completed' ? task : null;
    }, 'scan ' + name);
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
    const phase = (
      await invoke('read_http_text', { path: root + '/phase.txt' })
    ).trim();
    if (phase === 'reopen') {
      const w = await invoke('get_workspace'),
        e = w.evidence.find((e) => e.name === 'nested.php');
      check(
        'Layer graph and derived SHA-256 survive application restart',
        e.report.webshell.layers.some(
          (l) => l.operation === 'gzinflate' && l.sha256.length === 64,
        ),
      );
      check(
        'Derived finding keeps its independent event node after restart',
        w.nodes.length === 1 &&
          w.nodes[0].evidenceId === e.id &&
          w.nodes[0].findingId,
      );
      const d = await invoke('get_report_draft', { caseId });
      check(
        'All three templates and original node links persist',
        d.steps.some(
          (s) => s.title === 'WebShell 与内存马分析' && s.nodeIds.length === 1,
        ) &&
          d.steps.some((s) => s.title === '样本与加密行为分析') &&
          d.steps.some((s) => s.title === '容器基线与进入路径'),
      );
      await invoke('record_ui_verification', {
        result: {
          phase,
          passed,
          errors: [],
          synthetic: true,
          externalModelCalled: false,
        },
      });
      return;
    }
    await invoke('update_case', {
      id: caseId,
      title: '[合成演练] 多层 WebShell 静态分析',
      status: 'open',
    });
    const first = await job(root, 'nested.php');
    const w = await invoke('get_workspace'),
      e = w.evidence.find((e) => e.id === first.evidenceId),
      a = e.report.webshell;
    check(
      'Real Docker returns versioned multilevel WebShell analysis',
      a.version === 'gaga-webshell/1' && a.layers.length >= 3,
    );
    const inner = a.layers.find((l) => l.operation === 'gzinflate');
    check(
      'Nested compression links to its decoded parent and expression source',
      inner.parentId !== inner.sourceLayerId &&
        inner.sourceLayerId === 'L000' &&
        inner.preview.includes('system'),
    );
    check(
      'Every derived layer has input/output hashes and exact expression bounds',
      a.layers
        .slice(1)
        .every(
          (l) =>
            l.sha256.length === 64 &&
            l.inputSha256.length === 64 &&
            l.sourceEnd > l.sourceStart &&
            !!l.sourceExcerpt,
        ),
    );
    const target = e.report.findings.find(
      (f) => f.title === '系统命令调用' && f.location.startsWith(inner.id),
    );
    check(
      'Hidden sink and source are recovered as unverified lexical clues',
      !!target &&
        a.traces.some(
          (t) =>
            t.layerId === inner.id &&
            t.sources.includes('$_POST') &&
            t.sinks.includes('system'),
        ),
    );
    const material = await invoke('preview_ai_material', { evidenceId: e.id });
    check(
      'AI preview carries derived digests, source ranges and execution gaps',
      material.includes(inner.sha256) &&
        material.includes('字节 [') &&
        material.includes('没有执行样本'),
    );
    check(
      'Coverage explicitly keeps dynamic execution and residency untested',
      a.checks.some(
        (c) => c.status === 'not_checked' && c.title.includes('动态'),
      ),
    );
    document.querySelector('[data-action="show-local-analysis"]').click();
    await wait(
      () => document.querySelector('[data-action="open-local-result"]'),
      'result shortcut',
    );
    document.querySelector('[data-action="open-local-result"]').click();
    await wait(
      () => document.querySelector('.webshell-workbench'),
      'layer workspace',
    );
    document.querySelector('[aria-label="收起分析任务"]')?.click();
    check(
      'WebShell opens a dedicated layer workspace',
      document
        .querySelector('.webshell-layers')
        .textContent.includes('gzinflate'),
    );
    [...document.querySelectorAll('.webshell-layers button')]
      .find((b) => b.textContent.includes(inner.id))
      .click();
    await pause();
    document.querySelector('.webshell-layer-metadata').open = true;
    check(
      'Selecting a layer shows decoded code and its SHA-256',
      document.querySelector('.webshell-code').textContent.includes('system') &&
        document
          .querySelector('.webshell-layer')
          .textContent.includes(inner.sha256),
    );
    check(
      'Layer source expression is available without claiming one-to-one output offsets',
      document
        .querySelector('.webshell-expression pre')
        .textContent.includes('gzinflate') &&
        document
          .querySelector('.webshell-layer dl')
          .textContent.includes('L000'),
    );
    document.querySelector('.webshell-layer-metadata').open = false;
    for (const theme of ['light', 'dark']) {
      const select = document.querySelector('[aria-label="主题模式"]');
      select.value = theme;
      select.dispatchEvent(new Event('change', { bubbles: true }));
      await invoke('resize_ui_verification', { width: 960, height: 660 });
      await pause();
      check(
        'Layer workspace fits minimum ' + theme + ' native window',
        document.documentElement.scrollWidth <= innerWidth &&
          document.querySelector('.webshell-workbench').scrollWidth <=
            document.querySelector('.webshell-workbench').clientWidth + 1,
      );
    }
    check(
      'Code is visible inside a pane with independent scrolling',
      document.querySelector('.webshell-code').getBoundingClientRect().top <
        document.querySelector('.webshell-layer').getBoundingClientRect()
          .bottom -
          10 &&
        getComputedStyle(document.querySelector('.webshell-layer'))
          .overflowY === 'auto',
    );
    document.querySelector('.webshell-clues .button').click();
    await wait(
      () => document.querySelector('.capture-modal'),
      'capture dialog',
    );
    check(
      'Derived finding opens normal evidence and screenshot capture',
      !!document.querySelector('.capture-modal') &&
        document.querySelector('.capture-modal').textContent.includes('截图'),
    );
    await wait(
      () => button('保存并打开报告') && !button('保存并打开报告').disabled,
      'capture options',
    );
    button('保存并打开报告').click();
    await wait(
      () =>
        document.querySelector('.report-save-status')?.dataset.state ===
        'saved',
      'open report',
    );
    const node = (await invoke('get_workspace')).nodes[0];
    check(
      'UI records original evidence, derived finding and layer digest',
      node.evidenceId === e.id &&
        node.findingId === target.id &&
        node.body.includes(inner.sha256),
    );
    const before = await invoke('get_report_draft', { caseId });
    let count = before.steps.length;
    for (const [kind, title] of [
      ['web', 'WebShell 与内存马分析'],
      ['ransomware', '样本与加密行为分析'],
      ['container', '容器基线与进入路径'],
    ]) {
      const select = document.querySelector('[aria-label="插入报告模板"]');
      select.value = kind;
      select.dispatchEvent(new Event('change', { bubbles: true }));
      await pause();
      await save();
      const d = await invoke('get_report_draft', { caseId });
      check(
        'Editable ' +
          kind +
          ' template appends without replacing original sections',
        d.steps.length === count + 6 &&
          d.steps.some((s) => s.title === title) &&
          before.steps.every((old) => d.steps.some((s) => s.id === old.id)),
      );
      count = d.steps.length;
    }
    let d = await invoke('get_report_draft', { caseId });
    const section = d.steps.find((s) => s.title === 'WebShell 与内存马分析');
    document.querySelector(`[data-report-section="${section.id}"]`).click();
    await pause();
    document
      .querySelector(`[aria-label="${section.id}-关联节点-${node.id}"]`)
      .click();
    await save();
    check(
      'Template chapter can cite a derived finding node',
      (await invoke('get_report_draft', { caseId })).steps
        .find((s) => s.id === section.id)
        .nodeIds.includes(node.id),
    );
    for (const format of ['html', 'docx']) {
      const j = await invoke('start_report_export', {
        caseId,
        path: root + '/webshell-case.' + format,
        format,
      });
      await wait(async () => {
        const task = (await invoke('get_report_exports')).find(
          (row) => row.id === j.id,
        );
        if (task?.state === 'failed') throw Error(task.error);
        return task?.state === 'completed';
      }, 'export ' + format);
      check('Derived-evidence ' + format + ' report actually completes', true);
    }
    const control = await job(root, 'benign.php');
    const controlE = (await invoke('get_workspace')).evidence.find(
      (e) => e.id === control.evidenceId,
    );
    check(
      'Normal comment and string controls do not become executable-call findings',
      controlE.report.findings.length === 0 &&
        controlE.report.webshell.layers.length === 1,
    );
    const java = await job(root, 'class.php');
    const javaE = (await invoke('get_workspace')).evidence.find(
      (e) => e.id === java.evidenceId,
    );
    check(
      'Java class constants recovered inside Docker without loading a class',
      javaE.report.findings.some(
        (f) =>
          f.title === 'Java 类常量池线索' &&
          f.description.includes(
            javaE.report.webshell.layers.find((l) =>
              l.format.startsWith('Java class'),
            ).sha256,
          ),
      ) &&
        javaE.report.webshell.layers.some((l) =>
          l.format.startsWith('Java class'),
        ),
    );
    const broken = await job(root, 'broken.php');
    const brokenE = (await invoke('get_workspace')).evidence.find(
      (e) => e.id === broken.evidenceId,
    );
    check(
      'Damaged compressed input remains partial with a clear explanation',
      brokenE.report.webshell.limits.some((s) => s.includes('压缩数据')) &&
        brokenE.report.webshell.checks.some((c) => c.status === 'partial'),
    );
    // Leave the verified decoded layer visible for the driver's own-window screenshot.
    document.querySelector('[data-action="show-local-analysis"]').click();
    await pause();
    const tasks = document.querySelector('.local-analysis-panel select');
    tasks.value = first.id;
    tasks.dispatchEvent(new Event('change', { bubbles: true }));
    await pause();
    document.querySelector('[data-action="open-local-result"]').click();
    await wait(
      () => document.querySelector('.webshell-workbench'),
      'return layer view',
    );
    document.querySelector('[aria-label="收起分析任务"]')?.click();
    [...document.querySelectorAll('.webshell-layers button')]
      .find((b) => b.textContent.includes(inner.id))
      .click();
    await invoke('resize_ui_verification', { width: 1320, height: 860 });
    await invoke('record_ui_verification', {
      result: {
        phase,
        passed,
        errors: [],
        synthetic: true,
        externalModelCalled: false,
        samplesExecuted: false,
        realDockerStaticAnalysis: true,
      },
    });
  } catch (error) {
    await invoke('record_ui_verification', {
      result: {
        passed,
        errors: [String(error), error.stack],
        synthetic: true,
        externalModelCalled: false,
      },
    });
  }
})();
