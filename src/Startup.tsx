import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { invoke, isTauri } from './bridge';
import {
  AlertCircle,
  Check,
  Copy,
  LoaderCircle,
  ShieldCheck,
} from 'lucide-react';
import type { Workspace, AiConfig, AiConnectionTest } from './types';
import release from './release-manifest.json';
import './startup.css';

type Step = {
  id: string;
  title: string;
  detail: string;
  state: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  elapsedMs: number;
};
export type StartupSnapshot = {
  state: 'running' | 'ready' | 'failed';
  steps: Step[];
  error: string | null;
  elapsedMs: number;
};
type InitialData = {
  workspace: Workspace;
  config: AiConfig;
  profiles: AiConfig[];
  connectionTests: AiConnectionTest[];
};
const stages = [
  ['workspace', '检查本地工作区', '确认工作区路径与恢复指针'],
  ['database', '加载数据库', '打开 SQLite 并校验数据结构'],
  ['components', '加载安全组件', '恢复本地身份与通信存储'],
  ['services', '注册本地服务', '连接采集、报告与调度组件'],
  ['records', '恢复事件与配置', '读取本地调查记录和模型配置'],
  ['ui', '加载工作界面', '装配工作区与交互组件'],
];
const pending = (): Step[] =>
  stages.map(([id, title, detail]) => ({
    id,
    title,
    detail,
    state: 'pending',
    elapsedMs: 0,
  }));

/** Native readiness gates every Store-dependent component. No timer advances a stage. */
export function useStartup(onHydrate: (data: InitialData) => void) {
  const hydrate = useRef(onHydrate);
  hydrate.current = onHydrate;
  const [attempt, setAttempt] = useState(0);
  const [dataReady, setDataReady] = useState(!isTauri());
  const [snapshot, setSnapshot] = useState<StartupSnapshot>({
    state: 'running',
    steps: pending(),
    error: null,
    elapsedMs: 0,
  });
  const [retryable, setRetryable] = useState(false);
  const uiStarted = useRef(0);
  useLayoutEffect(() => {
    if (
      !dataReady ||
      !snapshot.steps.some((s) => s.id === 'ui' && s.state === 'running')
    )
      return;
    // A hidden/minimized WKWebView may suspend animation frames indefinitely.
    // React's DOM commit is the readiness boundary; animation is only cosmetic.
    setSnapshot((previous) => ({
      ...previous,
      state: 'ready',
      steps: previous.steps.map((s) =>
        s.id === 'ui'
          ? {
              ...s,
              state: 'completed',
              elapsedMs: performance.now() - uiStarted.current,
            }
          : s,
      ),
    }));
  }, [dataReady, snapshot.steps]);
  useEffect(() => {
    let alive = true;
    const started = performance.now();
    let steps = pending();
    const publish = (
      state: StartupSnapshot['state'],
      error: string | null = null,
    ) => {
      if (alive)
        setSnapshot({
          state,
          steps: [...steps],
          error,
          elapsedMs: performance.now() - started,
        });
    };
    const change = (id: string, state: Step['state'], elapsedMs = 0) => {
      steps = steps.map((s) => (s.id === id ? { ...s, state, elapsedMs } : s));
      publish('running');
    };
    async function load() {
      setRetryable(false);
      publish('running');
      if (isTauri()) {
        try {
          for (;;) {
            const backend = await invoke<StartupSnapshot>('get_startup_state');
            if (!alive) return;
            steps = steps.map(
              (s) => backend.steps.find((b) => b.id === s.id) || s,
            );
            publish(
              backend.state === 'failed' ? 'failed' : 'running',
              backend.error,
            );
            // A failed database is not bypassed or silently replaced by a new workspace.
            if (backend.state === 'failed') return;
            if (backend.state === 'ready') break;
            await new Promise((resolve) => setTimeout(resolve, 100));
            if (!alive) return;
          }
          change('records', 'running');
          const reading = performance.now();
          const [workspace, config, profiles, connectionTests] =
            await Promise.all([
              invoke<Workspace>('get_workspace'),
              invoke<AiConfig>('get_ai_config'),
              invoke<AiConfig[]>('get_ai_profiles'),
              invoke<AiConnectionTest[]>('get_ai_connection_tests'),
            ]);
          if (!alive) return;
          hydrate.current({ workspace, config, profiles, connectionTests });
          change('records', 'completed', performance.now() - reading);
        } catch (error) {
          if (!alive) return;
          steps = steps.map((s) =>
            s.state === 'running' ? { ...s, state: 'failed' } : s,
          );
          publish('failed', String(error));
          setRetryable(true);
          return;
        }
      } else {
        steps = steps.map((s) =>
          s.id === 'ui'
            ? s
            : {
                ...s,
                state: 'skipped',
                detail: '浏览器预览，未运行本地初始化',
              },
        );
      }
      change('ui', 'running');
      uiStarted.current = performance.now();
      setDataReady(true);
    }
    void load();
    return () => {
      alive = false;
    };
  }, [attempt]);
  return {
    snapshot,
    dataReady,
    retryable,
    retry: () => setAttempt((n) => n + 1),
  };
}

const duration = (ms: number) =>
  ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
export function StartupScreen({
  snapshot,
  animate,
  replay,
  retryable,
  onRetry,
  onClose,
  onReduce,
}: {
  snapshot: StartupSnapshot;
  animate: boolean;
  replay: boolean;
  retryable: boolean;
  onRetry: () => void;
  onClose: () => void;
  onReduce: () => void;
}) {
  const focus = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);
  const ready = snapshot.state === 'ready';
  const failed = snapshot.state === 'failed';
  const completed = snapshot.steps.filter(
    (s) => s.state === 'completed',
  ).length;
  const current = snapshot.steps.find((s) => s.state === 'running');
  useEffect(() => {
    const previous = document.activeElement;
    focus.current?.focus();
    return () => {
      if (previous instanceof HTMLElement && previous.isConnected)
        previous.focus();
      else
        document
          .querySelector<HTMLButtonElement>('.dashboard-primary')
          ?.focus();
    };
  }, []);
  return (
    <div
      className="splash startup-screen"
      data-motion={animate ? 'full' : 'reduced'}
      data-state={snapshot.state}
      role="dialog"
      aria-modal="true"
      aria-label="嘎嘎安全助手启动动画"
      tabIndex={-1}
      ref={focus}
      onKeyDown={(e) => {
        if (e.key === 'Tab') {
          const buttons = Array.from(
            focus.current?.querySelectorAll<HTMLButtonElement>(
              'button:not(:disabled)',
            ) || [],
          );
          const index = buttons.indexOf(
            document.activeElement as HTMLButtonElement,
          );
          if (
            index < 0 ||
            (e.shiftKey ? index === 0 : index === buttons.length - 1)
          ) {
            e.preventDefault();
            buttons[e.shiftKey ? buttons.length - 1 : 0]?.focus();
          }
        }
        if (e.key === 'Escape') {
          e.preventDefault();
          if (ready) onClose();
          else onReduce();
        }
      }}
    >
      <div className="startup-grid" aria-hidden="true" />
      <header className="startup-topline">
        <span>
          <ShieldCheck size={15} /> J4TEAM / GAGA
        </span>
        <button
          className="button text-button splash-skip"
          onClick={ready ? onClose : onReduce}
        >
          {ready ? '进入工作台' : animate ? '收起动效' : '等待初始化完成'}
        </button>
      </header>
      <main className="startup-layout">
        <section className="startup-brand">
          <div className="startup-orbit" aria-hidden="true">
            <svg className="startup-ring" viewBox="0 0 240 240">
              <circle cx="120" cy="120" r="107" />
              <circle cx="120" cy="120" r="91" />
            </svg>
            <span className="startup-cross cross-a" />
            <span className="startup-cross cross-b" />
            <img src="/gaga-icon.svg" alt="" className="splash-duck" />
            <span className="startup-verified">
              <ShieldCheck size={17} />
            </span>
          </div>
          <span className="startup-eyebrow">YOUR LOCAL DEFENSE WORKSPACE</span>
          <h1>嘎嘎安全助手</h1>
          <p>让每一条线索，都有据可循。</p>
          <div className="startup-build">
            <span>DESKTOP</span>
            <code>v{release.version}</code>
          </div>
        </section>
        <section className="startup-console" aria-label="实际启动阶段">
          <header>
            <span>{replay ? '本次启动记录 · 动效重播' : '工作区初始化'}</span>
            <code>{String(completed).padStart(2, '0')} / 06</code>
          </header>
          <ol>
            {snapshot.steps.map((step, i) => (
              <li key={step.id} data-step={step.id} data-state={step.state}>
                <span className="startup-step-symbol" aria-hidden="true">
                  {step.state === 'completed' ? (
                    <Check size={13} />
                  ) : step.state === 'running' ? (
                    <LoaderCircle size={13} className="spinning" />
                  ) : step.state === 'failed' ? (
                    <AlertCircle size={13} />
                  ) : (
                    String(i + 1).padStart(2, '0')
                  )}
                </span>
                <div>
                  <strong>{step.title}</strong>
                  <small>{step.detail}</small>
                </div>
                <code>
                  {step.state === 'completed'
                    ? duration(step.elapsedMs)
                    : step.state === 'running'
                      ? '进行中'
                      : step.state === 'failed'
                        ? '失败'
                        : step.state === 'skipped'
                          ? '预览'
                          : '待加载'}
                </code>
              </li>
            ))}
          </ol>
          <footer role="status" aria-live="polite">
            {failed ? (
              <AlertCircle size={14} />
            ) : ready ? (
              <Check size={14} />
            ) : (
              <span className="startup-status-dot" />
            )}
            <span>
              {failed
                ? '初始化未完成，原工作区保留'
                : ready
                  ? '工作区已就绪'
                  : current?.title || '等待本地服务响应'}
            </span>
          </footer>
          {failed && (
            <div className="startup-error" role="alert">
              <p>{snapshot.error}</p>
              <small>请保留工作区，检查路径、权限或磁盘空间后重新启动。</small>
              <div>
                {retryable && (
                  <button className="button" onClick={onRetry}>
                    重试加载
                  </button>
                )}
                <button
                  className="button"
                  onClick={() =>
                    void navigator.clipboard
                      .writeText(snapshot.error || '')
                      .then(() => setCopied(true))
                      .catch(() => setCopied(false))
                  }
                >
                  <Copy size={12} />
                  {copied ? '已复制' : '复制错误'}
                </button>
                {isTauri() && (
                  <button
                    className="button"
                    onClick={() => void invoke('close_startup')}
                  >
                    关闭客户端
                  </button>
                )}
              </div>
            </div>
          )}
        </section>
      </main>
      <footer className="startup-bottomline">
        <span>
          J4team <i /> 一站式防御团队终端
        </span>
        <span>
          LOCAL FIRST <i /> READY FOR EVIDENCE
        </span>
      </footer>
    </div>
  );
}
