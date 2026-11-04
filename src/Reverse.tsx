import { TextEditor } from './TextEditor';
import { useEffect, useRef, useState } from 'react';
import { invoke, isTauri } from './bridge';
import { listen } from '@tauri-apps/api/event';
import {
  Play,
  RefreshCw,
  ShieldCheck,
  LoaderCircle,
  Plus,
  Square,
} from 'lucide-react';
import type { AiConfig, Workspace } from './types';
import './reverse.css';
type Environment = {
  docker: {
    daemonReady: boolean;
    message: string;
    version: string;
    context: string;
    serverOs: string;
  };
  imageId: string | null;
  policy: string;
  leftovers: string[];
};
import { mergeReverseJobs, type ReverseJob } from './reverse-state';
export type { ReverseJob } from './reverse-state';
type Props = {
  view: 'environment' | 'pi';
  workspace: Workspace;
  preferredId: string;
  onRefresh: () => Promise<Workspace>;
  onEnvironment: () => void;
  onSettings: () => void;
  onRecord: (job: ReverseJob) => void;
};
const labels: Record<string, string> = {
  running: '分析中',
  completed: '已归档 · 待复核',
  failed: '未完成',
  cancelled: '已取消',
};
export function ReversePanel({
  view,
  workspace,
  preferredId,
  onRefresh,
  onEnvironment,
  onSettings,
  onRecord,
}: Props) {
  const [env, setEnv] = useState<Environment | null>(null);
  const [config, setConfig] = useState<AiConfig | null>(null);
  const [jobs, setJobs] = useState<ReverseJob[]>([]);
  const [selected, setSelected] = useState('');
  const [sampleId, setSampleId] = useState(preferredId);
  const [question, setQuestion] = useState(
    '检查入口逻辑、外部输入和可疑调用，引用原文行号或文件偏移，说明证据缺口与下一步取证建议。',
  );
  const activeJob = useRef('');
  const [working, setWorking] = useState('');
  const [error, setError] = useState('');
  const [detail, setDetail] = useState('analysis');
  const mounted = useRef(true);
  const environmentRequest = useRef(0);
  const caseId = workspace.activeCase;
  const samples = workspace.evidence.filter((e) =>
    ['binary', 'webshell'].includes(e.kind),
  );
  const sample = samples.find((e) => e.id === sampleId) || samples[0];
  const job = jobs.find((j) => j.id === selected) || jobs[0];
  const running = jobs.some((j) => j.state === 'running');
  const put = (j: ReverseJob) =>
    setJobs((old) => mergeReverseJobs(old, [j], caseId));
  const action = async (label: string, fn: () => Promise<unknown>) => {
    setWorking(label);
    setError('');
    try {
      await fn();
    } catch (e) {
      if (mounted.current) setError(String(e));
    } finally {
      if (mounted.current) setWorking('');
    }
  };
  const check = async () => {
    const request = ++environmentRequest.current;
    const value = await invoke<Environment>('reverse_environment');
    if (mounted.current && request === environmentRequest.current)
      setEnv(value);
  };
  useEffect(() => {
    // 每次 effect 有独立失效标记；旧事件的异步响应不能污染新事件。
    let disposed = false;
    let stop: (() => void) | undefined;
    let loading = false;
    mounted.current = true;
    activeJob.current = '';
    setJobs([]);
    setSelected('');
    setError('');
    setEnv(null);
    setConfig(null);
    const load = async () => {
      if (loading || disposed) return;
      loading = true;
      try {
        const snapshot = await invoke<ReverseJob[]>('get_reverse_jobs');
        if (!disposed)
          setJobs((old) => mergeReverseJobs(old, snapshot, caseId));
      } catch (e) {
        if (!disposed) setError(`任务列表同步失败：${String(e)}`);
      } finally {
        loading = false;
      }
    };
    const request = ++environmentRequest.current;
    if (isTauri()) {
      // 先订阅再快照；合并 revision，同时用轮询补偿丢失的终态事件。
      void listen<ReverseJob>('reverse-progress', (e) => {
        if (disposed || e.payload.caseId !== caseId) return;
        setJobs((old) => mergeReverseJobs(old, [e.payload], caseId));
        if (
          e.payload.state === 'running' &&
          activeJob.current !== e.payload.id
        ) {
          activeJob.current = e.payload.id;
          setSelected(e.payload.id);
          setDetail('process');
        }
      })
        .then((unlisten) => {
          if (disposed) unlisten();
          else {
            stop = unlisten;
            void load();
          }
        })
        .catch((e) => {
          if (!disposed) {
            setError(`实时进度订阅失败，正在定期同步：${String(e)}`);
            void load();
          }
        });
      void Promise.allSettled([
        invoke<Environment>('reverse_environment').then((v) => {
          if (!disposed && request === environmentRequest.current) setEnv(v);
        }),
        invoke<AiConfig>('get_ai_config').then((v) => {
          if (!disposed) setConfig(v);
        }),
      ]).then((results) => {
        const failed = results.find((r) => r.status === 'rejected');
        if (!disposed && failed?.status === 'rejected')
          setError(String(failed.reason));
      });
    }
    const timer = isTauri()
      ? setInterval(() => {
          if (!document.hidden) void load();
        }, 3000)
      : undefined;
    const onVisibilityChange = () => {
      if (!document.hidden) void load();
    };
    if (isTauri())
      document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      disposed = true;
      mounted.current = false;
      stop?.();
      clearInterval(timer);
      if (isTauri())
        document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [caseId]);
  useEffect(() => {
    if (preferredId) setSampleId(preferredId);
  }, [preferredId]);
  const disabled = !!working || !isTauri();
  return (
    <section className="reverse-workspace" data-reverse-view={view}>
      {error && (
        <div className="reverse-error" role="alert">
          {error}
        </div>
      )}
      {view === 'environment' ? (
        <div className="reverse-environment">
          <div className="reverse-environment-title">
            <ShieldCheck size={28} />
            <div>
              <h2>隔离分析环境</h2>
              <p>解析工具与 Pi 在临时容器运行；样本不会被执行。</p>
            </div>
          </div>
          <div className="reverse-status-grid">
            <div>
              <small>Docker 引擎</small>
              <strong>
                {env ? (env.docker.daemonReady ? '可用' : '不可用') : '检测中…'}
              </strong>
              <span>{env?.docker.version || '需要启动 Docker Desktop'}</span>
            </div>
            <div>
              <small>分析镜像</small>
              <strong>
                {env ? (env.imageId ? '已就绪' : '待构建') : '检测中…'}
              </strong>
              <span>gaga-analysis:0.6.7</span>
            </div>
            <div>
              <small>当前工作区遗留</small>
              <strong>{env?.leftovers.length ?? '—'} 个容器</strong>
              <span>正常结束会自动删除</span>
            </div>
          </div>
          <p className="reverse-muted">{env?.docker.message}</p>
          <div className="toolbar-group">
            <button
              className="button"
              disabled={disabled}
              onClick={() => void action('检查', check)}
            >
              <RefreshCw size={14} />
              重新检查
            </button>
            <button
              className="button primary"
              disabled={disabled || !env?.docker.daemonReady || running}
              onClick={() =>
                void action('构建镜像', async () => {
                  const request = ++environmentRequest.current;
                  const value = await invoke<Environment>(
                    'build_reverse_environment',
                  );
                  if (mounted.current && request === environmentRequest.current)
                    setEnv(value);
                })
              }
            >
              {working === '构建镜像' ? (
                <LoaderCircle className="spinning" size={14} />
              ) : (
                <Plus size={14} />
              )}
              构建 / 更新分析镜像
            </button>
            {!!env?.leftovers.length && (
              <button
                className="button"
                disabled={disabled || running}
                onClick={() =>
                  void action('清理', async () => {
                    const request = ++environmentRequest.current;
                    const value = await invoke<Environment>(
                      'cleanup_reverse_environment',
                    );
                    if (
                      mounted.current &&
                      request === environmentRequest.current
                    )
                      setEnv(value);
                  })
                }
              >
                清理本工作区遗留容器
              </button>
            )}
          </div>
          {working && (
            <p role="status">
              {working}中…首次构建需要下载基础镜像与 Pi 依赖，可能需要数分钟。
            </p>
          )}
          <div className="reverse-policy">
            <h3>运行边界</h3>
            <p>
              {env?.policy ||
                '禁网、只读根、非 root、无宿主机目录挂载、无 Docker socket，CPU / 内存 / 进程数受限。'}
            </p>
            <p>
              只开放元信息、脚本片段、字符串搜索、x86 / x64
              入口反汇编四个工具。模型 Key
              留在客户端系统凭据服务，模型请求由客户端代理；Pi 容器无真实 Key。
            </p>
            <p>
              镜像构建需要联网，分析容器禁网。缺少环境时停止，不会回退到宿主机解析。普通
              Docker 共享内核；动态运行未知木马请使用专用可回滚虚拟机。
            </p>
          </div>
          {env?.imageId && <code className="hash">{env.imageId}</code>}
        </div>
      ) : (
        <div className="reverse-split">
          <aside className="reverse-task-pane">
            <h2>Pi 辅助逆向</h2>
            <p className="reverse-muted">当前事件的脚本与可执行样本</p>
            <label>
              分析样本
              <select
                aria-label="逆向样本"
                value={sample?.id || ''}
                onChange={(e) => setSampleId(e.target.value)}
                disabled={running || !!working}
              >
                {!samples.length && (
                  <option value="">请先在静态结果中导入样本</option>
                )}
                {samples.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>
            {sample && <code className="hash">SHA-256 {sample.sha256}</code>}
            <TextEditor
              label="调查问题"
              aria-label="逆向调查问题"
              value={question}
              maxLength={4000}
              onChange={(e) => setQuestion(e.target.value)}
              disabled={running}
            />
            <button className="reverse-model" onClick={onSettings}>
              {config?.hasKey
                ? `${config.provider} · ${config.model}`
                : '配置官方模型 Key'}
              <span>模型设置 ↗</span>
            </button>
            <p className="reverse-muted">
              启动后，所调用的样本片段和工具结果会发送至你配置的官方模型。最多 8
              次模型请求、16 次工具调用、300 秒。
            </p>
            {(!env || !config) && (
              <p role="status" className="reverse-muted">
                正在读取模型配置与检查 Docker 环境…
              </p>
            )}
            <button
              className="button primary"
              data-action="start-reverse"
              disabled={
                disabled ||
                running ||
                !sample ||
                !env?.imageId ||
                !config?.hasKey ||
                !question.trim()
              }
              onClick={() =>
                void action('隔离逆向', async () => {
                  const result = await invoke<ReverseJob>('start_reverse', {
                    evidenceId: sample!.id,
                    question,
                  });
                  if (mounted.current) {
                    put(result);
                    setSelected(result.id);
                    await onRefresh();
                  }
                })
              }
            >
              {working === '隔离逆向' || running ? (
                <LoaderCircle className="spinning" size={14} />
              ) : (
                <Play size={14} />
              )}
              启动隔离分析
            </button>
            {env && !env.imageId && (
              <button className="button" onClick={onEnvironment}>
                检查并构建隔离环境
              </button>
            )}
            <div className="reverse-history">
              <h3>
                本事件任务 <small>{jobs.length}</small>
              </h3>
              {jobs.map((j) => (
                <button
                  key={j.id}
                  className={job?.id === j.id ? 'selected' : ''}
                  onClick={() => {
                    setSelected(j.id);
                    setDetail('analysis');
                  }}
                >
                  <strong>{j.sampleName || j.sampleSha256.slice(0, 12)}</strong>
                  <span>
                    {labels[j.state] || j.state} · {j.model || '历史记录'}
                  </span>
                  <span>
                    {new Date(j.createdAt).toLocaleString('zh-CN', {
                      hour12: false,
                    })}
                  </span>
                </button>
              ))}
            </div>
          </aside>
          <section className="reverse-result-pane">
            {!job ? (
              <div className="reverse-empty">
                <ShieldCheck size={36} />
                <h2>工具举证，再形成判断</h2>
                <p>
                  每个工具返回值都会保存 Hash
                  与定位信息，结论可加入事件时间线和报告。当前不提供反编译、自动脱壳或样本执行。
                </p>
              </div>
            ) : (
              <>
                <div className="reverse-result-head">
                  <div>
                    <h2>{labels[job.state] || job.state}</h2>
                    <p>
                      {job.sampleName || '历史样本'} ·{' '}
                      {job.model || '模型未记录'}
                    </p>
                    <code className="hash">SHA-256 {job.sampleSha256}</code>
                    <span>
                      {job.modelRequests} 次模型请求 · {job.artifacts.length}{' '}
                      份工具工件 · 容器清理
                      {job.cleanupConfirmed ? '已确认' : '尚未确认'}
                    </span>
                  </div>
                  <div className="toolbar-group">
                    {job.state === 'running' && (
                      <button
                        className="button"
                        data-action="cancel-reverse"
                        onClick={() => {
                          setError('');
                          void invoke('cancel_reverse', { id: job.id }).catch(
                            (e) => setError(String(e)),
                          );
                        }}
                      >
                        <Square size={13} />
                        取消
                      </button>
                    )}
                    {job.reportEvidenceId && (
                      <button
                        className="button"
                        data-action="record-reverse"
                        onClick={() => onRecord(job)}
                      >
                        <Plus size={14} />
                        加入时间线 / 报告
                      </button>
                    )}
                  </div>
                </div>
                <div className="tabs" role="tablist" aria-label="逆向任务详情">
                  {[
                    ['analysis', '分析草稿'],
                    ['process', '调用过程'],
                    ['artifacts', '工具举证'],
                  ].map(([id, label]) => (
                    <button
                      key={id}
                      role="tab"
                      aria-selected={detail === id}
                      onClick={() => setDetail(id)}
                    >
                      {label}
                    </button>
                  ))}
                </div>
                <div className="reverse-result-body">
                  {job.error && (
                    <div className="reverse-error">{job.error}</div>
                  )}
                  {detail === 'analysis' ? (
                    <>
                      {job.content ? (
                        <pre className="reverse-analysis">{job.content}</pre>
                      ) : (
                        <p className="reverse-muted">
                          {job.state === 'running'
                            ? '正在调用受控工具与模型，过程记录实时更新。'
                            : '任务未形成完整结论，可查看过程与已保存工件。'}
                        </p>
                      )}
                      <p className="reverse-muted">
                        静态观察不代表行为已发生。模型结论待人工复核；完整工具工件与原始样本分别保存。
                      </p>
                    </>
                  ) : detail === 'process' ? (
                    <ol className="reverse-events">
                      {job.events.map((e, i) => (
                        <li key={i}>
                          <time>
                            {new Date(e.at).toLocaleTimeString('zh-CN', {
                              hour12: false,
                            })}
                          </time>
                          <span>{e.title}</span>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <>
                      {!job.artifacts.length && <p>尚无工具工件。</p>}
                      {job.artifacts.map((a) => (
                        <details className="reverse-artifact" key={a.id}>
                          <summary>
                            {a.tool} · {a.id.slice(0, 8)}
                          </summary>
                          <code className="hash">SHA-256 {a.sha256}</code>
                          <pre>
                            {JSON.stringify(a.params)}
                            {'\n'}
                            {a.preview}
                          </pre>
                        </details>
                      ))}
                    </>
                  )}
                </div>
              </>
            )}
          </section>
        </div>
      )}
    </section>
  );
}
