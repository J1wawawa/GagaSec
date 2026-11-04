import { useEffect, useState } from 'react';
import { invoke, isTauri } from './bridge';
import { listen } from '@tauri-apps/api/event';
import { open } from '@tauri-apps/plugin-dialog';
import {
  Play,
  RefreshCw,
  Upload,
  Plus,
  ShieldCheck,
  LoaderCircle,
} from 'lucide-react';
import type { Evidence, Workspace } from './types';
type DockerCheck = {
  cliFound: boolean;
  daemonReady: boolean;
  cliPath: string;
  context: string;
  serverOs: string;
  architecture: string;
  version: string;
  runnerImage: string | null;
  leftovers: string[];
  leftoverVolumes: string[];
  message: string;
};
export type SandboxJob = {
  id: string;
  caseId: string;
  evidenceId: string;
  provider: string;
  state: string;
  createdAt: string;
  updatedAt: string;
  containerName: string;
  imageId: string;
  taskId: number | null;
  endpoint: string;
  events: { time: string; text: string }[];
  reportEvidenceId: string | null;
  exitCode: number | null;
  timedOut: boolean;
  cleanupConfirmed: boolean;
  output: string;
  tracePreview: string;
  error: string | null;
};
type Config = { endpoint: string; machine: string; hasKey: boolean };
interface Props {
  workspace: Workspace;
  busy: string;
  perform: <T>(
    label: string,
    fn: () => Promise<T>,
    done?: (value: T) => void,
  ) => Promise<T | undefined>;
  refresh: () => Promise<Workspace>;
  onReview: (e: Evidence) => void;
  onRecord: (job: SandboxJob) => void;
}
const time = (v: string) =>
  new Date(v).toLocaleString('zh-CN', { hour12: false });
const stateLabel = (v: string) =>
  ({
    preparing: '准备中',
    running: '执行中',
    completed: '已归档',
    failed: '失败',
    collection_incomplete: '采集不完整',
    submitted: '已提交',
    pending: '排队中',
    reported: '报告已生成',
    processing: '处理报告',
    failed_analysis: '沙箱执行失败',
    failed_processing: '报告处理失败',
  })[v] || v;
export function SandboxPanel({
  workspace,
  busy,
  perform,
  refresh,
  onReview,
  onRecord,
}: Props) {
  const [view, setView] = useState('environment');
  const [provider, setProvider] = useState<'docker' | 'cape-windows'>('docker');
  const [docker, setDocker] = useState<DockerCheck | null>(null);
  const [checking, setChecking] = useState(false);
  const [jobs, setJobs] = useState<SandboxJob[]>([]);
  const [sampleId, setSampleId] = useState('');
  const [seconds, setSeconds] = useState(20);
  const [mirror, setMirror] = useState('https://dl-cdn.alpinelinux.org/alpine');
  const [ack, setAck] = useState(false);
  const [config, setConfig] = useState<Config>({
    endpoint: '',
    machine: '',
    hasKey: false,
  });
  const [token, setToken] = useState('');
  const [machineResult, setMachineResult] = useState('');
  const samples = workspace.evidence.filter((e) => e.kind === 'binary');
  const selected = samples.find((e) => e.id === sampleId) || samples[0];
  const blocked = !!busy || !isTauri();
  const putJob = (job: SandboxJob) =>
    setJobs((previous) =>
      [job, ...previous.filter((j) => j.id !== job.id)].sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt),
      ),
    );
  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let stop: (() => void) | undefined;
    setChecking(true);
    Promise.allSettled([
      invoke<DockerCheck>('check_docker'),
      invoke<SandboxJob[]>('get_sandbox_jobs'),
      invoke<Config>('get_windows_sandbox_config'),
    ]).then(([d, j, c]) => {
      if (disposed) return;
      if (d.status === 'fulfilled') setDocker(d.value);
      else
        setDocker({
          cliFound: false,
          daemonReady: false,
          cliPath: '',
          context: '',
          serverOs: '',
          architecture: '',
          version: '',
          runnerImage: null,
          leftovers: [],
          leftoverVolumes: [],
          message: String(d.reason),
        });
      if (j.status === 'fulfilled') setJobs(j.value);
      if (c.status === 'fulfilled') setConfig(c.value);
      setChecking(false);
    });
    listen<SandboxJob>('sandbox-progress', (event) => {
      if (!disposed && event.payload.caseId === workspace.activeCase)
        putJob(event.payload);
    }).then((unlisten) => {
      if (disposed) unlisten();
      else stop = unlisten;
    });
    return () => {
      disposed = true;
      stop?.();
    };
  }, [workspace.activeCase]);
  async function importSample() {
    const path = await open({
      multiple: false,
      title: '选择样本，仅归档与静态检查，不在宿主机运行',
    });
    if (typeof path === 'string')
      await perform('归档样本', async () => {
        const e = await invoke<Evidence>('analyze_file', {
          path,
          kind: 'binary',
        });
        await refresh();
        setSampleId(e.id);
      });
  }
  async function start() {
    if (!selected) return;
    await perform(
      provider === 'docker' ? '容器动态观察' : '提交 Windows 沙箱',
      async () => {
        const job = await invoke<SandboxJob>(
          provider === 'docker' ? 'run_linux_sample' : 'submit_windows_sample',
          { evidenceId: selected.id, seconds, labAck: ack },
        );
        putJob(job);
        await refresh();
      },
    );
  }
  return (
    <section className="sandbox-desktop" data-sandbox-view={view}>
      <div className="page-head">
        <div>
          <div className="eyebrow">分析工具 / 隔离实验环境</div>
          <h1>动态行为分析</h1>
          <p>从样本启动到行为归档，保留采集范围、原始记录和执行结果。</p>
        </div>
        <button
          className="button"
          disabled={blocked}
          onClick={() =>
            perform(
              '刷新动态任务',
              () => invoke<SandboxJob[]>('get_sandbox_jobs'),
              setJobs,
            )
          }
        >
          <RefreshCw size={14} />
          刷新任务
        </button>
      </div>
      <div className="sandbox-provider tabs" aria-label="动态分析环境">
        {[
          ['docker', 'Linux · Docker'],
          ['cape-windows', 'Windows · 虚拟机沙箱'],
        ].map(([id, label]) => (
          <button
            key={id}
            className={provider === id ? 'active' : ''}
            disabled={!!busy}
            onClick={() => {
              setProvider(id as typeof provider);
              setSeconds(id === 'docker' ? 20 : 120);
              setAck(false);
            }}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="sandbox-view-tabs" role="tablist">
        {[
          ['environment', '环境配置'],
          ['new', '新建任务'],
          ['history', '任务记录'],
        ].map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={view === id}
            onClick={() => setView(id)}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="sandbox-desktop-body">
        <section className="sandbox-card" data-sandbox-panel="environment">
          <div className="detail-head">
            <h2>
              {provider === 'docker'
                ? 'Docker 环境预检'
                : 'Windows VM · CAPE API v2'}
            </h2>
            {provider === 'docker' && (
              <button
                className="button small"
                disabled={blocked || checking}
                onClick={() =>
                  perform(
                    '检查 Docker',
                    () => invoke<DockerCheck>('check_docker'),
                    setDocker,
                  )
                }
              >
                <RefreshCw size={13} />
                重新检查
              </button>
            )}
          </div>
          {provider === 'docker' ? (
            <>
              <div className="sandbox-checks">
                <div>
                  <span>Docker CLI</span>
                  <strong>
                    {checking
                      ? '检查中'
                      : docker?.cliFound
                        ? '已找到'
                        : '未就绪'}
                  </strong>
                </div>
                <div>
                  <span>引擎</span>
                  <strong>
                    {docker?.daemonReady
                      ? `${docker.serverOs} / ${docker.architecture}`
                      : '未连接'}
                  </strong>
                </div>
                <div>
                  <span>当前 context</span>
                  <strong>{docker?.context || '—'}</strong>
                </div>
                <div>
                  <span>监控镜像</span>
                  <strong>{docker?.runnerImage ? '已安装' : '待构建'}</strong>
                </div>
              </div>
              <p className="small-note">
                {checking
                  ? '正在检测客户端、引擎与监控镜像。'
                  : docker?.message || '打开桌面客户端后检查 Docker。'}
              </p>
              <div className="toolbar-group">
                <select
                  aria-label="监控镜像软件包来源"
                  value={mirror}
                  disabled={blocked}
                  onChange={(e) => setMirror(e.target.value)}
                >
                  <option value="https://dl-cdn.alpinelinux.org/alpine">
                    Alpine 官方源
                  </option>
                  <option value="https://mirrors.aliyun.com/alpine">
                    阿里云 Alpine 镜像源
                  </option>
                </select>
                <button
                  className="button"
                  disabled={blocked || !docker?.daemonReady}
                  onClick={() =>
                    perform(
                      '构建监控镜像',
                      () =>
                        invoke<DockerCheck>('build_sandbox_runner', { mirror }),
                      setDocker,
                    )
                  }
                >
                  {busy === '构建监控镜像' ? (
                    <LoaderCircle size={14} className="spinning" />
                  ) : (
                    <Plus size={14} />
                  )}
                  构建监控镜像（联网）
                </button>
                {!!docker &&
                  docker.leftovers.length + docker.leftoverVolumes.length >
                    0 && (
                    <button
                      className="button"
                      disabled={blocked}
                      onClick={() =>
                        perform(
                          '清理本助手遗留容器',
                          () =>
                            invoke<DockerCheck>('cleanup_sandbox_containers'),
                          setDocker,
                        )
                      }
                    >
                      清理本助手遗留容器与卷 ·{' '}
                      {docker.leftovers.length + docker.leftoverVolumes.length}
                    </button>
                  )}
              </div>
              <p className="small-note">
                默认禁网、无主机目录或 Docker socket 挂载、只读根目录、移除
                capability、普通用户与资源限额。观察进程 / 文件 /
                网络系统调用；只记录连接尝试，不提供互联网响应或完整 PCAP。ELF
                架构须与引擎一致，Alpine 不能保证运行 glibc 程序。
              </p>
            </>
          ) : (
            <>
              <p className="small-note">
                连接你部署的 CAPE 服务，由它启动专用 Windows
                VM、采集行为并生成报告。客户端不会在当前 macOS / Windows
                宿主机直接运行 EXE，也不会安装或还原虚拟机。
              </p>
              <div className="sandbox-config">
                <label>
                  CAPE API 基础地址
                  <input
                    aria-label="CAPE API 地址"
                    value={config.endpoint}
                    onChange={(e) =>
                      setConfig({ ...config, endpoint: e.target.value })
                    }
                    placeholder="http://127.0.0.1:8000/apiv2"
                  />
                </label>
                <label>
                  Windows 机器名 · 可留空
                  <input
                    aria-label="Windows 沙箱机器名"
                    value={config.machine}
                    onChange={(e) =>
                      setConfig({ ...config, machine: e.target.value })
                    }
                    placeholder="由沙箱选择 windows 平台机器"
                  />
                </label>
                <label>
                  API Token · 存系统凭据
                  <input
                    aria-label="CAPE API Token"
                    type="password"
                    autoComplete="off"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder={
                      config.hasKey
                        ? '已保存；留空保留'
                        : '本机免鉴权服务可留空'
                    }
                  />
                </label>
              </div>
              <div className="toolbar-group">
                <button
                  className="button"
                  disabled={blocked || !config.endpoint.trim()}
                  onClick={() =>
                    perform(
                      '保存 Windows 沙箱配置',
                      () =>
                        invoke<Config>('save_windows_sandbox_config', {
                          endpoint: config.endpoint,
                          machine: config.machine,
                          token,
                        }),
                      (c) => {
                        setConfig(c);
                        setToken('');
                      },
                    )
                  }
                >
                  保存配置
                </button>
                <button
                  className="button"
                  disabled={blocked || !config.endpoint.trim()}
                  onClick={() =>
                    perform(
                      '检查 Windows 沙箱',
                      () => invoke<unknown>('check_windows_sandbox'),
                      (v) => setMachineResult(JSON.stringify(v, null, 2)),
                    )
                  }
                >
                  检查已保存服务
                </button>
              </div>
              {machineResult && (
                <details className="limitations">
                  <summary>沙箱机器列表</summary>
                  <pre>{machineResult}</pre>
                </details>
              )}
            </>
          )}
        </section>
        <section className="sandbox-card" data-sandbox-panel="new">
          <div className="detail-head">
            <h2>新建观察任务</h2>
            <button
              className="button small"
              disabled={blocked}
              onClick={importSample}
            >
              <Upload size={13} />
              导入样本
            </button>
          </div>
          <div className="sandbox-task-fields">
            <label>
              当前事件的归档样本
              <select
                aria-label="动态分析样本"
                value={selected?.id || ''}
                onChange={(e) => setSampleId(e.target.value)}
              >
                <option value="" disabled>
                  先导入样本，仅做静态检查
                </option>
                {samples.map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              观察时间上限 · 秒
              <input
                aria-label="动态观察时间"
                type="number"
                min={provider === 'docker' ? 5 : 15}
                max={provider === 'docker' ? 60 : 300}
                value={seconds}
                onChange={(e) => setSeconds(Number(e.target.value))}
              />
            </label>
          </div>
          {selected && (
            <code className="hash sandbox-hash">
              SHA-256 · {selected.sha256}
            </code>
          )}
          <label className="sandbox-ack">
            <input
              aria-label="确认专用隔离环境"
              type="checkbox"
              checked={ack}
              disabled={!!busy}
              onChange={(e) => setAck(e.target.checked)}
            />
            <span>
              {provider === 'docker'
                ? '我已确认当前 Docker 位于专用、可丢弃的隔离虚拟机；普通容器不能保证隔离恶意样本。'
                : '我已确认 CAPE 使用专用 Windows VM、具备干净快照，并配置了隔离网络。'}
            </span>
          </label>
          <div className="http-compose-footer">
            <p>
              {provider === 'docker'
                ? '支持 Linux ELF 与 sh 脚本；运行结束收集轨迹并删除临时容器。异常退出后请检查遗留容器。'
                : '样本文件会上传到已保存的 CAPE 地址；虚拟机和监控由沙箱端管理，任务记录保留服务地址。'}
            </p>
            <button
              className="button primary"
              disabled={
                blocked ||
                !selected ||
                !ack ||
                !seconds ||
                (provider === 'docker'
                  ? !docker?.runnerImage
                  : !config.endpoint)
              }
              onClick={() => {
                setView('history');
                start();
              }}
            >
              {busy === '容器动态观察' ? (
                <LoaderCircle className="spinning" size={14} />
              ) : (
                <Play size={14} />
              )}{' '}
              {provider === 'docker'
                ? '启动临时容器并观察'
                : '提交到 Windows 虚拟机'}
            </button>
          </div>
        </section>
        <div data-sandbox-panel="history">
          <div className="detail-head sandbox-history-heading">
            <h2>本事件观察记录</h2>
            <small>{jobs.length} 条 · 最多显示最近 30 条</small>
          </div>
          {!jobs.length ? (
            <div className="quiet-empty">
              尚无动态任务。运行不会自动触发
              AI；行为报告可先核对，再选择材料研判。
            </div>
          ) : (
            jobs.map((job) => {
              const report = workspace.evidence.find(
                (e) => e.id === job.reportEvidenceId,
              );
              return (
                <article className="sandbox-card sandbox-job" key={job.id}>
                  <div className="detail-head">
                    <div>
                      <h3>
                        {workspace.evidence.find((e) => e.id === job.evidenceId)
                          ?.name || '归档样本'}{' '}
                        · {job.provider === 'docker' ? 'Linux' : 'Windows'}
                      </h3>
                      <small>
                        {time(job.createdAt)} · 记录状态：
                        {stateLabel(job.state)}
                      </small>
                    </div>
                    <span>
                      <ShieldCheck size={14} />{' '}
                      {job.provider === 'docker'
                        ? job.cleanupConfirmed
                          ? '临时容器已清理'
                          : '清理尚未确认'
                        : 'VM 还原由沙箱端确认'}
                    </span>
                  </div>
                  <code className="sandbox-id">
                    任务 {job.id}
                    {job.taskId ? ` · CAPE #${job.taskId}` : ''}
                  </code>
                  <p className="small-note" data-behavior-limit="unverified">
                    观察受限 ·
                    未观察到行为不等于安全。样本可能等待触发条件、检测调试器或识别沙箱；需结合静态线索、其他环境及真实主机证据复核。当前未自动验证反沙箱分支。
                  </p>
                  <ol className="sandbox-events">
                    {job.events.map((e, i) => (
                      <li key={i}>
                        <time>{time(e.time)}</time>
                        <span>{e.text}</span>
                      </li>
                    ))}
                  </ol>
                  {job.error && (
                    <p className="small-note">失败原因：{job.error}</p>
                  )}
                  {job.exitCode != null && (
                    <p className="small-note">
                      容器退出码 {job.exitCode}
                      {job.timedOut
                        ? ' · 达到时限或收到 SIGKILL，无法仅凭退出码区分'
                        : ''}
                    </p>
                  )}
                  {job.output && (
                    <details className="limitations">
                      <summary>标准输出与采集器信息</summary>
                      <pre>{job.output}</pre>
                    </details>
                  )}
                  {job.tracePreview && (
                    <details className="limitations">
                      <summary>
                        {job.provider === 'docker'
                          ? '进程 / 文件 / 网络系统调用节选'
                          : '进程 / 文件 / 注册表 / 网络摘要'}
                      </summary>
                      <pre>{job.tracePreview}</pre>
                    </details>
                  )}
                  <div className="toolbar-group">
                    {job.provider === 'cape-windows' &&
                      job.taskId &&
                      !job.reportEvidenceId && (
                        <button
                          className="button"
                          disabled={blocked}
                          onClick={() =>
                            perform('查询 Windows 任务', async () => {
                              const j = await invoke<SandboxJob>(
                                'refresh_windows_task',
                                { id: job.id },
                              );
                              putJob(j);
                              await refresh();
                            })
                          }
                        >
                          <RefreshCw size={13} />
                          查询状态 / 获取报告
                        </button>
                      )}
                    {report && (
                      <>
                        <button
                          className="button"
                          disabled={blocked}
                          onClick={() => onReview(report)}
                        >
                          查看报告并 AI 研判
                        </button>
                        <button
                          className="button"
                          disabled={blocked}
                          onClick={() => onRecord(job)}
                        >
                          <Plus size={13} />
                          记录到事件时间线
                        </button>
                      </>
                    )}
                  </div>
                  <p className="small-note">
                    系统调用与沙箱报告可能被规避或篡改；未出现行为不代表安全。
                    {job.state === 'running'
                      ? '这只是最近保存状态；若客户端曾退出，请先检查并清理遗留容器。'
                      : ''}
                  </p>
                </article>
              );
            })
          )}
        </div>
      </div>
    </section>
  );
}
