import { useEffect, useState } from 'react';
import { invoke, isTauri } from './bridge';
import { open, save } from '@tauri-apps/plugin-dialog';
import type { Module, Workspace } from './types';
import release from './release-manifest.json';
import './support.css';

// 分类只给可操作的提示，原始错误保留在当前界面；支持包不会导出原始错误。
export function explainFailure(message: string) {
  const rules: [RegExp, string, string][] = [
    [
      /AI 外发已锁定|隐私设置损坏/,
      'AI_PRIVACY_LOCK',
      '在隐私与外发检查设置；本地分析与报告仍可使用。',
    ],
    [
      /API.*(?:401|403)|(?:401|403).*API|API.?Key|鉴权|认证失败/i,
      'MODEL_AUTH',
      '在模型连接中确认服务商、账号权限与已保存的 Key，再测试连接。',
    ],
    [
      /429|rate.limit|限流/i,
      'MODEL_LIMIT',
      '降低并发与自动 AI 频率，确认官方账号额度后手动重试。',
    ],
    [
      /钥匙串|keychain|credential|凭据服务/i,
      'CREDENTIAL_ACCESS',
      '检查系统凭据授权；无需在问题反馈中提供 Key。',
    ],
    [
      /docker|镜像|容器引擎/i,
      'ISOLATION_ENV',
      '打开本机环境检查，确认 Docker 运行及分析镜像就绪，再重试。',
    ],
    [
      /no space|disk.full|磁盘空间|空间不足/i,
      'STORAGE_FULL',
      '在数据与维护查看占用，备份后选择有足够空间的目录。',
    ],
    [
      /database.*lock|工作区.*另|数据库.*锁/i,
      'WORKSPACE_BUSY',
      '关闭占用同一工作区的其他客户端，再重新打开。',
    ],
    [
      /摘要|Hash|SHA|完整性|篡改/i,
      'INTEGRITY_CHECK',
      '保留原始材料，核对来源和摘要；不要跳过完整性检查。',
    ],
    [
      /HTTP|请求行|响应行|报文|消息头/i,
      'HTTP_INPUT',
      '检查请求与响应是否放在对应输入框，消息头和正文间是否有空行。',
    ],
    [
      /timeout|timed.out|超时/i,
      'OPERATION_TIMEOUT',
      '检查当前步骤所需的网络或运行环境；输入保留后可手动重试。',
    ],
  ];
  const found = rules.find(([pattern]) => pattern.test(message));
  return {
    code: found?.[1] || 'OPERATION_FAILED',
    suggestion:
      found?.[2] ||
      '查看原始错误与功能状态；可从数据与维护导出脱敏诊断，连同复现步骤反馈。',
  };
}
export function FailureDetails({
  message,
  stage,
}: {
  message: string;
  stage: string;
}) {
  const error = explainFailure(message);
  return (
    <div className="failure-details">
      <strong>{stage}未完成</strong>
      <p>{message}</p>
      <small>
        {error.code} · {error.suggestion}
      </small>
    </div>
  );
}
export function CapabilityMatrix({
  onNavigate,
}: {
  onNavigate: (page: Module) => void;
}) {
  return (
    <div className="capability-matrix">
      <h2>功能与验证状态</h2>
      <p className="setting-note">
        本机回归表示固定案例通过；实验功能和外部环境仍需针对你的目标验收。
      </p>
      {release.features.map((feature) => (
        <article key={feature.id} data-feature={feature.id}>
          <div>
            <strong>{feature.title}</strong>
            <span className="capability-status">{feature.status}</span>
          </div>
          <p>{feature.boundary}</p>
          <button
            className="button small"
            onClick={() => onNavigate(feature.module as Module)}
          >
            打开功能
          </button>
        </article>
      ))}
      <h3>平台兼容情况</h3>
      {release.platforms.map((platform) => (
        <article key={platform.name}>
          <strong>
            {platform.name} · {platform.status}
          </strong>
          <p>{platform.note}</p>
        </article>
      ))}
    </div>
  );
}
type Storage = {
  path: string;
  schemaVersion: number;
  cases: number;
  databaseBytes: number;
  databaseMainBytes: number;
  databaseWalBytes: number;
  databaseShmBytes: number;
  categories: { id: string; title: string; bytes: number; files: number }[];
};
const size = (bytes: number) =>
  bytes >= 1073741824
    ? `${(bytes / 1073741824).toFixed(2)} GiB`
    : `${(bytes / 1048576).toFixed(2)} MiB`;
export function MaintenancePanel({
  workspace,
  busy,
}: {
  workspace: Workspace;
  busy: string;
}) {
  const [info, setInfo] = useState<Storage>();
  const [working, setWorking] = useState('');
  const [error, setError] = useState('');
  const [result, setResult] = useState<{ path: string; kind: string }>();
  const [switched, setSwitched] = useState(false);
  const load = () =>
    invoke<Storage>('workspace_maintenance', {
      operation: 'info',
      path: null,
      parent: null,
    }).then(setInfo);
  useEffect(() => {
    let alive = true;
    if (isTauri())
      invoke<Storage>('workspace_maintenance', {
        operation: 'info',
        path: null,
        parent: null,
      })
        .then((value) => {
          if (alive) setInfo(value);
        })
        .catch((e) => {
          if (alive) setError(String(e));
        });
    return () => {
      alive = false;
    };
  }, [workspace.dataDir]);
  async function act(
    kind: 'backup' | 'restore' | 'diagnostic' | 'activate' | 'rollback',
  ) {
    if (!isTauri()) {
      setError('请在桌面客户端执行维护操作。');
      return;
    }
    setError('');
    setWorking(kind);
    try {
      if (kind === 'diagnostic') {
        const path = await save({
          defaultPath: `gaga-diagnostics-${Date.now()}.json`,
          filters: [{ name: '脱敏诊断', extensions: ['json'] }],
        });
        if (path) {
          await invoke('export_diagnostics', { path });
          setResult({ path, kind: 'diagnostic' });
        }
      } else if (
        (kind === 'activate' && result?.kind === 'restore') ||
        kind === 'rollback'
      ) {
        await invoke('activate_workspace', {
          path: kind === 'rollback' ? workspace.dataDir : result!.path,
        });
        setSwitched(kind !== 'rollback');
      } else {
        if (kind === 'backup') {
          const prefix = `gaga-report-draft/1/${encodeURIComponent(workspace.dataDir)}/`;
          if (Object.keys(localStorage).some((key) => key.startsWith(prefix)))
            throw Error(
              '有报告草稿尚未确认保存。请回到报告页完成恢复或保存，再创建备份。',
            );
        }
        const source =
          kind === 'restore'
            ? await open({
                directory: true,
                multiple: false,
                title: '选择含 manifest.json 的嘎嘎备份文件夹',
              })
            : null;
        if (kind === 'restore' && typeof source !== 'string') return;
        const parent = await open({
          directory: true,
          multiple: false,
          title:
            kind === 'backup'
              ? '选择备份存放位置'
              : '选择恢复到的父文件夹（自动新建工作区）',
        });
        if (typeof parent !== 'string') return;
        const value = await invoke<{ path: string }>('workspace_maintenance', {
          operation: kind,
          path: source,
          parent,
        });
        setSwitched(false);
        setResult({ path: value.path, kind });
        await load();
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setWorking('');
    }
  }
  return (
    <div className="maintenance-panel">
      <h2>数据与维护</h2>
      <p className="setting-note">
        事件备份包含明文证据和样本，请妥善保管。聊天记录、配对关系及电子水印密钥不在此备份内；诊断文件只包含版本、计数和功能状态。
      </p>
      {error && (
        <div role="alert">
          <FailureDetails message={error} stage="工作区维护" />
        </div>
      )}
      <div className="maintenance-actions">
        <button
          className="button"
          disabled={!!working || !!busy}
          onClick={() => act('backup')}
        >
          创建事件备份
        </button>
        <button
          className="button"
          disabled={!!working || !!busy}
          onClick={() => act('restore')}
        >
          恢复到新工作区
        </button>
        <button
          className="button"
          disabled={!!working}
          onClick={() => act('diagnostic')}
        >
          导出脱敏诊断
        </button>
      </div>
      {working && (
        <p role="status">
          正在处理，请保持客户端打开；大文件备份需要等待磁盘复制完成。
        </p>
      )}
      {result && (
        <div className="maintenance-result" role="status">
          <strong>
            {result.kind === 'backup'
              ? '备份已完成'
              : result.kind === 'restore'
                ? '已校验并恢复到新目录'
                : '脱敏诊断已导出'}
          </strong>
          <code>{result.path}</code>
          {result.kind === 'restore' && (
            <>
              <p>
                当前工作区保持可用；恢复后的后台任务默认停用。系统凭据不在备份内，模型需重新配置。
              </p>
              <button
                className="button"
                disabled={!!working || switched}
                onClick={() => act('activate')}
              >
                {switched ? '重启客户端后生效' : '下次启动使用此工作区'}
              </button>
              {switched && (
                <button className="button" onClick={() => act('rollback')}>
                  撤销下次切换
                </button>
              )}
            </>
          )}
        </div>
      )}
      {info && (
        <>
          <h3>本地存储 · {info.cases} 个事件</h3>
          <code className="data-path">{info.path}</code>
          <div className="storage-row">
            <span>
              数据库合计 · 结构版本 {info.schemaVersion}
              <small>
                主文件 {size(info.databaseMainBytes)} · WAL{' '}
                {size(info.databaseWalBytes)} · 共享内存{' '}
                {size(info.databaseShmBytes)}
              </small>
            </span>
            <strong>{size(info.databaseBytes)}</strong>
          </div>
          {info.categories.map((category) => (
            <div className="storage-row" key={category.id}>
              <span>
                {category.title}
                <small>{category.files} 个文件</small>
              </span>
              <strong>{size(category.bytes)}</strong>
            </div>
          ))}
        </>
      )}
      <details className="maintenance-notes">
        <summary>备份范围与恢复说明</summary>
        <p>
          包含 SQLite
          一致快照、原始证据、截图、静态逆向工件和动态报告；不含系统钥匙串、Docker
          镜像、临时输入、WebView
          未保存草稿和可重建日志索引。备份验证后才报告完成，恢复失败会清除本次新建目录。
        </p>
        <p>
          恢复后从日志页重建派生时间线索引。已有解密证据可继续查看；跨电脑接收新的旧
          Agent
          包仍需要原电脑系统凭据。升级前自动保留数据库快照，原始证据不参与结构修改。
        </p>
        <p>
          本版保留证据，暂不自动删除。结案后建议创建备份并验证恢复，长期材料可分工作区保管。
        </p>
      </details>
    </div>
  );
}
export function WorkflowGuide({
  workspace,
  onNavigate,
}: {
  workspace: Workspace;
  onNavigate: (page: Module) => void;
}) {
  const key = `gaga-workflow-guide/1/${encodeURIComponent(workspace.dataDir)}`;
  const [hidden, setHidden] = useState(
    () => localStorage.getItem(key) === 'hidden',
  );
  return (
    <details
      className="workflow-guide"
      open={!hidden && workspace.evidence.length === 0}
    >
      <summary>开始一次调查 · 从材料到报告</summary>
      <p>
        {release.positioning}。先建立独立事件，再把分析结果作为证据加入时间线。
      </p>
      <div>
        {(
          [
            ['cases', '1 · 建立事件'],
            ['http', '2 · 导入与分析'],
            ['evidence', '3 · AI 复核'],
            ['timeline', '4 · 举证与处置'],
            ['reports', '5 · 编辑并交付报告'],
          ] as [Module, string][]
        ).map(([page, label]) => (
          <button key={page} onClick={() => onNavigate(page)}>
            {label}
          </button>
        ))}
      </div>
      <button
        className="guide-dismiss"
        onClick={() => {
          localStorage.setItem(key, 'hidden');
          setHidden(true);
        }}
      >
        收起，下次不自动展开
      </button>
    </details>
  );
}
