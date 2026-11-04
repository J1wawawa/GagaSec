import { useEffect, useState } from 'react';
import { invoke, isTauri } from './bridge';
import { listen } from '@tauri-apps/api/event';
import { LockKeyhole, LockKeyholeOpen, ShieldQuestion } from 'lucide-react';
import { FailureDetails } from './Support';
import './support.css';

type Privacy = { aiLocked: boolean };
function useAiPrivacy() {
  const [value, setValue] = useState<Privacy>();
  const [error, setError] = useState('');
  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let stop: (() => void) | undefined;
    let eventRevision = 0;
    // Subscribe before reading, so a change during mount is not silently lost.
    listen<Privacy>('ai-privacy-changed', ({ payload }) => {
      if (!disposed) {
        eventRevision += 1;
        setValue(payload);
        setError('');
      }
    })
      .then(async (unlisten) => {
        if (disposed) return unlisten();
        stop = unlisten;
        const revision = eventRevision;
        const state = await invoke<Privacy>('get_ai_privacy');
        if (!disposed && eventRevision === revision) setValue(state);
      })
      .catch((e) => {
        if (!disposed) setError(String(e));
      });
    return () => {
      disposed = true;
      stop?.();
    };
  }, []);
  return { value, setValue, error, setError };
}

export function AiPrivacyIndicator({ onOpen }: { onOpen: () => void }) {
  const { value, error } = useAiPrivacy();
  const label = error
    ? 'AI 隐私状态不可用，点击检查'
    : value?.aiLocked
      ? 'AI 外发已锁定'
      : value
        ? 'AI 外发未锁定，发送前仍需选择材料'
        : '查看 AI 外发设置';
  return (
    <button
      className="icon-button ai-privacy-indicator"
      data-ai-locked={value?.aiLocked ? 'true' : 'false'}
      aria-label={label}
      title={label}
      onClick={onOpen}
    >
      {error ? (
        <ShieldQuestion size={15} />
      ) : value?.aiLocked ? (
        <LockKeyhole size={15} />
      ) : (
        <LockKeyholeOpen size={15} />
      )}
    </button>
  );
}

export function PrivacyPanel() {
  const { value, setValue, error, setError } = useAiPrivacy();
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  async function toggle(locked: boolean) {
    setSaving(true);
    setError('');
    setSaved(false);
    try {
      const result = await invoke<Privacy>('set_ai_privacy', {
        settings: { aiLocked: locked },
      });
      setValue(result);
      setSaved(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }
  return (
    <div className="privacy-panel">
      <h2>隐私与外发</h2>
      <p className="setting-note">
        证据与报告在本机保存。没有模型 Key 也可以分析 HTTP、日志并编写报告。
      </p>
      <div className="privacy-lock-card">
        <div>
          <strong>{value?.aiLocked ? 'AI 外发已锁定' : 'AI 外发锁'}</strong>
          <p>
            锁定后拦截研判、追问、连接测试和 Pi 的新模型请求，同时停用自动
            AI。解锁不会恢复自动研判授权。
          </p>
        </div>
        <button
          className="button"
          data-action="toggle-ai-privacy"
          disabled={!isTauri() || saving}
          onClick={() => toggle(value ? !value.aiLocked : true)}
        >
          {saving
            ? '保存中…'
            : value?.aiLocked
              ? '解锁 AI 外发'
              : '锁定 AI 外发'}
        </button>
      </div>
      {error && <FailureDetails message={error} stage="隐私设置" />}
      {saved && (
        <p role="status" className="privacy-saved">
          已保存到当前工作区。
          {value?.aiLocked
            ? '自动 AI 已停用。'
            : '自动 AI 需到监控页重新授权。'}
        </p>
      )}
      <p className="setting-note">
        已进入发送阶段的请求可能完成。外发锁只控制本程序的 AI
        请求；在线情报查询在「情报服务」单独锁定，资产巡检、镜像拉取和采集回传分别在对应功能控制。
      </p>
      <h3>什么情况下会联网</h3>
      <div className="privacy-table-wrap">
        <table className="privacy-table">
          <thead>
            <tr>
              <th>功能</th>
              <th>发送内容与触发方式</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>在线情报查询</td>
              <td>
                默认锁定。启用服务并确认后，发送选中的公网 IP、域名或 Hash
                及查询参数；不发送样本或完整 URL。密钥保存在系统凭据库。与 AI
                外发锁独立控制。
              </td>
            </tr>
            <tr>
              <td>手动 AI / 追问</td>
              <td>
                发送选中的文本、问题和相关对话至当前官方模型；发送前可预览。常见凭据遮盖后仍需检查
                IP、路径与客户标识。
              </td>
            </tr>
            <tr>
              <td>自动 AI</td>
              <td>
                默认关闭。仅授权事件自保存启用后新增的观测摘要、名单匹配和最多前
                100 条流；历史积压需人工选择。
              </td>
            </tr>
            <tr>
              <td>Pi 辅助逆向</td>
              <td>
                显式启动后发送任务问题及受控工具结果，可能包含源码与样本字符串；模型
                Key 由宿主代理使用，不进入 Pi 容器。
              </td>
            </tr>
            <tr>
              <td>连接测试</td>
              <td>点击测试后向所选官方模型发送固定短句，不附证据材料。</td>
            </tr>
            <tr>
              <td>动态分析</td>
              <td>
                显式启动时，Linux 样本送入所选 Docker 环境；Windows
                样本原文件会上传到你配置的 CAPE 服务。AI
                外发锁不阻止这些操作，请核对服务地址与隔离环境。
              </td>
            </tr>
            <tr>
              <td>资产 / Agent / Docker</td>
              <td>
                登记并启动资产巡检时请求目标页面；在线 Agent
                按任务回传；构建镜像可能下载依赖。 这些行为不受 AI 外发锁控制。
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <h3>导出和存储</h3>
      <p className="setting-note">
        工作区、完整备份和报告可能包含明文客户材料。反馈问题优先使用“数据与维护”的脱敏诊断，
        不要公开完整工作区。当前没有数据库加密或团队身份认证；负责人姓名是人工记录字段。
      </p>
    </div>
  );
}
