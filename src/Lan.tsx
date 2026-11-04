import { useEffect, useRef, useState } from 'react';
import { invoke, isTauri } from './bridge';
import { open, save } from '@tauri-apps/plugin-dialog';
import {
  Copy,
  File,
  ImagePlus,
  MessageCircle,
  Paperclip,
  Plus,
  Send,
  ShieldCheck,
  Smile,
  Wifi,
  X,
} from 'lucide-react';
import { Modal } from './Modal';
import { TextEditor } from './TextEditor';
import './lan.css';

type Peer = {
  id: string;
  alias: string;
  endpoint: string;
  paired: boolean;
  online: boolean;
};
type Nearby = { id: string; alias: string; endpoint: string };
type Group = {
  id: string;
  name: string;
  groupType: string;
  role: string;
  createdAt: string;
  memberIds: string[];
};
type GroupMessage = {
  seq: number;
  id: string;
  groupId: string;
  senderId: string;
  senderAlias: string;
  kind: string;
  createdAt: string;
  body: Message['body'];
};
type Notification = {
  seq: number;
  id: string;
  groupId?: string;
  kind: string;
  createdAt: string;
  state: string;
  title: string;
  body: string;
  caseId?: string;
  actionId?: string;
};
type Message = {
  seq: number;
  id: string;
  peerId: string;
  direction: string;
  kind: string;
  state: string;
  createdAt: string;
  body: {
    text: string;
    name: string;
    size: number;
    sha256: string;
    mime: string;
  };
};
type Snapshot = {
  enabled: boolean;
  alias: string;
  id: string;
  addresses: string[];
  contacts: Peer[];
  discovered: Nearby[];
  messages: Message[];
  groups: Group[];
  groupMessages: GroupMessage[];
  notifications: Notification[];
  notice: string;
  storage: string;
};
type Draft = { text: string; path?: string; image?: string; name?: string };
const empty: Snapshot = {
  enabled: false,
  alias: '嘎嘎安全助手',
  id: '',
  addresses: [],
  contacts: [],
  discovered: [],
  messages: [],
  groups: [],
  groupMessages: [],
  notifications: [],
  notice: '',
  storage: '',
};
const labels: Record<string, string> = {
  sending: '发送中',
  delivered: '对方已保存',
  failed: '未确认送达',
  offered: '等待接收',
  receiving: '接收中',
  received: '已接收',
  declined: '已拒绝',
  accepted: '对方已接收',
  declined_by_peer: '对方已拒绝',
  recovered: '已恢复',
  recovered_metadata: '历史元数据 · 待取回附件',
  recovering: '附件恢复中',
};
const emojis = [
  '🦆',
  '👍',
  '✅',
  '👀',
  '🤝',
  '收到',
  '🔍',
  '🚨',
  '🙏',
  '😂',
  '💪',
  '❤️',
];
function bytes(n: number) {
  return n < 1024
    ? `${n} B`
    : n < 1024 * 1024
      ? `${(n / 1024).toFixed(1)} KiB`
      : `${(n / 1024 / 1024).toFixed(1)} MiB`;
}
function timestamp(value: string) {
  return new Date(value).toLocaleString('zh-CN', { hour12: false });
}

function ChatImage({ message }: { message: Message }) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  useEffect(() => {
    let alive = true;
    invoke<{ url: string }>('lan_action', {
      action: 'image',
      messageId: message.id,
    })
      .then((r) => {
        if (alive) setUrl(r.url);
      })
      .catch((e) => {
        if (alive) setError(String(e));
      });
    return () => {
      alive = false;
    };
  }, [message.id]);
  return url ? (
    <img className="lan-chat-image" src={url} alt={message.body.name} />
  ) : (
    <span className="lan-small" role={error ? 'alert' : 'status'}>
      {error || '加载图片…'}
    </span>
  );
}

export function LanPanel() {
  const [state, setState] = useState<Snapshot>(empty);
  const [alias, setAlias] = useState('嘎嘎安全助手');
  const [selected, setSelected] = useState('');
  const [selectedGroup, setSelectedGroup] = useState('');
  const [groupEditor, setGroupEditor] = useState<{
    id: string;
    text: string;
  } | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [drafts, setDrafts] = useState<Record<string, Draft>>({});
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [revision, setRevision] = useState(0);
  const [emoji, setEmoji] = useState(false);
  const [pairing, setPairing] = useState(false);
  const [invite, setInvite] = useState('');
  const [remoteInvite, setRemoteInvite] = useState('');
  const [address, setAddress] = useState('');
  const [unpair, setUnpair] = useState(false);
  const [more, setMore] = useState(true);
  const [recoveryBefore, setRecoveryBefore] = useState<number | null>(null);
  const list = useRef<HTMLDivElement>(null);
  const previousCount = useRef(0);
  const loadedPeer = useRef('');
  const aliasInitialized = useRef(false);
  const [dismissedNotice, setDismissedNotice] = useState('');
  const peer = state.contacts.find((p) => p.id === selected);
  const draft = drafts[selected] || { text: '' };
  const ready = state.enabled && !!peer?.paired;

  function updateDraft(value: Partial<Draft>) {
    setDrafts((previous) => ({
      ...previous,
      [selected]: { ...(previous[selected] || { text: '' }), ...value },
    }));
  }
  function merge(incoming: Message[], reset = false) {
    setMessages((previous) => {
      const map = new Map((reset ? [] : previous).map((m) => [m.id, m]));
      for (const message of incoming) map.set(message.id, message);
      return [...map.values()].sort((a, b) => a.seq - b.seq).slice(-500);
    });
  }
  useEffect(() => {
    if (!isTauri()) return;
    let alive = true,
      request = 0;
    if (loadedPeer.current !== selected) {
      loadedPeer.current = selected;
      setMessages([]);
      previousCount.current = 0;
      setMore(true);
      setRecoveryBefore(null);
    }
    async function load() {
      const sequence = ++request;
      try {
        const result = await invoke<Snapshot>('lan_state', {
          peerId: selected || null,
          beforeSeq: null,
          groupId: selectedGroup || null,
        });
        if (!alive || sequence !== request) return;
        setState(result);
        if (!aliasInitialized.current) {
          setAlias(result.alias);
          aliasInitialized.current = true;
        }
        if (!selected && result.contacts.length)
          setSelected(result.contacts[0].id);
        merge(result.messages);
      } catch (e) {
        if (alive) setError(String(e));
      }
    }
    void load();
    const timer = window.setInterval(() => {
      if (!document.hidden) void load();
    }, 2000);
    const onVisibilityChange = () => {
      if (!document.hidden) void load();
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      alive = false;
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [selected, selectedGroup, revision]);
  useEffect(() => {
    const element = list.current;
    if (
      element &&
      messages.length > previousCount.current &&
      (previousCount.current === 0 ||
        element.scrollHeight - element.scrollTop - element.clientHeight < 240)
    )
      element.scrollTop = element.scrollHeight;
    previousCount.current = messages.length;
  }, [messages]);

  async function act(action: string, args: Record<string, unknown> = {}) {
    setBusy(action);
    setError('');
    setNotice('');
    try {
      if (!isTauri()) throw Error('请在桌面客户端中使用局域网协作。');
      return await invoke<Record<string, unknown>>('lan_action', {
        action,
        ...args,
      });
    } catch (e) {
      setError(String(e));
      throw e;
    } finally {
      setBusy('');
      setRevision((v) => v + 1);
    }
  }
  function run(action: string, args: Record<string, unknown> = {}) {
    void act(action, args).catch(() => {});
  }
  async function send() {
    const target = selected,
      content = draft;
    try {
      if (selectedGroup && !content.path && !content.image) {
        await act('group_text', { groupId: selectedGroup, text: content.text });
        setDrafts((previous) => ({ ...previous, [target]: { text: '' } }));
        return;
      }
      if (content.path || content.image)
        await act('file', {
          peerId: target,
          path: content.path || null,
          dataUrl: content.image || null,
        });
      else await act('text', { peerId: target, text: content.text });
      setDrafts((previous) => ({
        ...previous,
        [target]: { text: content.path || content.image ? content.text : '' },
      }));
    } catch (e) {
      // 已落盘但未获 ACK 的消息从气泡重试，避免再次创建一条相同消息。
      if (String(e).includes('发送未确认'))
        setDrafts((previous) => ({
          ...previous,
          [target]: { text: content.path || content.image ? content.text : '' },
        }));
    }
  }
  async function chooseFile(sticker = false) {
    setError('');
    try {
      const path = await open({
        title: sticker
          ? '选择表情图片（PNG / JPEG / WebP / GIF）'
          : '选择要发送的文件（不超过 32 MiB）',
        multiple: false,
        ...(sticker
          ? {
              filters: [
                {
                  name: '表情图片',
                  extensions: ['png', 'jpg', 'jpeg', 'webp', 'gif'],
                },
              ],
            }
          : {}),
      });
      if (typeof path === 'string')
        updateDraft({
          path,
          image: undefined,
          name: path.split(/[/\\]/).at(-1),
        });
    } catch (e) {
      setError(String(e));
    }
  }
  async function exportFile(message: Message) {
    try {
      const path = await save({
        title: '另存聊天附件',
        defaultPath: message.body.name,
      });
      if (path) {
        await act('save', { messageId: message.id, path });
        setNotice('附件已保存；客户端不会自动打开或执行文件。');
      }
    } catch (e) {
      setError(String(e));
    }
  }
  async function moreHistory() {
    const target = selected;
    setBusy('history');
    try {
      const result = await invoke<Snapshot>('lan_state', {
        peerId: target,
        beforeSeq: messages[0]?.seq || null,
      });
      if (loadedPeer.current === target) {
        merge(result.messages);
        setMore(result.messages.length === 50);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy('');
    }
  }
  async function recoverHistory() {
    if (!peer) return;
    try {
      const result = await act('recover_history', {
        peerId: peer.id,
        beforeSeq: recoveryBefore,
      });
      const recovered = Number(result.recovered || 0);
      const hasMore = result.hasMore === true;
      const nextBefore =
        typeof result.nextBeforeSeq === 'number' ? result.nextBeforeSeq : null;
      setRecoveryBefore(hasMore ? nextBefore : null);
      setNotice(
        recovered
          ? '已从 ' +
              peer.alias +
              ' 恢复 ' +
              recovered +
              ' 条历史消息；重复记录已自动跳过。' +
              (hasMore ? ' 仍有更早记录，可继续恢复。' : '')
          : hasMore
            ? '本页没有新增记录；仍有更早记录，可继续恢复。'
            : '已核对 ' + peer.alias + ' 的历史，没有新增记录。',
      );
    } catch {
      // act already exposes a bounded error in the banner.
    }
  }
  function paste(event: React.ClipboardEvent) {
    if (!ready || busy) return;
    const image = Array.from(event.clipboardData.items)
      .find(
        (item) =>
          item.kind === 'file' &&
          ['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(
            item.type,
          ),
      )
      ?.getAsFile();
    if (!image) return;
    event.preventDefault();
    if (image.size > 8 * 1024 * 1024) {
      setError('粘贴图片超过 8 MiB。');
      return;
    }
    const target = selected;
    const reader = new FileReader();
    reader.onload = () =>
      setDrafts((previous) => ({
        ...previous,
        [target]: {
          ...(previous[target] || { text: '' }),
          image: String(reader.result),
          path: undefined,
          name: '粘贴截图',
        },
      }));
    reader.onerror = () => setError('无法读取剪贴板图片。');
    reader.readAsDataURL(image);
  }
  function openPair(nearby?: Nearby) {
    setPairing(true);
    setAddress(nearby?.endpoint || '');
    setRemoteInvite('');
    setInvite('');
  }
  function enterInvitation(value: string) {
    setRemoteInvite(value);
    if (address.trim()) return;
    try {
      const raw = value.trim().split('GAGA-LAN-1.')[1];
      const parsed = JSON.parse(
        atob(raw.replace(/-/g, '+').replace(/_/g, '/')),
      );
      if (
        Array.isArray(parsed.addresses) &&
        typeof parsed.addresses[0] === 'string'
      )
        setAddress(parsed.addresses[0]);
    } catch {
      /* 完整校验在原生端执行；输入未完成时保持当前编辑。 */
    }
  }
  return (
    <section className="lan-workspace" aria-label="局域网协作">
      {groupEditor && (
        <Modal
          title="编写群消息"
          busy={!!busy}
          onClose={() => setGroupEditor(null)}
        >
          <form
            className="modal wide"
            onSubmit={(event) => {
              event.preventDefault();
              void act('group_text', {
                groupId: groupEditor.id,
                text: groupEditor.text,
              })
                .then(() => setGroupEditor(null))
                .catch(() => {});
            }}
          >
            <div className="modal-title">
              <h2>
                {state.groups.find((g) => g.id === groupEditor.id)?.name ||
                  '群消息'}
              </h2>
              <button
                type="button"
                className="icon-button"
                disabled={!!busy}
                aria-label="关闭群消息"
                onClick={() => setGroupEditor(null)}
              >
                <X size={16} />
              </button>
            </div>
            <TextEditor
              label="群消息"
              size="large"
              required
              maxLength={16384}
              disabled={!!busy}
              value={groupEditor.text}
              onChange={(event) =>
                setGroupEditor({ ...groupEditor, text: event.target.value })
              }
            />
            {error && (
              <p role="alert" className="modal-error">
                {error}
              </p>
            )}
            <button
              className="button primary"
              disabled={!!busy || !groupEditor.text.trim()}
            >
              发送群消息
            </button>
          </form>
        </Modal>
      )}
      <header className="lan-topbar">
        <div>
          <h1>
            <MessageCircle size={19} />
            局域网协作
          </h1>
          <span>点对点通讯 · 本工作区独立保存</span>
        </div>
        <div className="lan-controls">
          <label>
            本机名称
            <input
              aria-label="局域网设备名称"
              value={alias}
              disabled={state.enabled || !!busy}
              onChange={(e) => setAlias(e.target.value)}
              maxLength={40}
            />
          </label>
          <button
            className={`button ${state.enabled ? '' : 'primary'}`}
            disabled={!!busy}
            onClick={() =>
              run(state.enabled ? 'stop' : 'start', { text: alias })
            }
          >
            <Wifi size={14} />
            {state.enabled ? '关闭协作' : '开启协作'}
          </button>
          <button
            className="button"
            disabled={!state.enabled || !!busy}
            onClick={() => openPair()}
          >
            <Plus size={14} />
            配对设备
          </button>
        </div>
      </header>
      {(error ||
        notice ||
        (state.notice && state.notice !== dismissedNotice)) && (
        <div
          className={`lan-banner ${error ? 'is-error' : ''}`}
          role={error ? 'alert' : 'status'}
        >
          {error || notice || state.notice}
          <button
            aria-label="关闭协作提示"
            onClick={() => {
              setError('');
              setNotice('');
              setDismissedNotice(state.notice);
            }}
          >
            <X size={13} />
          </button>
        </div>
      )}
      {state.notifications.some((n) => n.state === 'unread') && (
        <div className="lan-notifications" aria-label="协作通知">
          <strong>协作通知</strong>
          {state.notifications
            .filter((n) => n.state === 'unread')
            .slice(0, 3)
            .map((n) => (
              <span key={n.id}>
                {n.title} · {n.body}
              </span>
            ))}
        </div>
      )}
      <div className="lan-body">
        <aside className="lan-roster" aria-label="局域网联系人">
          <div className="lan-roster-heading">
            <strong>我的设备联系人</strong>
            <span>{state.contacts.length}</span>
          </div>
          <div className="lan-peer-list">
            {state.contacts.map((p) => (
              <button
                key={p.id}
                className={`lan-peer ${p.id === selected ? 'selected' : ''}`}
                onClick={() => setSelected(p.id)}
                aria-pressed={p.id === selected}
              >
                <span className="lan-avatar">{p.alias.slice(0, 1)}</span>
                <span>
                  <strong>{p.alias}</strong>
                  <small>
                    <i className={`lan-dot ${p.online ? 'online' : ''}`} />
                    {!p.paired
                      ? '已取消配对'
                      : !state.enabled
                        ? '本机协作已关闭'
                        : p.online
                          ? '在线'
                          : '离线 / 暂不可达'}
                  </small>
                </span>
              </button>
            ))}
            {!state.contacts.length && (
              <p className="lan-roster-empty">
                开启协作，与同网段的伙伴交换一次性邀请。
              </p>
            )}
          </div>
          <div className="lan-roster-heading">
            <strong>协作群组</strong>
            <button
              className="icon-button"
              aria-label="新建协作群组"
              disabled={!state.enabled || !!busy}
              onClick={() => {
                const name = window.prompt('群组名称', '处置组');
                if (!name) return;
                const members = state.contacts
                  .filter((p) => p.paired)
                  .map((p) => p.id);
                run('group_create', {
                  groupName: name,
                  groupType: name.includes('封禁') ? 'block' : 'custom',
                  memberIds: members,
                });
              }}
            >
              <Plus size={13} />
            </button>
          </div>
          <div className="lan-group-list">
            {state.groups.map((g) => (
              <button
                key={g.id}
                className={selectedGroup === g.id ? 'selected' : ''}
                onClick={() => setSelectedGroup(g.id)}
              >
                <span className="lan-avatar">群</span>
                <span>
                  <strong>{g.name}</strong>
                  <small>
                    {g.memberIds.length} 位成员 · {g.role}
                  </small>
                </span>
              </button>
            ))}
            {!state.groups.length && (
              <p>可从已配对设备创建处置组、封禁组或自定义组。</p>
            )}
          </div>
          {selectedGroup && (
            <button
              className="button small"
              disabled={!state.enabled || !!busy}
              onClick={() => {
                setGroupEditor({ id: selectedGroup, text: '' });
              }}
            >
              发送群消息
            </button>
          )}
          <div className="lan-roster-heading">
            <strong>附近设备</strong>
            <span>{state.enabled ? '自动发现' : '未开启'}</span>
          </div>
          <div className="lan-nearby">
            {state.discovered.map((p) => (
              <button key={p.id} onClick={() => openPair(p)} disabled={!!busy}>
                <Wifi size={14} />
                <span>
                  <strong>{p.alias}</strong>
                  <small>{p.endpoint} · 未配对</small>
                </span>
                <Plus size={13} />
              </button>
            ))}
            {state.enabled && !state.discovered.length && (
              <p>
                正在发现同网段设备…
                <br />
                发现不到时，可用对方地址和邀请手动连接。
              </p>
            )}
          </div>
          <details className="lan-storage">
            <summary>
              <ShieldCheck size={13} />
              本地保存与连接
            </summary>
            <p>{state.storage || '聊天保存在本机，联网服务默认关闭。'}</p>
            <p>下次启动需重新开启协作。聊天记录不发往模型或公共中继服务器。</p>
            {state.addresses.map((a) => (
              <code key={a}>{a}</code>
            ))}
            <small>设备指纹</small>
            <code>{state.id}</code>
            <p>
              同一台路由器下的访客隔离、系统防火墙或局域网权限可能阻止通信。
            </p>
          </details>
        </aside>
        <div className="lan-conversation">
          {peer ? (
            <>
              <header className="lan-chat-header">
                <div>
                  <strong>{peer.alias}</strong>
                  <span>
                    <i className={`lan-dot ${peer.online ? 'online' : ''}`} />
                    {peer.online ? '已认证连接在线' : '离线 / 暂不可达'} ·{' '}
                    {peer.endpoint}
                  </span>
                </div>
                <button
                  className="button"
                  disabled={!!busy || !peer.paired}
                  onClick={() => setUnpair(true)}
                >
                  取消配对
                </button>
                <button
                  className="button"
                  disabled={!!busy || !peer.paired || !peer.online}
                  onClick={() => void recoverHistory()}
                  title="从该在线伙伴恢复文本和附件元数据；附件正文需单独确认取回"
                >
                  {recoveryBefore !== null ? '继续恢复' : '恢复历史'}
                </button>
              </header>
              <div
                className="lan-message-list"
                ref={list}
                role="log"
                aria-label={`与 ${peer.alias} 的消息`}
              >
                {messages.length >= 50 && more && (
                  <button
                    className="lan-load-history"
                    disabled={!!busy}
                    onClick={() => void moreHistory()}
                  >
                    加载更早消息（最多展示 500 条）
                  </button>
                )}
                {!messages.length && (
                  <div className="lan-chat-empty">
                    <MessageCircle size={28} />
                    <strong>开始这次协作</strong>
                    <span>发送消息、表情图片，或粘贴一张截图。</span>
                  </div>
                )}
                {messages.map((message) => (
                  <article
                    key={message.id}
                    className={`lan-message ${message.direction === 'out' ? 'outgoing' : ''}`}
                  >
                    <small className="lan-message-time">
                      {timestamp(message.createdAt)}
                    </small>
                    <div className="lan-bubble">
                      {message.kind === 'text' ? (
                        <p>{message.body.text}</p>
                      ) : (
                        <>
                          {message.kind === 'image' &&
                            (message.direction === 'out' ||
                              message.state === 'received') &&
                            message.state !== 'recovered_metadata' && (
                              <ChatImage message={message} />
                            )}
                          <div className="lan-file">
                            <File size={18} />
                            <div>
                              <strong>{message.body.name}</strong>
                              <small>
                                {bytes(message.body.size)} ·{' '}
                                {message.kind === 'image'
                                  ? '图片 / 表情'
                                  : '文件'}
                              </small>
                            </div>
                          </div>
                          <details className="lan-file-hash">
                            <summary>SHA-256</summary>
                            <code>{message.body.sha256}</code>
                          </details>
                          {message.direction === 'in' &&
                            message.state === 'offered' && (
                              <div className="lan-message-actions">
                                <button
                                  className="button primary"
                                  disabled={!!busy || !ready}
                                  onClick={() =>
                                    run('receive', { messageId: message.id })
                                  }
                                >
                                  接收
                                  {message.kind === 'image' ? '图片' : '文件'}
                                </button>
                                <button
                                  className="button"
                                  disabled={!!busy}
                                  onClick={() =>
                                    run('decline', { messageId: message.id })
                                  }
                                >
                                  拒绝
                                </button>
                              </div>
                            )}
                          {((message.direction === 'out' &&
                            message.state !== 'recovered_metadata') ||
                            message.state === 'received') && (
                            <button
                              className="button"
                              disabled={!!busy}
                              onClick={() => void exportFile(message)}
                            >
                              另存文件
                            </button>
                          )}
                          {message.direction === 'out' &&
                            message.state === 'recovered_metadata' && (
                              <button
                                className="button primary"
                                disabled={!!busy || !ready}
                                onClick={() =>
                                  run('recover_attachment', {
                                    messageId: message.id,
                                  })
                                }
                              >
                                从伙伴恢复附件正文
                              </button>
                            )}
                        </>
                      )}
                    </div>
                    <div className="lan-message-status">
                      <span>
                        {message.kind !== 'text' &&
                        message.direction === 'out' &&
                        message.state === 'delivered'
                          ? '已通知 · 等待对方接收'
                          : labels[message.state] || message.state}
                      </span>
                      {message.state === 'failed' && (
                        <button
                          disabled={!!busy || !ready}
                          onClick={() =>
                            run('retry', { messageId: message.id })
                          }
                        >
                          重试
                        </button>
                      )}
                      {message.direction === 'out' &&
                        message.kind !== 'text' &&
                        message.state === 'delivered' && (
                          <button
                            disabled={!!busy || !ready}
                            onClick={() =>
                              run('retry', { messageId: message.id })
                            }
                          >
                            查询接收状态
                          </button>
                        )}
                    </div>
                  </article>
                ))}
              </div>
              <div className="lan-composer" onPaste={paste}>
                <div className="lan-composer-tools">
                  <button
                    aria-label="插入表情"
                    title="表情"
                    disabled={!ready || !!busy}
                    onClick={() => setEmoji(!emoji)}
                  >
                    <Smile size={18} />
                  </button>
                  <button
                    aria-label="发送表情图片"
                    title="发送表情图片 / GIF"
                    disabled={!ready || !!busy}
                    onClick={() => void chooseFile(true)}
                  >
                    <ImagePlus size={18} />
                  </button>
                  <button
                    aria-label="发送文件"
                    title="发送文件"
                    disabled={!ready || !!busy}
                    onClick={() => void chooseFile()}
                  >
                    <Paperclip size={18} />
                  </button>
                  <span>⌘V / Ctrl+V 粘贴截图 · ⌘Enter / Ctrl+Enter 发送</span>
                </div>
                {emoji && (
                  <div className="lan-emojis">
                    {emojis.map((value) => (
                      <button
                        key={value}
                        disabled={!ready}
                        onClick={() => {
                          updateDraft({ text: draft.text + value });
                          setEmoji(false);
                        }}
                      >
                        {value}
                      </button>
                    ))}
                  </div>
                )}
                {(draft.path || draft.image) && (
                  <div className="lan-attachment-draft">
                    {draft.image ? (
                      <img src={draft.image} alt="待发送截图预览" />
                    ) : (
                      <File size={24} />
                    )}
                    <div>
                      <strong>{draft.name}</strong>
                      <span>待发送 · 接收方确认后下载</span>
                    </div>
                    <button
                      className="icon-button"
                      aria-label="移除待发送附件"
                      disabled={!!busy}
                      onClick={() =>
                        updateDraft({
                          path: undefined,
                          image: undefined,
                          name: undefined,
                        })
                      }
                    >
                      <X size={15} />
                    </button>
                  </div>
                )}
                <TextEditor
                  label="消息"
                  aria-label="局域网消息输入"
                  value={draft.text}
                  disabled={!ready || !!busy}
                  onChange={(e) => updateDraft({ text: e.target.value })}
                  onKeyDown={(e) => {
                    if (
                      !e.nativeEvent.isComposing &&
                      (e.metaKey || e.ctrlKey) &&
                      e.key === 'Enter'
                    ) {
                      e.preventDefault();
                      if (!busy) void send();
                    }
                  }}
                  placeholder={
                    !state.enabled
                      ? '开启局域网协作后发送'
                      : !peer.paired
                        ? '此设备已取消配对'
                        : '输入消息，或粘贴截图…'
                  }
                  maxLength={16384}
                />
                <footer>
                  <span>
                    {busy
                      ? '正在处理…'
                      : draft.path || draft.image
                        ? '本次发送附件；文字草稿保留'
                        : peer.online
                          ? '消息确认保存后显示“对方已保存”'
                          : '对方离线时发送可能失败，可从消息旁重试'}
                  </span>
                  <button
                    className="button primary"
                    disabled={
                      !ready ||
                      !!busy ||
                      (!draft.text.trim() && !draft.path && !draft.image)
                    }
                    onClick={() => void send()}
                  >
                    <Send size={14} />
                    发送
                  </button>
                </footer>
              </div>
            </>
          ) : (
            <div className="lan-welcome">
              <span className="lan-welcome-icon">
                <MessageCircle size={42} strokeWidth={1.3} />
              </span>
              <h2>和同网段的伙伴一起排查</h2>
              <p>
                文字、表情、截图和文件直接在两台客户端之间传输。
                <br />
                选择联系人，或开启协作配对一台设备。
              </p>
              <small>
                通用工作区备份不包含聊天与配对数据。
                <br />
                事件资料仅在你主动选择文件时发送。
              </small>
            </div>
          )}
        </div>
      </div>
      {pairing && (
        <Modal
          title="配对局域网设备"
          busy={!!busy}
          onClose={() => setPairing(false)}
        >
          <section className="lan-pair-modal">
            <header>
              <h2>配对局域网设备</h2>
              <button
                className="icon-button"
                aria-label="关闭设备配对"
                disabled={!!busy}
                onClick={() => setPairing(false)}
              >
                <X size={18} />
              </button>
            </header>
            <p>
              一方生成邀请，通过可信渠道交给另一方。邀请固定设备证书，5
              分钟有效、仅使用一次，请勿公开。
            </p>
            <div className="lan-pair-own">
              <button
                className="button"
                disabled={!!busy}
                onClick={() => {
                  void act('invite')
                    .then((value) => setInvite(String(value.code)))
                    .catch(() => {});
                }}
              >
                生成我的邀请
              </button>
              {invite && (
                <>
                  <textarea
                    aria-label="我的局域网配对邀请"
                    readOnly
                    value={invite}
                  />
                  <button
                    className="button"
                    onClick={() => {
                      void navigator.clipboard
                        .writeText(invite)
                        .then(() => setNotice('邀请已复制，5 分钟内有效。'))
                        .catch(() =>
                          setError('复制失败，可选中邀请文字手动复制。'),
                        );
                    }}
                  >
                    <Copy size={13} />
                    复制邀请
                  </button>
                  <p>本机地址：{state.addresses.join(' / ')}</p>
                </>
              )}
            </div>
            <label>
              对方的设备地址
              <input
                aria-label="对方设备地址"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                placeholder="例如 192.168.1.20:端口"
              />
            </label>
            <TextEditor
              label="对方配对邀请"
              aria-label="对方配对邀请"
              value={remoteInvite}
              onChange={(e) => enterInvitation(e.target.value)}
              placeholder="GAGA-LAN-1.…"
              maxLength={4096}
            />
            {error && (
              <p role="alert" className="lan-pair-error">
                {error}
              </p>
            )}
            <footer>
              <button
                className="button primary"
                disabled={!!busy || !address.trim() || !remoteInvite.trim()}
                onClick={() => {
                  void act('pair', {
                    path: address.trim(),
                    text: remoteInvite.trim(),
                  })
                    .then(() => {
                      setPairing(false);
                      setNotice('设备已配对，可以开始通讯。');
                    })
                    .catch(() => {});
                }}
              >
                确认配对
              </button>
            </footer>
          </section>
        </Modal>
      )}
      {unpair && peer && (
        <Modal
          title="取消设备配对"
          busy={!!busy}
          onClose={() => setUnpair(false)}
        >
          <section className="lan-pair-modal">
            <h2>取消与 {peer.alias} 配对？</h2>
            <p>
              此设备的旧凭据将无法再接收消息或索取附件。本机聊天记录保留；再次通讯需要重新交换邀请。
            </p>
            <footer>
              <button className="button" onClick={() => setUnpair(false)}>
                返回
              </button>
              <button
                className="button primary"
                disabled={!!busy}
                onClick={() => {
                  void act('unpair', { peerId: peer.id })
                    .then(() => setUnpair(false))
                    .catch(() => {});
                }}
              >
                取消配对
              </button>
            </footer>
          </section>
        </Modal>
      )}
    </section>
  );
}
