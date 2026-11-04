import { useEffect, useState } from 'react';
import {
  Activity,
  BookOpen,
  CodeXml,
  Container,
  Database,
  FileCode2,
  FileSearch,
  FolderOpen,
  LayoutGrid,
  Monitor,
  Network,
  Radar,
  Route,
  ScanLine,
  Search,
  Settings2,
  ShieldCheck,
  X,
  ArrowUpRight,
  MessageCircle,
} from 'lucide-react';
import { Modal } from './Modal';
import { moduleInfo, type Module } from './types';

export const moduleIcons: Record<Module, typeof Activity> = {
  dashboard: Activity,
  cases: FolderOpen,
  assets: Monitor,
  flows: Activity,
  agents: Container,
  knowledge: Database,
  lists: ShieldCheck,
  samples: FileCode2,
  environment: Monitor,
  logs: FileSearch,
  http: Network,
  triage: Radar,
  containers: Container,
  webshell: CodeXml,
  binary: ScanLine,
  sandbox: Activity,
  intel: Radar,
  evidence: FolderOpen,
  timeline: Route,
  reports: BookOpen,
  lan: MessageCircle,
  settings: Settings2,
};

type NavigationGroup = {
  id: string;
  label: string;
  description: string;
  modules: Module[];
};

export const navigationGroups: NavigationGroup[] = [
  {
    id: 'investigation',
    label: '事件调查',
    description: '独立事件 · 原始证据 · 处置举证 · 报告交付',
    modules: ['cases', 'evidence', 'timeline'],
  },
  {
    id: 'reports',
    label: '报告',
    description: '报告正文编辑 · 节点与截图 · 预览与导出',
    modules: ['reports'],
  },
  {
    id: 'logs',
    label: '日志分析',
    description: '访问日志 · 系统日志 · 攻击时间线',
    modules: ['logs'],
  },
  {
    id: 'http',
    label: 'HTTP',
    description: '请求与响应联合分析 · HAR 交互 · AI 复核',
    modules: ['http'],
  },
  {
    id: 'triage',
    label: '告警研判',
    description: 'NDR / WAF / EDR 原文 · 证据核对 · AI 研判',
    modules: ['triage'],
  },
  {
    id: 'collection',
    label: '采集排查',
    description: '专属采集任务 · 加密回收 · 容器配置检查',
    modules: ['agents', 'containers'],
  },
  {
    id: 'samples',
    label: '样本分析',
    description: '脚本与可执行文件 · 静态检查 · 动态观察 · 案例归档',
    modules: ['webshell', 'binary', 'sandbox', 'samples'],
  },
  {
    id: 'monitoring',
    label: '持续监控',
    description: '页面与脚本基线 · 重点主机流量',
    modules: ['assets', 'flows'],
  },
  {
    id: 'intelligence',
    label: '威胁情报',
    description: 'IOC 来源 · 黑白名单 · 线索提取',
    modules: ['knowledge', 'lists', 'intel'],
  },
];

type NavigationProps = {
  page: Module;
  onNavigate: (page: Module) => void;
};

export function PrimaryNavigation({ page, onNavigate }: NavigationProps) {
  const [lastPages, setLastPages] = useState<Record<string, Module>>({});
  useEffect(() => {
    const group = navigationGroups.find((g) => g.modules.includes(page));
    if (group) setLastPages((previous) => ({ ...previous, [group.id]: page }));
  }, [page]);
  return (
    <nav className="primary-navigation" aria-label="主工作区">
      <button
        className="dashboard-primary"
        aria-current={page === 'dashboard' ? 'page' : undefined}
        onClick={() => onNavigate('dashboard')}
      >
        总览
      </button>
      {navigationGroups.map((group) => (
        <button
          key={group.id}
          data-group={group.id}
          title={group.description}
          aria-current={group.modules.includes(page) ? 'page' : undefined}
          onClick={() => onNavigate(lastPages[group.id] || group.modules[0])}
        >
          {group.label}
        </button>
      ))}
    </nav>
  );
}

export function ToolNavigation({
  page,
  onNavigate,
  nodeCount,
}: NavigationProps & { nodeCount: number }) {
  const activeGroup = navigationGroups.find((group) =>
    group.modules.includes(page),
  );
  const showTools = !!activeGroup && activeGroup.modules.length > 1;
  return (
    <nav
      className="module-navigation"
      aria-label="当前工作区工具"
      hidden={!showTools}
    >
      {navigationGroups.map((group) => (
        <div
          key={group.id}
          data-group={group.id}
          data-active={group.modules.includes(page)}
        >
          {group.modules.map((module) => {
            const Icon = moduleIcons[module];
            return (
              <button
                key={module}
                className={`nav-item ${page === module ? 'active' : ''}`}
                data-module={module}
                aria-current={page === module ? 'page' : undefined}
                onClick={() => onNavigate(module)}
              >
                <Icon size={16} strokeWidth={1.65} />
                <span>{moduleInfo[module].title}</span>
                {module === 'timeline' && nodeCount > 0 && (
                  <small>{nodeCount}</small>
                )}
              </button>
            );
          })}
          <span className="navigation-context">{group.description}</span>
        </div>
      ))}
    </nav>
  );
}

const searchAliases: Partial<Record<Module, string>> = {
  logs: 'log nginx apache auth syslog ssh',
  http: 'request response har 请求包 响应包',
  triage: 'alert ndr waf edr',
  agents: 'agent 取证 信息收集 加密 解密',
  containers: 'docker baseline 基线',
  webshell: 'php jsp asp 脚本 木马',
  binary: 'pe elf exe dll 病毒 木马',
  sandbox: 'docker cape windows vm 虚拟机 沙箱 病毒',
  samples: 'hash md5 sha256 exe 木马 病毒',
  assets: 'javascript js 暗链 劫持',
  flows: 'ebpf bpf 流量 网络',
  knowledge: 'ioc stix ip hash 威胁指标',
  reports: 'doc docx html pdf 报告',
  lan: 'p2p lan 聊天 通讯 消息 文件 表情 截图 在线 局域网',
  settings: 'ai deepseek qwen glm kimi 模型 api key 主题',
};

export function ToolLauncher({ page, onNavigate }: NavigationProps) {
  const [opened, setOpened] = useState(false);
  const [query, setQuery] = useState('');
  const [highlighted, setHighlighted] = useState<Module | null>(null);
  const groups = [
    ...navigationGroups,
    {
      id: 'client',
      label: '客户端',
      description: '',
      modules: ['dashboard', 'lan', 'environment', 'settings'] as Module[],
    },
  ];
  const terms = query.toLocaleLowerCase().trim().split(/\s+/);
  const matches = groups
    .map((group) => ({
      ...group,
      modules: group.modules.filter((module) => {
        const searchable =
          `${group.label} ${moduleInfo[module].title} ${moduleInfo[module].subtitle} ${searchAliases[module] || ''}`.toLocaleLowerCase();
        return terms.every((term) => searchable.includes(term));
      }),
    }))
    .filter((group) => group.modules.length);
  const results = matches.flatMap((group) => group.modules);
  const active =
    highlighted && results.includes(highlighted) ? highlighted : results[0];
  function openTools() {
    setQuery('');
    setHighlighted(null);
    setOpened(true);
  }
  function choose(module: Module) {
    setOpened(false);
    onNavigate(module);
  }
  useEffect(() => {
    function shortcut(event: KeyboardEvent) {
      if (
        (event.metaKey || event.ctrlKey) &&
        event.key.toLowerCase() === 'k' &&
        !event.altKey &&
        !document.querySelector('[role="dialog"]')
      ) {
        event.preventDefault();
        openTools();
      }
    }
    document.addEventListener('keydown', shortcut);
    return () => document.removeEventListener('keydown', shortcut);
  }, []);
  useEffect(() => {
    if (opened && active)
      document
        .getElementById(`tool-option-${active}`)
        ?.scrollIntoView({ block: 'nearest' });
  }, [opened, active]);
  return (
    <>
      <button
        className="tool-launcher-button"
        onClick={openTools}
        title="全部工具（⌘K / Ctrl+K）"
        aria-label="全部工具"
        aria-haspopup="dialog"
        aria-expanded={opened}
      >
        <LayoutGrid size={16} />
        <span>全部工具</span>
      </button>
      {opened && (
        <Modal title="全部工具" onClose={() => setOpened(false)}>
          <section className="tool-palette">
            <header>
              <div>
                <h2>全部工具</h2>
                <span>按任务查找，直接打开</span>
              </div>
              <button
                className="icon-button"
                aria-label="关闭全部工具"
                onClick={() => setOpened(false)}
              >
                <X size={17} />
              </button>
            </header>
            <div className="tool-search">
              <Search size={17} />
              <input
                role="combobox"
                aria-label="搜索工具"
                aria-controls="tool-search-results"
                aria-expanded="true"
                aria-autocomplete="list"
                aria-activedescendant={
                  active ? `tool-option-${active}` : undefined
                }
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setHighlighted(null);
                }}
                onKeyDown={(event) => {
                  if (event.nativeEvent.isComposing) return;
                  if (event.key === 'Enter' && active) {
                    event.preventDefault();
                    choose(active);
                  }
                  if (
                    ['ArrowDown', 'ArrowUp'].includes(event.key) &&
                    results.length
                  ) {
                    event.preventDefault();
                    const direction = event.key === 'ArrowDown' ? 1 : -1;
                    const next =
                      (results.indexOf(active) + direction + results.length) %
                      results.length;
                    setHighlighted(results[next]);
                  }
                }}
                placeholder="搜索功能，例如 HTTP、Docker、截图、IOC…"
              />
              <kbd>Esc</kbd>
            </div>
            <div className="tool-result-summary" aria-live="polite">
              {query
                ? `找到 ${results.length} 个工具`
                : `${results.length} 个独立功能入口`}
            </div>
            <div
              className="tool-results"
              id="tool-search-results"
              role="listbox"
              aria-label="工具搜索结果"
            >
              {matches.map((group) => (
                <section role="group" aria-label={group.label} key={group.id}>
                  <h3>{group.label}</h3>
                  <div className="tool-group-items">
                    {group.modules.map((module) => {
                      const Icon = moduleIcons[module];
                      return (
                        <button
                          key={module}
                          id={`tool-option-${module}`}
                          role="option"
                          aria-selected={module === active}
                          data-tool={module}
                          className={module === active ? 'highlighted' : ''}
                          onClick={() => choose(module)}
                        >
                          <Icon size={17} strokeWidth={1.6} />
                          <span>
                            <strong>{moduleInfo[module].title}</strong>
                            <small>{moduleInfo[module].subtitle}</small>
                          </span>
                          {page === module ? (
                            <em>当前</em>
                          ) : (
                            <ArrowUpRight size={14} />
                          )}
                        </button>
                      );
                    })}
                  </div>
                </section>
              ))}
              {!results.length && (
                <div className="tools-empty">
                  <Search size={24} />
                  <strong>没有找到相关工具</strong>
                  <span>试试“日志”“样本”“Agent”或“报告”</span>
                </div>
              )}
            </div>
            <footer>
              <span>↑ ↓ 选择 · Enter 打开 · Esc 关闭</span>
              <span>⌘K / Ctrl+K 随时查找</span>
            </footer>
          </section>
        </Modal>
      )}
    </>
  );
}
