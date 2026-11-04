import { Component, type ReactNode } from 'react';
import { invoke, isTauri } from './bridge';
import { reportError } from './bridge';

// A rendering failure must leave a recoverable message instead of a blank window.
// Reloading the UI reuses the already initialized backend; it does not reopen DBs.
export class AppErrorBoundary extends Component<
  { children: ReactNode },
  { failure: string }
> {
  state = { failure: '' };
  static getDerivedStateFromError(error: unknown) {
    return { failure: String(error) };
  }
  componentDidCatch(error: unknown) {
    reportError('render', error);
  }
  render() {
    if (!this.state.failure) return this.props.children;
    return (
      <div className="splash startup-screen" role="alert">
        <section className="startup-console">
          <header>
            <strong>工作界面载入失败</strong>
          </header>
          <div className="startup-error">
            <p>{this.state.failure}</p>
            <small>
              本地工作区保留。可以重新加载界面；若反复出现，请附版本和此错误反馈。
            </small>
            <div>
              <button
                className="button"
                onClick={() => window.location.reload()}
              >
                重新加载界面
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
        </section>
      </div>
    );
  }
}
