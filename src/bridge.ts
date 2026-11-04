// One IPC boundary records failures without serializing arguments or results.
// Use the native invoke directly for the log sink to prevent recursive logging.
import {
  invoke as nativeInvoke,
  isTauri,
  type InvokeArgs,
  type InvokeOptions,
} from '@tauri-apps/api/core';
export { isTauri };
export function reportError(component: string, error: unknown) {
  if (!isTauri()) return;
  void nativeInvoke('record_client_error', {
    component: component.slice(0, 80),
    message: String(error).slice(0, 2048),
  }).catch(() => {
    // A broken log sink cannot trigger another IPC/log loop. The log page also
    // reports its own read/write health so a disk failure stays visible.
  });
}
export function invoke<T>(
  command: string,
  args?: InvokeArgs,
  options?: InvokeOptions,
): Promise<T> {
  return nativeInvoke<T>(command, args, options).catch((error: unknown) => {
    if (!['record_client_error', 'get_runtime_logs'].includes(command))
      reportError(command, error);
    throw error;
  });
}
export function installErrorCapture() {
  window.addEventListener('error', (event) =>
    reportError('frontend', event.message || 'UI resource failed'),
  );
  window.addEventListener('unhandledrejection', (event) =>
    reportError('promise', event.reason),
  );
}
