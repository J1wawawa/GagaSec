import { useLayoutEffect, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

const dialogs: HTMLElement[] = [];
let previousInert = false;

export function Modal({
  title,
  busy = false,
  onClose,
  children,
}: {
  title: string;
  busy?: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const trigger = useRef(document.activeElement as HTMLElement | null);
  const latest = useRef({ busy, onClose });
  latest.current = { busy, onClose };
  useLayoutEffect(() => {
    const dialog = ref.current!;
    const root = document.getElementById('root');
    if (!dialogs.length && root) {
      previousInert = root.inert;
      root.inert = true;
    }
    dialogs.push(dialog);
    const focusable = () =>
      Array.from(
        dialog.querySelectorAll<HTMLElement>(
          'button, input, textarea, select, a[href], [tabindex]',
        ),
      ).filter(
        (element) =>
          element.tabIndex >= 0 &&
          !element.matches(':disabled') &&
          element.getClientRects().length > 0,
      );
    const initial = dialog.querySelector<HTMLElement>(
      '[aria-label="粘贴截图区域"], [autofocus], input, textarea, select',
    );
    (initial || focusable()[0] || dialog).focus();
    function keydown(event: KeyboardEvent) {
      if (dialogs.at(-1) !== dialog) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        if (!latest.current.busy) latest.current.onClose();
      }
      if (event.key === 'Tab') {
        const items = focusable();
        const index = items.indexOf(document.activeElement as HTMLElement);
        if (!items.length) {
          event.preventDefault();
          dialog.focus();
        } else if (
          index < 0 ||
          (event.shiftKey ? index === 0 : index === items.length - 1)
        ) {
          event.preventDefault();
          items[event.shiftKey ? items.length - 1 : 0].focus();
        }
      }
    }
    document.addEventListener('keydown', keydown, true);
    return () => {
      document.removeEventListener('keydown', keydown, true);
      dialogs.splice(dialogs.indexOf(dialog), 1);
      if (!dialogs.length && root) root.inert = previousInert;
      if (trigger.current?.isConnected && !trigger.current.closest('[inert]'))
        trigger.current.focus();
    };
  }, []);
  return createPortal(
    <div
      ref={ref}
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      tabIndex={-1}
    >
      {children}
    </div>,
    document.body,
  );
}
