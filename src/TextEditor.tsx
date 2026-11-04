import {
  useId,
  useRef,
  useState,
  type ReactNode,
  type TextareaHTMLAttributes,
} from 'react';
import { Maximize2, Minimize2 } from 'lucide-react';
import { Modal } from './Modal';
import './text-editor.css';

type Props = Omit<
  TextareaHTMLAttributes<HTMLTextAreaElement>,
  'value' | 'size'
> & {
  label: string;
  value: string;
  hint?: string;
  actions?: ReactNode;
  size?: 'note' | 'large' | 'document' | 'fill';
  fieldClassName?: string;
  code?: boolean;
};

/** The expanded editor shares the original controlled value. Opening/closing
 * never saves, submits or discards a form; the owning workflow keeps authority. */
export function TextEditor({
  label,
  hint,
  actions,
  size = 'note',
  fieldClassName = '',
  code = false,
  ...props
}: Props) {
  const id = useId();
  const source = useRef<HTMLTextAreaElement>(null);
  const [expanded, setExpanded] = useState(false);
  const selection = useRef({ start: 0, end: 0 });
  const close = () => {
    setExpanded(false);
    requestAnimationFrame(() => {
      source.current?.focus({ preventScroll: true });
      source.current?.setSelectionRange(
        selection.current.start,
        selection.current.end,
      );
    });
  };
  const count = `${props.value.length.toLocaleString()}${props.maxLength ? ' / ' + props.maxLength.toLocaleString() : ''} 字`;
  return (
    <div
      className={`text-editor ${fieldClassName}`}
      data-size={size}
      data-code={code}
    >
      <div className="text-editor-heading">
        <label className="text-editor-label" htmlFor={props.id || id}>
          {label}
        </label>
        <div className="text-editor-actions">
          {actions}
          <button
            type="button"
            className="button small text-editor-expand"
            aria-label={`放大编辑 ${label}`}
            disabled={props.disabled}
            onClick={(event) => {
              event.currentTarget.focus();
              selection.current = {
                start: source.current?.selectionStart || 0,
                end: source.current?.selectionEnd || 0,
              };
              setExpanded(true);
            }}
          >
            <Maximize2 size={14} />
            放大编辑
          </button>
        </div>
      </div>
      {hint && <p className="text-editor-hint">{hint}</p>}
      <textarea
        {...props}
        id={props.id || id}
        ref={source}
        aria-label={props['aria-label'] || label}
      />
      <small className="text-editor-count">{count}</small>
      {expanded && (
        <Modal title={`编辑 ${label}`} onClose={close}>
          <section className="text-editor-focus" data-code={code}>
            <header>
              <div>
                <h2>{label}</h2>
                <p>与原表单同步 · Esc 返回继续填写</p>
              </div>
              <button type="button" className="button primary" onClick={close}>
                <Minimize2 size={15} />
                完成编辑
              </button>
            </header>
            {hint && <p className="text-editor-hint">{hint}</p>}
            <textarea
              {...props}
              id={id + '-expanded'}
              aria-label={props['aria-label'] || label}
              ref={(element) => {
                if (element && document.activeElement !== element) {
                  element.focus({ preventScroll: true });
                  element.setSelectionRange(
                    selection.current.start,
                    selection.current.end,
                  );
                }
              }}
              onSelect={(event) => {
                selection.current = {
                  start: event.currentTarget.selectionStart,
                  end: event.currentTarget.selectionEnd,
                };
                props.onSelect?.(event);
              }}
            />
            <footer>
              <span>关闭编辑区不会提交表单；请按原流程保存或发送。</span>
              <small>{count}</small>
            </footer>
          </section>
        </Modal>
      )}
    </div>
  );
}
