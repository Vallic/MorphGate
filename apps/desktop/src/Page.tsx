import type { ReactNode } from "react";

interface Props {
  title: ReactNode;
  /** Beside the title: a role, a count. */
  badge?: ReactNode;
  /** Under the title: what the page is for, or its state. */
  lead?: ReactNode;
  /** A link back to the page this one belongs to. */
  back?: { label: string; onClick: () => void };
  /** Buttons beside the title ("New …"). */
  actions?: ReactNode;
  onClose?: () => void;
  /** The narrow right-hand column (stacks under the main one in narrow windows). */
  aside?: ReactNode;
  children: ReactNode;
}

/** A page that fills the workspace: a title, then one or two columns. */
export function Page({ title, badge, lead, back, actions, onClose, aside, children }: Props) {
  return (
    <div className="panel page">
      <div className="page-inner">
        <header className="page-head">
          {back && (
            <button type="button" className="link align-start" onClick={back.onClick}>
              ← {back.label}
            </button>
          )}
          <div className="page-title">
            <h1>{title}</h1>
            {badge}
            {(actions || onClose) && (
              <div className="page-actions">
                {actions}
                {onClose && (
                  <button type="button" className="secondary page-close" onClick={onClose}>
                    Close
                  </button>
                )}
              </div>
            )}
          </div>
          {lead && <div className="page-lead">{lead}</div>}
        </header>
        {aside ? (
          <div className="page-columns">
            <div className="page-main">{children}</div>
            <aside className="page-aside">{aside}</aside>
          </div>
        ) : (
          <div className="page-main">{children}</div>
        )}
      </div>
    </div>
  );
}
