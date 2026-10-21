// The list pattern the pages share (Lists.tsx, TeamsPanel.tsx): a table with a row per item, its
// name first (its main action), the columns people scan, then the row's other actions, shown on
// hover or keyboard focus; a toolbar with search, filters and Select; states as squares and chips.

import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { Icon, type IconName } from "./Icon";
import type { pickOf, Selection } from "./Selection";
import type { LiveState } from "./Sidebar";

/** What a row needs while its list is selecting (see Selection.tsx). */
export type Pick = ReturnType<typeof pickOf>;

/** A list as a table. `cols`: the grid's columns, the actions' column last; `head`: their titles. */
export function Table({ cols, label, head, children }: { cols: string; label: string; head: string[]; children: ReactNode }) {
  return (
    <div className="ltable" role="table" aria-label={label} style={{ "--cols": cols } as CSSProperties}>
      <div className="lthead" role="row">
        {head.map((h, i) => (
          <span key={i} role="columnheader" className="section-title">
            {h}
          </span>
        ))}
        <span role="columnheader">
          <span className="visually-hidden">Actions</span>
        </span>
      </div>
      {children}
    </div>
  );
}

/** One row: its cells, then its actions. Picking: the whole row toggles it, and no actions. */
export function TRow({ index, pick, className, children, actions }: { index: number; pick?: Pick; className?: string; children: ReactNode; actions?: ReactNode }) {
  const classes = ["lrow", index % 2 === 1 && "band", pick && "picking", pick?.on && "picked", className].filter(Boolean).join(" ");
  return (
    <div role="row" className={classes} onClick={pick?.toggle}>
      {children}
      <span role="cell" className="rowact">
        {!pick && actions}
      </span>
    </div>
  );
}

/** A row's first cell: its name (a button for the row's main action) with what goes beside it,
 * and a line under it. Picking: a checkbox in front, and the name is only text. */
export function NameCell({
  pick,
  onOpen,
  title,
  lead,
  name,
  beside,
  sub,
  subTone,
}: {
  pick?: Pick;
  onOpen?: () => void;
  /** What the name's button does ("Connect to web-1"). */
  title?: string;
  /** Before the name: a status square or an icon. */
  lead?: ReactNode;
  name: string;
  beside?: ReactNode;
  /** The line under it: text only, so it shrinks to an ellipsis (the whole of it on hover). */
  sub?: string;
  /** That line is machine text (an address), or a problem. */
  subTone?: "mono" | "error";
}) {
  const inner = (
    <>
      {lead}
      <span className="lstack">
        <span className="lname-row">
          <span className="lname">{name}</span>
          {beside}
        </span>
        {sub && (
          <span className={`lsub ${subTone === "mono" ? "mono" : subTone === "error" ? "error-text" : ""}`} title={sub}>
            {sub}
          </span>
        )}
      </span>
    </>
  );
  return (
    <span role="cell" className="lcell lfirst">
      {pick && (
        <input type="checkbox" className="pick" checked={pick.on} onChange={pick.toggle} onClick={(e) => e.stopPropagation()} aria-label={`Select ${pick.label}`} />
      )}
      {pick || !onOpen ? (
        <span className="lnamebtn">{inner}</span>
      ) : (
        <button type="button" className="lnamebtn" onClick={onOpen} title={title}>
          {inner}
        </button>
      )}
    </span>
  );
}

export const Cell = ({ children, className }: { children?: ReactNode; className?: string }) => (
  <span role="cell" className={`lcell ${className ?? ""}`}>
    {children}
  </span>
);

/** A connection's state as a square, from the mark's cursor: shape and colour. */
export function StatusSq({ state }: { state: LiveState | undefined }) {
  return <span className={`sq ${state ?? "idle"}`} title={state === "connected" ? "Connected" : state === "connecting" ? "Connecting" : "Not connected"} />;
}

/** A state in a word, with its square. */
export function Chip({ state, children }: { state: "connected" | "idle" | "attention" | "failed"; children: ReactNode }) {
  return (
    <span className={`chip ${state}`}>
      <i aria-hidden="true" />
      {children}
    </span>
  );
}

/** A row action as an icon. */
export function IconAction({ icon, label, onClick }: { icon: IconName; label: string; onClick: () => void }) {
  return (
    <button type="button" className="icon small" onClick={onClick} title={label} aria-label={label}>
      <Icon name={icon} size={14} />
    </button>
  );
}

/** A row action in words (Connect, Run). */
export function TextAction({ children, onClick, warn }: { children: ReactNode; onClick: () => void; warn?: boolean }) {
  return (
    <button type="button" className={`text-action ${warn ? "warn" : ""}`} onClick={onClick}>
      {children}
    </button>
  );
}

/** A list's toolbar: the search, filters, and Select (which the bar replaces while selecting). */
export function Toolbar({
  query,
  setQuery,
  placeholder,
  label,
  filters,
  sel,
  any,
}: {
  query: string;
  setQuery: (q: string) => void;
  placeholder: string;
  label: string;
  filters?: ReactNode;
  sel: Selection;
  any: boolean;
}) {
  return (
    <div className="ltoolbar">
      <label className="search page-search">
        <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <circle cx="11" cy="11" r="6" />
          <path d="M20 20l-4.5-4.5" />
        </svg>
        <input placeholder={placeholder} aria-label={label} value={query} onChange={(e) => setQuery(e.target.value)} spellCheck={false} />
      </label>
      {filters}
      <span className="spacer" />
      {any && !sel.on && (
        <button type="button" className="quiet small-button" onClick={sel.start}>
          Select
        </button>
      )}
    </div>
  );
}

/** Filter buttons: one shown at a time ("all", or one of the others). */
export function Filters({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: { key: string; label: string; count?: number }[] }) {
  return (
    <div className="filters" role="group" aria-label="Show">
      {options.map((o) => (
        <button key={o.key} type="button" className={`filter ${value === o.key ? "on" : ""}`} aria-pressed={value === o.key} onClick={() => onChange(value === o.key ? "all" : o.key)}>
          {o.label}
          {o.count !== undefined && <b>{o.count}</b>}
        </button>
      ))}
    </div>
  );
}

/** "Add from…": the other ways to add, in a menu. */
export function AddFrom({ items }: { items: { label: string; sub: string; onClick: () => void }[] }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => (document.removeEventListener("mousedown", away), document.removeEventListener("keydown", esc));
  }, [open]);
  return (
    <div className="add-from" ref={ref}>
      <button type="button" className="secondary" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>
        Add from…
        <Icon name="chevron" size={12} />
      </button>
      {open && (
        <div className="menu" role="menu">
          {items.map((it) => (
            <button key={it.label} type="button" role="menuitem" className="menu-item" onClick={() => (setOpen(false), it.onClick())}>
              <span className="menu-title">{it.label}</span>
              <span className="menu-sub">{it.sub}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

