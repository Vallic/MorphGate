import { useCallback, useEffect, useRef, useState, type DragEvent, type KeyboardEvent, type ReactNode } from "react";
import {
  errorText,
  isDir,
  localFs,
  sftp,
  type ConnectTarget,
  type FileEntry,
  type Listing,
  type TransferEvent,
  type TransferProgress,
} from "./api";
import type { TabStatus } from "./TerminalView";

type Side = "local" | "remote";
const DRAG_TYPE = "application/x-morphgate-files";

interface Props {
  target: ConnectTarget;
  title: string;
  active: boolean;
  onStatus: (status: TabStatus) => void;
}

// ------------------------------------------------------------------ paths & formatting

const sepOf = (path: string) => (path.includes("\\") && !path.includes("/") ? "\\" : "/");

const FOLDER = "M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z";
const FILE = "M6 3h8l4 4v14H6zM14 3v4h4";
const LINK = "M6 3h8l4 4v14H6zM14 3v4h4M9 15h6M12 12l3 3-3 3";

export function joinPath(dir: string, name: string): string {
  const sep = sepOf(dir);
  return dir.endsWith(sep) ? dir + name : dir + sep + name;
}

export function parentPath(path: string): string {
  const sep = sepOf(path);
  const trimmed = path.length > 1 && path.endsWith(sep) ? path.slice(0, -1) : path;
  const i = trimmed.lastIndexOf(sep);
  if (i <= 0) return sep === "/" ? "/" : trimmed.slice(0, 3);
  const parent = trimmed.slice(0, i);
  return /^[A-Za-z]:$/.test(parent) ? parent + sep : parent;
}

export function formatSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[u]}`;
}

export function formatMode(mode: number | null, dir: boolean): string {
  if (mode === null) return "";
  const bits = ["r", "w", "x"];
  let s = dir ? "d" : "-";
  for (let i = 8; i >= 0; i--) s += mode & (1 << i) ? bits[(8 - i) % 3] : "-";
  return s;
}

const formatTime = (t: number | null) =>
  t === null ? "" : new Date(t * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

// ------------------------------------------------------------------ panes

interface PaneState {
  path: string;
  entries: FileEntry[];
  selected: Set<string>;
  error: string;
  loading: boolean;
}

function usePane(lister: ((path: string) => Promise<Listing>) | null) {
  const [state, setState] = useState<PaneState>({ path: "", entries: [], selected: new Set(), error: "", loading: false });
  const pathRef = useRef("");

  const load = useCallback(
    async (path: string) => {
      if (!lister) return;
      setState((s) => ({ ...s, loading: true }));
      try {
        const l = await lister(path);
        pathRef.current = l.path;
        setState({ path: l.path, entries: l.entries, selected: new Set(), error: "", loading: false });
      } catch (e) {
        setState((s) => ({ ...s, error: errorText(e), loading: false }));
      }
    },
    [lister],
  );
  const refresh = useCallback(() => load(pathRef.current), [load]);
  const select = (selected: Set<string>) => setState((s) => ({ ...s, selected }));
  return { ...state, load, refresh, select };
}

type PaneApi = ReturnType<typeof usePane>;

interface PaneProps {
  side: Side;
  title: string;
  pane: PaneApi;
  toolbar: ReactNode;
  onDropFiles: (from: Side, paths: string[], into: string) => void;
  onDelete?: () => void;
  innerRef?: (el: HTMLDivElement | null) => void;
}

function Pane({ side, title, pane, toolbar, onDropFiles, onDelete, innerRef }: PaneProps) {
  const [editing, setEditing] = useState<string | null>(null);
  const [over, setOver] = useState<string | null>(null);
  const anchor = useRef<number>(-1);

  const click = (e: React.MouseEvent, i: number, name: string) => {
    const next = new Set(e.metaKey || e.ctrlKey ? pane.selected : []);
    if (e.shiftKey && anchor.current >= 0) {
      const [a, b] = [anchor.current, i].sort((x, y) => x - y);
      for (let k = a; k <= b; k++) next.add(pane.entries[k].name);
    } else if ((e.metaKey || e.ctrlKey) && pane.selected.has(name)) {
      next.delete(name);
    } else {
      next.add(name);
      anchor.current = i;
    }
    pane.select(next);
  };

  const open = (entry: FileEntry) => {
    if (isDir(entry)) void pane.load(joinPath(pane.path, entry.name));
  };

  const dragStart = (e: DragEvent, name: string) => {
    const names = pane.selected.has(name) ? [...pane.selected] : [name];
    if (!pane.selected.has(name)) pane.select(new Set([name]));
    e.dataTransfer.setData(DRAG_TYPE, JSON.stringify({ side, paths: names.map((n) => joinPath(pane.path, n)) }));
    e.dataTransfer.effectAllowed = "copy";
  };

  const accepts = (e: DragEvent) => e.dataTransfer.types.includes(DRAG_TYPE);

  const drop = (e: DragEvent, into: string) => {
    e.preventDefault();
    e.stopPropagation();
    setOver(null);
    const raw = e.dataTransfer.getData(DRAG_TYPE);
    if (!raw) return;
    const data = JSON.parse(raw) as { side: Side; paths: string[] };
    if (data.side !== side) onDropFiles(data.side, data.paths, into);
  };

  const keys = (e: KeyboardEvent) => {
    if (e.target instanceof HTMLInputElement) return;
    if (e.key === "Backspace") {
      e.preventDefault();
      void pane.load(parentPath(pane.path));
    } else if (e.key === "Enter" && pane.selected.size === 1) {
      const entry = pane.entries.find((x) => pane.selected.has(x.name));
      if (entry) open(entry);
    } else if (e.key === "Delete" && onDelete && pane.selected.size > 0) {
      onDelete();
    } else if (e.key === "a" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      pane.select(new Set(pane.entries.map((x) => x.name)));
    }
  };

  return (
    <div
      className={`fpane ${over === "" ? "drop" : ""}`}
      ref={innerRef}
      data-side={side}
      tabIndex={0}
      onKeyDown={keys}
      onDragOver={(e) => {
        if (accepts(e)) {
          e.preventDefault();
          setOver((o) => o ?? "");
        }
      }}
      onDragLeave={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) setOver(null);
      }}
      onDrop={(e) => drop(e, pane.path)}
    >
      <div className="fpane-head">
        <span className={`fpane-icon ${side}`} aria-hidden="true">
          {side === "local" ? (
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="4" width="18" height="12" rx="2" />
              <path d="M8 20h8M12 16v4" />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <rect x="4" y="4" width="16" height="7" rx="2" />
              <rect x="4" y="13" width="16" height="7" rx="2" />
              <path d="M8 7.5h.01M8 16.5h.01" />
            </svg>
          )}
        </span>
        <strong className="fpane-title">{title}</strong>
        <button type="button" className="icon small" title="Up" aria-label="Parent folder" onClick={() => void pane.load(parentPath(pane.path))}>
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M12 19V5M6 11l6-6 6 6" />
          </svg>
        </button>
        {editing === null ? (
          <button type="button" className="path-text mono" title="Type a path" onClick={() => setEditing(pane.path)}>
            {pane.path || "…"}
          </button>
        ) : (
          <input
            className="mono"
            autoFocus
            value={editing}
            onChange={(e) => setEditing(e.target.value)}
            onBlur={() => setEditing(null)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                void pane.load(editing.trim() || pane.path);
                setEditing(null);
              } else if (e.key === "Escape") setEditing(null);
            }}
            spellCheck={false}
          />
        )}
        <button type="button" className="icon small" title="Refresh" aria-label="Refresh" onClick={() => void pane.refresh()}>
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5" />
          </svg>
        </button>
      </div>
      <div className="fpane-tools">{toolbar}</div>
      {pane.error && <p className="error fpane-error">{pane.error}</p>}
      <div className="flist" role="grid" aria-busy={pane.loading}>
        <div className="frow fhead" role="row">
          <span>Name</span>
          <span>Size</span>
          <span>Modified</span>
          <span>Permissions</span>
        </div>
        {pane.path !== "" && pane.entries.length === 0 && !pane.loading && !pane.error && <p className="hint empty-dir">Empty folder</p>}
        {pane.entries.map((e, i) => (
          <div
            key={e.name}
            role="row"
            aria-selected={pane.selected.has(e.name)}
            className={`frow ${pane.selected.has(e.name) ? "sel" : ""} ${over === e.name ? "drop" : ""}`}
            draggable
            onDragStart={(ev) => dragStart(ev, e.name)}
            onDragOver={(ev) => {
              if (isDir(e) && accepts(ev)) {
                ev.preventDefault();
                ev.stopPropagation();
                setOver(e.name);
              }
            }}
            onDrop={(ev) => isDir(e) && drop(ev, joinPath(pane.path, e.name))}
            onClick={(ev) => click(ev, i, e.name)}
            onDoubleClick={() => open(e)}
          >
            <span className="fname">
              <svg className={`ficon ${isDir(e) ? "dir" : e.kind}`} viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" aria-hidden="true">
                <path d={isDir(e) ? FOLDER : e.kind === "symlink" ? LINK : FILE} />
              </svg>
              <span className="fname-text">{e.name}</span>
            </span>
            <span className="fsize">{isDir(e) ? "" : formatSize(e.size)}</span>
            <span className="ftime">{formatTime(e.modified)}</span>
            <span className="fmode mono">{formatMode(e.mode, isDir(e))}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ dialogs

export type Dialog =
  | { kind: "name"; title: string; label: string; value: string; action: string; submit: (v: string) => Promise<void> }
  | { kind: "confirm"; title: string; message: string; action: string; submit: () => Promise<void> };

export function DialogView({ dialog, onClose }: { dialog: Dialog; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [value, setValue] = useState(dialog.kind === "name" ? dialog.value : "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => ref.current?.showModal(), []);

  const run = (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    fn().then(onClose, (e) => (setError(errorText(e)), setBusy(false)));
  };

  return (
    <dialog ref={ref} className="modal" onCancel={(e) => (e.preventDefault(), onClose())}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (dialog.kind === "name") {
            if (value.trim()) run(() => dialog.submit(value.trim()));
          } else run(dialog.submit);
        }}
      >
        <h2>{dialog.title}</h2>
        {dialog.kind === "confirm" ? (
          <p>{dialog.message}</p>
        ) : (
          <label className="modal-field">
            <span>{dialog.label}</span>
            <input autoFocus value={value} onChange={(e) => setValue(e.target.value)} spellCheck={false} onFocus={(e) => e.target.select()} />
          </label>
        )}
        {error && <p className="error">{error}</p>}
        <div className="actions">
          <span className="spacer" />
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className={dialog.kind === "confirm" ? "danger" : "primary"} disabled={busy}>
            {dialog.action}
          </button>
        </div>
      </form>
    </dialog>
  );
}

// ------------------------------------------------------------------ transfers

interface Transfer {
  key: number;
  id: number | null;
  up: boolean;
  paths: string[];
  dest: string;
  label: string;
  progress: TransferProgress | null;
  state: "running" | "done" | "failed" | "cancelled";
  message: string;
  exists: string | null;
  started: number;
}

let nextTransfer = 0;

function TransferRow({ t, onCancel, onReplace, onDismiss }: { t: Transfer; onCancel: () => void; onReplace: () => void; onDismiss: () => void }) {
  const p = t.progress;
  const pct = p && p.bytesTotal > 0 ? Math.min(100, (p.bytesDone / p.bytesTotal) * 100) : t.state === "done" ? 100 : 0;
  const secs = (Date.now() - t.started) / 1000;
  const speed = p && secs > 0.5 ? `${formatSize(p.bytesDone / secs)}/s` : "";
  const detail =
    t.state === "running"
      ? p
        ? `${formatSize(p.bytesDone)} of ${formatSize(p.bytesTotal)}${p.filesTotal > 1 ? ` · file ${Math.min(p.filesDone + 1, p.filesTotal)} of ${p.filesTotal}` : ""}${speed ? ` · ${speed}` : ""}`
        : "Preparing…"
      : t.message;
  return (
    <li className={`transfer ${t.state} ${t.up ? "up" : "down"}`}>
      <span className="transfer-dir" aria-hidden="true">
        {t.up ? "↑" : "↓"}
      </span>
      <div className="transfer-main">
        <div className="transfer-label">{t.label}</div>
        <div className="bar">
          <i style={{ width: `${pct}%` }} />
        </div>
        <small>{detail}</small>
      </div>
      {t.state === "running" && t.id !== null && (
        <button type="button" className="small-button" onClick={onCancel}>
          Cancel
        </button>
      )}
      {t.state === "failed" && t.exists && (
        <button type="button" className="small-button primary" onClick={onReplace}>
          Replace
        </button>
      )}
      {t.state !== "running" && (
        <button type="button" className="icon small" aria-label="Dismiss" onClick={onDismiss}>
          <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
            <path d="M6 6l12 12M18 6L6 18" />
          </svg>
        </button>
      )}
    </li>
  );
}

// ------------------------------------------------------------------ the tab

export function SftpView({ target, title, active, onStatus }: Props) {
  const [conn, setConn] = useState<{ id: number; home: string } | null>(null);
  const [fatal, setFatal] = useState("");
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const remoteEl = useRef<HTMLDivElement | null>(null);
  const onStatusRef = useRef(onStatus);
  onStatusRef.current = onStatus;

  useEffect(() => {
    let id: number | null = null;
    let disposed = false;
    onStatusRef.current("connecting");
    sftp.open(target).then(
      (c) => {
        if (disposed) return void sftp.close(c.id);
        id = c.id;
        setConn(c);
        onStatusRef.current("connected");
      },
      (e) => {
        setFatal(errorText(e));
        onStatusRef.current("failed");
      },
    );
    return () => {
      disposed = true;
      if (id !== null) void sftp.close(id);
    };
    // Bound to the target it was opened with, like a terminal tab.
  }, []);

  const remoteLister = useCallback((path: string) => sftp.list(conn!.id, path), [conn]);
  const remote = usePane(conn ? remoteLister : null);
  const local = usePane(localFs.list);

  useEffect(() => {
    if (conn) void remote.load(conn.home);
  }, [conn]);
  useEffect(() => {
    void localFs.home().then((h) => local.load(h));
  }, []);

  const update = (key: number, patch: Partial<Transfer>) => setTransfers((ts) => ts.map((t) => (t.key === key ? { ...t, ...patch } : t)));

  const transfer = (up: boolean, paths: string[], dest: string, overwrite = false, reuse?: number) => {
    if (!conn || paths.length === 0) return;
    const key = reuse ?? ++nextTransfer;
    const names = paths.map((p) => p.split(/[\\/]/).filter(Boolean).pop() ?? p);
    const label = `${up ? "Upload" : "Download"} ${names.length === 1 ? names[0] : `${names.length} items`} to ${dest}`;
    const fresh: Transfer = { key, id: null, up, paths, dest, label, progress: null, state: "running", message: "", exists: null, started: Date.now() };
    setTransfers((ts) => (reuse ? ts.map((t) => (t.key === key ? fresh : t)) : [fresh, ...ts]));
    const onEvent = (e: TransferEvent) => {
      if (e.kind === "progress") update(key, { progress: e });
      else if (e.kind === "done") {
        const skipped = e.skipped.length ? ` · skipped ${e.skipped.length} linked folder(s)` : "";
        update(key, { state: "done", message: `Done · ${e.files} file${e.files === 1 ? "" : "s"}, ${formatSize(e.bytes)}${skipped}` });
        void (up ? remote : local).refresh();
      } else if (e.kind === "failed") update(key, { state: "failed", message: e.message, exists: e.exists });
      else update(key, { state: "cancelled", message: "Cancelled" });
    };
    const call = up ? sftp.upload(conn.id, paths, dest, overwrite, onEvent) : sftp.download(conn.id, paths, dest, overwrite, onEvent);
    call.then(
      (id) => update(key, { id }),
      (e) => update(key, { state: "failed", message: errorText(e) }),
    );
  };

  const selectedPaths = (p: PaneApi) => [...p.selected].map((n) => joinPath(p.path, n));

  const onDrop = (to: Side) => (from: Side, paths: string[], into: string) => {
    if (from === to) return;
    transfer(to === "remote", paths, into);
  };

  // Files dropped from the OS onto the remote pane are uploaded.
  useEffect(() => {
    if (!active || !conn) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    import("@tauri-apps/api/webview")
      .then(({ getCurrentWebview }) =>
        getCurrentWebview().onDragDropEvent((event) => {
          if (event.payload.type !== "drop" || !remoteEl.current) return;
          const ratio = window.devicePixelRatio || 1;
          const { x, y } = event.payload.position;
          const hit = document.elementFromPoint(x / ratio, y / ratio);
          if (hit && remoteEl.current.contains(hit)) transfer(true, event.payload.paths, remote.path);
        }),
      )
      .then((u) => (cancelled ? u() : (unlisten = u)))
      .catch(() => {});
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [active, conn, remote.path]);

  const newFolder = (side: Side) => {
    const p = side === "remote" ? remote : local;
    setDialog({
      kind: "name",
      title: "New folder",
      label: `In ${p.path}`,
      value: "",
      action: "Create",
      submit: async (name) => {
        const path = joinPath(p.path, name);
        await (side === "remote" ? sftp.mkdir(conn!.id, path) : localFs.mkdir(path));
        await p.refresh();
      },
    });
  };

  const rename = () => {
    const [name] = [...remote.selected];
    setDialog({
      kind: "name",
      title: "Rename",
      label: "New name",
      value: name,
      action: "Rename",
      submit: async (to) => {
        await sftp.rename(conn!.id, joinPath(remote.path, name), joinPath(remote.path, to));
        await remote.refresh();
      },
    });
  };

  const chmod = () => {
    const [name] = [...remote.selected];
    const entry = remote.entries.find((e) => e.name === name);
    setDialog({
      kind: "name",
      title: `Permissions of ${name}`,
      label: "Octal mode (e.g. 644, 755, 600)",
      value: entry?.mode != null ? (entry.mode & 0o777).toString(8) : "644",
      action: "Apply",
      submit: async (v) => {
        if (!/^[0-7]{3,4}$/.test(v)) throw "Use three or four octal digits, like 644 or 0755.";
        await sftp.chmod(conn!.id, joinPath(remote.path, name), parseInt(v, 8));
        await remote.refresh();
      },
    });
  };

  const remove = () => {
    const paths = selectedPaths(remote);
    if (!paths.length) return;
    const what = paths.length === 1 ? `“${[...remote.selected][0]}”` : `${paths.length} items`;
    const folders = remote.entries.some((e) => remote.selected.has(e.name) && e.kind === "dir");
    setDialog({
      kind: "confirm",
      title: `Delete ${what}?`,
      message: `This deletes ${what} on ${title}${folders ? ", including everything inside" : ""}. It can't be undone.`,
      action: "Delete",
      submit: async () => {
        await sftp.remove(conn!.id, paths);
        await remote.refresh();
      },
    });
  };

  if (fatal) {
    return (
      <div className="sftp" hidden={!active}>
        <div className="sftp-fatal">
          <p className="error">{fatal}</p>
        </div>
      </div>
    );
  }

  const one = remote.selected.size === 1;
  return (
    <div className="sftp" hidden={!active}>
      <div className="sftp-panes">
        <Pane
          side="local"
          title="This computer"
          pane={local}
          onDropFiles={onDrop("local")}
          toolbar={
            <>
              <button type="button" className="small-button" onClick={() => newFolder("local")}>
                New folder
              </button>
              <button
                type="button"
                className="small-button primary"
                disabled={!conn || local.selected.size === 0}
                onClick={() => transfer(true, selectedPaths(local), remote.path)}
                title="Copy the selection to the remote folder"
              >
                Upload →
              </button>
            </>
          }
        />
        <Pane
          side="remote"
          title={conn ? title : `${title} (connecting…)`}
          pane={remote}
          innerRef={(el) => (remoteEl.current = el)}
          onDropFiles={onDrop("remote")}
          onDelete={remove}
          toolbar={
            <>
              <button
                type="button"
                className="small-button primary"
                disabled={!conn || remote.selected.size === 0}
                onClick={() => transfer(false, selectedPaths(remote), local.path)}
                title="Copy the selection to the local folder"
              >
                ← Download
              </button>
              <button type="button" className="small-button" disabled={!conn} onClick={() => newFolder("remote")}>
                New folder
              </button>
              <button type="button" className="small-button" disabled={!one} onClick={rename}>
                Rename
              </button>
              <button type="button" className="small-button" disabled={!one} onClick={chmod}>
                Permissions
              </button>
              <button type="button" className="small-button ghost-danger" disabled={remote.selected.size === 0} onClick={remove}>
                Delete
              </button>
            </>
          }
        />
      </div>
      {transfers.length > 0 && (
        <ul className="transfers">
          {transfers.map((t) => (
            <TransferRow
              key={t.key}
              t={t}
              onCancel={() => t.id !== null && void sftp.cancel(t.id)}
              onReplace={() => transfer(t.up, t.paths, t.dest, true, t.key)}
              onDismiss={() => setTransfers((ts) => ts.filter((x) => x.key !== t.key))}
            />
          ))}
        </ul>
      )}
      {dialog && <DialogView dialog={dialog} onClose={() => setDialog(null)} />}
    </div>
  );
}
