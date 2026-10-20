import { useCallback, useEffect, useRef, useState } from "react";
import { downloadDir } from "@tauri-apps/api/path";
import { errorText, isDir, localFs, sftp, type ConnectTarget, type FileEntry, type TransferEvent } from "../api";
import { DialogView, formatMode, formatSize, joinPath, parentPath, type Dialog } from "../SftpView";
import type { TabStatus } from "../TerminalView";

interface Props {
  target: ConnectTarget;
  title: string;
  active: boolean;
  onStatus: (s: TabStatus) => void;
  onBack: () => void;
}

interface Transfer {
  id: number | null;
  up: boolean;
  label: string;
  done: number;
  total: number;
  started: number;
  state: "running" | "done" | "failed" | "cancelled";
  message: string;
}

const FOLDER = "M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z";
const FILE = "M6 3h8l4 4v14H6zM14 3v4h4";

const Svg = ({ d, size = 21, width = 2 }: { d: string; size?: number; width?: number }) => (
  <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth={width} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d={d} />
  </svg>
);

/** "Oct 16 22:44" */
const shortTime = (t: number | null) => {
  if (t === null) return "";
  const d = new Date(t * 1000);
  return `${d.toLocaleString(undefined, { month: "short" })} ${String(d.getDate()).padStart(2, "0")} ${d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false })}`;
};

const meta = (e: FileEntry) =>
  [isDir(e) ? "folder" : formatSize(e.size), shortTime(e.modified), formatMode(e.mode, isDir(e)).replace(/^d/, "")].filter(Boolean).join(" · ");

/**
 * SFTP on a phone: one remote folder at a time. Tap a folder to open it, a file to select it;
 * downloads go to the device's Downloads folder, uploads come from a local folder picker.
 */
export function MobileSftp({ target, title, active, onStatus, onBack }: Props) {
  const [conn, setConn] = useState<{ id: number; home: string } | null>(null);
  const [path, setPath] = useState("");
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [transfer, setTransfer] = useState<Transfer | null>(null);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [picking, setPicking] = useState(false);
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
        setError(errorText(e));
        onStatusRef.current("failed");
      },
    );
    return () => {
      disposed = true;
      if (id !== null) void sftp.close(id);
    };
    // Bound to the target it was opened with, like a terminal tab.
  }, []);

  const load = useCallback(
    async (to: string) => {
      if (!conn) return;
      setLoading(true);
      try {
        const l = await sftp.list(conn.id, to);
        setPath(l.path);
        setEntries(l.entries);
        setSelected(new Set());
        setError("");
      } catch (e) {
        setError(errorText(e));
      } finally {
        setLoading(false);
      }
    },
    [conn],
  );

  useEffect(() => {
    if (conn) void load(conn.home);
  }, [conn, load]);

  const tap = (e: FileEntry) => {
    if (isDir(e)) return void load(joinPath(path, e.name));
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(e.name)) next.delete(e.name);
      else next.add(e.name);
      return next;
    });
  };

  const run = (up: boolean, paths: string[], dest: string, label: string) => {
    if (!conn) return;
    const started = Date.now();
    setTransfer({ id: null, up, label, done: 0, total: 0, started, state: "running", message: "" });
    const on = (e: TransferEvent) =>
      setTransfer((t) => {
        if (!t || t.started !== started) return t;
        if (e.kind === "progress") return { ...t, done: e.bytesDone, total: e.bytesTotal };
        if (e.kind === "done") {
          if (up) void load(path);
          return { ...t, state: "done", done: e.bytes, total: e.bytes, message: `${formatSize(e.bytes)} · done in ${Math.max(1, Math.round((Date.now() - started) / 1000))} s` };
        }
        if (e.kind === "failed") return { ...t, state: "failed", message: e.message };
        return { ...t, state: "cancelled", message: "Cancelled" };
      });
    (up ? sftp.upload(conn.id, paths, dest, false, on) : sftp.download(conn.id, paths, dest, false, on)).then(
      (id) => setTransfer((t) => (t && t.started === started ? { ...t, id } : t)),
      (e) => setTransfer((t) => (t && t.started === started ? { ...t, state: "failed", message: errorText(e) } : t)),
    );
  };

  const names = [...selected];
  const chosen = entries.filter((e) => selected.has(e.name));
  const bytes = chosen.reduce((n, e) => n + (isDir(e) ? 0 : e.size), 0);

  const download = async () => {
    const dir = await downloadDir().catch(() => localFs.home());
    run(false, names.map((n) => joinPath(path, n)), dir, `${names.length === 1 ? names[0] : `${names.length} items`} → Downloads`);
    setSelected(new Set());
  };

  const newFolder = () =>
    conn &&
    setDialog({
      kind: "name",
      title: "New folder",
      label: "Name",
      value: "",
      action: "Create",
      submit: async (name) => {
        await sftp.mkdir(conn.id, joinPath(path, name));
        await load(path);
      },
    });

  const rename = () =>
    conn &&
    names.length === 1 &&
    setDialog({
      kind: "name",
      title: `Rename ${names[0]}`,
      label: "New name",
      value: names[0],
      action: "Rename",
      submit: async (name) => {
        await sftp.rename(conn.id, joinPath(path, names[0]), joinPath(path, name));
        await load(path);
      },
    });

  const remove = () =>
    conn &&
    setDialog({
      kind: "confirm",
      title: `Delete ${names.length === 1 ? names[0] : `${names.length} items`}?`,
      message: "Folders are deleted with everything in them. This can't be undone.",
      action: "Delete",
      submit: async () => {
        await sftp.remove(conn.id, names.map((n) => joinPath(path, n)));
        await load(path);
      },
    });

  const split = path.lastIndexOf("/", path.length - 2);
  const pct = transfer && transfer.total > 0 ? Math.min(100, (transfer.done / transfer.total) * 100) : transfer?.state === "done" ? 100 : 0;
  const secs = transfer ? (Date.now() - transfer.started) / 1000 : 0;

  return (
    <div className="m-sftp" hidden={!active}>
      <header className="m-bar">
        <button type="button" className="m-icon" aria-label="Back" onClick={onBack}>
          <Svg d="M15 6l-6 6 6 6" size={22} />
        </button>
        <h1 className="m-bar-title start">
          <span className="m-chip outline">SFTP</span>
          <span className="m-ellipsis">{title}</span>
        </h1>
        <button type="button" className="m-icon" aria-label="Upload" disabled={!conn} onClick={() => setPicking(true)}>
          <Svg d="M12 19V7M7 12l5-5 5 5M5 4h14" />
        </button>
        <button type="button" className="m-icon" aria-label="New folder" disabled={!conn} onClick={newFolder}>
          <Svg d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM12 10v6M9 13h6" />
        </button>
      </header>

      <nav className="m-path-bar" aria-label="Path">
        <button type="button" className="m-parent" aria-label="Parent folder" disabled={!conn || path === "/"} onClick={() => void load(parentPath(path))}>
          <Svg d="M12 19V5M6 11l6-6 6 6" size={16} />
        </button>
        <span className="m-path-text mono" title={path}>
          {split > 0 && <span className="m-path-prefix muted">{path.slice(0, split + 1)}</span>}
          <span className="m-path-leaf">{split > 0 ? path.slice(split + 1) : path || (conn ? "" : "Connecting…")}</span>
        </span>
      </nav>

      {error && <p className="error m-pad">{error}</p>}
      <ul className="m-files" aria-label="Files" aria-busy={loading}>
        {conn && !loading && entries.length === 0 && !error && <li className="m-empty-text">Empty folder</li>}
        {entries.map((e) => {
          const on = selected.has(e.name);
          return (
            <li key={e.name} aria-selected={on} className={on ? "selected" : ""}>
              <button type="button" className="m-file" onClick={() => tap(e)}>
                <span className={`m-file-icon ${isDir(e) ? "dir" : ""}`}>
                  <Svg d={isDir(e) ? FOLDER : FILE} size={17} />
                </span>
                <span className="m-row-text">
                  <span className="m-file-name m-ellipsis">{e.name}</span>
                  <span className="m-row-sub mono">{meta(e)}</span>
                </span>
                {on && (
                  <span className="m-check" aria-hidden="true">
                    <Svg d="M5 12l5 5 9-10" size={14} width={3} />
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ul>

      {(transfer || selected.size > 0) && (
        <div className="m-sftp-foot">
          {transfer && (
            <div className={`m-transfer ${transfer.state}`} role="status">
              <span className={`m-transfer-dir ${transfer.up ? "up" : "down"}`} aria-hidden="true">
                {transfer.up ? "↑" : "↓"}
              </span>
              <div className="m-transfer-main">
                <span className="m-transfer-label m-ellipsis">{transfer.label}</span>
                <span className="bar" role="progressbar" aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100} aria-label="Transfer progress">
                  <i style={{ width: `${pct}%` }} />
                </span>
                <span className="m-transfer-detail mono">
                  {transfer.state === "running"
                    ? transfer.total
                      ? `${formatSize(transfer.done)} of ${formatSize(transfer.total)}${secs > 0.5 ? ` · ${formatSize(transfer.done / secs)}/s` : ""}`
                      : "Preparing…"
                    : transfer.message}
                </span>
              </div>
              {transfer.state === "running" ? (
                <button type="button" className="m-button small" disabled={transfer.id === null} onClick={() => transfer.id !== null && void sftp.cancel(transfer.id)}>
                  Cancel
                </button>
              ) : (
                <button type="button" className="m-icon" aria-label="Dismiss" onClick={() => setTransfer(null)}>
                  <Svg d="M6 6l12 12M18 6L6 18" size={18} />
                </button>
              )}
            </div>
          )}
          {selected.size > 0 && (
            <div className="m-selection" role="toolbar" aria-label="Selection">
              <span className="muted">
                {selected.size} selected{bytes > 0 ? ` · ${formatSize(bytes)}` : ""}
              </span>
              <button type="button" className="m-tool" aria-label="Rename" disabled={selected.size !== 1} onClick={rename}>
                <Svg d="M4 20h4L19 9l-4-4L4 16v4z" size={18} />
              </button>
              <button type="button" className="m-tool danger" aria-label="Delete" onClick={remove}>
                <Svg d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13" size={18} />
              </button>
              <button type="button" className="m-button primary" onClick={() => void download()}>
                <Svg d="M12 4v11M7 10l5 5 5-5M5 20h14" size={17} width={2.2} />
                Download
              </button>
            </div>
          )}
        </div>
      )}

      {picking && (
        <LocalPicker
          onClose={() => setPicking(false)}
          onPick={(paths) => {
            setPicking(false);
            run(true, paths, path, `${paths.length === 1 ? paths[0].split(/[\\/]/).pop() : `${paths.length} items`} → ${path}`);
          }}
        />
      )}
      {dialog && <DialogView dialog={dialog} onClose={() => setDialog(null)} />}
    </div>
  );
}

/** Picks files to upload from this device's folders (starting at Downloads). */
function LocalPicker({ onClose, onPick }: { onClose: () => void; onPick: (paths: string[]) => void }) {
  const [path, setPath] = useState("");
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [error, setError] = useState("");

  const open = (to: string) =>
    localFs.list(to).then(
      (l) => (setPath(l.path), setEntries(l.entries), setPicked(new Set()), setError("")),
      (e) => setError(errorText(e)),
    );

  useEffect(() => {
    downloadDir()
      .then(open)
      .catch(() => localFs.home().then(open));
  }, []);

  return (
    <div className="m-sheet-scrim" onClick={onClose}>
      <section className="m-sheet tall" role="dialog" aria-label="Upload from this device" onClick={(e) => e.stopPropagation()}>
        <span className="m-grabber" aria-hidden="true" />
        <div className="m-sheet-bar">
          <h2>Upload</h2>
          <button type="button" className="m-icon" aria-label="Close" onClick={onClose}>
            <Svg d="M6 6l12 12M18 6L6 18" size={20} />
          </button>
        </div>
        <nav className="m-path-bar inset" aria-label="Local path">
          <button type="button" className="m-parent" aria-label="Parent folder" onClick={() => void open(parentPath(path))}>
            <Svg d="M12 19V5M6 11l6-6 6 6" size={16} />
          </button>
          <span className="mono m-ellipsis">{path}</span>
        </nav>
        {error && <p className="error">{error}</p>}
        <ul className="m-files">
          {entries.map((e) => {
            const on = picked.has(e.name);
            return (
              <li key={e.name} className={on ? "selected" : ""}>
                <button
                  type="button"
                  className="m-file"
                  onClick={() =>
                    isDir(e)
                      ? void open(joinPath(path, e.name))
                      : setPicked((s) => {
                          const next = new Set(s);
                          if (next.has(e.name)) next.delete(e.name);
                          else next.add(e.name);
                          return next;
                        })
                  }
                >
                  <span className={`m-file-icon ${isDir(e) ? "dir" : ""}`}>
                    <Svg d={isDir(e) ? FOLDER : FILE} size={17} />
                  </span>
                  <span className="m-row-text">
                    <span className="m-file-name m-ellipsis">{e.name}</span>
                    <span className="m-row-sub mono">{meta(e)}</span>
                  </span>
                  {on && (
                    <span className="m-check" aria-hidden="true">
                      <Svg d="M5 12l5 5 9-10" size={14} width={3} />
                    </span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
        <button type="button" className="m-button primary big" disabled={picked.size === 0} onClick={() => onPick([...picked].map((n) => joinPath(path, n)))}>
          Upload {picked.size > 0 ? `${picked.size} file${picked.size === 1 ? "" : "s"}` : ""}
        </button>
      </section>
    </div>
  );
}
