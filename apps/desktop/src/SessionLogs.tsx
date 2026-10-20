import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { Terminal } from "@xterm/xterm";
import { errorText, openLink, sessionLogs, type HostView, type SessionLogView } from "./api";
import { DEFAULT_FONT, xtermTheme } from "./themes";
import type { TerminalLook } from "./TerminalView";
import { Page } from "./Page";
import { mobileOs } from "./mobile/useMobile";

/** Pauses longer than this play as this long. */
const MAX_IDLE = 2;
const SPEEDS = [1, 2, 4, 8];

interface Cast {
  cols: number;
  rows: number;
  /** `[time, code, data]`, time with long pauses shortened. */
  events: [number, string, string][];
  duration: number;
}

/** An asciicast v2 file, with idle time capped. */
export function parseCast(text: string): Cast {
  const lines = text.split("\n").filter((l) => l.trim() !== "");
  const header = lines.length ? JSON.parse(lines[0]) : {};
  const events: [number, string, string][] = [];
  let last = 0;
  let clock = 0;
  for (const line of lines.slice(1)) {
    let e: unknown;
    try {
      e = JSON.parse(line);
    } catch {
      continue;
    }
    if (!Array.isArray(e) || e.length < 3) continue;
    const t = Number(e[0]);
    // A header repeated by a later chunk has no events to add.
    if (!Number.isFinite(t)) continue;
    clock += Math.min(Math.max(t - last, 0), MAX_IDLE);
    last = t;
    events.push([clock, String(e[1]), String(e[2])]);
  }
  return { cols: Number(header.width) || 80, rows: Number(header.height) || 24, events, duration: clock };
}

const clock = (s: number) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;

const when = (ms: number) => new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

function length(l: SessionLogView): string {
  if (!l.endedAt) return "recording or cut short";
  const s = Math.round((l.endedAt - l.startedAt) / 1000);
  return s < 60 ? `${s} s` : s < 3600 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`;
}

function size(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

const STATE_NAMES: Record<SessionLogView["state"], string> = {
  local: "Synced",
  uploading: "Uploading",
  remote: "On another device",
  failed: "Not uploaded",
};

/** Plays a recording in a read-only terminal. */
export function SessionPlayer({ cast, look, onClose, onSave }: { cast: Cast; look: TerminalLook; onClose: () => void; onSave: () => void }) {
  const el = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);
  // Where playback is: the next event to write and the time reached.
  const at = useRef({ next: 0, pos: 0 });
  const [pos, setPos] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);

  useEffect(() => {
    const t = new Terminal({
      cols: cast.cols,
      rows: cast.rows,
      theme: xtermTheme(look.theme),
      fontFamily: look.fontFamily || DEFAULT_FONT,
      fontSize: look.fontSize,
      cursorStyle: look.cursorStyle,
      disableStdin: true,
      scrollback: 5000,
      allowProposedApi: false,
    });
    t.open(el.current!);
    term.current = t;
    // Measure the cells again once the bundled font is in.
    void document.fonts.ready.then(() => {
      if (term.current === t) t.options.fontFamily = look.fontFamily || DEFAULT_FONT;
    });
    setPlaying(true);
    return () => {
      term.current = null;
      t.dispose();
    };
  }, [cast, look]);

  /** Writes every event up to `target` (from the start when going back). */
  const seek = useCallback(
    (target: number) => {
      const t = term.current;
      if (!t) return;
      if (target < at.current.pos) {
        t.reset();
        t.resize(cast.cols, cast.rows);
        at.current = { next: 0, pos: 0 };
      }
      let { next } = at.current;
      let out = "";
      while (next < cast.events.length && cast.events[next][0] <= target) {
        const [, code, data] = cast.events[next];
        if (code === "o") out += data;
        else if (code === "r") {
          if (out) (t.write(out), (out = ""));
          const [c, r] = data.split("x").map(Number);
          if (c > 0 && r > 0) t.resize(c, r);
        }
        next++;
      }
      if (out) t.write(out);
      at.current = { next, pos: target };
      setPos(target);
    },
    [cast],
  );

  useEffect(() => {
    if (!playing) return;
    const start = performance.now();
    const from = at.current.pos >= cast.duration ? 0 : at.current.pos;
    if (from === 0 && at.current.pos > 0) seek(0);
    let timer = 0;
    const tick = () => {
      const target = Math.min(from + ((performance.now() - start) / 1000) * speed, cast.duration);
      seek(target);
      if (target >= cast.duration) setPlaying(false);
      else timer = window.setTimeout(tick, 30);
    };
    tick();
    return () => clearTimeout(timer);
  }, [playing, speed, cast, seek]);

  return (
    <section className="player" aria-label="Recording">
      <div className="player-bar">
        <button type="button" className="secondary small-button" onClick={() => setPlaying(!playing)}>
          {playing ? "Pause" : at.current.pos >= cast.duration ? "Replay" : "Play"}
        </button>
        <span className="player-time mono">
          {clock(pos)} / {clock(cast.duration)}
        </span>
        <input
          type="range"
          className="player-seek"
          aria-label="Position"
          min={0}
          max={cast.duration || 1}
          step={0.1}
          value={pos}
          onChange={(e) => (setPlaying(false), seek(Number(e.target.value)))}
        />
        <div className="segmented compact" role="radiogroup" aria-label="Speed">
          {SPEEDS.map((s) => (
            <button key={s} type="button" role="radio" aria-checked={speed === s} className={speed === s ? "on" : ""} onClick={() => setSpeed(s)}>
              {s}×
            </button>
          ))}
        </div>
        <button type="button" className="secondary small-button" onClick={onSave}>
          Save .cast
        </button>
        <button type="button" className="secondary small-button" onClick={onClose}>
          Close
        </button>
      </div>
      <div className="player-screen" style={{ background: look.theme.background }}>
        <div ref={el} />
      </div>
      <p className="hint">Pauses longer than {MAX_IDLE} seconds are shortened.</p>
    </section>
  );
}

interface Props {
  /** Only this host's logs. */
  hostId?: string;
  hosts: HostView[];
  look: TerminalLook;
  onClose: () => void;
}

export function SessionLogsPanel({ hostId, hosts, look, onClose }: Props) {
  const [logs, setLogs] = useState<SessionLogView[] | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [playing, setPlaying] = useState<{ id: string; cast: Cast } | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const host = hosts.find((h) => h.id === hostId);

  const load = useCallback(() => {
    sessionLogs.list(hostId).then(setLogs, (e) => setError(errorText(e)));
  }, [hostId]);
  useEffect(() => {
    load();
    const off = [listen("session-logs-changed", load), listen("vault-changed", load)];
    return () => off.forEach((u) => void u.then((f) => f()));
  }, [load]);

  const play = (id: string) => {
    setLoading(id);
    setError("");
    sessionLogs.cast(id).then(
      (text) => (setPlaying({ id, cast: parseCast(text) }), setLoading(null), load()),
      (e) => (setError(errorText(e)), setLoading(null)),
    );
  };
  const save = (id: string) =>
    sessionLogs.save(id).then(
      (path) => (setNotice(`Saved ${path}`), load()),
      (e) => setError(errorText(e)),
    );
  const remove = (id: string) =>
    sessionLogs.remove(id).then(
      () => (setDeleting(null), playing?.id === id && setPlaying(null), load()),
      (e) => setError(errorText(e)),
    );
  const failed = logs?.filter((l) => l.state === "failed") ?? [];

  return (
    <Page
      title={host ? `Session logs · ${host.label}` : "Session logs"}
      lead="Recorded sessions are encrypted with their vault's key and synced like the rest of it. Turn recording on per host, in the host editor."
      onClose={onClose}
    >
        {error && <p className="error">{error}</p>}
        {notice && <p className="ok">{notice}</p>}
        {failed.length > 0 && (
          <div className="notice-box row align-center">
            <p className="warn grow">
              {failed.length === 1 ? "A recording wasn't" : `${failed.length} recordings weren't`} uploaded: {failed[0].problem}
              {failed[0].upgradeUrl && ". They stay on this device until the team is on that plan, then go up with the next try."}
            </p>
            {failed[0].upgradeUrl && !mobileOs && (
              <button type="button" className="secondary small-button" onClick={() => void openLink(failed[0].upgradeUrl!).catch((e) => setError(errorText(e)))}>
                Upgrade
              </button>
            )}
            <button type="button" className="secondary small-button" onClick={() => void sessionLogs.retry().then(load)}>
              Try again
            </button>
          </div>
        )}
        {playing && <SessionPlayer cast={playing.cast} look={look} onClose={() => setPlaying(null)} onSave={() => void save(playing.id)} />}
        {logs === null && !error && <p className="hint">Loading…</p>}
        {logs?.length === 0 && <p className="hint">No recordings yet.</p>}
        {logs && logs.length > 0 && (
          <ul className="device-list">
            {logs.map((l) => (
              <li key={l.id} className={playing?.id === l.id ? "current" : ""}>
                <div>
                  <strong>{l.title}</strong>
                  <span className={`kind-badge ${l.state === "failed" ? "danger" : ""}`} title={l.problem ?? undefined}>
                    {STATE_NAMES[l.state]}
                  </span>
                  <small>
                    {when(l.startedAt)} · {length(l)} · {size(l.outputBytes)} printed
                  </small>
                  <small className="mono">
                    {l.address} · recorded on {l.device}
                  </small>
                </div>
                <button type="button" className="primary small-button" disabled={loading !== null} onClick={() => play(l.id)}>
                  {loading === l.id ? "Opening…" : "Play"}
                </button>
                <button type="button" className="secondary small-button" onClick={() => void save(l.id)}>
                  Save .cast
                </button>
                {deleting === l.id ? (
                  <button type="button" className="danger small-button" onClick={() => void remove(l.id)}>
                    Really delete?
                  </button>
                ) : (
                  <button type="button" className="ghost-danger small-button" onClick={() => setDeleting(l.id)}>
                    Delete
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
    </Page>
  );
}
