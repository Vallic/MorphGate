import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { Terminal } from "@xterm/xterm";
import { errorText, openLink, sessionLogs, type GroupView, type HostView, type SessionLogView, type VaultEntry } from "./api";
import { DEFAULT_FONT, xtermTheme } from "./themes";
import type { TerminalLook } from "./TerminalView";
import { Page } from "./Page";
import { Cell, Chip, NameCell, Table, TextAction, Toolbar, TRow } from "./ListParts";
import { useSelection } from "./Selection";
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
  groups: GroupView[];
  vaults: VaultEntry[];
  look: TerminalLook;
  onClose: () => void;
}

const STATE_CHIPS: Record<SessionLogView["state"], "connected" | "idle" | "failed"> = {
  local: "connected",
  uploading: "idle",
  remote: "idle",
  failed: "failed",
};

/** A filter as a menu: "all", or one of its options. Only when there's more than one to choose. */
function FilterSelect({ label, all, value, onChange, options }: { label: string; all: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  if (options.length < 2 && !value) return null;
  return (
    <select className={`filter-select ${value ? "on" : ""}`} aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{all}</option>
      {options.map(([id, name]) => (
        <option key={id} value={id}>
          {name}
        </option>
      ))}
    </select>
  );
}

export function SessionLogsPanel({ hostId, hosts, groups, vaults, look, onClose }: Props) {
  const [logs, setLogs] = useState<SessionLogView[] | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [playing, setPlaying] = useState<{ id: string; cast: Cast } | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [vaultF, setVaultF] = useState("");
  const [groupF, setGroupF] = useState("");
  const [hostF, setHostF] = useState("");
  const sel = useSelection();
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
  const all = logs ?? [];
  const failed = all.filter((l) => l.state === "failed");
  const groupOf = (l: SessionLogView) => hosts.find((h) => h.id === l.hostId)?.groupId ?? null;
  // What the filters offer: the vaults, groups and hosts the recordings are from.
  const seen = <T,>(ids: (T | null)[]) => new Set(ids.filter((x): x is T => x !== null));
  const vaultIds = seen(all.map((l) => l.vaultId));
  const groupIds = seen(all.map(groupOf));
  const hostIds = seen(all.map((l) => l.hostId));
  const q = query.trim().toLowerCase();
  const shown = all.filter(
    (l) =>
      (!q || [l.title, l.address, l.device].some((t) => t.toLowerCase().includes(q))) &&
      (!vaultF || l.vaultId === vaultF) &&
      (!groupF || groupOf(l) === groupF) &&
      (!hostF || l.hostId === hostF),
  );
  const narrowed = !!q || !!vaultF || !!groupF || !!hostF;

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
      {all.length > 0 && (
        <>
          <Toolbar
            query={query}
            setQuery={setQuery}
            placeholder="Search by host, address or device"
            label="Search session logs"
            sel={sel}
            any={false}
            filters={
              <div className="filters" role="group" aria-label="Show">
                <FilterSelect
                  label="Vault"
                  all="Every vault"
                  value={vaultF}
                  onChange={setVaultF}
                  options={vaults.filter((v) => vaultIds.has(v.id)).map((v) => [v.id, v.label])}
                />
                <FilterSelect
                  label="Group"
                  all="Every group"
                  value={groupF}
                  onChange={setGroupF}
                  options={groups.filter((g) => g.id && groupIds.has(g.id)).map((g) => [g.id!, g.name])}
                />
                {!hostId && (
                  <FilterSelect
                    label="Host"
                    all="Every host"
                    value={hostF}
                    onChange={setHostF}
                    options={hosts.filter((h) => hostIds.has(h.id)).map((h) => [h.id, h.label])}
                  />
                )}
              </div>
            }
          />
          {shown.length === 0 ? (
            <p className="hint page-pad">No recordings match{q ? ` “${query}”` : narrowed ? " these filters" : ""}.</p>
          ) : (
            <Table
              cols="minmax(170px, 1.5fr) minmax(130px, 1fr) 70px minmax(110px, 1fr) 130px 150px"
              label="Session logs"
              head={["Session", "Started", "Length", "Recorded on", "State"]}
            >
              {shown.map((l, i) => (
                <TRow
                  key={l.id}
                  index={i}
                  className={playing?.id === l.id ? "current" : undefined}
                  actions={
                    <>
                      <TextAction onClick={() => play(l.id)}>{loading === l.id ? "Opening…" : "Play"}</TextAction>
                      <TextAction onClick={() => void save(l.id)}>Save .cast</TextAction>
                      {deleting === l.id ? (
                        <button type="button" className="text-action danger" onClick={() => void remove(l.id)}>
                          Really delete?
                        </button>
                      ) : (
                        <button type="button" className="text-action danger" onClick={() => setDeleting(l.id)}>
                          Delete
                        </button>
                      )}
                    </>
                  }
                >
                  <NameCell onOpen={() => play(l.id)} title={`Play ${l.title}`} name={l.title} sub={l.address} subTone="mono" />
                  <Cell>{when(l.startedAt)}</Cell>
                  <Cell className="num">{length(l)}</Cell>
                  <Cell className="lstack">
                    <span className="trunc">{l.device}</span>
                    <span className="lsub">{size(l.outputBytes)} printed</span>
                  </Cell>
                  <Cell>
                    <span title={l.problem ?? undefined}>
                      <Chip state={STATE_CHIPS[l.state]}>{STATE_NAMES[l.state]}</Chip>
                    </span>
                  </Cell>
                </TRow>
              ))}
            </Table>
          )}
        </>
      )}
    </Page>
  );
}
