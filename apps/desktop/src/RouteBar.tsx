import { useEffect, useRef, useState } from "react";
import {
  hostCas,
  hosts as hostsApi,
  keyType,
  REACH_NAMES,
  type ConnectTarget,
  type HostView,
  type PinnedKey,
  type SnippetView,
  type VpnView,
} from "./api";
import { Icon } from "./Icon";
import type { TabStatus } from "./TerminalView";

interface Props {
  target: ConnectTarget;
  status: TabStatus;
  hosts: HostView[];
  vpns: VpnView[];
  /** Open the host's files; absent for a quick connection. */
  onFiles?: () => void;
  snippets: SnippetView[];
  /** Paste a snippet into this session, or run it. */
  onSend: (body: string, run: boolean) => void;
  onNewSnippet: () => void;
  /** The session is recorded into the vault. */
  recording?: boolean;
  onLogs?: () => void;
  /** Opens a host (`null`: this one again) in a new pane beside or below this one. */
  onSplit?: (dir: "row" | "column", hostId: string | null) => void;
  /** This session's split: whether typing goes to all its panes. `null`: not split. */
  broadcast?: { on: boolean; panes: number } | null;
  onBroadcast?: () => void;
}

const Arrow = () => (
  <svg className="route-arrow" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M5 12h14M13 6l6 6-6 6" />
  </svg>
);

/** The hops a saved host is reached through: its jump hosts, first hop first. */
export function jumpChain(host: HostView, hosts: HostView[]): HostView[] {
  const chain: HostView[] = [];
  let id = host.jumpId;
  while (id && chain.length < 8) {
    const hop = hosts.find((h) => h.id === id);
    if (!hop || hop.id === host.id || chain.includes(hop)) break;
    chain.unshift(hop);
    id = hop.jumpId;
  }
  return chain;
}

/** Why `host` can't be reached from a phone, or null. A phone runs no commands of its own (a proxy
 * command, a cloud's CLI for Session Manager, Instance Connect or IAP), which only the first hop
 * of a route uses, and has no SSH agent, which any hop may sign in with. */
export function desktopOnly(host: HostView, hosts: HostView[]): string | null {
  const chain = jumpChain(host, hosts);
  const first = chain[0] ?? host;
  const whose = (h: HostView) => (h.id === host.id ? "It" : `Its jump host ${h.label}`);
  if (first.source?.via) {
    const cli = first.source.via.startsWith("aws") ? "aws" : "gcloud";
    return `${whose(first)} connects through ${REACH_NAMES[first.source.via]}, which needs ${cli} on a computer.`;
  }
  if (first.proxyCommand) return `${whose(first)} connects through a command run on the computer (a proxy command).`;
  const agent = [...chain, host].find((h) => h.auth.kind === "agent");
  if (agent) return `${whose(agent)} signs in with an SSH agent, which phones don't have: give it a key from the vault.`;
  return null;
}

/** "SHA256:q3Xv…T0wE" */
const shortFingerprint = (f: string) => {
  const [alg, hash = ""] = f.split(":");
  return hash.length > 12 ? `${alg}:${hash.slice(0, 4)}…${hash.slice(-4)}` : f;
};

/** Above a session: how it gets there (VPN → jump hosts → host), the pinned host key, Files and Snippets. */
export function RouteBar({ target, status, hosts, vpns, onFiles, snippets, onSend, onNewSnippet, recording, onLogs, onSplit, broadcast, onBroadcast }: Props) {
  const host = target.kind === "saved" ? hosts.find((h) => h.id === target.hostId) : undefined;
  const [pinned, setPinned] = useState<PinnedKey | null>(null);
  // Not pinned: the host CA that vouches for it, if one does.
  const [certifiedBy, setCertifiedBy] = useState<string | null>(null);
  const [hostname, port] = target.kind === "adhoc" ? [target.host, target.port] : host ? [host.hostname, host.port] : ["", 0];

  // Read once connected: the first connection pins the key.
  useEffect(() => {
    if (!hostname || status !== "connected") return;
    let live = true;
    hostsApi.pinnedKey(hostname, port).then(
      (k) => {
        if (!live) return;
        setPinned(k);
        if (!k) hostCas.certifiedBy(hostname, port).then((c) => live && setCertifiedBy(c), () => {});
      },
      () => {},
    );
    return () => {
      live = false;
    };
  }, [hostname, port, status]);

  const chain = host ? jumpChain(host, hosts) : [];
  // The VPN comes up for the first hop (it carries everything behind it).
  const vpnId = (chain[0] ?? host)?.vpnId;
  const vpn = vpns.find((v) => v.id === vpnId);
  const address =
    target.kind === "adhoc"
      ? `${target.user}@${target.host}:${target.port}`
      : host
        ? `${host.user}@${host.hostname}:${host.port}`
        : "";

  return (
    <div className="route-bar">
      <div className="route" aria-label="Route">
        {vpn && (
          <>
            <span className={`route-chip vpn ${vpn.active ? "up" : ""}`} title={`${vpn.label}: ${vpn.active ? "connected" : "comes up with the session"}`}>
              <Icon name="vpn" size={13} />
              <span className="strong">{vpn.label}</span>
              {vpn.active && vpn.address && <span className="mono">{vpn.address}</span>}
            </span>
            <Arrow />
          </>
        )}
        {chain.map((hop) => (
          <span key={hop.id} className="route-hop">
            <span className="route-chip" title={`Jump host: ${hop.user}@${hop.hostname}:${hop.port}`}>
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
                <rect x="4" y="4" width="16" height="7" rx="2" />
                <rect x="4" y="13" width="16" height="7" rx="2" />
                <path d="M8 7.5h.01M8 16.5h.01" />
              </svg>
              <span>{hop.label}</span>
            </span>
            <Arrow />
          </span>
        ))}
        <span className="route-chip">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M5 8l4 4-4 4M12 16h7" />
          </svg>
          {host && <span className="strong">{host.label}</span>}
          <span className="mono muted">{address}</span>
        </span>
      </div>
      {recording && (
        <button type="button" className="rec-chip" onClick={onLogs} title="This session is recorded, encrypted, into the host's vault. Open its session logs">
          <i aria-hidden="true" />
          Recording
        </button>
      )}
      {pinned && (
        <span className="pinned-key mono" title={`Host key pinned on first connect: ${pinned.algorithm} ${pinned.fingerprint}`}>
          {keyType(pinned.algorithm)} {shortFingerprint(pinned.fingerprint)}
        </span>
      )}
      {!pinned && certifiedBy && (
        <span className="pinned-key" title={`Its host certificate is signed by ${certifiedBy}, a host CA trusted for it`}>
          certified by {certifiedBy}
        </span>
      )}
      <div className="route-actions">
        {onFiles && (
          <button type="button" className="route-button" onClick={onFiles}>
            <Icon name="files" size={13} />
            Files
          </button>
        )}
        {broadcast && (
          <button
            type="button"
            className={`route-button broadcast-toggle ${broadcast.on ? "on" : ""}`}
            aria-pressed={broadcast.on}
            title={broadcast.on ? "Typing goes to every pane of this tab. Click to type in one pane only" : "Type into every pane of this tab at once"}
            onClick={onBroadcast}
          >
            {broadcast.on ? `Broadcasting to ${broadcast.panes}` : "Broadcast"}
          </button>
        )}
        {onSplit && <SplitMenu hosts={hosts} current={host?.label ?? address} onSplit={onSplit} />}
        <SnippetMenu snippets={snippets} connected={status === "connected"} onSend={onSend} onNew={onNewSnippet} all={broadcast?.on ? broadcast.panes : 0} />
      </div>
    </div>
  );
}

/** Closes `open` on a click elsewhere or Escape. */
function useDismiss(open: boolean, setOpen: (v: boolean) => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => ref.current?.contains(e.target as Node) || setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", esc);
    };
  }, [open, setOpen]);
  return ref;
}

/** A new pane beside or below this one: this host again, or another. */
function SplitMenu({ hosts, current, onSplit }: { hosts: HostView[]; current: string; onSplit: (dir: "row" | "column", hostId: string | null) => void }) {
  const [open, setOpen] = useState(false);
  const [dir, setDir] = useState<"row" | "column">("row");
  const [query, setQuery] = useState("");
  const ref = useDismiss(open, setOpen);
  const q = query.trim().toLowerCase();
  const found = hosts.filter((h) => !q || [h.label, h.hostname, h.user, ...h.tags].some((s) => s.toLowerCase().includes(q))).slice(0, 8);
  const pick = (id: string | null) => {
    setOpen(false);
    setQuery("");
    onSplit(dir, id);
  };
  return (
    <div className="snippet-menu split-menu" ref={ref}>
      <button type="button" className="route-button" aria-expanded={open} aria-haspopup="menu" onClick={() => setOpen(!open)}>
        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
          <rect x="3" y="4" width="18" height="16" rx="2" />
          <path d={dir === "row" ? "M12 4v16" : "M3 12h18"} />
        </svg>
        Split
      </button>
      {open && (
        <div className="menu" role="menu">
          <div className="segmented two small" role="radiogroup" aria-label="Where the new pane goes">
            <button type="button" role="radio" aria-checked={dir === "row"} className={dir === "row" ? "on" : ""} onClick={() => setDir("row")}>
              Side by side
            </button>
            <button type="button" role="radio" aria-checked={dir === "column"} className={dir === "column" ? "on" : ""} onClick={() => setDir("column")}>
              Below
            </button>
          </div>
          <button type="button" role="menuitem" className="menu-item" onClick={() => pick(null)}>
            <span className="menu-title">{current}</span>
            <span className="menu-sub">This host again, a new session</span>
          </button>
          <input className="menu-search" placeholder="Another host…" aria-label="Find a host" value={query} onChange={(e) => setQuery(e.target.value)} />
          {found.map((h) => (
            <button key={h.id} type="button" role="menuitem" className="menu-item" onClick={() => pick(h.id)}>
              <span className="menu-title">{h.label}</span>
              <span className="menu-sub mono">
                {h.user}@{h.hostname}
              </span>
            </button>
          ))}
          {found.length === 0 && <p className="menu-empty">No host matches.</p>}
        </div>
      )}
    </div>
  );
}

function SnippetMenu({
  snippets,
  connected,
  onSend,
  onNew,
  all,
}: {
  snippets: SnippetView[];
  connected: boolean;
  onSend: (body: string, run: boolean) => void;
  onNew: () => void;
  /** Broadcasting: snippets go to this many panes (0: just this one). */
  all: number;
}) {
  const [open, setOpen] = useState(false);
  const ref = useDismiss(open, setOpen);

  const send = (body: string, run: boolean) => {
    setOpen(false);
    onSend(body, run);
  };

  return (
    <div className="snippet-menu" ref={ref}>
      <button type="button" className="route-button" aria-expanded={open} aria-haspopup="menu" onClick={() => setOpen(!open)}>
        <span className="mono prompt-glyph">&gt;_</span>
        Snippets
      </button>
      {open && (
        <div className="menu" role="menu">
          {all > 0 && <p className="menu-empty broadcast-note">Broadcasting: snippets go to all {all} panes.</p>}
          {snippets.length === 0 && <p className="menu-empty">No snippets yet.</p>}
          {snippets.map((s) => (
            <div key={s.id} className="menu-row">
              <button
                type="button"
                role="menuitem"
                className="menu-item"
                disabled={!connected}
                title={`Paste into the session: ${s.body}`}
                onClick={() => send(s.body, false)}
              >
                <span className="menu-title">{s.name}</span>
                <span className="menu-sub mono">{s.body.split("\n")[0]}</span>
              </button>
              <button type="button" className="menu-run" disabled={!connected} title="Run it" aria-label={`Run ${s.name}`} onClick={() => send(s.body, true)}>
                Run
              </button>
            </div>
          ))}
          <button
            type="button"
            role="menuitem"
            className="menu-item new"
            onClick={() => {
              setOpen(false);
              onNew();
            }}
          >
            New snippet…
          </button>
        </div>
      )}
    </div>
  );
}
