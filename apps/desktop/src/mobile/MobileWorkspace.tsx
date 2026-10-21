import { useEffect, useState, type ReactNode } from "react";
import {
  ago,
  describeForward,
  hosts as hostsApi,
  keyType,
  totpTitle,
  vpnKindName,
  type ConnectTarget,
  type ForwardView,
  type GroupView,
  type HostView,
  type KeyView,
  type PinnedKey,
  type SnippetView,
  type ApprovalNeed,
  type SsoNeed,
  type SyncStatus,
  type UpdateInfo,
  type VaultEntry,
  type VpnView,
} from "../api";
import { Icon } from "../Icon";
import { desktopOnly, jumpChain } from "../RouteBar";
import type { ExtraKey, TabStatus } from "../TerminalView";
import { MobileSftp } from "./MobileSftp";
import { since } from "./useMobile";
import "./mobile.css";

export interface MobileTab {
  key: number;
  kind: "terminal" | "sftp";
  title: string;
  target: ConnectTarget;
  status: TabStatus;
  /** When it was opened (ms). */
  opened: number;
  /** On the Production scheme. */
  prod: boolean;
}

type Section = "hosts" | "keys" | "snippets" | "vpns" | "more";

/** Screens opened from More, by the panel they show. */
export type MorePanel = "quick" | "forwards" | "logs" | "teams" | "sync" | "security" | "appearance" | "about";

interface Props {
  hosts: HostView[];
  /** Host groups: their hosts are listed under them. */
  groups: GroupView[];
  keys: KeyView[];
  snippets: SnippetView[];
  vpns: VpnView[];
  forwards: ForwardView[];
  pendingForwards: Set<string>;
  vaults: VaultEntry[];
  syncStatus: SyncStatus | null;
  update: UpdateInfo | null;
  tabs: MobileTab[];
  /** The session in front, when one is. */
  activeTab: number | null;
  /** An editor or settings screen to show full screen, with its title. */
  panel: { title: string; node: ReactNode } | null;
  /** A notice or error to show on top. */
  banner: ReactNode;
  /** The terminal of a session (kept mounted while the session is open). */
  terminal: (tab: MobileTab, active: boolean) => ReactNode;
  onSftpStatus: (key: number, status: TabStatus) => void;
  onConnect: (host: HostView, kind?: "terminal" | "sftp") => void;
  onShowTab: (key: number) => void;
  onCloseTab: (key: number) => void;
  onHome: () => void;
  onEditHost: (id?: string) => void;
  onOpenKey: (id?: string) => void;
  onOpenSnippet: (id?: string) => void;
  /** Snippets from a CSV file. */
  onImportSnippets: () => void;
  onOpenVpn: (id?: string) => void;
  onOpenForward: (id?: string) => void;
  onToggleForward: (f: ForwardView) => void;
  onOpenMore: (panel: MorePanel) => void;
  onLock: () => void;
  /** Turn on two-step verification: organizations' vaults wait for it. */
  onTotp: () => void;
  /** Sign in at an organization's identity provider. */
  onSso: (need: SsoNeed) => void;
  /** An organization's vaults wait for this device's approval. */
  onApproval: (need: ApprovalNeed) => void;
  onSend: (key: number, body: string, run: boolean) => void;
  onKey: (key: number, k: ExtraKey) => void;
  /** Latches Ctrl for the next key typed in the session; `used` is called when it applies. */
  onCtrl: (key: number, on: boolean, used: () => void) => void;
}

const NAV: { id: Section; label: string; icon: string }[] = [
  { id: "hosts", label: "Hosts", icon: "M4 4h16v7H4zM4 13h16v7H4zM8 7.5h.01M8 16.5h.01" },
  { id: "keys", label: "Keys", icon: "M11 12l8-8M16 7l2 2M12 15a4 4 0 1 1-8 0 4 4 0 0 1 8 0z" },
  { id: "snippets", label: "Snippets", icon: "M5 8l4 4-4 4M12 16h7" },
  { id: "vpns", label: "VPNs", icon: "M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6z" },
  {
    id: "more",
    label: "More",
    icon: "M4 12a1 1 0 1 0 2 0a1 1 0 1 0-2 0M11 12a1 1 0 1 0 2 0a1 1 0 1 0-2 0M18 12a1 1 0 1 0 2 0a1 1 0 1 0-2 0",
  },
];

const Svg = ({ d, size = 20, width = 2 }: { d: string; size?: number; width?: number }) => (
  <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth={width} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d={d} />
  </svg>
);

const BACK = "M15 6l-6 6 6 6";
const CLOSE = "M6 6l12 12M18 6L6 18";
const CHEVRON = "M9 6l6 6-6 6";
const PLUS = "M12 5v14M5 12h14";

const hostOf = (t: MobileTab, hosts: HostView[]) => (t.target.kind === "saved" ? hosts.find((h) => h.id === (t.target as { hostId: string }).hostId) : undefined);

/** "via bastion.eu-west · eu-west-wg": how a session gets there. */
function routeLine(t: MobileTab, hosts: HostView[], vpns: VpnView[]): string {
  const host = hostOf(t, hosts);
  if (!host) return t.target.kind === "adhoc" ? `${t.target.user}@${t.target.host}` : "";
  const chain = jumpChain(host, hosts);
  const vpn = vpns.find((v) => v.id === (chain[0] ?? host).vpnId);
  return [chain.length ? `via ${chain.map((h) => h.label).join(" → ")}` : `${host.user}@${host.hostname}`, vpn?.label].filter(Boolean).join(" · ");
}

export function MobileWorkspace(p: Props) {
  const [section, setSection] = useState<Section>("hosts");
  const [sheet, setSheet] = useState<string | null>(null);
  const current = p.tabs.find((t) => t.key === p.activeTab) ?? null;
  const sheetHost = p.hosts.find((h) => h.id === sheet);

  let screen: ReactNode;
  if (p.panel) {
    screen = (
      <div className="m-screen m-panel">
        <header className="m-bar">
          <button type="button" className="m-icon" aria-label="Back" onClick={p.onHome}>
            <Svg d={BACK} size={22} />
          </button>
          <h1 className="m-bar-title">{p.panel.title}</h1>
          <span className="m-icon-space" />
        </header>
        <div className="m-panel-body">{p.panel.node}</div>
      </div>
    );
  } else if (!current) {
    screen = <Home {...p} section={section} onSection={setSection} onHost={(h) => setSheet(h.id)} />;
  }

  return (
    <div className="m-app">
      {p.banner}
      {screen}
      {/* Sessions stay mounted (hidden) while you browse, so they keep running. */}
      <div className="m-sessions" hidden={!current || !!p.panel}>
        {current?.kind === "terminal" && <TerminalBar {...p} tab={current} />}
        <div className="m-term-area">
          {p.tabs.map((t) =>
            t.kind === "terminal" ? (
              <div key={t.key} className="m-term" hidden={t.key !== current?.key}>
                {p.terminal(t, !p.panel && t.key === current?.key)}
              </div>
            ) : (
              <MobileSftp
                key={t.key}
                target={t.target}
                title={t.title}
                active={!p.panel && t.key === current?.key}
                onStatus={(s) => p.onSftpStatus(t.key, s)}
                onBack={p.onHome}
              />
            ),
          )}
        </div>
        {current?.kind === "terminal" && <ExtraKeys tab={current} onKey={p.onKey} onCtrl={p.onCtrl} />}
      </div>
      {sheetHost && (
        <HostSheet
          host={sheetHost}
          hosts={p.hosts}
          keys={p.keys}
          vpns={p.vpns}
          onClose={() => setSheet(null)}
          onConnect={(kind) => (setSheet(null), p.onConnect(sheetHost, kind))}
          onEdit={() => (setSheet(null), p.onEditHost(sheetHost.id))}
        />
      )}
    </div>
  );
}

// ------------------------------------------------------------------ home

function Home(p: Props & { section: Section; onSection: (s: Section) => void; onHost: (h: HostView) => void }) {
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();
  const shown = q ? p.hosts.filter((h) => [h.label, h.hostname, h.user, ...h.tags].some((s) => s.toLowerCase().includes(q))) : p.hosts;
  const live = new Set(p.tabs.filter((t) => t.status === "connected" || t.status === "connecting").map((t) => hostOf(t, p.hosts)?.id));
  const tag = (vaultId: string) => {
    const v = p.vaults.find((x) => x.id === vaultId);
    return v && !v.personal ? <span className="m-chip outline">{v.name ?? "shared"}</span> : null;
  };
  const titles: Record<Section, string> = { hosts: "Hosts", keys: "Keys", snippets: "Snippets", vpns: "VPNs", more: "More" };
  const add: Partial<Record<Section, () => void>> = {
    hosts: () => p.onEditHost(),
    keys: () => p.onOpenKey(),
    snippets: () => p.onOpenSnippet(),
    vpns: () => p.onOpenVpn(),
  };

  return (
    <div className="m-screen m-home">
      <header className="m-home-head">
        <h1>{titles[p.section]}</h1>
        <button type="button" className="m-icon" aria-label="Lock vault" onClick={p.onLock}>
          <Icon name="lock" size={20} />
        </button>
        {add[p.section] && (
          <button type="button" className="m-icon add" aria-label={`New ${p.section === "vpns" ? "VPN" : p.section.slice(0, -1)}`} onClick={add[p.section]}>
            <Svg d={PLUS} width={2.4} />
          </button>
        )}
      </header>

      <div className="m-scroll">
        {p.section === "hosts" && (
          <>
            {!!p.syncStatus?.totpRequired.length && (
              <button type="button" className="m-sso" onClick={p.onTotp}>
                <span className="m-row-text">
                  <span className="m-row-title">Turn on two-step verification</span>
                  <span className="m-row-sub">{totpTitle(p.syncStatus.totpRequired)}.</span>
                </span>
                <span className="m-chevron">
                  <Svg d={CHEVRON} size={18} />
                </span>
              </button>
            )}
            {p.syncStatus?.ssoRequired.map((n) => (
              <button key={n.orgId} type="button" className="m-sso" onClick={() => p.onSso(n)}>
                <span className="m-row-text">
                  <span className="m-row-title">Sign in to {n.orgName}</span>
                  <span className="m-row-sub">Its vaults sync once you've signed in with its identity provider.</span>
                </span>
                <span className="m-chevron">
                  <Svg d={CHEVRON} size={18} />
                </span>
              </button>
            ))}
            {p.syncStatus?.approvalRequired.map((n) => (
              <button key={n.orgId} type="button" className="m-sso" onClick={() => p.onApproval(n)}>
                <span className="m-row-text">
                  <span className="m-row-title">{n.denied ? `${n.orgName} denied this device` : `Waiting for ${n.orgName}`}</span>
                  <span className="m-row-sub">
                    {n.denied ? "Its vaults stay closed here." : "Its vaults sync once an admin, or another of your devices, approves this one."}
                  </span>
                </span>
                <span className="m-chevron">
                  <Svg d={CHEVRON} size={18} />
                </span>
              </button>
            ))}
            <div className="m-search-wrap">
              <label className="m-search">
                <Svg d="M20 20l-4.5-4.5M17 11a6 6 0 1 1-12 0 6 6 0 0 1 12 0z" size={18} />
                <input placeholder="Search hosts" aria-label="Search hosts" value={query} onChange={(e) => setQuery(e.target.value)} spellCheck={false} />
              </label>
            </div>
            {p.tabs.length > 0 && (
              <>
                <h2 className="m-label">Open sessions</h2>
                <div className="m-session-cards">
                  {p.tabs.map((t, i) => (
                    <button key={t.key} type="button" className={`m-session-card ${i === 0 ? "first" : ""}`} onClick={() => p.onShowTab(t.key)}>
                      <span className="m-session-title">
                        <i className={`status-square ${t.status}`} />
                        {t.kind === "sftp" && <span className="m-chip outline">SFTP</span>}
                        {t.prod && <span className="tab-marker">PROD</span>}
                        <span className="m-ellipsis">{t.title}</span>
                      </span>
                      <span className="m-session-sub mono">
                        {routeLine(t, p.hosts, p.vpns)} · {since(t.opened)}
                      </span>
                    </button>
                  ))}
                </div>
              </>
            )}
            <h2 className="m-label">All hosts · {p.hosts.length}</h2>
            {p.hosts.length === 0 && (
              <button type="button" className="m-empty" onClick={() => p.onEditHost()}>
                Add your first host
              </button>
            )}
            {p.hosts.length > 0 && shown.length === 0 && <p className="m-empty-text">No hosts match “{query}”.</p>}
            {[
              { id: "", name: null as string | null, hosts: shown.filter((h) => !h.groupId || !p.groups.some((g) => g.id === h.groupId)) },
              ...p.groups.map((g) => ({ id: g.id ?? "", name: g.name as string | null, hosts: shown.filter((h) => h.groupId === g.id) })),
            ]
              .filter((section) => section.name === null || section.hosts.length > 0)
              .map((section) => (
                <div key={section.id} className="m-host-section">
                {section.name !== null && (
                  <h2 className="m-label">
                    {section.name} · {section.hosts.length}
                  </h2>
                )}
                <ul className="m-list">
                  {section.hosts.map((h) => (
                    <li key={h.id}>
                      <button type="button" className="m-row" onClick={() => p.onHost(h)}>
                        <span className="m-avatar">
                          {(h.label[0] ?? "?").toUpperCase()}
                          {live.has(h.id) && <i className="live" />}
                        </span>
                        <span className="m-row-text">
                          <span className="m-row-title">
                            <span className="m-ellipsis">{h.label}</span>
                            {h.vpnId && !h.jumpId && <span className="m-chip vpn">VPN</span>}
                            {desktopOnly(h, p.hosts) && <span className="m-chip outline">desktop</span>}
                            {tag(h.vaultId)}
                          </span>
                          <span className="m-row-sub mono">
                            {h.user}@{h.hostname}
                            {h.port !== 22 && `:${h.port}`}
                            {h.jumpId && ` via ${p.hosts.find((x) => x.id === h.jumpId)?.label ?? "?"}`}
                          </span>
                        </span>
                        <span className="m-chevron">
                          <Svg d={CHEVRON} size={18} />
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
                </div>
              ))}
            <SyncLine status={p.syncStatus} onOpen={() => p.onOpenMore("sync")} />
          </>
        )}

        {p.section === "keys" && (
          <ItemList
            empty="Generate or import a key"
            onEmpty={() => p.onOpenKey()}
            items={p.keys.map((k) => ({ id: k.id, title: k.label, sub: k.algorithm.replace(/^ssh-/, ""), tag: tag(k.vaultId), icon: <Icon name="key" size={16} /> }))}
            onOpen={p.onOpenKey}
          />
        )}
        {p.section === "snippets" && (
          <ItemList
            empty="Save a command you run often"
            onEmpty={() => p.onOpenSnippet()}
            items={p.snippets.map((s) => ({ id: s.id, title: s.name, sub: s.body.split("\n")[0], tag: tag(s.vaultId), icon: <span className="mono">&gt;_</span> }))}
            onOpen={p.onOpenSnippet}
          />
        )}
        {p.section === "snippets" && (
          <button type="button" className="m-link under-list" onClick={p.onImportSnippets}>
            Import from a CSV file…
          </button>
        )}
        {p.section === "vpns" && (
          <ItemList
            empty="Add a client's VPN"
            onEmpty={() => p.onOpenVpn()}
            items={p.vpns.map((v) => ({
              id: v.id,
              title: v.label,
              sub: v.active ? `connected${v.address ? ` · ${v.address}` : ""}` : `${vpnKindName(v.kind)} · ${v.server}`,
              tag: tag(v.vaultId),
              icon: <Icon name="vpn" size={16} />,
              on: v.active,
            }))}
            onOpen={p.onOpenVpn}
          />
        )}
        {p.section === "more" && <More {...p} />}
      </div>

      <nav className="m-nav" aria-label="Sections">
        {NAV.map((n) => (
          <button key={n.id} type="button" aria-current={p.section === n.id ? "page" : undefined} className={p.section === n.id ? "on" : ""} onClick={() => p.onSection(n.id)}>
            <Svg d={n.icon} size={22} />
            {n.label}
          </button>
        ))}
      </nav>
    </div>
  );
}

interface Item {
  id: string;
  title: string;
  sub: string;
  tag: ReactNode;
  icon: ReactNode;
  on?: boolean;
}

function ItemList({ items, empty, onEmpty, onOpen }: { items: Item[]; empty: string; onEmpty: () => void; onOpen: (id: string) => void }) {
  return (
    <>
      {items.length === 0 && (
        <button type="button" className="m-empty" onClick={onEmpty}>
          {empty}
        </button>
      )}
      <ul className="m-list">
        {items.map((it) => (
          <li key={it.id}>
            <button type="button" className="m-row" onClick={() => onOpen(it.id)}>
              <span className={`m-avatar icon ${it.on ? "on" : ""}`}>{it.icon}</span>
              <span className="m-row-text">
                <span className="m-row-title">
                  <span className="m-ellipsis">{it.title}</span>
                  {it.tag}
                </span>
                <span className="m-row-sub mono">{it.sub}</span>
              </span>
              <span className="m-chevron">
                <Svg d={CHEVRON} size={18} />
              </span>
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}

function More(p: Props) {
  const rows: { panel: MorePanel; title: string; sub: string }[] = [
    { panel: "quick", title: "Quick connect", sub: "A host you haven't saved" },
    {
      panel: "forwards",
      title: "Tunnels",
      sub: p.forwards.length ? p.forwards.map((f) => `${f.label}${f.running ? " (on)" : ""}`).join(", ") : "Forward a port through a host",
    },
    { panel: "logs", title: "Session logs", sub: "Recorded sessions, encrypted in their vaults" },
    { panel: "teams", title: "Teams", sub: "Organizations and shared vaults" },
    { panel: "sync", title: "Sync", sub: syncText(p.syncStatus) },
    { panel: "security", title: "Security", sub: "Master password, recovery key, auto-lock" },
    { panel: "appearance", title: "Settings", sub: "App theme and terminal appearance" },
    { panel: "about", title: "About", sub: p.update ? `Update to ${p.update.version}` : "Version and updates" },
  ];
  return (
    <>
      <ul className="m-list">
        {rows.map((r) => (
          <li key={r.panel}>
            <button type="button" className="m-row" onClick={() => p.onOpenMore(r.panel)}>
              <span className="m-row-text">
                <span className="m-row-title">{r.title}</span>
                <span className="m-row-sub">{r.sub}</span>
              </span>
              <span className="m-chevron">
                <Svg d={CHEVRON} size={18} />
              </span>
            </button>
          </li>
        ))}
      </ul>
      {p.forwards.length > 0 && (
        <>
          <h2 className="m-label">Tunnels</h2>
          <ul className="m-list">
            {p.forwards.map((f) => (
              <li key={f.id} className="m-row static">
                <span className="m-row-text">
                  <span className="m-row-title">{f.label}</span>
                  <span className="m-row-sub mono">{describeForward(f)}</span>
                </span>
                <button
                  type="button"
                  role="switch"
                  aria-checked={f.running}
                  aria-label={`${f.running ? "Stop" : "Start"} ${f.label}`}
                  className={`switch ${f.running ? "on" : ""} ${p.pendingForwards.has(f.id) ? "busy" : ""}`}
                  disabled={p.pendingForwards.has(f.id)}
                  onClick={() => p.onToggleForward(f)}
                >
                  <i />
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}

function syncText(s: SyncStatus | null): string {
  if (!s?.enabled) return "Off";
  if (s.signedOut) return "Sign in to sync";
  if (s.syncing) return "Syncing…";
  if (s.lastError) return "Sync problem";
  return s.lastSyncAt ? `Synced ${ago(s.lastSyncAt)}` : "Sync pending";
}

function SyncLine({ status, onOpen }: { status: SyncStatus | null; onOpen: () => void }) {
  if (!status?.enabled) return null;
  return (
    <button type="button" className={`m-sync ${status.lastError || status.signedOut ? "error" : ""}`} onClick={onOpen}>
      <Icon name="sync" size={14} />
      {syncText(status)}
    </button>
  );
}

// ------------------------------------------------------------------ connect sheet

function HostSheet({
  host,
  hosts,
  keys,
  vpns,
  onClose,
  onConnect,
  onEdit,
}: {
  host: HostView;
  hosts: HostView[];
  keys: KeyView[];
  vpns: VpnView[];
  onClose: () => void;
  onConnect: (kind: "terminal" | "sftp") => void;
  onEdit: () => void;
}) {
  const [pinned, setPinned] = useState<PinnedKey | null>(null);
  const phoneCant = desktopOnly(host, hosts);
  useEffect(() => {
    hostsApi.pinnedKey(host.hostname, host.port).then(setPinned, () => {});
  }, [host.hostname, host.port]);
  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", esc);
    return () => document.removeEventListener("keydown", esc);
  }, [onClose]);

  const chain = jumpChain(host, hosts);
  const vpn = vpns.find((v) => v.id === (chain[0] ?? host).vpnId);
  const auth =
    host.auth.kind === "key" ? (
      <>
        SSH key <strong>{keys.find((k) => host.auth.kind === "key" && k.id === host.auth.keyId)?.label ?? "?"}</strong>
      </>
    ) : host.auth.kind === "agent" ? (
      "SSH agent"
    ) : host.auth.saved ? (
      "Password, saved in the vault"
    ) : (
      "Password, asked for each time"
    );

  return (
    <div className="m-sheet-scrim" onClick={onClose}>
      <section className="m-sheet" role="dialog" aria-labelledby="m-sheet-title" onClick={(e) => e.stopPropagation()}>
        <span className="m-grabber" aria-hidden="true" />
        <div className="m-sheet-head">
          <span className="m-avatar big" aria-hidden="true">
            {(host.label[0] ?? "?").toUpperCase()}
          </span>
          <div className="m-sheet-id">
            <h1 id="m-sheet-title">{host.label}</h1>
            <span className="mono muted">
              {host.user}@{host.hostname}:{host.port}
            </span>
            {host.tags.length > 0 && (
              <span className="m-tags">
                {host.tags.map((t) => (
                  <span key={t} className="m-chip outline">
                    {t}
                  </span>
                ))}
              </span>
            )}
          </div>
          <button type="button" className="m-icon" aria-label="Close" onClick={onClose}>
            <Svg d={CLOSE} />
          </button>
        </div>

        <ol className="m-path" aria-label="Connection path">
          {vpn && (
            <li className={vpn.active ? "up" : ""}>
              <span className="m-path-icon">
                <Icon name="vpn" size={15} />
              </span>
              <span className="m-path-text">
                <span className="m-path-title">
                  {vpn.label} <span className="muted">· {vpnKindName(vpn.kind)}</span>
                </span>
                <span className="m-path-sub mono">{vpn.active ? `Connected${vpn.address ? ` · ${vpn.address}` : ""}` : `${vpn.server}, comes up on connect`}</span>
              </span>
              {vpn.active && (
                <span className="m-up">
                  <i className="status-square connected" />
                  Up
                </span>
              )}
            </li>
          )}
          {chain.map((h) => (
            <li key={h.id}>
              <span className="m-path-icon">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
                  <rect x="4" y="4" width="16" height="7" rx="2" />
                  <rect x="4" y="13" width="16" height="7" rx="2" />
                  <path d="M8 7.5h.01M8 16.5h.01" />
                </svg>
              </span>
              <span className="m-path-text">
                <span className="m-path-title">
                  {h.label} <span className="muted">· jump host</span>
                </span>
                <span className="m-path-sub mono">
                  {h.user}@{h.hostname}
                </span>
              </span>
            </li>
          ))}
          <li>
            <span className="m-path-icon">
              <Svg d="M5 8l4 4-4 4M12 16h7" size={15} />
            </span>
            <span className="m-path-text">
              <span className="m-path-title">{host.label}</span>
              <span className="m-path-sub mono">
                {pinned ? `Key pinned · ${keyType(pinned.algorithm)} ${pinned.fingerprint.replace(/^(SHA256:.{4}).*(.{4})$/, "$1…$2")}` : "Key pinned on first connect"}
              </span>
            </span>
          </li>
        </ol>

        <div className="m-auth">
          <Icon name="key" size={16} />
          <span>{auth}</span>
        </div>

        <div className="m-sheet-actions">
          {phoneCant && <p className="m-footnote">Desktop only. {phoneCant}</p>}
          <button type="button" className="m-button primary big" disabled={!!phoneCant} onClick={() => onConnect("terminal")}>
            Connect
          </button>
          <div className="m-two">
            {!host.source?.noSftp && (
              <button type="button" className="m-button" disabled={!!phoneCant} onClick={() => onConnect("sftp")}>
                <Icon name="files" size={16} />
                Files
              </button>
            )}
            <button type="button" className="m-button" onClick={onEdit}>
              <Icon name="edit" size={16} />
              Edit host
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}

// ------------------------------------------------------------------ terminal

function TerminalBar(p: Props & { tab: MobileTab }) {
  const [menu, setMenu] = useState<"sessions" | "more" | "snippets" | null>(null);
  const host = hostOf(p.tab, p.hosts);
  const close = () => setMenu(null);
  return (
    <>
      <header className={`m-bar term ${p.tab.prod ? "prod" : ""}`}>
        <button type="button" className="m-icon" aria-label="Hosts" onClick={p.onHome}>
          <Svg d={BACK} size={22} />
        </button>
        <div className="m-term-title">
          <span className="m-term-name">
            <i className={`status-square ${p.tab.status}`} />
            {p.tab.prod && <span className="tab-marker">PROD</span>}
            <span className="m-ellipsis">{p.tab.title}</span>
          </span>
          <span className="m-term-route mono">{routeLine(p.tab, p.hosts, p.vpns)}</span>
        </div>
        <button type="button" className="m-icon" aria-label={`Open sessions: ${p.tabs.length}`} onClick={() => setMenu("sessions")}>
          <span className="m-count">{p.tabs.length}</span>
        </button>
        <button type="button" className="m-icon" aria-label="More" onClick={() => setMenu("more")}>
          <Svg d="M12 4a1 1 0 1 0 0 2a1 1 0 1 0 0-2M12 11a1 1 0 1 0 0 2a1 1 0 1 0 0-2M12 18a1 1 0 1 0 0 2a1 1 0 1 0 0-2" size={22} />
        </button>
      </header>

      {menu === "sessions" && (
        <Sheet title="Open sessions" onClose={close}>
          <ul className="m-list">
            {p.tabs.map((t) => (
              <li key={t.key} className={`m-row static ${t.key === p.tab.key ? "current" : ""}`}>
                <button type="button" className="m-row-main" onClick={() => (close(), p.onShowTab(t.key))}>
                  <i className={`status-square ${t.status}`} />
                  <span className="m-row-text">
                    <span className="m-row-title">
                      {t.kind === "sftp" && <span className="m-chip outline">SFTP</span>}
                      <span className="m-ellipsis">{t.title}</span>
                    </span>
                    <span className="m-row-sub mono">
                      {routeLine(t, p.hosts, p.vpns)} · {since(t.opened)}
                    </span>
                  </span>
                </button>
                <button type="button" className="m-icon" aria-label={`Close ${t.title}`} onClick={() => p.onCloseTab(t.key)}>
                  <Svg d={CLOSE} />
                </button>
              </li>
            ))}
          </ul>
          <button type="button" className="m-button" onClick={() => (close(), p.onHome())}>
            New session
          </button>
        </Sheet>
      )}

      {menu === "more" && (
        <Sheet title={p.tab.title} onClose={close}>
          <div className="m-menu">
            {host && !host.source?.noSftp && (
              <button type="button" className="m-button" onClick={() => (close(), p.onConnect(host, "sftp"))}>
                <Icon name="files" size={16} />
                Files
              </button>
            )}
            <button type="button" className="m-button" onClick={() => setMenu("snippets")}>
              <span className="mono">&gt;_</span>
              Snippets
            </button>
            <button type="button" className="m-button danger" onClick={() => (close(), p.onCloseTab(p.tab.key))}>
              Disconnect
            </button>
          </div>
        </Sheet>
      )}

      {menu === "snippets" && (
        <Sheet title="Snippets" onClose={close}>
          {p.snippets.length === 0 && <p className="m-empty-text">No snippets yet.</p>}
          <ul className="m-list">
            {p.snippets.map((s) => (
              <li key={s.id} className="m-row static">
                <button
                  type="button"
                  className="m-row-main"
                  disabled={p.tab.status !== "connected"}
                  onClick={() => (close(), p.onSend(p.tab.key, s.body, false))}
                >
                  <span className="m-row-text">
                    <span className="m-row-title">{s.name}</span>
                    <span className="m-row-sub mono">{s.body.split("\n")[0]}</span>
                  </span>
                </button>
                <button type="button" className="m-button small" disabled={p.tab.status !== "connected"} onClick={() => (close(), p.onSend(p.tab.key, s.body, true))}>
                  Run
                </button>
              </li>
            ))}
          </ul>
        </Sheet>
      )}
    </>
  );
}

/** A bottom sheet with a title and a close button. */
function Sheet({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="m-sheet-scrim" onClick={onClose}>
      <section className="m-sheet" role="dialog" aria-label={title} onClick={(e) => e.stopPropagation()}>
        <span className="m-grabber" aria-hidden="true" />
        <div className="m-sheet-bar">
          <h2>{title}</h2>
          <button type="button" className="m-icon" aria-label="Close" onClick={onClose}>
            <Svg d={CLOSE} />
          </button>
        </div>
        {children}
      </section>
    </div>
  );
}

const KEYS: { label: string; aria: string; key: ExtraKey | "ctrl" }[] = [
  { label: "Esc", aria: "Escape", key: "esc" },
  { label: "Tab", aria: "Tab", key: "tab" },
  { label: "Ctrl", aria: "Control", key: "ctrl" },
  { label: "↑", aria: "Up arrow", key: "up" },
  { label: "|", aria: "Pipe", key: "|" },
  { label: "~", aria: "Tilde", key: "~" },
  { label: "/", aria: "Slash", key: "/" },
  { label: "←", aria: "Left arrow", key: "left" },
  { label: "↓", aria: "Down arrow", key: "down" },
  { label: "→", aria: "Right arrow", key: "right" },
];

/** The page's height without the keyboard, per orientation: Android shrinks the WebView while the
 * keyboard is up (MainActivity.kt). */
const fullHeight = new Map<string, number>();
const orientation = () => (window.innerWidth > window.innerHeight * 1.2 ? "landscape" : "portrait");
const measure = () => fullHeight.set(orientation(), Math.max(fullHeight.get(orientation()) ?? 0, window.innerHeight));
measure();
window.addEventListener("resize", measure);
const keyboardUp = () => window.innerHeight < (fullHeight.get(orientation()) ?? window.innerHeight) - 120;

/** Pressing an extra key leaves the keyboard as it is. Up, the terminal keeps the focus (the
 * button doesn't take it). Down, the terminal lets go of it: Android brings the keyboard up for a
 * focused text field on any tap, the key's included. */
const keepKeyboard = (e: React.PointerEvent) => {
  e.preventDefault();
  const active = document.activeElement;
  if (e.pointerType === "touch" && !keyboardUp() && active instanceof HTMLTextAreaElement) active.blur();
};

/** The keys a phone keyboard lacks; Ctrl applies to the next key typed. */
function ExtraKeys({ tab, onKey, onCtrl }: { tab: MobileTab; onKey: Props["onKey"]; onCtrl: Props["onCtrl"] }) {
  const [ctrl, setCtrl] = useState(false);
  useEffect(() => setCtrl(false), [tab.key]);
  return (
    <div className="m-keys" role="toolbar" aria-label="Extra keys">
      {KEYS.map((k) =>
        k.key === "ctrl" ? (
          <button
            key={k.label}
            type="button"
            className={`m-key mod ${ctrl ? "on" : ""}`}
            aria-label={k.aria}
            aria-pressed={ctrl}
            onPointerDown={keepKeyboard}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => {
              const on = !ctrl;
              setCtrl(on);
              onCtrl(tab.key, on, () => setCtrl(false));
            }}
          >
            {k.label}
          </button>
        ) : (
          <button
            key={k.label}
            type="button"
            className="m-key"
            aria-label={k.aria}
            onPointerDown={keepKeyboard}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => onKey(tab.key, k.key as ExtraKey)}
          >
            {k.label}
          </button>
        ),
      )}
    </div>
  );
}
