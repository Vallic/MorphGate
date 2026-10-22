import { useState, type ReactNode } from "react";
import {
  ago,
  totpTitle,
  type ForwardView,
  type GroupView,
  type HostView,
  type IdentityView,
  type KeyView,
  type SnippetView,
  type ApprovalNeed,
  type SsoNeed,
  type SyncStatus,
  type UpdateInfo,
  type VaultEntry,
  type VpnView,
} from "./api";
import { Icon, type IconName } from "./Icon";
import { Logo } from "./Logo";

/** A host's open session, for its status square. */
export type LiveState = "connected" | "connecting";

/** The pages the sidebar's navigation opens. */
export type PageKind = "hosts" | "groups" | "keys" | "snippets" | "forwards" | "vpns" | "logs";

interface Props {
  hosts: HostView[];
  groups: GroupView[];
  onEditGroup: (id?: string) => void;
  /** A group's page: its hosts and everything they use. */
  onOpenGroup: (id: string) => void;
  /** For the navigation's counts and states. */
  identities: IdentityView[];
  keys: KeyView[];
  snippets: SnippetView[];
  forwards: ForwardView[];
  vpns: VpnView[];
  /** The page open, if one is. */
  page: PageKind | null;
  onOpenPage: (page: PageKind) => void;
  /** The item open in an editor. */
  selected: string | null;
  /** The host of the session in front. */
  activeHost: string | null;
  /** Hosts with an open session. */
  live: Map<string, LiveState>;
  onConnect: (host: HostView) => void;
  /** A host with a session: its tab. */
  onShowSession: (host: HostView) => void;
  onOpenFiles: (host: HostView) => void;
  onEditHost: (id?: string) => void;
  syncStatus: SyncStatus | null;
  onOpenSync: () => void;
  vaults: VaultEntry[];
  onOpenTeams: () => void;
  onOpenAppearance: () => void;
  onOpenSecurity: () => void;
  onLock: () => void;
  update: UpdateInfo | null;
  onOpenAbout: () => void;
  /** Turn on two-step verification: organizations' vaults wait for it. */
  onTotp: () => void;
  /** Sign in at an organization's identity provider. */
  onSso: (need: SsoNeed) => void;
  /** An organization's vaults wait for this device's approval. */
  onApproval: (need: ApprovalNeed) => void;
}

const matches = (h: HostView, q: string) =>
  [h.label, h.hostname, h.user, ...h.tags].some((s) => s.toLowerCase().includes(q));

const address = (h: HostView) => `${h.user}@${h.hostname}${h.port !== 22 ? `:${h.port}` : ""}`;

const COLLAPSED = "morphgate.collapsed-groups";

function loadCollapsed(): Set<string> {
  try {
    return new Set(JSON.parse(localStorage.getItem(COLLAPSED) ?? "[]") as string[]);
  } catch {
    return new Set();
  }
}

export function Sidebar({
  hosts,
  groups,
  onEditGroup,
  onOpenGroup,
  identities,
  keys,
  snippets,
  forwards,
  vpns,
  page,
  onOpenPage,
  selected,
  activeHost,
  live,
  onConnect,
  onShowSession,
  onOpenFiles,
  onEditHost,
  syncStatus,
  onOpenSync,
  vaults,
  onOpenTeams,
  onOpenAppearance,
  onOpenSecurity,
  onLock,
  update,
  onOpenAbout,
  onTotp,
  onSso,
  onApproval,
}: Props) {
  const [query, setQuery] = useState("");
  const [collapsed, setCollapsed] = useState(loadCollapsed);
  const toggleGroup = (id: string) =>
    setCollapsed((c) => {
      const next = new Set(c);
      if (!next.delete(id)) next.add(id);
      try {
        localStorage.setItem(COLLAPSED, JSON.stringify([...next]));
      } catch {
        // Remembering is a nicety.
      }
      return next;
    });
  const labelOf = (id: string | null) => hosts.find((h) => h.id === id)?.label;
  const q = query.trim().toLowerCase();
  const shown = q ? hosts.filter((h) => matches(h, q)) : hosts;
  // Items in shared vaults carry the vault's name.
  const tag = (vaultId: string) => {
    const v = vaults.find((x) => x.id === vaultId);
    return v && !v.personal ? (
      <span className="vault-tag" title={`Shared: ${v.label}${v.access === "read" ? " (view only)" : ""}`}>
        {v.name ?? "shared"}
      </span>
    ) : null;
  };
  const rotationDue = vaults.some((v) => v.rotationDue && v.access === "manage");
  const approvals = syncStatus?.approvalsWaiting.reduce((n, w) => n + w.count, 0) ?? 0;
  const keysDue = (syncStatus?.memberKeysDue.length ?? 0) > 0;
  const recorded = hosts.some((h) => h.recordSessions);
  const band = (i: number) => (i % 2 === 1 ? "banded" : "");
  const running = forwards.filter((f) => f.running).length;
  const connected = vpns.filter((v) => v.active).length;

  const nav = (kind: PageKind, icon: IconName, label: string, count: string, on = false) => (
    <button
      type="button"
      className={`nav-row ${page === kind ? "current" : ""}`}
      aria-current={page === kind ? "page" : undefined}
      onClick={() => onOpenPage(kind)}
    >
      <Icon name={icon} size={15} />
      <span className="grow">{label}</span>
      {count && <span className={`nav-count ${on ? "on" : ""}`}>{count}</span>}
    </button>
  );

  // `session`: a row of the Open list, which goes to the host's tab.
  const hostRow = (h: HostView, i: number, session = false) => {
    const on = selected === h.id || activeHost === h.id;
    const state = live.get(h.id);
    return (
      <li key={h.id} className={`${on ? "selected" : ""} ${band(i)} ${h.source?.gone ? "gone" : ""}`}>
        <button
          className="row-main"
          onClick={() => (session ? onShowSession(h) : onConnect(h))}
          title={session ? `Go to ${h.label}'s session` : `Connect to ${h.user}@${h.hostname}:${h.port}`}
        >
          <span
            className={`sq ${state ?? "idle"}`}
            title={state === "connected" ? "Connected" : state === "connecting" ? "Connecting" : "Not connected"}
          />
          <span className="row-text">
            <span className="row-title">{h.label}</span>
            <span className="row-sub mono">
              <span className="row-sub-text">
                {address(h)}
                {h.jumpId && ` via ${labelOf(h.jumpId) ?? "?"}`}
              </span>
              {h.vpnId && !h.jumpId && <span className="vpn-tag">VPN</span>}
              {h.source?.gone && (
                <span className="gone-tag" title="Vallic Cloud no longer lists it">
                  gone
                </span>
              )}
              {tag(h.vaultId)}
            </span>
          </span>
        </button>
        {!h.source?.noSftp && (
          <button className="icon small row-action second" onClick={() => onOpenFiles(h)} title="Browse files (SFTP)" aria-label={`Files on ${h.label}`}>
            <Icon name="files" size={13} />
          </button>
        )}
        <button className="icon small row-action" onClick={() => onEditHost(h.id)} title="Edit host" aria-label={`Edit ${h.label}`}>
          <Icon name="edit" size={13} />
        </button>
      </li>
    );
  };
  const ungrouped = shown.filter((h) => !h.groupId || !groups.some((g) => g.id === h.groupId));
  // Hosts with a session, first: where people go back to most.
  const sessions = [...live.keys()].map((id) => hosts.find((h) => h.id === id)).filter((h): h is HostView => !!h && (!q || matches(h, q)));

  return (
    <aside className="sidebar">
      <div className="sidebar-head">
        <button className="brand" onClick={onOpenAbout} title="About MorphGate and updates">
          <Logo size={18} />
        </button>
        <button className="icon" onClick={onOpenAppearance} title="Settings: app theme and terminal appearance" aria-label="Settings">
          <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M4 6h9M19 6h1M4 12h3M13 12h7M4 18h11M21 18h-1" />
            <circle cx="16" cy="6" r="2.5" />
            <circle cx="10" cy="12" r="2.5" />
            <circle cx="18" cy="18" r="2.5" />
          </svg>
        </button>
        <button className="icon" onClick={onOpenSecurity} title="Security: master password, recovery key, unlock and auto-lock" aria-label="Security">
          <Icon name="security" size={16} />
        </button>
        <button className="icon" onClick={onLock} title="Lock vault (closes open sessions)" aria-label="Lock vault">
          <Icon name="lock" size={16} />
        </button>
      </div>

      <nav className="sidebar-nav" aria-label="Pages">
        {nav("hosts", "host", "Hosts", hosts.length ? String(hosts.length) : "")}
        {nav("groups", "group", "Groups", groups.length ? String(groups.length) : "")}
        {nav("keys", "key", "Keys", keys.length + identities.length ? String(keys.length + identities.length) : "")}
        {nav("snippets", "snippet", "Snippets", snippets.length ? String(snippets.length) : "")}
        {nav("forwards", "tunnel", "Tunnels", running ? `${running} on` : forwards.length ? String(forwards.length) : "", running > 0)}
        {nav("vpns", "vpn", "VPNs", connected ? `${connected} up` : vpns.length ? String(vpns.length) : "", connected > 0)}
        {recorded && nav("logs", "logs", "Session logs", "")}
      </nav>

      <label className="search">
        <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <circle cx="11" cy="11" r="6" />
          <path d="M20 20l-4.5-4.5" />
        </svg>
        <input placeholder="Search hosts" aria-label="Search hosts" value={query} onChange={(e) => setQuery(e.target.value)} spellCheck={false} />
      </label>

      <div className="sidebar-scroll">
        {sessions.length > 0 && (
          <>
            <Section title="Open" />
            <ul className="list">{sessions.map((h, i) => hostRow(h, i, true))}</ul>
          </>
        )}
        <Section
          title="Hosts"
          onNew={() => onEditHost()}
          newLabel="New host"
          extra={
            <button className="icon small" onClick={() => onEditGroup()} title="New group" aria-label="New group">
              <Icon name="group" size={14} />
            </button>
          }
        />
        {hosts.length === 0 && (
          <button className="empty-hint" onClick={() => onEditHost()}>
            Add your first host
          </button>
        )}
        {hosts.length > 0 && shown.length === 0 && <p className="empty">No hosts match “{query}”.</p>}
        <ul className="list">
          {ungrouped.map((h, i) => hostRow(h, i))}
        </ul>
        {groups.map((g) => {
          const members = shown.filter((h) => h.groupId === g.id);
          if (q && members.length === 0) return null;
          const open = !collapsed.has(g.id!) || !!q;
          return (
            <div key={g.id} className={`host-group ${selected === g.id ? "selected" : ""}`}>
              <div className="group-head">
                <button className="group-toggle" onClick={() => toggleGroup(g.id!)} aria-expanded={open} title={open ? "Collapse" : "Expand"}>
                  <span className={`chevron ${open ? "open" : ""}`}>
                    <Icon name="chevron" size={12} />
                  </span>
                  <span className="group-name">{g.name}</span>
                  <span className="group-count">{members.length}</span>
                </button>
                <button className="icon small row-action" onClick={() => onOpenGroup(g.id!)} title="Open the group" aria-label={`Open group ${g.name}`}>
                  <Icon name="open" size={13} />
                </button>
              </div>
              {open && <ul className="list grouped">{members.map((h, i) => hostRow(h, i))}</ul>}
            </div>
          );
        })}
      </div>

      <div className="sidebar-foot-group">
        {update && (
          <button className="sidebar-foot update" onClick={onOpenAbout}>
            <Icon name="update" size={15} />
            <span>Update to {update.version}</span>
          </button>
        )}
        {!!syncStatus?.totpRequired.length && (
          <button className="sidebar-foot due totp" onClick={onTotp} title={totpTitle(syncStatus.totpRequired)}>
            <Icon name="teams" size={15} />
            <span className="grow">Turn on two-step verification</span>
            <i className="status-square connecting" aria-hidden="true" />
          </button>
        )}
        {syncStatus?.ssoRequired.map((n) => (
          <button
            key={n.orgId}
            className="sidebar-foot due sso"
            onClick={() => onSso(n)}
            title={`${n.orgName}'s vaults wait for you to sign in with its identity provider`}
          >
            <Icon name="teams" size={15} />
            <span className="grow">Sign in to {n.orgName}</span>
            <i className="status-square connecting" aria-hidden="true" />
          </button>
        ))}
        {syncStatus?.approvalRequired.map((n) => (
          <button
            key={n.orgId}
            className="sidebar-foot due approval"
            onClick={() => onApproval(n)}
            title={n.denied ? `${n.orgName} denied this device` : `${n.orgName}'s vaults wait until this device is approved`}
          >
            <Icon name="teams" size={15} />
            <span className="grow">{n.denied ? `${n.orgName} denied this device` : `Waiting for approval · ${n.orgName}`}</span>
            <i className={`status-square ${n.denied ? "failed" : "connecting"}`} aria-hidden="true" />
          </button>
        ))}
        {syncStatus?.enabled && (
          <button
            className={`sidebar-foot teams ${rotationDue || approvals > 0 || keysDue ? "due" : ""}`}
            onClick={onOpenTeams}
            title={
              approvals > 0
                ? `${approvals === 1 ? "A device waits" : `${approvals} devices wait`} for your approval`
                : keysDue
                  ? `${syncStatus!.memberKeysDue.map((d) => d.orgName).join(", ")} asks you to publish the SSH keys you use on its servers`
                  : rotationDue
                  ? "A shared vault's key should be rotated"
                  : "Organizations and shared vaults"
            }
          >
            <Icon name="teams" size={15} />
            <span className="grow">
              {approvals > 0 ? "Teams · approve a device" : keysDue ? "Teams · publish your keys" : rotationDue ? "Teams · rotate a key" : "Teams"}
            </span>
            {(rotationDue || approvals > 0 || keysDue) && <i className="status-square connecting" aria-hidden="true" />}
          </button>
        )}
        <button className={`sidebar-foot sync ${syncState(syncStatus)}`} onClick={onOpenSync} title={syncStatus?.lastError ?? undefined}>
          <Icon name="sync" size={15} />
          <span className="grow">{syncLabel(syncStatus)}</span>
          <i className={`status-square ${syncSquare(syncStatus)}`} aria-hidden="true" />
        </button>
      </div>
    </aside>
  );
}

function Section({ title, onNew, newLabel, extra }: { title: string; onNew?: () => void; newLabel?: string; extra?: ReactNode }) {
  return (
    <div className="section-head">
      <span className="grow">{title}</span>
      {extra}
      {onNew && (
        <button className="icon small" onClick={onNew} title={newLabel} aria-label={newLabel}>
          <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M12 5v14M5 12h14" />
          </svg>
        </button>
      )}
    </div>
  );
}

function syncState(s: SyncStatus | null): string {
  if (!s?.enabled) return "off";
  if (s.signedOut) return "error";
  if (s.syncing) return "busy";
  return s.lastError ? "error" : "on";
}

function syncSquare(s: SyncStatus | null): string {
  if (!s?.enabled) return "";
  if (s.signedOut || s.lastError) return "failed";
  if (s.syncing) return "connecting";
  return "connected";
}

function syncLabel(s: SyncStatus | null): string {
  if (!s?.enabled) return "Sync off";
  if (s.signedOut) return "Sign in to sync";
  if (s.syncing) return "Syncing…";
  if (s.lastError) return "Sync problem";
  return s.lastSyncAt ? `Synced ${ago(s.lastSyncAt)}` : "Sync pending";
}
