// Pages that list one kind of item each: hosts (by group), groups, keys and identities, snippets,
// tunnels and VPNs, and a group's page with everything in it. The sidebar keeps the host list for
// connecting; everything is managed here.
//
// Every list is a table: a row per item, its name first (its main action: connect a host, open
// anything else), then what people scan for, then the row's other actions, shown on hover or
// keyboard focus. Every other row carries the greenbar band. One primary button per page.

import { useEffect, useState, type ReactNode } from "react";
import {
  attachments as attachmentsApi,
  bulk,
  describeForward,
  errorText,
  forwards as forwardsApi,
  PROVIDERS,
  REACH_NAMES,
  vpns as vpnsApi,
  type AttachmentView,
  vpnKindName,
  type ForwardView,
  type GroupView,
  type HostCaView,
  type HostView,
  type IdentityView,
  type KeyView,
  type SnippetView,
  type VaultEntry,
  type VpnView,
} from "./api";
import { Icon, type IconName } from "./Icon";
import { AddFrom, Cell, Chip, Filters, IconAction, NameCell, StatusSq, Table, TextAction, Toolbar, TRow } from "./ListParts";
import { MoveButton } from "./Move";
import { Page } from "./Page";
import type { LiveState } from "./Sidebar";
import { agentDescription } from "./AgentField";
import { mobileOs } from "./mobile/useMobile";
import { eachOf, outcome, pickOf, SelectBar, useSelection, type Selection } from "./Selection";

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** The vault's name, for items in shared vaults. */
function VaultTag({ vaults, id }: { vaults: VaultEntry[]; id: string | undefined }) {
  const v = vaults.find((x) => x.id === id);
  if (!v || v.personal) return null;
  return (
    <span className="vault-tag" title={`Shared: ${v.label}${v.access === "read" ? " (view only)" : ""}`}>
      {v.name ?? "shared"}
    </span>
  );
}

function Empty({ text, action, onAction }: { text: string; action: string; onAction: () => void }) {
  return (
    <div className="empty-page">
      <p className="hint">{text}</p>
      <button type="button" className="secondary" onClick={onAction}>
        {action}
      </button>
    </div>
  );
}

// ------------------------------------------------------------------ hosts

/** What hosts are described with. */
interface Things {
  hosts: HostView[];
  identities: IdentityView[];
  keys: KeyView[];
  vpns: VpnView[];
  groups: GroupView[];
}

/** The identity a host signs in as: its own, or its group's when it leaves its user empty. */
const identityOf = (h: HostView, groups: GroupView[]) =>
  h.identityId ?? (h.own.user.trim() === "" ? (groups.find((g) => g.id === h.groupId)?.identityId ?? null) : null);

const nameOf = (id: string | null, list: { id?: string; label?: string; name?: string }[]) => {
  const it = list.find((x) => x.id === id);
  return it ? (it.label ?? it.name ?? "?") : "?";
};

/** How a host is reached: its jump host, cloud route or proxy command, and its VPN. */
function HostRoute({ h, t }: { h: HostView; t: Things }) {
  const vpn = h.vpnId ? t.vpns.find((v) => v.id === h.vpnId) : undefined;
  const route = h.jumpId ? (
    <>
      <span className="muted">via</span> <span className="mono trunc">{nameOf(h.jumpId, t.hosts)}</span>
    </>
  ) : h.source?.via ? (
    <span className="muted">through {REACH_NAMES[h.source.via]}</span>
  ) : h.proxyCommand ? (
    <span className={h.proxyAllowed ? "muted" : "error-text"}>{h.proxyAllowed ? "proxy command" : "proxy command not allowed here"}</span>
  ) : (
    <span className="muted">direct</span>
  );
  return (
    <>
      {route}
      {vpn && (
        <span className={`tag ${vpn.active ? "up" : ""}`} title={`VPN ${vpn.label}${vpn.active ? ": up" : ""}`}>
          {vpn.label}
        </span>
      )}
    </>
  );
}

/** How a host signs in, and what it does beyond that. */
function hostSignIn(h: HostView, t: Things): { how: ReactNode; more: string } {
  const identity = identityOf(h, t.groups);
  const how = identity ? (
    <>
      identity <span className="mono">{nameOf(identity, t.identities)}</span>
      {h.identityId ? "" : " (the group's)"}
    </>
  ) : h.auth.kind === "key" ? (
    <>
      key <span className="mono">{nameOf(h.auth.keyId, t.keys)}</span>
    </>
  ) : h.auth.kind === "agent" ? (
    agentDescription(h.auth)
  ) : h.auth.saved ? (
    "saved password"
  ) : (
    "password each time"
  );
  const more = [h.keepSession && "keeps its session", h.recordSessions && "recorded"].filter(Boolean).join(" · ");
  return { how, more };
}

/** What a group gives its hosts, in parts. */
const groupParts = (g: GroupView, t: Things) => {
  const parts: ReactNode[] = [];
  if (g.identityId) parts.push(<span key="i">identity <span className="mono">{nameOf(g.identityId, t.identities)}</span></span>);
  if (g.jumpId) parts.push(<span key="j">via <span className="mono">{nameOf(g.jumpId, t.hosts)}</span></span>);
  if (g.vpnId) parts.push(<span key="v">VPN <span className="mono">{nameOf(g.vpnId, t.vpns)}</span></span>);
  if (g.keepSession) parts.push(<span key="k">keeps sessions</span>);
  return parts;
};

/** The same in a line, for text. */
const groupHow = (g: GroupView, t: Things) => {
  const parts: string[] = [];
  if (g.identityId) parts.push(`identity ${nameOf(g.identityId, t.identities)}`);
  if (g.jumpId) parts.push(`via ${nameOf(g.jumpId, t.hosts)}`);
  if (g.vpnId) parts.push(`VPN ${nameOf(g.vpnId, t.vpns)}`);
  if (g.keepSession) parts.push("keeps sessions");
  return parts.join(" · ");
};

const HOST_COLS = "minmax(170px, 1.6fr) minmax(110px, 1fr) minmax(110px, 1fr) minmax(60px, 0.6fr) 116px";
const HOST_HEAD = ["Host", "Route", "Signs in with", "Tags"];

interface HostRowsProps {
  list: HostView[];
  things: Things;
  vaults: VaultEntry[];
  live: Map<string, LiveState>;
  onConnect: (h: HostView) => void;
  /** A host with a session: its tab. */
  onShowSession?: (h: HostView) => void;
  onFiles: (h: HostView) => void;
  onEdit: (id?: string) => void;
  sel?: Selection;
}

function HostRows({ list, things, ...p }: HostRowsProps) {
  return (
    <>
      {list.map((h, i) => {
        const state = p.live.get(h.id);
        const { how, more } = hostSignIn(h, things);
        const toSession = state && p.onShowSession;
        return (
          <TRow
            key={h.id}
            index={i}
            pick={p.sel && pickOf(p.sel, h.id, h.label)}
            actions={
              <>
                <TextAction onClick={() => p.onConnect(h)}>{state ? "New tab" : "Connect"}</TextAction>
                {!h.source?.noSftp && <IconAction icon="files" label="Browse files (SFTP)" onClick={() => p.onFiles(h)} />}
                <IconAction icon="edit" label={`Edit ${h.label}`} onClick={() => p.onEdit(h.id)} />
              </>
            }
          >
            <NameCell
              pick={p.sel && pickOf(p.sel, h.id, h.label)}
              onOpen={() => (toSession ? p.onShowSession!(h) : p.onConnect(h))}
              title={toSession ? `Go to ${h.label}'s session` : `Connect to ${h.user}@${h.hostname}:${h.port}`}
              lead={<StatusSq state={state} />}
              name={h.label}
              beside={
                <>
                  <VaultTag vaults={p.vaults} id={h.vaultId} />
                  {h.source?.gone && (
                    <span className="kind-badge gone" title="Its cloud no longer lists it: it was kept, remove it if it's gone for good">
                      gone from {h.source.provider === "feed" ? "its feed" : (PROVIDERS[h.source.provider || "vallic"]?.name ?? "its cloud")}
                    </span>
                  )}
                  {h.source?.state && !h.source.gone && (
                    <span className="kind-badge" title="Not running: it keeps its last address until it starts">
                      {h.source.state.replace(/^VM /, "").toLowerCase()}
                    </span>
                  )}
                </>
              }
              sub={`${h.user}@${h.hostname}:${h.port}`}
              subTone="mono"
            />
            <Cell>
              <HostRoute h={h} t={things} />
            </Cell>
            <Cell className="lstack">
              <span className="trunc">{how}</span>
              {more && <span className="lsub">{more}</span>}
            </Cell>
            <Cell className="ltags">
              {h.tags.slice(0, 2).map((t) => (
                <span key={t} className="tag">
                  {t}
                </span>
              ))}
              {h.tags.length > 2 && <span className="muted" title={h.tags.slice(2).join(", ")}>+{h.tags.length - 2}</span>}
            </Cell>
          </TRow>
        );
      })}
    </>
  );
}

interface HostsProps {
  hosts: HostView[];
  groups: GroupView[];
  identities: IdentityView[];
  keys: KeyView[];
  vpns: VpnView[];
  vaults: VaultEntry[];
  live: Map<string, LiveState>;
  onConnect: (h: HostView) => void;
  onShowSession: (h: HostView) => void;
  onFiles: (h: HostView) => void;
  onEdit: (id?: string) => void;
  onEditGroup: (id?: string) => void;
  onOpenGroup: (id: string) => void;
  /** Hosts from OpenSSH's configuration (desktop). */
  onImport: () => void;
  /** Clouds, or straight to adding a feed. */
  onCloud: (add?: "feed") => void;
  /** Quick connect (desktop, where this page is home once there are hosts). */
  onQuickConnect?: () => void;
  /** After a change made here (several deleted, moved to a group). */
  onChanged: () => void;
  onClose: () => void;
}

const matches = (h: HostView, q: string) => [h.label, h.hostname, h.user, ...h.tags].some((s) => s.toLowerCase().includes(q));

export function HostsPage(p: HostsProps) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const sel = useSelection();
  const q = query.trim().toLowerCase();
  const connected = p.hosts.filter((h) => p.live.has(h.id)).length;
  // The tags most hosts carry, as filters.
  const tagCounts = new Map<string, number>();
  p.hosts.forEach((h) => h.tags.forEach((t) => tagCounts.set(t, (tagCounts.get(t) ?? 0) + 1)));
  const tags = [...tagCounts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 5);
  const shown = p.hosts.filter(
    (h) => (!q || matches(h, q)) && (filter === "all" || (filter === "connected" ? p.live.has(h.id) : h.tags.includes(filter.slice(4)))),
  );
  const narrowed = !!q || filter !== "all";
  const ungrouped = shown.filter((h) => !h.groupId || !p.groups.some((g) => g.id === h.groupId));
  const rows = { things: p, vaults: p.vaults, live: p.live, onConnect: p.onConnect, onShowSession: p.onShowSession, onFiles: p.onFiles, onEdit: p.onEdit, sel };
  return (
    <Page
      title="Hosts"
      lead={
        p.hosts.length
          ? `${plural(p.hosts.length, "host")}${p.groups.length ? ` in ${plural(p.groups.length, "group")}` : ""}${connected ? `. ${connected} connected` : ""}.`
          : undefined
      }
      onClose={p.onClose}
      actions={
        <>
          {!mobileOs && (
            <AddFrom
              items={[
                { label: "Import…", sub: "OpenSSH's config, PuTTY, a CSV file, Royal TS", onClick: p.onImport },
                { label: "Clouds…", sub: "Machines from AWS, DigitalOcean, Vallic Cloud…", onClick: () => p.onCloud() },
                { label: "Feed URL…", sub: "Hosts and snippets your team publishes at an address", onClick: () => p.onCloud("feed") },
              ]}
            />
          )}
          {p.onQuickConnect && (
            <button type="button" className="secondary" onClick={p.onQuickConnect}>
              Quick connect
            </button>
          )}
          <button type="button" className="secondary" onClick={() => p.onEditGroup()}>
            New group
          </button>
          <button type="button" className="primary" onClick={() => p.onEdit()}>
            New host
          </button>
        </>
      }
    >
      {p.hosts.length === 0 ? (
        <Empty text="No hosts yet." action="Add your first host" onAction={() => p.onEdit()} />
      ) : (
        <>
          <Toolbar
            query={query}
            setQuery={setQuery}
            placeholder="Search by name, address, user or tag"
            label="Search hosts"
            sel={sel}
            any={p.hosts.length > 0}
            filters={
              (connected > 0 || tags.length > 0) && (
                <Filters
                  value={filter}
                  onChange={setFilter}
                  options={[
                    ...(connected > 0 ? [{ key: "connected", label: "Connected", count: connected }] : []),
                    ...tags.map(([t, n]) => ({ key: `tag:${t}`, label: t, count: n })),
                  ]}
                />
              )
            }
          />
          <SelectBar
            sel={sel}
            shown={shown.map((h) => ({ id: h.id, vaultId: h.vaultId }))}
            noun={["host", "hosts"]}
            onDelete={bulk.remove}
            onChanged={p.onChanged}
            more={(ids, vaultId, report) =>
              vaultId && (
                <select
                  className="small-select"
                  aria-label="Move to group"
                  value=""
                  onChange={(e) => {
                    const group = e.target.value;
                    bulk.setGroup(ids, group === "none" ? null : group).then(
                      (r) => (report(outcome(r, "Moved", ["host", "hosts"])), p.onChanged()),
                      (err) => report({ ok: false, text: errorText(err) }),
                    );
                  }}
                >
                  <option value="" disabled>
                    Move to group…
                  </option>
                  {p.groups
                    .filter((g) => g.vaultId === vaultId)
                    .map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                  <option value="none">No group</option>
                </select>
              )
            }
          />
          {shown.length === 0 ? (
            <p className="hint page-pad">No hosts match{q ? ` “${query}”` : " this filter"}.</p>
          ) : (
            <Table cols={HOST_COLS} label="Hosts" head={HOST_HEAD}>
              {ungrouped.length > 0 && (
                <section className="lsection">
                  {p.groups.length > 0 && (
                    <div className="lghead">
                      <span className="lgname">Not in a group</span>
                      <span className="lgcount">{ungrouped.length}</span>
                    </div>
                  )}
                  <HostRows list={ungrouped} {...rows} />
                </section>
              )}
              {p.groups.map((g) => {
                const members = shown.filter((h) => h.groupId === g.id);
                if (narrowed && members.length === 0) return null;
                const parts = groupParts(g, p);
                return (
                  <section key={g.id} className="lsection in-group">
                    <div className="lghead">
                      <button type="button" className="lgname" onClick={() => p.onOpenGroup(g.id!)} title={`Open the group ${g.name}`}>
                        <Icon name="group" size={14} />
                        {g.name}
                      </button>
                      <span className="lgcount">{members.length}</span>
                      <VaultTag vaults={p.vaults} id={g.vaultId} />
                      {parts.length > 0 && <span className="defaults">{parts}</span>}
                      <span className="spacer" />
                      <button type="button" className="text-action" onClick={() => p.onEditGroup(g.id)} aria-label={`Edit group ${g.name}`}>
                        Edit group
                      </button>
                    </div>
                    {members.length ? (
                      <HostRows list={members} {...rows} />
                    ) : (
                      <p className="hint lempty">No hosts in it yet. Pick the group in a host's editor.</p>
                    )}
                  </section>
                );
              })}
            </Table>
          )}
        </>
      )}
    </Page>
  );
}

// ------------------------------------------------------------------ groups

interface GroupsProps extends Things {
  vaults: VaultEntry[];
  live: Map<string, LiveState>;
  onOpen: (id: string) => void;
  onEdit: (id?: string) => void;
  onChanged: () => void;
  onClose: () => void;
}

export function GroupsPage(p: GroupsProps) {
  const sel = useSelection();
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();
  const shown = q ? p.groups.filter((g) => g.name.toLowerCase().includes(q)) : p.groups;
  return (
    <Page
      title="Groups"
      lead="Hosts that belong together. A group's settings (who to sign in as, a jump host, a VPN, a terminal scheme) apply to its hosts unless a host sets its own."
      onClose={p.onClose}
      actions={
        <button type="button" className="primary" onClick={() => p.onEdit()}>
          New group
        </button>
      }
    >
      {p.groups.length === 0 ? (
        <Empty text="No groups yet." action="Make a group" onAction={() => p.onEdit()} />
      ) : (
        <>
          <Toolbar query={query} setQuery={setQuery} placeholder="Search groups" label="Search groups" sel={sel} any />
          <SelectBar sel={sel} shown={shown.map((g) => ({ id: g.id!, vaultId: g.vaultId! }))} noun={["group", "groups"]} onDelete={bulk.remove} onChanged={p.onChanged} />
          <Table cols="minmax(170px, 1.2fr) 56px minmax(200px, 2fr) 80px 40px" label="Groups" head={["Group", "Hosts", "What its hosts get", "Connected"]}>
            {shown.map((g, i) => {
              const members = p.hosts.filter((h) => h.groupId === g.id);
              const live = members.filter((h) => p.live.has(h.id)).length;
              const parts = groupParts(g, p);
              return (
                <TRow key={g.id} index={i} pick={pickOf(sel, g.id!, g.name)} actions={<IconAction icon="edit" label={`Edit group ${g.name}`} onClick={() => p.onEdit(g.id)} />}>
                  <NameCell
                    pick={pickOf(sel, g.id!, g.name)}
                    onOpen={() => p.onOpen(g.id!)}
                    title={`Open ${g.name}`}
                    lead={<Icon name="group" size={15} />}
                    name={g.name}
                    beside={<VaultTag vaults={p.vaults} id={g.vaultId} />}
                    sub={sel.on && members.length > 0 ? "Deleting it keeps its hosts" : undefined}
                  />
                  <Cell className="num">{members.length}</Cell>
                  <Cell>{parts.length ? <span className="defaults">{parts}</span> : <span className="muted">Nothing: each host its own</span>}</Cell>
                  <Cell>
                    {live > 0 ? (
                      <>
                        <StatusSq state="connected" />
                        {live}
                      </>
                    ) : (
                      <span className="muted">None</span>
                    )}
                  </Cell>
                </TRow>
              );
            })}
          </Table>
        </>
      )}
    </Page>
  );
}

interface GroupProps extends Things {
  group: GroupView;
  forwards: ForwardView[];
  vaults: VaultEntry[];
  live: Map<string, LiveState>;
  pending: Set<string>;
  onConnect: (h: HostView) => void;
  onShowSession: (h: HostView) => void;
  onFiles: (h: HostView) => void;
  onEditHost: (id?: string) => void;
  onEditGroup: (id: string) => void;
  onToggleForward: (f: ForwardView) => void;
  onOpenForward: (id?: string) => void;
  onOpenKey: (id: string) => void;
  onOpenIdentity: (id: string) => void;
  onOpenVpn: (id: string) => void;
  onBack: () => void;
  onClose: () => void;
}

const sizeText = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${Math.round(n / 1024)} KB` : `${(n / 1048576).toFixed(1)} MB`);

/** One group and everything in it: what its hosts use to connect, its hosts, the tunnels through
 * them and their files. */
export function GroupPage(p: GroupProps) {
  const g = p.group;
  const members = p.hosts.filter((h) => h.groupId === g.id);
  const memberIds = new Set(members.map((h) => h.id));
  const tunnels = p.forwards.filter((f) => memberIds.has(f.hostId));
  const [files, setFiles] = useState<AttachmentView[] | null>(null);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const memberKey = members.map((h) => h.id).join();
  useEffect(() => {
    Promise.all(members.map((h) => attachmentsApi.list(h.id))).then(
      (lists) => setFiles(lists.flat()),
      (e) => setError(errorText(e)),
    );
  }, [memberKey]);

  // What the hosts use to connect, each once.
  const uniq = <T,>(xs: (T | undefined)[]) => [...new Set(xs.filter((x): x is T => x !== undefined))];
  const identities = uniq(members.map((h) => p.identities.find((i) => i.id === identityOf(h, p.groups))));
  const keyIds = uniq([
    ...members.map((h) => (h.auth.kind === "key" ? h.auth.keyId : undefined)),
    ...identities.map((i) => (i.auth.kind === "key" ? i.auth.keyId : undefined)),
  ]);
  const keys = p.keys.filter((k) => keyIds.includes(k.id));
  const vpns = p.vpns.filter((v) => members.some((h) => h.vpnId === v.id));
  const jumps = p.hosts.filter((j) => !memberIds.has(j.id) && members.some((h) => h.jumpId === j.id));
  const summary = groupHow(g, p);
  const hostLabel = (id: string | null) => p.hosts.find((h) => h.id === id)?.label ?? "";
  const uses: { kind: string; icon: IconName; label: string; sub: ReactNode; open: () => void }[] = [
    ...identities.map((i) => ({ kind: "Identity", icon: "identity" as const, label: i.label, sub: <span className="mono">{i.user}</span>, open: () => p.onOpenIdentity(i.id) })),
    ...keys.map((k) => ({ kind: "Key", icon: "key" as const, label: k.label, sub: k.algorithm.replace(/^ssh-/, ""), open: () => p.onOpenKey(k.id) })),
    ...jumps.map((j) => ({ kind: "Jump host", icon: "host" as const, label: j.label, sub: <span className="mono">{j.hostname}</span>, open: () => p.onEditHost(j.id) })),
    ...vpns.map((v) => ({
      kind: "VPN",
      icon: "vpn" as const,
      label: v.label,
      sub: (
        <>
          {vpnKindName(v.kind)}
          {v.active && <span className="tag up">up</span>}
        </>
      ),
      open: () => p.onOpenVpn(v.id),
    })),
  ];

  return (
    <Page
      back={{ label: "Groups", onClick: p.onBack }}
      title={g.name}
      badge={<VaultTag vaults={p.vaults} id={g.vaultId} />}
      lead={`${plural(members.length, "host")}. ${summary ? "Its settings apply to them unless a host sets its own." : "Its hosts each sign in and connect their own way."}`}
      onClose={p.onClose}
      actions={
        <>
          <MoveButton ids={[g.id!]} label={g.name} from={g.vaultId!} />
          <button type="button" className="secondary" onClick={() => p.onEditGroup(g.id!)}>
            Edit group
          </button>
        </>
      }
    >
      <section className="stack">
        <h2 className="section-title">What its hosts use</h2>
        {uses.length === 0 ? (
          <p className="hint">Nothing from the vault: they sign in with a password or the SSH agent, directly.</p>
        ) : (
          <div className="use-cards">
            {uses.map((u) => (
              <button key={`${u.kind}:${u.label}`} type="button" className="use-card" onClick={u.open} title={`Open ${u.label}`}>
                <span className="section-title">{u.kind}</span>
                <span className="use-name">
                  <Icon name={u.icon} size={14} />
                  {u.label}
                </span>
                <span className="lsub">{u.sub}</span>
              </button>
            ))}
          </div>
        )}
      </section>
      <section className="stack">
        <h2 className="section-title">Hosts</h2>
        {members.length ? (
          <Table cols={HOST_COLS} label={`Hosts in ${g.name}`} head={HOST_HEAD}>
            <HostRows list={members} things={p} vaults={p.vaults} live={p.live} onConnect={p.onConnect} onShowSession={p.onShowSession} onFiles={p.onFiles} onEdit={p.onEditHost} />
          </Table>
        ) : (
          <p className="hint">None yet. Pick the group in a host's editor.</p>
        )}
      </section>
      {tunnels.length > 0 && (
        <section className="stack">
          <h2 className="section-title">Tunnels</h2>
          <TunnelTable forwards={tunnels} hosts={p.hosts} vaults={p.vaults} live={p.live} pending={p.pending} onToggle={p.onToggleForward} onOpen={p.onOpenForward} />
        </section>
      )}
      {(files?.length ?? 0) > 0 && (
        <section className="stack">
          <h2 className="section-title">Files</h2>
          <Table cols="minmax(170px, 1.4fr) minmax(120px, 1fr) 70px 56px" label="Files" head={["File", "Host", "Size"]}>
            {files!.map((f, i) => (
              <TRow
                key={f.id}
                index={i}
                actions={<TextAction onClick={() => attachmentsApi.save(f.id).then((path) => setSaved(`Saved ${path}`), (e) => setError(errorText(e)))}>Save</TextAction>}
              >
                <NameCell lead={<Icon name="files" size={14} />} name={f.name} />
                <Cell className="trunc">{hostLabel(f.hostId)}</Cell>
                <Cell className="num muted">{sizeText(f.size)}</Cell>
              </TRow>
            ))}
          </Table>
        </section>
      )}
      {saved && <p className="ok">{saved}</p>}
      {error && <p className="error">{error}</p>}
    </Page>
  );
}

// ------------------------------------------------------------------ keys and identities

interface KeysProps {
  keys: KeyView[];
  identities: IdentityView[];
  hosts: HostView[];
  groups: GroupView[];
  vaults: VaultEntry[];
  onOpenKey: (id?: string) => void;
  onEditIdentity: (id?: string) => void;
  hostCas: HostCaView[];
  onEditHostCa: (id?: string) => void;
  /** The tab open; it's part of the view, so closing an editor returns to it. */
  tab: KeysTab;
  onTab: (tab: KeysTab) => void;
  onChanged: () => void;
  onClose: () => void;
}

export type KeysTab = "keys" | "identities" | "cas";

/** A key's certificate, as a state: none, valid (for how long), soon over, over or unreadable. */
function CertState({ k }: { k: KeyView }) {
  if (k.certificateError) return <Chip state="failed">Can't be read</Chip>;
  if (!k.certificate) return <span className="muted">None</span>;
  const left = k.certificate.validBefore - Date.now() / 1000;
  if (k.certificate.validBefore >= 2 ** 62) return <Chip state="connected">No expiry</Chip>;
  if (left <= 0) return <Chip state="failed">Expired</Chip>;
  const days = Math.floor(left / 86400);
  const when = days >= 1 ? `${days} d` : `${Math.max(1, Math.floor(left / 3600))} h`;
  return days < 7 ? <Chip state="attention">Expires in {when}</Chip> : <Chip state="connected">Valid {when}</Chip>;
}

export function KeysPage(p: KeysProps) {
  const sel = useSelection();
  const tab = p.tab;
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();
  const pickTab = (t: KeysTab) => (sel.stop(), setQuery(""), p.onTab(t));
  const keyUse = (k: KeyView) => {
    const hosts = p.hosts.filter((h) => h.auth.kind === "key" && h.auth.keyId === k.id).length;
    const ids = p.identities.filter((i) => i.auth.kind === "key" && i.auth.keyId === k.id).length;
    const parts = [hosts && plural(hosts, "host"), ids && plural(ids, "identity", "identities")].filter(Boolean);
    return parts.length ? parts.join(", ") : "Not used yet";
  };
  const idUse = (it: IdentityView) => {
    const hosts = p.hosts.filter((h) => h.identityId === it.id).length;
    const groups = p.groups.filter((g) => g.identityId === it.id).length;
    const parts = [hosts && plural(hosts, "host"), groups && plural(groups, "group")].filter(Boolean);
    return parts.length ? parts.join(", ") : "Not used yet";
  };
  const authText = (it: IdentityView) =>
    it.auth.kind === "key"
      ? `key ${p.keys.find((k) => it.auth.kind === "key" && k.id === it.auth.keyId)?.label ?? "?"}`
      : it.auth.kind === "agent"
        ? agentDescription(it.auth)
        : "password";
  const keys = q ? p.keys.filter((k) => `${k.label} ${k.fingerprint}`.toLowerCase().includes(q)) : p.keys;
  const identities = q ? p.identities.filter((i) => `${i.label} ${i.user}`.toLowerCase().includes(q)) : p.identities;
  const cas = q ? p.hostCas.filter((c) => `${c.label} ${c.hosts.join(" ")}`.toLowerCase().includes(q)) : p.hostCas;
  const shown = tab === "keys" ? keys : tab === "identities" ? identities : cas;
  const total = tab === "keys" ? p.keys.length : tab === "identities" ? p.identities.length : p.hostCas.length;
  const tabs: [KeysTab, string, number][] = [
    ["keys", "Keys", p.keys.length],
    ["identities", "Identities", p.identities.length],
    ["cas", "Host CAs", p.hostCas.length],
  ];
  const primary =
    tab === "keys" ? (
      <button type="button" className="primary" onClick={() => p.onOpenKey()}>
        New key
      </button>
    ) : tab === "identities" ? (
      <button type="button" className="primary" onClick={() => p.onEditIdentity()}>
        New identity
      </button>
    ) : (
      <button type="button" className="primary" onClick={() => p.onEditHostCa()}>
        New host CA
      </button>
    );

  return (
    <Page
      title="Keys"
      lead={
        tab === "keys"
          ? "SSH keys stay in the vault, encrypted, and are used from there: they are never written to disk."
          : tab === "identities"
            ? "A user and a key (or password) that several hosts share. Change it once and they all follow."
            : "Hosts whose keys a CA signed are trusted without pinning each one (@cert-authority)."
      }
      onClose={p.onClose}
      actions={primary}
    >
      <div className="page-tabs" role="tablist" aria-label="Keys, identities and host CAs">
        {tabs.map(([t, label, n]) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} className={`page-tab ${tab === t ? "on" : ""}`} onClick={() => pickTab(t)}>
            {label}
            <b>{n}</b>
          </button>
        ))}
      </div>
      {total === 0 ? (
        tab === "keys" ? (
          <Empty text="No keys yet." action="Generate or import a key" onAction={() => p.onOpenKey()} />
        ) : tab === "identities" ? (
          <Empty text="No identities yet." action="Make an identity" onAction={() => p.onEditIdentity()} />
        ) : (
          <Empty text="No host CAs yet." action="Trust a host CA" onAction={() => p.onEditHostCa()} />
        )
      ) : (
        <>
          <Toolbar
            query={query}
            setQuery={setQuery}
            placeholder={tab === "keys" ? "Search keys" : tab === "identities" ? "Search identities" : "Search host CAs"}
            label="Search"
            sel={sel}
            any
          />
          <SelectBar
            sel={sel}
            shown={shown.map((x) => ({ id: x.id, vaultId: x.vaultId }))}
            noun={tab === "keys" ? ["key", "keys"] : tab === "identities" ? ["identity", "identities"] : ["host CA", "host CAs"]}
            onDelete={bulk.remove}
            onChanged={p.onChanged}
          />
          {tab === "keys" && (
            <Table cols="minmax(170px, 1.2fr) minmax(160px, 1.5fr) minmax(100px, 0.9fr) 120px 40px" label="Keys" head={["Key", "Fingerprint", "Used by", "Certificate"]}>
              {keys.map((k, i) => (
                <TRow key={k.id} index={i} pick={pickOf(sel, k.id, k.label)} actions={<IconAction icon="edit" label={`Open ${k.label}`} onClick={() => p.onOpenKey(k.id)} />}>
                  <NameCell
                    pick={pickOf(sel, k.id, k.label)}
                    onOpen={() => p.onOpenKey(k.id)}
                    title={`Open ${k.label}`}
                    lead={<Icon name="key" size={15} />}
                    name={k.label}
                    beside={
                      <>
                        <span className="tag">{k.algorithm.replace(/^ssh-/, "")}</span>
                        {k.encrypted && <span className="tag">passphrase</span>}
                        <VaultTag vaults={p.vaults} id={k.vaultId} />
                      </>
                    }
                  />
                  <Cell className="mono lsub trunc">{k.fingerprint}</Cell>
                  <Cell className="trunc">{keyUse(k)}</Cell>
                  <Cell>
                    <CertState k={k} />
                  </Cell>
                </TRow>
              ))}
            </Table>
          )}
          {tab === "identities" && (
            <Table cols="minmax(170px, 1.2fr) minmax(170px, 1.4fr) minmax(110px, 0.9fr) 40px" label="Identities" head={["Identity", "Signs in as", "Used by"]}>
              {identities.map((it, i) => (
                <TRow key={it.id} index={i} pick={pickOf(sel, it.id, it.label)} actions={<IconAction icon="edit" label={`Edit ${it.label}`} onClick={() => p.onEditIdentity(it.id)} />}>
                  <NameCell
                    pick={pickOf(sel, it.id, it.label)}
                    onOpen={() => p.onEditIdentity(it.id)}
                    title={`Edit ${it.label}`}
                    lead={<Icon name="identity" size={15} />}
                    name={it.label}
                    beside={<VaultTag vaults={p.vaults} id={it.vaultId} />}
                  />
                  <Cell className="trunc">
                    <span className="mono">{it.user}</span>
                    <span className="muted">· {authText(it)}</span>
                  </Cell>
                  <Cell className="trunc">{idUse(it)}</Cell>
                </TRow>
              ))}
            </Table>
          )}
          {tab === "cas" && (
            <Table cols="minmax(170px, 1.2fr) minmax(150px, 1.4fr) minmax(150px, 1.4fr) 40px" label="Host CAs" head={["Host CA", "Trusted for", "Fingerprint"]}>
              {cas.map((ca, i) => (
                <TRow key={ca.id} index={i} pick={pickOf(sel, ca.id, ca.label)} actions={<IconAction icon="edit" label={`Edit ${ca.label}`} onClick={() => p.onEditHostCa(ca.id)} />}>
                  <NameCell
                    pick={pickOf(sel, ca.id, ca.label)}
                    onOpen={() => p.onEditHostCa(ca.id)}
                    title={`Edit ${ca.label}`}
                    lead={<Icon name="key" size={15} />}
                    name={ca.label}
                    beside={<VaultTag vaults={p.vaults} id={ca.vaultId} />}
                  />
                  <Cell className="mono trunc">{ca.hosts.join(", ")}</Cell>
                  <Cell className="mono lsub trunc">{ca.fingerprint}</Cell>
                </TRow>
              ))}
            </Table>
          )}
          {shown.length === 0 && <p className="hint page-pad">Nothing matches “{query}”.</p>}
        </>
      )}
    </Page>
  );
}

// ------------------------------------------------------------------ snippets

interface SnippetsProps {
  snippets: SnippetView[];
  vaults: VaultEntry[];
  /** The terminal a snippet would go to, if one is connected. */
  target: string | null;
  onOpen: (id?: string) => void;
  /** From a CSV file. */
  onImport: () => void;
  onSend: (body: string, run: boolean, snippet?: SnippetView) => void;
  onChanged: () => void;
  onClose: () => void;
}

export function SnippetsPage(p: SnippetsProps) {
  const sel = useSelection();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const q = query.trim().toLowerCase();
  const tagCounts = new Map<string, number>();
  p.snippets.forEach((s) => s.tags.forEach((t) => tagCounts.set(t, (tagCounts.get(t) ?? 0) + 1)));
  const tags = [...tagCounts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 5);
  const shown = p.snippets.filter(
    (s) => (!q || [s.name, s.body, ...s.tags].some((x) => x.toLowerCase().includes(q))) && (filter === "all" || s.tags.includes(filter.slice(4))),
  );
  return (
    <Page
      title="Snippets"
      lead={p.target ? `Paste or run one in ${p.target}.` : "Commands you run often. Open a session to send them to it."}
      onClose={p.onClose}
      actions={
        <>
          <button type="button" className="secondary" onClick={p.onImport}>
            Import…
          </button>
          <button type="button" className="primary" onClick={() => p.onOpen()}>
            New snippet
          </button>
        </>
      }
    >
      {p.snippets.length === 0 ? (
        <Empty text="No snippets yet." action="Save a command you run often" onAction={() => p.onOpen()} />
      ) : (
        <>
          <Toolbar
            query={query}
            setQuery={setQuery}
            placeholder="Search by name, command or tag"
            label="Search snippets"
            sel={sel}
            any
            filters={tags.length > 0 && <Filters value={filter} onChange={setFilter} options={tags.map(([t, n]) => ({ key: `tag:${t}`, label: t, count: n }))} />}
          />
          <SelectBar sel={sel} shown={shown.map((s) => ({ id: s.id, vaultId: s.vaultId }))} noun={["snippet", "snippets"]} onDelete={bulk.remove} onChanged={p.onChanged} />
          {shown.length === 0 ? (
            <p className="hint page-pad">No snippets match{q ? ` “${query}”` : " this filter"}.</p>
          ) : (
            <Table cols={`minmax(160px, 1fr) minmax(200px, 2.2fr) minmax(70px, 0.6fr) ${p.target ? "140px" : "40px"}`} label="Snippets" head={["Snippet", "Command", "Tags"]}>
              {shown.map((sn, i) => {
                const lines = sn.body.split("\n");
                return (
                  <TRow
                    key={sn.id}
                    index={i}
                    pick={pickOf(sel, sn.id, sn.name)}
                    actions={
                      <>
                        {p.target && (
                          <>
                            <TextAction onClick={() => p.onSend(sn.body, false, sn)}>Paste</TextAction>
                            <TextAction onClick={() => p.onSend(sn.body, true, sn)}>Run</TextAction>
                          </>
                        )}
                        <IconAction icon="edit" label={`${sn.source ? "Open" : "Edit"} ${sn.name}`} onClick={() => p.onOpen(sn.id)} />
                      </>
                    }
                  >
                    <NameCell
                      pick={pickOf(sel, sn.id, sn.name)}
                      onOpen={() => p.onOpen(sn.id)}
                      title={`${sn.source ? "Open" : "Edit"} ${sn.name}`}
                      lead={<Icon name="snippet" size={15} />}
                      name={sn.name}
                      beside={<VaultTag vaults={p.vaults} id={sn.vaultId} />}
                      sub={sn.source ? `From ${sn.source.label} (read-only)` : undefined}
                    />
                    <Cell className="lstack">
                      <span className="mono trunc">{lines[0]}</span>
                      {lines.length > 1 && <span className="lsub">{plural(lines.length, "line")}</span>}
                    </Cell>
                    <Cell className="ltags">
                      {sn.tags.slice(0, 2).map((t) => (
                        <span key={t} className="tag">
                          {t}
                        </span>
                      ))}
                      {sn.tags.length > 2 && <span className="muted">+{sn.tags.length - 2}</span>}
                    </Cell>
                  </TRow>
                );
              })}
            </Table>
          )}
        </>
      )}
    </Page>
  );
}

// ------------------------------------------------------------------ tunnels

interface TunnelsProps {
  forwards: ForwardView[];
  hosts: HostView[];
  vaults: VaultEntry[];
  live: Map<string, LiveState>;
  pending: Set<string>;
  onToggle: (f: ForwardView) => void;
  onOpen: (id?: string) => void;
  onChanged: () => void;
  onClose: () => void;
}

export function TunnelsPage(p: TunnelsProps) {
  const sel = useSelection();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const q = query.trim().toLowerCase();
  const running = p.forwards.filter((f) => f.running).length;
  const shown = p.forwards.filter((f) => (!q || `${f.label} ${describeForward(f)}`.toLowerCase().includes(q)) && (filter === "all" || f.running));
  return (
    <Page
      title="Tunnels"
      lead={p.forwards.length ? `${running} of ${p.forwards.length} running. A tunnel forwards a port through a host's SSH connection.` : undefined}
      onClose={p.onClose}
      actions={
        <button type="button" className="primary" onClick={() => p.onOpen()}>
          New tunnel
        </button>
      }
    >
      {p.forwards.length === 0 ? (
        <Empty text="No tunnels yet." action="Forward a port through a host" onAction={() => p.onOpen()} />
      ) : (
        <>
          <Toolbar
            query={query}
            setQuery={setQuery}
            placeholder="Search tunnels"
            label="Search tunnels"
            sel={sel}
            any
            filters={running > 0 && <Filters value={filter} onChange={setFilter} options={[{ key: "running", label: "Running", count: running }]} />}
          />
          <SelectBar sel={sel} shown={shown.map((f) => ({ id: f.id, vaultId: f.vaultId }))} noun={["tunnel", "tunnels"]} onDelete={(ids) => eachOf(ids, forwardsApi.remove)} onChanged={p.onChanged} />
          {shown.length === 0 ? (
            <p className="hint page-pad">No tunnels match{q ? ` “${query}”` : " this filter"}.</p>
          ) : (
            <TunnelTable forwards={shown} hosts={p.hosts} vaults={p.vaults} live={p.live} pending={p.pending} onToggle={p.onToggle} onOpen={p.onOpen} sel={sel} />
          )}
        </>
      )}
    </Page>
  );
}

/** Tunnels, their switch first: on or off is what people come here for. */
function TunnelTable(p: Omit<TunnelsProps, "onClose" | "onChanged"> & { sel?: Selection }) {
  return (
    <Table cols="36px minmax(120px, 1fr) minmax(140px, 1.4fr) minmax(100px, 1fr) 120px 32px" label="Tunnels" head={["On", "Tunnel", "Forwards", "Through", "State"]}>
      {p.forwards.map((f, i) => {
        const busy = p.pending.has(f.id);
        const host = p.hosts.find((h) => h.id === f.hostId);
        return (
          <TRow key={f.id} index={i} pick={p.sel && pickOf(p.sel, f.id, f.label)} actions={<IconAction icon="edit" label={`Edit ${f.label}`} onClick={() => p.onOpen(f.id)} />}>
            <Cell>
              <button
                type="button"
                role="switch"
                aria-checked={f.running}
                aria-label={`${f.running ? "Stop" : "Start"} ${f.label}`}
                title={f.running ? "Stop tunnel" : "Start tunnel"}
                className={`switch ${f.running ? "on" : ""} ${busy ? "busy" : ""}`}
                disabled={busy || !!p.sel?.on}
                onClick={(e) => (e.stopPropagation(), p.onToggle(f))}
              >
                <i />
              </button>
            </Cell>
            <NameCell pick={p.sel && pickOf(p.sel, f.id, f.label)} onOpen={() => p.onOpen(f.id)} title={`Edit ${f.label}`} name={f.label} beside={<VaultTag vaults={p.vaults} id={f.vaultId} />} />
            <Cell className="mono trunc">{describeForward(f)}</Cell>
            <Cell className="trunc">
              {host ? (
                <>
                  <StatusSq state={p.live.get(host.id)} />
                  <span className="mono trunc">{host.label}</span>
                </>
              ) : (
                <span className="error-text">a host that's gone</span>
              )}
            </Cell>
            <Cell>
              {busy ? (
                <Chip state="attention">{f.running ? "Stopping…" : "Starting…"}</Chip>
              ) : f.running ? (
                <Chip state="connected">{f.active > 0 ? `Running · ${f.active} open` : "Running"}</Chip>
              ) : (
                <Chip state="idle">Stopped</Chip>
              )}
            </Cell>
          </TRow>
        );
      })}
    </Table>
  );
}

// ------------------------------------------------------------------ VPNs

interface VpnsProps {
  vpns: VpnView[];
  hosts: HostView[];
  groups: GroupView[];
  vaults: VaultEntry[];
  onOpen: (id?: string) => void;
  onChanged: () => void;
  onClose: () => void;
}

export function VpnsPage(p: VpnsProps) {
  const sel = useSelection();
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();
  const use = (v: VpnView) => {
    const hosts = p.hosts.filter((h) => h.vpnId === v.id).length;
    const groups = p.groups.filter((g) => g.vpnId === v.id).length;
    const parts = [hosts && plural(hosts, "host"), groups && plural(groups, "group")].filter(Boolean);
    return parts.length ? parts.join(", ") : "No host yet";
  };
  const shown = q ? p.vpns.filter((v) => `${v.label} ${v.server}`.toLowerCase().includes(q)) : p.vpns;
  return (
    <Page
      title="VPNs"
      lead="Hosts that use a VPN connect through it. It starts with the first session or tunnel that needs it and stops after the last, inside MorphGate: nothing changes on the system."
      onClose={p.onClose}
      actions={
        <button type="button" className="primary" onClick={() => p.onOpen()}>
          New VPN
        </button>
      }
    >
      {p.vpns.length === 0 ? (
        <Empty text="No VPNs yet." action="Add a client's VPN (WireGuard, OpenVPN, AnyConnect…)" onAction={() => p.onOpen()} />
      ) : (
        <>
          <Toolbar query={query} setQuery={setQuery} placeholder="Search VPNs" label="Search VPNs" sel={sel} any />
          <SelectBar sel={sel} shown={shown.map((v) => ({ id: v.id, vaultId: v.vaultId }))} noun={["VPN", "VPNs"]} onDelete={(ids) => eachOf(ids, vpnsApi.remove)} onChanged={p.onChanged} />
          <Table cols="minmax(170px, 1.2fr) minmax(140px, 1.2fr) minmax(100px, 0.9fr) 100px 40px" label="VPNs" head={["VPN", "Server", "Used by", "State"]}>
            {shown.map((v, i) => (
              <TRow key={v.id} index={i} pick={pickOf(sel, v.id, v.label)} actions={<IconAction icon="edit" label={`Open ${v.label}`} onClick={() => p.onOpen(v.id)} />}>
                <NameCell
                  pick={pickOf(sel, v.id, v.label)}
                  onOpen={() => p.onOpen(v.id)}
                  title={`Open ${v.label}`}
                  lead={<Icon name="vpn" size={15} />}
                  name={v.label}
                  beside={<VaultTag vaults={p.vaults} id={v.vaultId} />}
                  sub={v.problem ?? `${vpnKindName(v.kind)}${v.active && v.address ? ` · ${v.address}` : ""}`}
                  subTone={v.problem ? "error" : undefined}
                />
                <Cell className="mono trunc">{v.server}</Cell>
                <Cell className="trunc">{use(v)}</Cell>
                <Cell>{v.problem ? <Chip state="failed">Problem</Chip> : v.active ? <Chip state="connected">Up</Chip> : <Chip state="idle">Down</Chip>}</Cell>
              </TRow>
            ))}
          </Table>
          {shown.length === 0 && <p className="hint page-pad">No VPNs match “{query}”.</p>}
        </>
      )}
    </Page>
  );
}
