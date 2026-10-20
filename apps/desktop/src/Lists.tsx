// Pages that list one kind of item each: hosts (by group), groups, keys and identities, snippets,
// tunnels and VPNs, and a group's page with everything in it. The sidebar keeps the host list for
// connecting; everything is managed here.

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
import { Icon } from "./Icon";
import { MoveButton } from "./Move";
import { Page } from "./Page";
import type { LiveState } from "./Sidebar";
import { agentDescription } from "./AgentField";
import { mobileOs } from "./mobile/useMobile";
import { eachOf, outcome, pickOf, SelectBar, useSelection, type Selection } from "./Selection";

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** "Select", for a list with something in it that isn't selecting yet. */
function SelectButton({ sel, any }: { sel: Selection; any: boolean }) {
  if (!any || sel.on) return null;
  return (
    <button type="button" className="secondary" onClick={sel.start}>
      Select
    </button>
  );
}

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

/** What a row needs while its list is selecting (see Selection.tsx). */
type Pick = ReturnType<typeof pickOf>;

/** One row: an avatar, a title line, detail lines, then buttons. Picking (`pick`): a checkbox
 * instead of the buttons, and the whole row toggles it. */
function Row({
  avatar,
  title,
  lines,
  children,
  on,
  pick,
}: {
  avatar: ReactNode;
  title: ReactNode;
  lines: ReactNode[];
  children?: ReactNode;
  on?: boolean;
  pick?: Pick;
}) {
  const classes = [on && "on", pick && "picking", pick?.on && "picked"].filter(Boolean).join(" ");
  return (
    <li className={classes || undefined} onClick={pick?.toggle}>
      {pick && (
        <input
          type="checkbox"
          className="pick"
          checked={pick.on}
          onChange={pick.toggle}
          onClick={(e) => e.stopPropagation()}
          aria-label={`Select ${pick.label}`}
        />
      )}
      <span className="list-avatar">{avatar}</span>
      <div>
        {title}
        {lines.filter(Boolean).map((l, i) => (
          <small key={i}>{l}</small>
        ))}
      </div>
      {children && !pick && <span className="list-buttons">{children}</span>}
    </li>
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

/** How a host connects, in a line. */
const hostHow = (h: HostView, t: Things) => {
  const parts: string[] = [];
  if (h.jumpId) parts.push(`via ${nameOf(h.jumpId, t.hosts)}`);
  else if (h.source?.via) parts.push(`through ${REACH_NAMES[h.source.via]}`);
  else if (h.proxyCommand) parts.push(h.proxyAllowed ? "through a proxy command" : "through a proxy command not allowed on this device");
  else if (h.vpnId) parts.push(`VPN ${nameOf(h.vpnId, t.vpns)}`);
  const identity = identityOf(h, t.groups);
  if (identity) parts.push(`identity ${nameOf(identity, t.identities)}${h.identityId ? "" : " (the group's)"}`);
  else if (h.auth.kind === "key") parts.push(`key ${nameOf(h.auth.keyId, t.keys)}`);
  else parts.push(h.auth.kind === "agent" ? agentDescription(h.auth) : h.auth.saved ? "saved password" : "password each time");
  if (h.keepSession) parts.push("keeps its session");
  if (h.recordSessions) parts.push("recorded");
  return parts.join(" · ");
};

/** What a group gives its hosts, in a line. */
const groupHow = (g: GroupView, t: Things) => {
  const parts: string[] = [];
  if (g.identityId) parts.push(`identity ${nameOf(g.identityId, t.identities)}`);
  if (g.jumpId) parts.push(`via ${nameOf(g.jumpId, t.hosts)}`);
  if (g.vpnId) parts.push(`VPN ${nameOf(g.vpnId, t.vpns)}`);
  if (g.keepSession) parts.push("keeps sessions");
  return parts.join(" · ");
};

interface HostRowsProps {
  list: HostView[];
  things: Things;
  vaults: VaultEntry[];
  live: Map<string, LiveState>;
  onConnect: (h: HostView) => void;
  onFiles: (h: HostView) => void;
  onEdit: (id?: string) => void;
  sel?: Selection;
}

function HostRows({ list, things, ...p }: HostRowsProps) {
  return (
    <ul className="device-list item-list">
      {list.map((h) => {
        const state = p.live.get(h.id);
        return (
          <Row
            key={h.id}
            on={!!state}
            pick={p.sel && pickOf(p.sel, h.id, h.label)}
            avatar={
              <>
                {(h.label[0] ?? "?").toUpperCase()}
                {state && <i className={`live ${state}`} title={state === "connected" ? "Connected" : "Connecting"} />}
              </>
            }
            title={
              <>
                <strong>{h.label}</strong>
                <VaultTag vaults={p.vaults} id={h.vaultId} />
                {h.source?.gone && (
                  <span className="kind-badge gone" title="Its cloud no longer lists it: it was kept, remove it if it's gone for good">
                    gone from {PROVIDERS[h.source.provider || "vallic"]?.name ?? "its cloud"}
                  </span>
                )}
                {h.source?.state && !h.source.gone && (
                  <span className="kind-badge" title="Not running: it keeps its last address until it starts">
                    {h.source.state.replace(/^VM /, "").toLowerCase()}
                  </span>
                )}
                {h.tags.map((t) => (
                  <span key={t} className="tag">
                    {t}
                  </span>
                ))}
              </>
            }
            lines={[
              <span className="mono">
                {h.user}@{h.hostname}
                {h.port !== 22 ? `:${h.port}` : ""}
              </span>,
              hostHow(h, things),
            ]}
          >
            <button type="button" className="primary small-button" onClick={() => p.onConnect(h)}>
              Connect
            </button>
            {!h.source?.noSftp && (
              <button type="button" className="secondary small-button" onClick={() => p.onFiles(h)}>
                Files
              </button>
            )}
            <button type="button" className="secondary small-button" onClick={() => p.onEdit(h.id)} aria-label={`Edit ${h.label}`}>
              Edit
            </button>
          </Row>
        );
      })}
    </ul>
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
  onFiles: (h: HostView) => void;
  onEdit: (id?: string) => void;
  onEditGroup: (id?: string) => void;
  onOpenGroup: (id: string) => void;
  /** Hosts from OpenSSH's configuration (desktop). */
  onImport: () => void;
  onCloud: () => void;
  /** After a change made here (several deleted, moved to a group). */
  onChanged: () => void;
  onClose: () => void;
}

const matches = (h: HostView, q: string) => [h.label, h.hostname, h.user, ...h.tags].some((s) => s.toLowerCase().includes(q));

export function HostsPage(p: HostsProps) {
  const [query, setQuery] = useState("");
  const sel = useSelection();
  const q = query.trim().toLowerCase();
  const shown = q ? p.hosts.filter((h) => matches(h, q)) : p.hosts;
  const ungrouped = shown.filter((h) => !h.groupId || !p.groups.some((g) => g.id === h.groupId));
  const rows = { things: p, vaults: p.vaults, live: p.live, onConnect: p.onConnect, onFiles: p.onFiles, onEdit: p.onEdit, sel };
  return (
    <Page
      title="Hosts"
      lead={
        p.hosts.length
          ? `${plural(p.hosts.length, "host")}${p.groups.length ? ` in ${plural(p.groups.length, "group")}` : ""}. A group's settings apply to its hosts unless a host sets its own.`
          : undefined
      }
      onClose={p.onClose}
      actions={
        <>
          {!mobileOs && (
            <button type="button" className="secondary" onClick={p.onImport}>
              Import…
            </button>
          )}
          {!mobileOs && (
            <button type="button" className="secondary" onClick={p.onCloud}>
              Clouds…
            </button>
          )}
          <SelectButton sel={sel} any={p.hosts.length > 0} />
          <button type="button" className="secondary" onClick={() => p.onEditGroup()}>
            New group
          </button>
          <button type="button" className="primary" onClick={() => p.onEdit()}>
            New host
          </button>
        </>
      }
    >
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
      {p.hosts.length === 0 ? (
        <Empty text="No hosts yet." action="Add your first host" onAction={() => p.onEdit()} />
      ) : (
        <>
          <label className="search page-search">
            <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <circle cx="11" cy="11" r="6" />
              <path d="M20 20l-4.5-4.5" />
            </svg>
            <input placeholder="Search by name, address, user or tag" aria-label="Search hosts" value={query} onChange={(e) => setQuery(e.target.value)} spellCheck={false} />
          </label>
          {shown.length === 0 && <p className="hint">No hosts match “{query}”.</p>}
          {ungrouped.length > 0 && (
            <section className="stack">
              {p.groups.length > 0 && <h2 className="section-title">Not in a group</h2>}
              <HostRows list={ungrouped} {...rows} />
            </section>
          )}
        </>
      )}
      {p.groups.map((g) => {
        const members = shown.filter((h) => h.groupId === g.id);
        if (q && members.length === 0) return null;
        const summary = groupHow(g, p);
        return (
          <section key={g.id} className="stack">
            <div className="group-title">
              <Icon name="group" size={15} />
              <h2>
                <button type="button" className="title-link" onClick={() => p.onOpenGroup(g.id!)}>
                  {g.name}
                </button>
              </h2>
              <span className="group-count">{members.length}</span>
              <VaultTag vaults={p.vaults} id={g.vaultId} />
              <span className="spacer" />
              <button type="button" className="secondary small-button" onClick={() => p.onEditGroup(g.id)} aria-label={`Edit group ${g.name}`}>
                Edit group
              </button>
            </div>
            {summary && <p className="hint">Hosts here use {summary}.</p>}
            {members.length ? (
              <HostRows list={members} {...rows} />
            ) : (
              <p className="hint">No hosts in it yet. Pick the group in a host's editor.</p>
            )}
          </section>
        );
      })}
    </Page>
  );
}

// ------------------------------------------------------------------ groups

interface GroupsProps extends Things {
  vaults: VaultEntry[];
  onOpen: (id: string) => void;
  onEdit: (id?: string) => void;
  onChanged: () => void;
  onClose: () => void;
}

export function GroupsPage(p: GroupsProps) {
  const sel = useSelection();
  return (
    <Page
      title="Groups"
      lead="Hosts that belong together. A group's settings (who to sign in as, a jump host, a VPN, a terminal scheme) apply to its hosts unless a host sets its own."
      onClose={p.onClose}
      actions={
        <>
          <SelectButton sel={sel} any={p.groups.length > 0} />
          <button type="button" className="primary" onClick={() => p.onEdit()}>
            New group
          </button>
        </>
      }
    >
      <SelectBar
        sel={sel}
        shown={p.groups.map((g) => ({ id: g.id!, vaultId: g.vaultId! }))}
        noun={["group", "groups"]}
        onDelete={bulk.remove}
        onChanged={p.onChanged}
      />
      {p.groups.length === 0 ? (
        <Empty text="No groups yet." action="Make a group" onAction={() => p.onEdit()} />
      ) : (
        <ul className="device-list item-list">
          {p.groups.map((g) => {
            const count = p.hosts.filter((h) => h.groupId === g.id).length;
            const summary = groupHow(g, p);
            return (
              <Row
                key={g.id}
                pick={pickOf(sel, g.id!, g.name)}
                avatar={<Icon name="group" size={14} />}
                title={
                  <>
                    <strong>
                      {sel.on ? (
                        g.name
                      ) : (
                        <button type="button" className="title-link" onClick={() => p.onOpen(g.id!)}>
                          {g.name}
                        </button>
                      )}
                    </strong>
                    <VaultTag vaults={p.vaults} id={g.vaultId} />
                  </>
                }
                lines={[plural(count, "host"), summary && `Its hosts use ${summary}`, sel.on && count > 0 && "Deleting it keeps its hosts"]}
              >
                <button type="button" className="secondary small-button" onClick={() => p.onOpen(g.id!)} aria-label={`Open ${g.name}`}>
                  Open
                </button>
                <button type="button" className="secondary small-button" onClick={() => p.onEdit(g.id)} aria-label={`Edit group ${g.name}`}>
                  Edit
                </button>
              </Row>
            );
          })}
        </ul>
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

/** One group and everything in it: its hosts, the tunnels through them, their files, and what they
 * use to connect. */
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

  const uses = (
    <div className="stack">
      <h2 className="section-title">What its hosts use</h2>
      {identities.length + keys.length + vpns.length + jumps.length === 0 ? (
        <p className="hint">Nothing from the vault: they sign in with a password or the SSH agent, directly.</p>
      ) : (
        <ul className="device-list item-list">
          {identities.map((i) => (
            <Row key={i.id} avatar={<Icon name="identity" size={14} />} title={<strong>{i.label}</strong>} lines={[`Identity · ${i.user}`]}>
              <button type="button" className="secondary small-button" onClick={() => p.onOpenIdentity(i.id)} aria-label={`Open ${i.label}`}>
                Open
              </button>
            </Row>
          ))}
          {keys.map((k) => (
            <Row key={k.id} avatar={<Icon name="key" size={14} />} title={<strong>{k.label}</strong>} lines={[`Key · ${k.algorithm.replace(/^ssh-/, "")}`]}>
              <button type="button" className="secondary small-button" onClick={() => p.onOpenKey(k.id)} aria-label={`Open ${k.label}`}>
                Open
              </button>
            </Row>
          ))}
          {jumps.map((j) => (
            <Row key={j.id} avatar={<Icon name="host" size={14} />} title={<strong>{j.label}</strong>} lines={["Jump host"]}>
              <button type="button" className="secondary small-button" onClick={() => p.onEditHost(j.id)} aria-label={`Edit ${j.label}`}>
                Edit
              </button>
            </Row>
          ))}
          {vpns.map((v) => (
            <Row key={v.id} on={v.active} avatar={<Icon name="vpn" size={14} />} title={<strong>{v.label}</strong>} lines={[`VPN · ${vpnKindName(v.kind)}`]}>
              <button type="button" className="secondary small-button" onClick={() => p.onOpenVpn(v.id)} aria-label={`Open ${v.label}`}>
                Open
              </button>
            </Row>
          ))}
        </ul>
      )}
    </div>
  );

  return (
    <Page
      back={{ label: "Groups", onClick: p.onBack }}
      title={g.name}
      badge={<VaultTag vaults={p.vaults} id={g.vaultId} />}
      lead={summary ? `Its hosts use ${summary}, unless they set their own.` : "Its hosts each sign in and connect their own way."}
      onClose={p.onClose}
      actions={
        <>
          <MoveButton ids={[g.id!]} label={g.name} from={g.vaultId!} />
          <button type="button" className="secondary" onClick={() => p.onEditGroup(g.id!)}>
            Edit group
          </button>
        </>
      }
      aside={uses}
    >
      <section className="stack">
        <h2 className="section-title">Hosts</h2>
        {members.length ? (
          <HostRows list={members} things={p} vaults={p.vaults} live={p.live} onConnect={p.onConnect} onFiles={p.onFiles} onEdit={p.onEditHost} />
        ) : (
          <p className="hint">None yet. Pick the group in a host's editor.</p>
        )}
      </section>
      {tunnels.length > 0 && (
        <section className="stack">
          <h2 className="section-title">Tunnels</h2>
          <TunnelRows forwards={tunnels} hosts={p.hosts} vaults={p.vaults} pending={p.pending} onToggle={p.onToggleForward} onOpen={p.onOpenForward} />
        </section>
      )}
      {(files?.length ?? 0) > 0 && (
        <section className="stack">
          <h2 className="section-title">Files</h2>
          <ul className="device-list item-list">
            {files!.map((f) => (
              <Row
                key={f.id}
                avatar={<Icon name="files" size={14} />}
                title={<strong>{f.name}</strong>}
                lines={[`${hostLabel(f.hostId)} · ${f.size < 1024 ? `${f.size} B` : f.size < 1048576 ? `${Math.round(f.size / 1024)} KB` : `${(f.size / 1048576).toFixed(1)} MB`}`]}
              >
                <button
                  type="button"
                  className="secondary small-button"
                  onClick={() => attachmentsApi.save(f.id).then((path) => setSaved(`Saved ${path}`), (e) => setError(errorText(e)))}
                >
                  Save
                </button>
              </Row>
            ))}
          </ul>
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
  onChanged: () => void;
  onClose: () => void;
}

export function KeysPage(p: KeysProps) {
  // Keys and identities together: a key can go with the identity that uses it.
  const sel = useSelection();
  const keyUse = (k: KeyView) => {
    const hosts = p.hosts.filter((h) => h.auth.kind === "key" && h.auth.keyId === k.id).length;
    const ids = p.identities.filter((i) => i.auth.kind === "key" && i.auth.keyId === k.id).length;
    const parts = [hosts && plural(hosts, "host"), ids && plural(ids, "identity", "identities")].filter(Boolean);
    return parts.length ? `Used by ${parts.join(" and ")}` : "Not used yet";
  };
  const idUse = (it: IdentityView) => {
    const hosts = p.hosts.filter((h) => h.identityId === it.id).length;
    const groups = p.groups.filter((g) => g.identityId === it.id).length;
    const parts = [hosts && plural(hosts, "host"), groups && plural(groups, "group")].filter(Boolean);
    return parts.length ? `Used by ${parts.join(" and ")}` : "Not used yet";
  };
  const authText = (it: IdentityView) =>
    it.auth.kind === "key"
      ? `key ${p.keys.find((k) => it.auth.kind === "key" && k.id === it.auth.keyId)?.label ?? "?"}`
      : it.auth.kind === "agent"
        ? agentDescription(it.auth)
        : "password";

  return (
    <Page
      title="Keys"
      lead="SSH keys stay in the vault, encrypted, and are used from there: they are never written to disk."
      onClose={p.onClose}
      actions={
        <>
          <SelectButton sel={sel} any={p.keys.length + p.identities.length + p.hostCas.length > 0} />
          <button type="button" className="primary" onClick={() => p.onOpenKey()}>
            New key
          </button>
        </>
      }
      aside={
        <div className="stack">
          <div className="row align-center">
            <h2 className="section-title grow">Identities</h2>
            <button type="button" className="secondary small-button" onClick={() => p.onEditIdentity()}>
              New identity
            </button>
          </div>
          <p className="hint">A user and a key (or password) that several hosts share. Change it once and they all follow.</p>
          {p.identities.length > 0 && (
            <ul className="device-list item-list">
              {p.identities.map((it) => (
                <Row
                  key={it.id}
                  pick={pickOf(sel, it.id, it.label)}
                  avatar={<Icon name="identity" size={14} />}
                  title={
                    <>
                      <strong>{it.label}</strong>
                      <VaultTag vaults={p.vaults} id={it.vaultId} />
                    </>
                  }
                  lines={[`${it.user} · ${authText(it)}`, idUse(it)]}
                >
                  <button type="button" className="secondary small-button" onClick={() => p.onEditIdentity(it.id)} aria-label={`Edit ${it.label}`}>
                    Edit
                  </button>
                </Row>
              ))}
            </ul>
          )}
          <div className="row align-center">
            <h2 className="section-title grow">Host CAs</h2>
            <button type="button" className="secondary small-button" onClick={() => p.onEditHostCa()}>
              New host CA
            </button>
          </div>
          <p className="hint">Hosts whose keys a CA signed are trusted without pinning each one (@cert-authority).</p>
          {p.hostCas.length > 0 && (
            <ul className="device-list item-list">
              {p.hostCas.map((ca) => (
                <Row
                  key={ca.id}
                  pick={pickOf(sel, ca.id, ca.label)}
                  avatar={<Icon name="key" size={14} />}
                  title={
                    <>
                      <strong>{ca.label}</strong>
                      <VaultTag vaults={p.vaults} id={ca.vaultId} />
                    </>
                  }
                  lines={[<span className="mono">{ca.hosts.join(", ")}</span>, <span className="mono">{ca.fingerprint}</span>]}
                >
                  <button type="button" className="secondary small-button" onClick={() => p.onEditHostCa(ca.id)} aria-label={`Edit ${ca.label}`}>
                    Edit
                  </button>
                </Row>
              ))}
            </ul>
          )}
        </div>
      }
    >
      <SelectBar
        sel={sel}
        shown={[...p.keys, ...p.identities, ...p.hostCas].map((x) => ({ id: x.id, vaultId: x.vaultId }))}
        noun={["item", "items"]}
        onDelete={bulk.remove}
        onChanged={p.onChanged}
      />
      {p.keys.length === 0 ? (
        <Empty text="No keys yet." action="Generate or import a key" onAction={() => p.onOpenKey()} />
      ) : (
        <ul className="device-list item-list">
          {p.keys.map((k) => (
            <Row
              key={k.id}
              pick={pickOf(sel, k.id, k.label)}
              avatar={<Icon name="key" size={14} />}
              title={
                <>
                  <strong>{k.label}</strong>
                  <span className="kind-badge">{k.algorithm.replace(/^ssh-/, "")}</span>
                  {k.encrypted && <span className="kind-badge">passphrase</span>}
                  <VaultTag vaults={p.vaults} id={k.vaultId} />
                </>
              }
              lines={[<span className="mono">{k.fingerprint}</span>, keyUse(k)]}
            >
              <button type="button" className="secondary small-button" onClick={() => p.onOpenKey(k.id)} aria-label={`Open ${k.label}`}>
                Open
              </button>
            </Row>
          ))}
        </ul>
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
  onSend: (body: string, run: boolean) => void;
  onChanged: () => void;
  onClose: () => void;
}

export function SnippetsPage(p: SnippetsProps) {
  const sel = useSelection();
  return (
    <Page
      title="Snippets"
      lead={p.target ? `Paste or run one in ${p.target}.` : "Commands you run often. Open a session to send them to it."}
      onClose={p.onClose}
      actions={
        <>
          <SelectButton sel={sel} any={p.snippets.length > 0} />
          <button type="button" className="secondary" onClick={p.onImport}>
            Import…
          </button>
          <button type="button" className="primary" onClick={() => p.onOpen()}>
            New snippet
          </button>
        </>
      }
    >
      <SelectBar
        sel={sel}
        shown={p.snippets.map((s) => ({ id: s.id, vaultId: s.vaultId }))}
        noun={["snippet", "snippets"]}
        onDelete={bulk.remove}
        onChanged={p.onChanged}
      />
      {p.snippets.length === 0 ? (
        <Empty text="No snippets yet." action="Save a command you run often" onAction={() => p.onOpen()} />
      ) : (
        <ul className="device-list item-list">
          {p.snippets.map((sn) => {
            const lines = sn.body.split("\n");
            return (
              <Row
                key={sn.id}
                pick={pickOf(sel, sn.id, sn.name)}
                avatar={<Icon name="snippet" size={14} />}
                title={
                  <>
                    <strong>{sn.name}</strong>
                    <VaultTag vaults={p.vaults} id={sn.vaultId} />
                    {sn.tags.map((t) => (
                      <span key={t} className="tag">
                        {t}
                      </span>
                    ))}
                  </>
                }
                lines={[<span className="mono">{lines[0]}</span>, lines.length > 1 && `${lines.length} lines`]}
              >
                {p.target && (
                  <>
                    <button type="button" className="secondary small-button" onClick={() => p.onSend(sn.body, false)}>
                      Paste
                    </button>
                    <button type="button" className="primary small-button" onClick={() => p.onSend(sn.body, true)}>
                      Run
                    </button>
                  </>
                )}
                <button type="button" className="secondary small-button" onClick={() => p.onOpen(sn.id)} aria-label={`Edit ${sn.name}`}>
                  Edit
                </button>
              </Row>
            );
          })}
        </ul>
      )}
    </Page>
  );
}

// ------------------------------------------------------------------ tunnels

interface TunnelsProps {
  forwards: ForwardView[];
  hosts: HostView[];
  vaults: VaultEntry[];
  pending: Set<string>;
  onToggle: (f: ForwardView) => void;
  onOpen: (id?: string) => void;
  onChanged: () => void;
  onClose: () => void;
}

export function TunnelsPage(p: TunnelsProps) {
  const sel = useSelection();
  const running = p.forwards.filter((f) => f.running).length;
  return (
    <Page
      title="Tunnels"
      lead={p.forwards.length ? `${running} of ${p.forwards.length} running. A tunnel forwards a port through a host's SSH connection.` : undefined}
      onClose={p.onClose}
      actions={
        <>
          <SelectButton sel={sel} any={p.forwards.length > 0} />
          <button type="button" className="primary" onClick={() => p.onOpen()}>
            New tunnel
          </button>
        </>
      }
    >
      <SelectBar
        sel={sel}
        shown={p.forwards.map((f) => ({ id: f.id, vaultId: f.vaultId }))}
        noun={["tunnel", "tunnels"]}
        onDelete={(ids) => eachOf(ids, forwardsApi.remove)}
        onChanged={p.onChanged}
      />
      {p.forwards.length === 0 ? (
        <Empty text="No tunnels yet." action="Forward a port through a host" onAction={() => p.onOpen()} />
      ) : (
        <TunnelRows forwards={p.forwards} hosts={p.hosts} vaults={p.vaults} pending={p.pending} onToggle={p.onToggle} onOpen={p.onOpen} sel={sel} />
      )}
    </Page>
  );
}

function TunnelRows(p: Omit<TunnelsProps, "onClose" | "onChanged"> & { sel?: Selection }) {
  return (
    <ul className="device-list item-list">
      {p.forwards.map((f) => {
        const busy = p.pending.has(f.id);
        return (
          <Row
            key={f.id}
            on={f.running}
            pick={p.sel && pickOf(p.sel, f.id, f.label)}
            avatar={<Icon name="tunnel" size={14} />}
            title={
              <>
                <strong>{f.label}</strong>
                <VaultTag vaults={p.vaults} id={f.vaultId} />
              </>
            }
            lines={[
              <span className="mono">
                {describeForward(f)}
                {f.running && f.active > 0 ? ` · ${f.active} open` : ""}
              </span>,
              `Through ${p.hosts.find((h) => h.id === f.hostId)?.label ?? "a host that's gone"}`,
            ]}
          >
            <button type="button" className="secondary small-button" onClick={() => p.onOpen(f.id)} aria-label={`Edit ${f.label}`}>
              Edit
            </button>
            <button
              type="button"
              role="switch"
              aria-checked={f.running}
              aria-label={`${f.running ? "Stop" : "Start"} ${f.label}`}
              title={f.running ? "Stop tunnel" : "Start tunnel"}
              className={`switch ${f.running ? "on" : ""} ${busy ? "busy" : ""}`}
              disabled={busy}
              onClick={() => p.onToggle(f)}
            >
              <i />
            </button>
          </Row>
        );
      })}
    </ul>
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
  const use = (v: VpnView) => {
    const hosts = p.hosts.filter((h) => h.vpnId === v.id).length;
    const groups = p.groups.filter((g) => g.vpnId === v.id).length;
    const parts = [hosts && plural(hosts, "host"), groups && plural(groups, "group")].filter(Boolean);
    return parts.length ? `Used by ${parts.join(" and ")}` : "Not used by a host yet";
  };
  return (
    <Page
      title="VPNs"
      lead="Hosts that use a VPN connect through it. It starts with the first session or tunnel that needs it and stops after the last, inside MorphGate: nothing changes on the system."
      onClose={p.onClose}
      actions={
        <>
          <SelectButton sel={sel} any={p.vpns.length > 0} />
          <button type="button" className="primary" onClick={() => p.onOpen()}>
            New VPN
          </button>
        </>
      }
    >
      <SelectBar
        sel={sel}
        shown={p.vpns.map((v) => ({ id: v.id, vaultId: v.vaultId }))}
        noun={["VPN", "VPNs"]}
        onDelete={(ids) => eachOf(ids, vpnsApi.remove)}
        onChanged={p.onChanged}
      />
      {p.vpns.length === 0 ? (
        <Empty text="No VPNs yet." action="Add a client's VPN (WireGuard, OpenVPN, AnyConnect…)" onAction={() => p.onOpen()} />
      ) : (
        <ul className="device-list item-list">
          {p.vpns.map((v) => (
            <Row
              key={v.id}
              on={v.active}
              pick={pickOf(sel, v.id, v.label)}
              avatar={<Icon name="vpn" size={14} />}
              title={
                <>
                  <strong>{v.label}</strong>
                  <span className="kind-badge">{vpnKindName(v.kind)}</span>
                  <VaultTag vaults={p.vaults} id={v.vaultId} />
                </>
              }
              lines={[
                <span className="mono">{v.server}</span>,
                v.problem ? <span className="error-text">{v.problem}</span> : v.active ? `Connected${v.address ? ` · ${v.address}` : ""}` : use(v),
              ]}
            >
              <button type="button" className="secondary small-button" onClick={() => p.onOpen(v.id)} aria-label={`Open ${v.label}`}>
                Open
              </button>
            </Row>
          ))}
        </ul>
      )}
    </Page>
  );
}
