// Teams: the teams this account is in, each team's page, and joining one.
//
// A team's page puts what needs you first (a member to confirm, a device to approve, a key to
// rotate), then tabs: Members, Vaults, your SSH keys, and for owners and admins Settings and
// Activity. Lists are tables (ListParts.tsx), as on the other pages; inviting people is the
// page's one primary action.

import { Fragment, useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  ACCESS_NAMES,
  ROLE_NAMES,
  dateText,
  dateTimeText,
  errorText,
  platformName,
  teamLimit,
  offboard,
  sync,
  teams,
  type Access,
  type Activity,
  type InvitePreview,
  type InviteView,
  type KeyView,
  type MemberKeyView,
  type MemberView,
  type OrgDetails,
  type OrgInfo,
  type HostResult,
  type KeyReplaced,
  type OffboardSummary,
  type OrgPlan,
  type Policies,
  type Role,
  type SharingStatus,
  type SsoView,
  type DeviceRequest,
  type SyncStatus,
  type VaultAccess,
  type VaultEntry,
} from "./api";
import { Icon } from "./Icon";
import { Cell, Chip, NameCell, Table, TextAction, TRow } from "./ListParts";
import { Page } from "./Page";
import { mobileOs } from "./mobile/useMobile";

interface Props {
  vaults: VaultEntry[];
  orgs: OrgInfo[];
  /** SSH keys in the vault (the personal ones can be published to an organization). */
  keys: KeyView[];
  /** What sync knows each team waits on: sign-ins, approvals, keys to publish. */
  syncStatus: SyncStatus | null;
  /** Reloads organizations, vaults and items. */
  onChanged: () => Promise<void>;
  onClose: () => void;
  /** Sign in at an organization's identity provider. */
  onSso: (orgId: string, orgName: string) => void;
  /** Organizations whose vaults wait until the account has two-step verification. */
  totpRequired: string[];
  /** Turn on two-step verification. */
  onTotp: () => void;
  /** From a link: an invite to look up, or the team to open. */
  invite?: string;
  openOrg?: string;
}

const ACCESS_LEVELS: Access[] = ["read", "write", "manage"];
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function TeamsPanel({ vaults, orgs, keys, syncStatus, onChanged, onClose, onSso, totpRequired, onTotp, invite, openOrg }: Props) {
  const personal = vaults.find((v) => v.personal)?.id;
  const personalKeys = keys.filter((k) => k.vaultId === personal);
  const [status, setStatus] = useState<SharingStatus | null>(null);
  const [error, setError] = useState("");
  const [open, setOpen] = useState<string | null>(openOrg ?? null);
  const [creating, setCreating] = useState(false);
  useEffect(() => {
    teams.status().then(setStatus, (e) => setError(errorText(e)));
  }, []);
  const org = orgs.find((o) => o.id === open);
  const opened = (id: string) => void onChanged().then(() => (setCreating(false), setOpen(id)));

  if (org) {
    return (
      <OrgView
        key={org.id}
        org={org}
        vaults={vaults.filter((v) => v.orgId === org.id)}
        personalKeys={personalKeys}
        fingerprint={status?.fingerprint ?? null}
        me={status?.accountId ?? null}
        onBack={() => setOpen(null)}
        onClose={onClose}
        onChanged={onChanged}
        onGone={() => void onChanged().then(() => setOpen(null))}
        onSso={() => onSso(org.id, org.name)}
        totpRequired={totpRequired.includes(org.id)}
        onTotp={onTotp}
      />
    );
  }

  // What each team waits on from this account or device, from what's known here.
  const needsOf = (o: OrgInfo): string[] => {
    if (o.status === "accepted") return [];
    const out: string[] = [];
    if (totpRequired.includes(o.id)) out.push("Turn on two-step verification");
    if (syncStatus?.ssoRequired.some((n) => n.orgId === o.id)) out.push("Sign in with single sign-on");
    const held = syncStatus?.approvalRequired.find((n) => n.orgId === o.id);
    if (held) out.push(held.denied ? "This device was denied" : "This device waits for approval");
    const waiting = syncStatus?.approvalsWaiting.find((w) => w.orgId === o.id)?.count ?? 0;
    if (waiting) out.push(`${plural(waiting, "device")} to approve`);
    if (syncStatus?.memberKeysDue.some((d) => d.orgId === o.id)) out.push("Publish your SSH keys");
    if (vaults.some((v) => v.orgId === o.id && v.access === "manage" && v.rotationDue)) out.push("Rotate a vault's key");
    return out;
  };

  return (
    <Page
      title="Teams"
      lead="Share hosts, keys, tunnels and VPNs through a team's vaults. They stay end-to-end encrypted: the sync server can't read them either."
      onClose={onClose}
      actions={
        status?.available && (
          <button type="button" className="primary" onClick={() => setCreating(true)} disabled={creating}>
            New team
          </button>
        )
      }
    >
      {error && <p className="error">{error}</p>}
      {!status && !error && <p className="hint">Loading…</p>}
      {status && !status.available && <p className="warn">{status.reason}</p>}
      {creating && <CreateOrg onCreated={opened} onCancel={() => setCreating(false)} />}
      {orgs.length === 0
        ? status?.available && !creating && <p className="hint">No teams yet. Make one, or join with an invite someone sent you.</p>
        : (
            <Table cols="minmax(160px, 1.3fr) 80px minmax(120px, 1fr) minmax(160px, 1.5fr) 56px" label="Your teams" head={["Team", "You are", "Vaults you open", "Needs you"]}>
              {orgs.map((o, i) => {
                const names = vaults.filter((v) => v.orgId === o.id && !v.directory).map((v) => v.name ?? "Shared vault");
                const needs = needsOf(o);
                return (
                  <TRow key={o.id} index={i} actions={<TextAction onClick={() => setOpen(o.id)}>Open</TextAction>}>
                    <NameCell onOpen={() => setOpen(o.id)} title={`Open ${o.name}`} lead={<Icon name="teams" size={15} />} name={o.name} />
                    <Cell>{o.status === "accepted" ? <span className="muted">Joined</span> : ROLE_NAMES[o.role]}</Cell>
                    <Cell className="trunc">{names.length ? names.join(", ") : <span className="muted">None yet</span>}</Cell>
                    <Cell className="ltags">
                      {o.status === "accepted" ? (
                        <span className="muted">An admin confirms you next</span>
                      ) : needs.length ? (
                        needs.map((n) => (
                          <Chip key={n} state="attention">
                            {n}
                          </Chip>
                        ))
                      ) : (
                        <span className="muted">Nothing</span>
                      )}
                    </Cell>
                  </TRow>
                );
              })}
            </Table>
          )}
      {status?.available && (
        <div className="teams-foot">
          <JoinOrg onJoined={opened} invite={invite} />
          {status.fingerprint && (
            <div className="stack">
              <h2 className="section-title">Your fingerprint</h2>
              <Fingerprint value={status.fingerprint} />
              <p className="hint">
                Before an admin gives you a team's vaults, they compare this with you on a call or in person. It proves that the keys
                the server showed them are yours.
              </p>
            </div>
          )}
        </div>
      )}
    </Page>
  );
}

function CreateOrg({ onCreated, onCancel }: { onCreated: (id: string) => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // Too many teams without a plan (hosted): what the server said.
  const [limit, setLimit] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError("");
    setLimit("");
    teams.createOrg(name.trim()).then(
      (id) => (setName(""), setBusy(false), onCreated(id)),
      (err) => (teamLimit(err) ? setLimit(teamLimit(err)!) : setError(errorText(err)), setBusy(false)),
    );
  };
  return (
    <form className="quick-bar" onSubmit={submit}>
      <span className="section-title">New team</span>
      <input className="grow" value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Ops" aria-label="Team name" autoFocus />
      <button type="button" className="quiet" onClick={onCancel}>
        Cancel
      </button>
      <button type="submit" className="secondary" disabled={!name.trim() || busy}>
        Create team
      </button>
      <small className="hint quick-hint">You'll be its owner. Then create vaults in it and invite people.</small>
      {error && <p className="error quick-hint">{error}</p>}
      {limit && (
        <div className="notice-box stack team-limit quick-hint">
          <p className="warn">{limit.charAt(0).toUpperCase() + limit.slice(1)}.</p>
          {!mobileOs && (
            <div className="row">
              <button
                type="button"
                className="secondary"
                onClick={() => sync.openPortal("/account").catch((e) => (setLimit(""), setError(errorText(e))))}
              >
                Choose a plan ↗
              </button>
            </div>
          )}
        </div>
      )}
    </form>
  );
}

interface OrgProps {
  org: OrgInfo;
  vaults: VaultEntry[];
  personalKeys: KeyView[];
  fingerprint: string | null;
  /** This account's id. */
  me: string | null;
  onBack: () => void;
  onClose: () => void;
  onChanged: () => Promise<void>;
  /** This account left or deleted the organization. */
  onGone: () => void;
  /** Sign in at the organization's identity provider. */
  onSso: () => void;
  /** Its vaults wait until the account has two-step verification. */
  totpRequired: boolean;
  onTotp: () => void;
}

type OrgTab = "members" | "vaults" | "keys" | "settings" | "activity";

function OrgView({ org, vaults, personalKeys, fingerprint, me, onBack, onClose, onChanged, onGone, onSso, totpRequired, onTotp }: OrgProps) {
  const [members, setMembers] = useState<MemberView[] | null>(null);
  const [memberKeys, setMemberKeys] = useState<MemberKeyView[]>([]);
  const shared = vaults.filter((v) => !v.directory);
  const hasDirectory = vaults.some((v) => v.directory);
  // Local: reloaded whenever a sync brings vault changes.
  const loadKeys = useCallback(() => {
    teams.memberKeys(org.id).then(setMemberKeys, () => {});
  }, [org.id]);
  useEffect(loadKeys, [loadKeys, vaults]);
  const [invites, setInvites] = useState<InviteView[]>([]);
  const [details, setDetails] = useState<OrgDetails | null>(null);
  const [requests, setRequests] = useState<DeviceRequest[]>([]);
  const [offboarding, setOffboarding] = useState<MemberView | null>(null);
  // The member whose fingerprint is being compared (to confirm them, or certify them again).
  const [confirming, setConfirming] = useState<string | null>(null);
  const [inviting, setInviting] = useState(false);
  const [newVault, setNewVault] = useState(false);
  // Plans enforced and no usable plan (usable as the server counts it: a trial, an active plan or
  // its grace period): nothing in the team changes until it has one. Removing people,
  // transferring and deleting the team stay possible.
  const locked =
    !!details?.plansEnforced && !(details.plan && (!details.plan.status || ["trialing", "active", "grace"].includes(details.plan.status)));
  const [error, setError] = useState("");
  const confirmed = org.status === "confirmed";
  const admin = confirmed && (org.role === "owner" || org.role === "admin");
  const owner = org.role === "owner";
  const canCreateVaults = admin || (confirmed && !!details?.policies.membersCanCreateVaults);
  const [tab, setTab] = useState<OrgTab>(admin ? "members" : "vaults");

  const loadRequests = useCallback(() => {
    if (confirmed) teams.deviceRequests(org.id).then(setRequests, () => {});
  }, [org.id, confirmed]);
  const load = useCallback(() => {
    // Only confirmed members see the member list.
    if (!confirmed) return;
    teams.members(org.id).then(setMembers, (e) => setError(errorText(e)));
    teams.details(org.id).then(setDetails, (e) => setError(errorText(e)));
    if (admin) teams.invites(org.id).then(setInvites, (e) => setError(errorText(e)));
    loadRequests();
  }, [org.id, confirmed, admin, loadRequests]);
  useEffect(load, [load]);
  // Back from the browser (a plan bought, say): the plan again.
  useEffect(() => {
    if (!confirmed) return;
    const again = () => void teams.details(org.id).then(setDetails, () => {});
    window.addEventListener("focus", again);
    return () => window.removeEventListener("focus", again);
  }, [org.id, confirmed]);

  const changed = () => {
    load();
    void onChanged();
  };

  if (offboarding) {
    return (
      <div className="panel page">
        <div className="page-inner">
          <div className="org-page narrow">
            <Offboard
              org={org}
              member={offboarding}
              onBack={() => (setOffboarding(null), changed())}
              onChanged={changed}
            />
          </div>
        </div>
      </div>
    );
  }

  // The owner, on desktop, chooses or manages the team's plan in the account portal (servers with plans).
  const portal = owner && !!details?.plansOffered && details.portal && !mobileOs;
  const billing = () => void sync.openPortal(`/account/team/${org.id}/billing`).catch((e) => setError(errorText(e)));

  const published = (account: string) => memberKeys.filter((k) => k.accountId === account && k.verified).length;
  const keysRequired = details?.policies.requireMemberKeys === true;
  const keysDue = confirmed && keysRequired && hasDirectory && !!me && published(me) === 0 && personalKeys.length > 0;
  const confirm = (accountId: string) => (setTab("members"), setConfirming(accountId));

  const tabs: [OrgTab, string, number | null][] = !confirmed
    ? []
    : admin
      ? [
          ["members", "Members", members?.length ?? null],
          ["vaults", "Vaults", shared.length],
          ["keys", "Your SSH keys", null],
          ["settings", "Settings", null],
          ["activity", "Activity", null],
        ]
      : [
          ["vaults", "Vaults", shared.length],
          ["members", "Members", members?.length ?? null],
          ["keys", "Your SSH keys", null],
        ];

  return (
    <Page
      back={{ label: "Teams", onClick: onBack }}
      onClose={onClose}
      title={org.name}
      badge={<span className="kind-badge">{ROLE_NAMES[org.role]}</span>}
      lead={
        (details?.plansOffered || (confirmed && details?.ssoOffered)) && (
          <>
            {details?.plansOffered && (
              <PlanLine
                plan={details.plan}
                enforced={details.plansEnforced}
                seatsUsed={members?.filter((m) => m.status === "confirmed").length ?? null}
              />
            )}
            {confirmed && details?.ssoOffered && <SsoLine org={org} onSignIn={onSso} />}
          </>
        )
      }
      actions={
        (portal || (confirmed && canCreateVaults) || admin) && (
          <>
            {confirmed && canCreateVaults && (
              <button type="button" className="secondary" disabled={locked || newVault} onClick={() => (setTab("vaults"), setNewVault(true))}>
                New vault
              </button>
            )}
            {portal && (
              <button type="button" className="secondary" onClick={billing}>
                {details?.plan ? "Manage plan ↗" : "Choose a plan ↗"}
              </button>
            )}
            {admin && (
              <button type="button" className="primary" disabled={locked} onClick={() => setInviting(true)}>
                Invite people
              </button>
            )}
          </>
        )
      }
    >
      {!confirmed && (
        <div className="notice-box stack">
          <p className="warn">You joined. An admin confirms you next: when they ask, read them your fingerprint.</p>
          {fingerprint && <Fingerprint value={fingerprint} />}
          {me && <Leave org={org} me={me} onGone={onGone} />}
        </div>
      )}
      {error && <p className="error">{error}</p>}
      {locked && (
        <p className="notice-box warn team-locked">
          {org.name} is locked until it has a plan: no new vaults, edits, invites, policies or published keys.
          {mobileOs ? "" : owner ? " Choose a plan above." : " Its owner can choose one."} Removing people, taking access away, rotating keys and
          leaving still work.
        </p>
      )}
      {confirmed && (
        <NeedsYou
          org={org}
          admin={admin}
          members={members ?? []}
          requests={requests}
          vaults={vaults}
          totpRequired={totpRequired}
          keysDue={keysDue}
          onTotp={onTotp}
          onConfirm={confirm}
          onKeys={() => setTab("keys")}
          onChanged={() => (loadRequests(), changed())}
        />
      )}
      {tabs.length > 0 && (
        <div className="page-tabs" role="tablist" aria-label={org.name}>
          {tabs.map(([t, label, n]) => (
            <button key={t} type="button" role="tab" aria-selected={tab === t} className={`page-tab ${tab === t ? "on" : ""}`} onClick={() => setTab(t)}>
              {label}
              {n !== null && <b>{n}</b>}
            </button>
          ))}
        </div>
      )}
      {confirmed && tab === "members" && (
        <>
          <MembersTab
            org={org}
            members={members}
            invites={admin ? invites : []}
            published={published}
            keysRequired={keysRequired}
            admin={admin}
            owner={owner}
            locked={locked}
            confirming={confirming}
            setConfirming={setConfirming}
            onChanged={changed}
            onGone={onGone}
            onOffboard={setOffboarding}
          />
          <DeviceRequests requests={requests} admin={admin} required={!!details?.policies.requireDeviceApproval} locked={locked} org={org} onChanged={loadRequests} />
        </>
      )}
      {confirmed && tab === "vaults" && (
        <VaultsTab
          vaults={vaults}
          members={members ?? []}
          orgId={org.id}
          canCreate={canCreateVaults}
          creating={newVault && !locked}
          onCreating={setNewVault}
          locked={locked}
          onChanged={changed}
        />
      )}
      {confirmed && tab === "keys" && (
        <fieldset className="plain" disabled={locked}>
          <MyKeys org={org} keys={personalKeys} published={memberKeys.filter((k) => k.mine)} ready={hasDirectory} waiting={totpRequired} onChanged={loadKeys} />
        </fieldset>
      )}
      {admin && tab === "settings" && details && (
        <>
          <fieldset className="plain" disabled={locked}>
            <Settings key={JSON.stringify(details.policies)} org={org} details={details} onChanged={changed} />
          </fieldset>
          {owner && <OwnerZone org={org} members={members ?? []} onChanged={changed} onGone={onGone} />}
        </>
      )}
      {admin && tab === "activity" && <ActivityLog org={org} />}
      {inviting && (
        <InviteDialog
          org={org}
          owner={owner}
          vaults={shared}
          domains={details?.policies.allowedEmailDomains ?? []}
          onClose={() => setInviting(false)}
          onChanged={changed}
        />
      )}
    </Page>
  );
}

/** What waits for this account in the team: a member to confirm or certify again, a device to
 * approve, a key to rotate, two-step verification, SSH keys to publish. Each with its action. */
function NeedsYou({
  org,
  admin,
  members,
  requests,
  vaults,
  totpRequired,
  keysDue,
  onTotp,
  onConfirm,
  onKeys,
  onChanged,
}: {
  org: OrgInfo;
  admin: boolean;
  members: MemberView[];
  requests: DeviceRequest[];
  vaults: VaultEntry[];
  totpRequired: boolean;
  keysDue: boolean;
  onTotp: () => void;
  onConfirm: (accountId: string) => void;
  onKeys: () => void;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const run = (what: string, p: Promise<unknown>) => {
    setBusy(what);
    setError("");
    p.then(
      () => (setBusy(""), onChanged()),
      (e) => (setError(errorText(e)), setBusy("")),
    );
  };
  const rows: { key: string; text: ReactNode; actions: ReactNode }[] = [];
  if (totpRequired) {
    rows.push({
      key: "totp",
      text: <>{org.name} requires two-step verification: its vaults open on your devices once your account has it.</>,
      actions: (
        <button type="button" className="primary small-button" onClick={onTotp}>
          Turn on two-step verification
        </button>
      ),
    });
  }
  if (admin) {
    for (const m of members.filter((m) => m.status === "accepted")) {
      rows.push({
        key: `confirm:${m.accountId}`,
        text: (
          <>
            <b>{m.email} joined.</b> Compare their fingerprint with them on a call or in person, then confirm them
            {m.pendingVaults.length > 0 ? ": they get the vaults their invite offered." : "."}
          </>
        ),
        actions: (
          <button type="button" className="secondary small-button" onClick={() => onConfirm(m.accountId)}>
            Confirm {m.email.split("@")[0]}…
          </button>
        ),
      });
    }
    for (const m of members.filter((m) => m.status === "confirmed" && !m.verified && !m.me)) {
      rows.push({
        key: `verify:${m.accountId}`,
        text: (
          <>
            <b>Certify {m.email} again:</b> the admin who confirmed them left, so devices that never verified them can't yet.
          </>
        ),
        actions: (
          <button type="button" className="secondary small-button" onClick={() => onConfirm(m.accountId)}>
            Verify…
          </button>
        ),
      });
    }
  }
  for (const r of requests.filter((r) => r.status === "pending" && !r.thisDevice && (admin || r.mine))) {
    const whose = r.mine ? "Your" : `${r.email ?? "A member"}'s`;
    rows.push({
      key: `device:${r.accountId}/${r.deviceId}`,
      text: (
        <>
          <b>
            {whose} new device{r.name ? `, ${r.name}` : ""}
          </b>
          {r.platform ? ` (${platformName(r.platform)})` : ""}, waits for approval to open the team's vaults.
        </>
      ),
      actions: (
        <>
          <button
            type="button"
            className="secondary small-button"
            disabled={!!busy}
            onClick={() => run(`a:${r.deviceId}`, teams.decideDevice(org.id, r.accountId, r.deviceId, true))}
          >
            Approve
          </button>
          <button
            type="button"
            className="quiet small-button"
            disabled={!!busy}
            onClick={() => run(`d:${r.deviceId}`, teams.decideDevice(org.id, r.accountId, r.deviceId, false))}
          >
            Deny
          </button>
        </>
      ),
    });
  }
  for (const v of vaults.filter((v) => v.access === "manage" && v.rotationDue)) {
    rows.push({
      key: `rotate:${v.id}`,
      text: (
        <>
          <b>{v.name ?? "A vault"}'s key should be rotated:</b> someone lost access since it was made. A new key keeps them out of what's
          added next.
        </>
      ),
      actions: (
        <button type="button" className="secondary small-button" disabled={!!busy} onClick={() => run(`r:${v.id}`, teams.rotate(v.id))}>
          {busy === `r:${v.id}` ? "Rotating…" : "Rotate key"}
        </button>
      ),
    });
  }
  if (keysDue) {
    rows.push({
      key: "keys",
      text: <>{org.name} asks members to publish the SSH keys they use on its servers, so that leaving can remove them.</>,
      actions: (
        <button type="button" className="secondary small-button" onClick={onKeys}>
          Publish a key
        </button>
      ),
    });
  }
  if (rows.length === 0 && !error) return null;
  return (
    <section className="needs" aria-label="Needs you">
      {rows.map((r) => (
        <div key={r.key} className="need-row">
          <span className="sq attention" aria-hidden="true" />
          <span className="need-text">{r.text}</span>
          <span className="need-actions">{r.actions}</span>
        </div>
      ))}
      {error && <p className="error">{error}</p>}
    </section>
  );
}

/** The team's vaults: what you can do in each, its key, and (for those you manage) who can open it. */
function VaultsTab({
  vaults,
  members,
  orgId,
  canCreate,
  creating,
  onCreating,
  locked,
  onChanged,
}: {
  vaults: VaultEntry[];
  members: MemberView[];
  orgId: string;
  canCreate: boolean;
  /** New vault (the page's action) opened its bar. */
  creating: boolean;
  onCreating: (on: boolean) => void;
  locked: boolean;
  onChanged: () => void;
}) {
  const [editing, setEditing] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const shared = vaults.filter((v) => !v.directory);
  const rotate = (v: VaultEntry) => {
    setBusy(v.id);
    setError("");
    teams.rotate(v.id).then(
      () => (setBusy(null), onChanged()),
      (e) => (setError(errorText(e)), setBusy(null)),
    );
  };
  // Shared vaults by name, then the member key directory.
  const rows = [...shared, ...vaults.filter((v) => v.directory)];
  return (
    <>
      {creating && <NewVault orgId={orgId} onCreated={() => (onCreating(false), onChanged())} onCancel={() => onCreating(false)} />}
      {shared.length === 0 && !creating && (
        <p className="hint">{canCreate ? "No vaults yet. Create one (New vault), then give members access." : "You can't open any of its vaults yet."}</p>
      )}
      {rows.length > 0 && (
        <Table cols="minmax(170px, 1.4fr) 60px 100px 110px 140px" label="Vaults" head={["Vault", "Items", "You can", "Key"]}>
          {rows.map((v, i) => {
            const manage = v.access === "manage";
            return (
              <Fragment key={v.id}>
                <TRow
                  index={i}
                  actions={
                    <>
                      {manage && v.rotationDue && (
                        <TextAction warn onClick={() => rotate(v)}>
                          {busy === v.id ? "Rotating…" : "Rotate key"}
                        </TextAction>
                      )}
                      {manage && !v.directory && (
                        <TextAction onClick={() => setEditing(editing === v.id ? null : v.id)}>{editing === v.id ? "Done" : "Access"}</TextAction>
                      )}
                    </>
                  }
                >
                  <NameCell
                    lead={<Icon name={v.directory ? "key" : "lock"} size={15} />}
                    name={v.name ?? "Shared vault"}
                    sub={v.directory ? "Members' SSH public keys" : undefined}
                  />
                  <Cell className="num">{v.items}</Cell>
                  <Cell>{v.directory ? <span className="muted">Every member</span> : ACCESS_NAMES[v.access]}</Cell>
                  <Cell>
                    {v.rotationDue ? (
                      <Chip state="attention">{manage ? "Rotate" : "Rotation due"}</Chip>
                    ) : (
                      <span className="muted">Current</span>
                    )}
                  </Cell>
                </TRow>
                {editing === v.id && (
                  <div className="lexpand">
                    <AccessEditor vault={v} members={members} locked={locked} onChanged={onChanged} />
                  </div>
                )}
              </Fragment>
            );
          })}
        </Table>
      )}
      {error && <p className="error">{error}</p>}
    </>
  );
}

interface MembersProps {
  org: OrgInfo;
  members: MemberView[] | null;
  /** Invites not accepted yet (owners and admins). */
  invites: InviteView[];
  /** How many SSH keys an account published (verified). */
  published: (account: string) => number;
  admin: boolean;
  owner: boolean;
  /** The organization asks members to publish their SSH keys. */
  keysRequired: boolean;
  /** The team has no usable plan: confirming people and changing roles wait for one. */
  locked: boolean;
  confirming: string | null;
  setConfirming: (id: string | null) => void;
  onChanged: () => void;
  onGone: () => void;
  /** Removing a confirmed member goes through offboarding. */
  onOffboard: (m: MemberView) => void;
}

/** Members, and the invites not accepted yet, in one table. */
function MembersTab({ org, members, invites, published, keysRequired, admin, owner, locked, confirming, setConfirming, onChanged, onGone, onOffboard }: MembersProps) {
  const [matches, setMatches] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => setMatches(false), [confirming]);

  const act = (p: Promise<void>, then: () => void = onChanged) => {
    setBusy(true);
    setError("");
    p.then(
      () => (setBusy(false), setConfirming(null), setRemoving(null), then()),
      (e) => (setError(errorText(e)), setBusy(false)),
    );
  };
  if (members === null) return error ? <p className="error">{error}</p> : <p className="hint">Loading…</p>;

  return (
    <>
      <Table cols="minmax(160px, 1.8fr) 104px 110px 90px 130px" label="Members" head={["Member", "Role", "Keys", "SSH keys"]}>
        {members.map((m, i) => {
          const canRemove = !m.me && m.role !== "owner" && admin && (m.role === "member" || owner);
          const n = published(m.accountId);
          return (
            <Fragment key={m.accountId}>
              <TRow
                index={i}
                actions={
                  <>
                    {admin && m.status === "accepted" && (
                      <TextAction onClick={() => setConfirming(confirming === m.accountId ? null : m.accountId)}>Confirm…</TextAction>
                    )}
                    {admin && m.status === "confirmed" && !m.verified && !m.me && (
                      <TextAction onClick={() => setConfirming(confirming === m.accountId ? null : m.accountId)}>Verify…</TextAction>
                    )}
                    {canRemove && m.status === "confirmed" && (
                      <button type="button" className="text-action danger" onClick={() => onOffboard(m)}>
                        Remove…
                      </button>
                    )}
                    {((canRemove && m.status === "accepted") || (m.me && m.role !== "owner")) &&
                      (removing === m.accountId ? (
                        <button
                          type="button"
                          className="text-action danger"
                          disabled={busy}
                          onClick={() => act(teams.remove(org.id, m.accountId), m.me ? onGone : onChanged)}
                        >
                          {m.me ? "Really leave?" : "Really remove?"}
                        </button>
                      ) : (
                        <button type="button" className="text-action danger" onClick={() => setRemoving(m.accountId)}>
                          {m.me ? "Leave" : "Remove"}
                        </button>
                      ))}
                  </>
                }
              >
                <NameCell name={m.email} beside={m.me && <span className="kind-badge me">you</span>} sub={m.fingerprint} subTone="mono" />
                <Cell>
                  {owner && !m.me && m.status === "confirmed" && m.role !== "owner" ? (
                    <select
                      className="cell-select"
                      value={m.role}
                      disabled={busy || locked}
                      aria-label={`Role of ${m.email}`}
                      title="Admins manage every vault and member"
                      onChange={(e) => act(teams.setRole(org.id, m.accountId, e.target.value as Role))}
                    >
                      <option value="member">Member</option>
                      <option value="admin">Admin</option>
                    </select>
                  ) : (
                    ROLE_NAMES[m.role]
                  )}
                </Cell>
                <Cell>
                  {m.status === "accepted" ? (
                    <Chip state="attention">To confirm</Chip>
                  ) : m.verified ? (
                    <Chip state="connected">Verified</Chip>
                  ) : (
                    <Chip state="attention">Not verified</Chip>
                  )}
                </Cell>
                <Cell>
                  {m.status !== "confirmed" ? (
                    <span className="muted">–</span>
                  ) : n > 0 ? (
                    `${n} published`
                  ) : keysRequired ? (
                    <span className="warn-text">None yet</span>
                  ) : (
                    <span className="muted">None</span>
                  )}
                </Cell>
              </TRow>
              {confirming === m.accountId && (
                <div className="lexpand stack">
                  <p className="hint">
                    Ask {m.email} to read you their fingerprint (Teams, on their device), on a call or in person. Confirm only if it
                    matches:
                  </p>
                  <Fingerprint value={m.fingerprint} />
                  {m.status === "accepted" && m.pendingVaults.length > 0 && <p className="hint">Confirming gives them the vault access their invite offered.</p>}
                  <label className="check">
                    <input type="checkbox" checked={matches} onChange={(e) => setMatches(e.target.checked)} />
                    <span>It matches what they read to me</span>
                  </label>
                  <div className="row">
                    <button type="button" className="quiet" onClick={() => setConfirming(null)}>
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="primary"
                      disabled={!matches || busy || (m.status === "accepted" && locked)}
                      onClick={() =>
                        act(
                          m.status === "confirmed"
                            ? teams.recertify(org.id, m.accountId, m.fingerprint)
                            : teams.confirm(org.id, m.accountId, m.fingerprint),
                        )
                      }
                    >
                      {m.status === "confirmed" ? `Certify ${m.email} again` : `Confirm ${m.email}`}
                    </button>
                  </div>
                </div>
              )}
            </Fragment>
          );
        })}
        {invites.map((inv, i) => (
          <TRow
            key={inv.id}
            index={members.length + i}
            actions={
              <button
                type="button"
                className="text-action danger"
                onClick={() => (setError(""), teams.cancelInvite(org.id, inv.id).then(onChanged, (e) => setError(errorText(e))))}
              >
                Cancel invite
              </button>
            }
          >
            <NameCell name={inv.email} sub={`Invited · works until ${dateText(inv.expiresAt)}`} />
            <Cell>{ROLE_NAMES[inv.role]}</Cell>
            <Cell>
              <Chip state="idle">Invited</Chip>
            </Cell>
            <Cell>
              <span className="muted">–</span>
            </Cell>
          </TRow>
        ))}
      </Table>
      {error && <p className="error">{error}</p>}
    </>
  );
}

/** The team's devices that asked to open its vaults, and the ones denied (approving is also in
 * Needs you). */
function DeviceRequests({
  org,
  requests,
  admin,
  required,
  locked,
  onChanged,
}: {
  org: OrgInfo;
  requests: DeviceRequest[];
  admin: boolean;
  required: boolean;
  locked: boolean;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  if (requests.length === 0) {
    return required ? (
      <p className="hint">
        New devices wait for approval before they open the team's vaults. None is waiting.
        {!admin && " When you sign in on a new device, approve it here, from this one."}
      </p>
    ) : null;
  }
  const decide = (r: DeviceRequest, approve: boolean) => {
    setBusy(r.deviceId);
    setError("");
    teams.decideDevice(org.id, r.accountId, r.deviceId, approve).then(
      () => (setBusy(null), onChanged()),
      (e) => (setError(errorText(e)), setBusy(null)),
    );
  };
  return (
    <section className="stack device-requests">
      <h2 className="section-title">Devices waiting</h2>
      <Table cols="minmax(170px, 1.4fr) minmax(150px, 1fr) 100px 170px" label="Devices waiting" head={["Device", "Whose", "State"]}>
        {requests.map((r, i) => (
          <TRow
            key={`${r.accountId}/${r.deviceId}`}
            index={i}
            actions={
              r.thisDevice ? (
                <span className="hint">Approve it from another of your devices</span>
              ) : (
                <>
                  <TextAction onClick={() => decide(r, true)}>Approve</TextAction>
                  {r.status === "pending" && (
                    <button type="button" className="text-action danger" disabled={busy !== null || locked} onClick={() => decide(r, false)}>
                      Deny
                    </button>
                  )}
                </>
              )
            }
          >
            <NameCell name={r.name ?? "A device"} sub={[r.platform && platformName(r.platform), `asked ${dateTimeText(r.requestedAt)}`].filter(Boolean).join(" · ")} />
            <Cell className="trunc">{r.thisDevice ? "This device" : r.mine ? "Your device" : (r.email ?? "A member")}</Cell>
            <Cell>{r.status === "denied" ? <Chip state="failed">Denied</Chip> : <Chip state="attention">Waiting</Chip>}</Cell>
          </TRow>
        ))}
      </Table>
      {error && <p className="error">{error}</p>}
    </section>
  );
}

const domainOf = (email: string) => email.trim().split("@").pop()?.toLowerCase() ?? "";

/** Invite people: several addresses at once, a role, and the vaults they get once confirmed. */
function InviteDialog({
  org,
  owner,
  vaults,
  domains,
  onClose,
  onChanged,
}: {
  org: OrgInfo;
  owner: boolean;
  vaults: VaultEntry[];
  /** The organization only invites addresses at these domains (empty = any). */
  domains: string[];
  onClose: () => void;
  onChanged: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    ref.current?.showModal();
  }, []);
  const [text, setText] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [grants, setGrants] = useState<Record<string, Access>>({});
  const [sent, setSent] = useState<InviteView[] | null>(null);
  const [copied, setCopied] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const emails = [...new Set(text.split(/[,;\s]+/).map((e) => e.trim()).filter(Boolean))];
  const malformed = emails.filter((e) => !/^[^@\s]+@[^@\s]+$/.test(e));
  const outside = domains.length ? emails.filter((e) => !malformed.includes(e) && !domains.includes(domainOf(e))) : [];
  const valid = emails.length > 0 && malformed.length === 0 && outside.length === 0;
  const send = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError("");
    const vaultGrants = role === "admin" ? [] : Object.entries(grants).map(([vaultId, access]) => ({ vaultId, access }));
    const done: InviteView[] = [];
    const failed: string[] = [];
    for (const email of emails) {
      try {
        done.push(await teams.invite(org.id, email, role, vaultGrants));
      } catch (err) {
        failed.push(`${email}: ${errorText(err)}`);
      }
    }
    setBusy(false);
    if (done.length) {
      setSent(done);
      onChanged();
    }
    if (failed.length) setError(failed.join(" "));
  };
  const toggle = (id: string, on: boolean) =>
    setGrants((g) => {
      const next = { ...g };
      if (on) next[id] = "write";
      else delete next[id];
      return next;
    });

  return (
    <dialog ref={ref} className="sheet invite-dialog" onCancel={(e) => (e.preventDefault(), onClose())} aria-labelledby="invite-title">
      <h1 id="invite-title">Invite people to {org.name}</h1>
      {sent ? (
        <div className="stack">
          {sent.some((i) => i.token) ? (
            <>
              <p>This server doesn't email invites. Send each person their code (it works once, for that address, for 7 days):</p>
              {sent.map((i) => (
                <div key={i.id} className="stack invite-sent">
                  <span className="muted">{i.email}</span>
                  <div className="row">
                    <code className="invite-code grow">{i.token}</code>
                    <button
                      type="button"
                      className="secondary small-button"
                      onClick={() => void navigator.clipboard?.writeText(i.token ?? "").then(() => setCopied(i.id))}
                    >
                      {copied === i.id ? "Copied" : "Copy code"}
                    </button>
                  </div>
                </div>
              ))}
            </>
          ) : (
            <p className="ok">Invite emailed to {sent.map((i) => i.email).join(", ")}.</p>
          )}
          <p className="hint">When they join, you compare each person's fingerprint with them before confirming them.</p>
          {error && <p className="error">{error}</p>}
          <div className="actions">
            <span className="spacer" />
            <button type="button" className="primary" onClick={onClose}>
              Done
            </button>
          </div>
        </div>
      ) : (
        <form className="stack" onSubmit={(e) => void send(e)}>
          <label>
            <span>Email addresses</span>
            <input
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="colleague@example.com, another@example.com"
              aria-label="Emails to invite"
              autoCapitalize="off"
              spellCheck={false}
              autoFocus
            />
          </label>
          <p className={malformed.length || outside.length ? "warn" : "hint"}>
            {malformed.length
              ? `Not an email address: ${malformed.join(", ")}.`
              : outside.length
                ? `Invites go only to ${domains.map((d) => `@${d}`).join(", ")}: not ${outside.join(", ")}.`
                : `MorphGate's server emails each one an invite that works once, for that address, for 7 days${domains.length ? `. Only addresses at ${domains.map((d) => `@${d}`).join(", ")}` : ""}.`}
          </p>
          {owner && (
            <label>
              <span>Role</span>
              <select value={role} onChange={(e) => setRole(e.target.value as Role)} aria-label="Role">
                <option value="member">Member: the vaults you give them</option>
                <option value="admin">Admin: every vault and member</option>
              </select>
            </label>
          )}
          {role === "member" && vaults.length > 0 && (
            <div className="stack grants">
              <span className="field-label">Vaults they get once you confirm them</span>
              {vaults.map((v) => (
                <div className="row access-row" key={v.id}>
                  <label className="check grow">
                    <input type="checkbox" checked={v.id in grants} onChange={(e) => toggle(v.id, e.target.checked)} />
                    <span>{v.name ?? "Shared vault"}</span>
                  </label>
                  {v.id in grants && (
                    <AccessSelect value={grants[v.id]} label={`Access to ${v.name}`} onChange={(a) => setGrants((g) => ({ ...g, [v.id]: a }))} />
                  )}
                </div>
              ))}
            </div>
          )}
          {error && <p className="error">{error}</p>}
          <div className="actions">
            <span className="spacer" />
            <button type="button" className="quiet" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="primary" disabled={!valid || busy}>
              {busy ? "Sending…" : emails.length > 1 ? `Send ${emails.length} invites` : "Send invite"}
            </button>
          </div>
        </form>
      )}
    </dialog>
  );
}

/** One setting: what it is and does, and its control. */
function SettingRow({ name, desc, children }: { name: ReactNode; desc: ReactNode; children: ReactNode }) {
  return (
    <div className="setting">
      <span className="lstack setting-text">
        <span className="setting-name">{name}</span>
        <span className="lsub setting-desc">{desc}</span>
      </span>
      {children}
    </div>
  );
}

function Switch({ on, label, disabled, onChange }: { on: boolean; label: string; disabled?: boolean; onChange: (on: boolean) => void }) {
  return (
    <button type="button" role="switch" aria-checked={on} aria-label={label} className={`switch ${on ? "on" : ""}`} disabled={disabled} onClick={() => onChange(!on)}>
      <i />
    </button>
  );
}

/** The team's policies, grouped, saved together. */
function Settings({ org, details, onChanged }: { org: OrgInfo; details: OrgDetails; onChanged: () => void }) {
  const [p, setP] = useState<Policies>(details.policies);
  const [domains, setDomains] = useState(details.policies.allowedEmailDomains.join(", "));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const list = domains
    .split(/[,\s]+/)
    .map((d) => d.trim().replace(/^@/, "").toLowerCase())
    .filter(Boolean);
  const next: Policies = { ...p, allowedEmailDomains: list };
  const approvalOffered = details.features === null || details.features.includes("device_approval");
  const dirty = JSON.stringify(next) !== JSON.stringify(details.policies);
  const save = () => {
    setBusy(true);
    setError("");
    teams.setPolicies(org.id, next).then(
      () => (setBusy(false), onChanged()),
      (e) => (setError(errorText(e)), setBusy(false)),
    );
  };
  const discard = () => (setP(details.policies), setDomains(details.policies.allowedEmailDomains.join(", ")));
  return (
    <div className="stack team-settings">
      <h2 className="section-title">Security</h2>
      <div className="settings">
        <SettingRow
          name="Require two-step verification"
          desc={
            details.totpOffered
              ? "Members without it can't open the team's vaults until they turn it on. MorphGate tells them why."
              : "This server doesn't offer two-step verification."
          }
        >
          <Switch on={p.requireTotp} label="Require two-step verification" disabled={!details.totpOffered && !p.requireTotp} onChange={(v) => setP({ ...p, requireTotp: v })} />
        </SettingRow>
        <SettingRow
          name={
            <>
              Approve new devices
              {!approvalOffered && <span className="kind-badge">Business plan</span>}
            </>
          }
          desc="An owner or admin, or the member from a device already approved, approves each new device before it opens the team's vaults. Devices in use now stay approved."
        >
          <Switch
            on={p.requireDeviceApproval}
            label="Approve new devices"
            disabled={!approvalOffered && !p.requireDeviceApproval}
            onChange={(v) => setP({ ...p, requireDeviceApproval: v })}
          />
        </SettingRow>
        {p.requireSso && (
          <SettingRow name="Single sign-on" desc="Required for the team's vaults. It is set where the identity provider is, on the website.">
            <span className="muted">Required</span>
          </SettingRow>
        )}
      </div>
      <h2 className="section-title">Members</h2>
      <div className="settings">
        <SettingRow name="Members can create vaults" desc="They manage the vaults they create. Owners and admins always can.">
          <Switch on={p.membersCanCreateVaults} label="Members can create vaults" onChange={(v) => setP({ ...p, membersCanCreateVaults: v })} />
        </SettingRow>
        <SettingRow name="Invite only these domains" desc="Separate them with commas. Empty: any address.">
          <input
            className="setting-input"
            value={domains}
            onChange={(e) => setDomains(e.target.value)}
            placeholder="example.com"
            aria-label="Invite only these domains"
            spellCheck={false}
            autoCapitalize="off"
          />
        </SettingRow>
        <SettingRow name="Ask members to publish their SSH keys" desc="So that removing someone finds their keys on the team's hosts. MorphGate reminds those who haven't.">
          <Switch on={p.requireMemberKeys === true} label="Ask members to publish their SSH keys" onChange={(v) => setP({ ...p, requireMemberKeys: v })} />
        </SettingRow>
      </div>
      {details.sessionLogsOffered && (
        <>
          <h2 className="section-title">Session logs</h2>
          <div className="settings">
            <SettingRow name="Delete session logs after" desc="Days after a session ends. 0 keeps them.">
              <span className="row align-center">
                <input
                  className="setting-input days"
                  type="number"
                  min={0}
                  max={3650}
                  value={p.sessionLogRetentionDays}
                  aria-label="Days to keep session logs"
                  onChange={(e) => setP({ ...p, sessionLogRetentionDays: Math.max(0, Math.min(3650, Math.floor(Number(e.target.value) || 0))) })}
                />
                <span className="muted">days</span>
              </span>
            </SettingRow>
          </div>
        </>
      )}
      {dirty && (
        <div className="settings-save">
          <span className="muted grow">Not saved yet.</span>
          <button type="button" className="quiet" disabled={busy} onClick={discard}>
            Discard
          </button>
          <button type="button" className="primary" disabled={busy} onClick={save}>
            Save settings
          </button>
        </div>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

/** Ownership: handing the team to an admin, or deleting it (the master password confirms). */
function OwnerZone({ org, members, onChanged, onGone }: { org: OrgInfo; members: MemberView[]; onChanged: () => void; onGone: () => void }) {
  const [mode, setMode] = useState<"transfer" | "delete" | null>(null);
  const [to, setTo] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const admins = members.filter((m) => !m.me && m.role === "admin" && m.status === "confirmed");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const p = mode === "transfer" ? teams.transfer(org.id, to, password) : teams.deleteOrg(org.id, password);
    p.then(
      () => (setPassword(""), setBusy(false), setMode(null), mode === "delete" ? onGone() : onChanged()),
      (err) => (setError(errorText(err)), setBusy(false)),
    );
  };

  return (
    <div className="stack">
      <h2 className="section-title danger-title">Ownership</h2>
      <div className="settings danger-zone">
        <SettingRow name="Transfer ownership" desc={admins.length ? "To one of the team's admins. You stay an admin." : "To hand the team over, make someone an admin first."}>
          <button type="button" className="secondary small-button" disabled={admins.length === 0 || mode !== null} onClick={() => setMode("transfer")}>
            Transfer…
          </button>
        </SettingRow>
        <SettingRow name={`Delete ${org.name}`} desc="Its vaults leave every member's devices, and the server deletes them. Members' own vaults stay. This can't be undone.">
          <button type="button" className="ghost-danger small-button" disabled={mode !== null} onClick={() => setMode("delete")}>
            Delete team…
          </button>
        </SettingRow>
      </div>
      {mode && (
        <form className="notice-box stack" onSubmit={submit}>
          {mode === "transfer" ? (
            <>
              <p>The new owner gets every right you have; you stay on as an admin.</p>
              <select value={to} onChange={(e) => setTo(e.target.value)} aria-label="New owner">
                <option value="">Choose an admin…</option>
                {admins.map((m) => (
                  <option key={m.accountId} value={m.accountId}>
                    {m.email}
                  </option>
                ))}
              </select>
            </>
          ) : (
            <p className="warn">
              Deletes {org.name} and all its vaults for everyone. Items in them disappear from every member's devices on their next sync.
              This can't be undone.
            </p>
          )}
          <label>
            <span>Your master password</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          </label>
          <div className="row">
            <button type="button" className="secondary grow" onClick={() => (setMode(null), setPassword(""), setError(""))}>
              Cancel
            </button>
            <button
              type="submit"
              className={`${mode === "delete" ? "danger" : "primary"} grow`}
              disabled={!password || busy || (mode === "transfer" && !to)}
            >
              {mode === "transfer" ? "Transfer" : `Delete ${org.name}`}
            </button>
          </div>
        </form>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

const PAGE = 50;

/** The audit log: what the server saw (owners and admins). */
function ActivityLog({ org }: { org: OrgInfo }) {
  const [log, setLog] = useState<Activity | null>(null);
  const [shown, setShown] = useState(PAGE);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  useEffect(() => {
    teams.activity(org.id).then(setLog, (e) => setError(errorText(e)));
  }, [org.id]);
  const download = (format: "csv" | "jsonl") => {
    setError("");
    setSaved("");
    teams.exportActivity(org.id, format).then(setSaved, (e) => setError(errorText(e)));
  };
  return (
    <div className="stack">
      {!log && !error && <p className="hint">Loading…</p>}
      {log && (
        <>
          <div className="row wrap align-center">
            <p className="hint grow">
              The server records what it sees: membership, access, keys and policy changes. It can't see which hosts anyone opened or
              what they ran.
            </p>
            <button type="button" className="secondary small-button" onClick={() => download("csv")}>
              Download CSV
            </button>
            <button type="button" className="secondary small-button" onClick={() => download("jsonl")}>
              Download JSON lines
            </button>
          </div>
          {saved && <p className="ok">Saved {saved}</p>}
          <ul className="activity">
            {log.events.slice(0, shown).map((e) => (
              <li key={e.seq}>
                <time dateTime={e.at}>{dateTimeText(e.at)}</time>
                <span>{describe(e, log.names)}</span>
              </li>
            ))}
          </ul>
          {shown < log.events.length && (
            <button type="button" className="link align-start" onClick={() => setShown(shown + PAGE)}>
              Show older
            </button>
          )}
          {shown >= log.events.length && log.truncated && <p className="hint">Older events aren't shown in the app.</p>}
        </>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

/** A fingerprint in groups of four, easy to read out loud. */
function Fingerprint({ value }: { value: string }) {
  return (
    <div className="fingerprint" aria-label={`Fingerprint ${value}`}>
      {value.split("-").map((g, i) => (
        <span key={i}>{g}</span>
      ))}
    </div>
  );
}

/** `invite`: from a link, looked up at once (joining still waits for the fingerprint check). */
function JoinOrg({ onJoined, invite }: { onJoined: (id: string) => void; invite?: string }) {
  const [token, setToken] = useState(invite ?? "");
  const [preview, setPreview] = useState<InvitePreview | null>(null);
  const [matches, setMatches] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const look = (code: string) => {
    if (!code.trim()) return;
    setBusy(true);
    setError("");
    teams.preview(code.trim()).then(
      (p) => (setPreview(p), setMatches(false), setBusy(false)),
      (err) => (setError(errorText(err)), setBusy(false)),
    );
  };
  const lookUp = (e: FormEvent) => {
    e.preventDefault();
    look(token);
  };
  useEffect(() => {
    if (invite) look(invite);
  }, [invite]);
  const join = () => {
    if (!preview) return;
    setBusy(true);
    setError("");
    teams.accept(token.trim(), preview.ownerFingerprint).then(
      (id) => (setToken(""), setPreview(null), setBusy(false), onJoined(id)),
      (err) => (setError(errorText(err)), setBusy(false)),
    );
  };

  return (
    <form className="stack" onSubmit={lookUp}>
      <h2 className="section-title">Join with an invite</h2>
      {!preview ? (
        <div className="row">
          <input
            className="grow mono"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Invite code"
            aria-label="Invite code"
            spellCheck={false}
            autoCapitalize="off"
          />
          <button type="submit" className="secondary" disabled={!token.trim() || busy}>
            Look up
          </button>
        </div>
      ) : (
        <div className="notice-box stack">
          <p>
            <strong>{preview.orgName}</strong> invites {preview.email} as {ROLE_NAMES[preview.role].toLowerCase()} (sent by{" "}
            {preview.inviterEmail}).
          </p>
          <p className="hint">
            Ask the owner (or whoever invited you: it's in their member list) to read you the owner's fingerprint. Join only if
            it matches this one:
          </p>
          <Fingerprint value={preview.ownerFingerprint} />
          <label className="check">
            <input type="checkbox" checked={matches} onChange={(e) => setMatches(e.target.checked)} />
            <span>It matches the fingerprint they read to me</span>
          </label>
          <div className="row">
            <button type="button" className="secondary grow" onClick={() => setPreview(null)}>
              Cancel
            </button>
            <button type="button" className="primary grow" disabled={!matches || busy} onClick={join}>
              Join {preview.orgName}
            </button>
          </div>
        </div>
      )}
      {error && <p className="error">{error}</p>}
    </form>
  );
}

function Leave({ org, me, onGone }: { org: OrgInfo; me: string; onGone: () => void }) {
  const [sure, setSure] = useState(false);
  const [error, setError] = useState("");
  return (
    <>
      <button
        type="button"
        className={`${sure ? "danger" : "ghost-danger"} small-button align-start`}
        onClick={() => (sure ? teams.remove(org.id, me).then(onGone, (e) => setError(errorText(e))) : setSure(true))}
      >
        {sure ? `Really leave ${org.name}?` : "Leave"}
      </button>
      {error && <p className="error">{error}</p>}
    </>
  );
}

function AccessSelect({ value, onChange, label, disabled }: { value: Access; onChange: (a: Access) => void; label: string; disabled?: boolean }) {
  return (
    <select className="compact" value={value} onChange={(e) => onChange(e.target.value as Access)} aria-label={label} disabled={disabled}>
      {ACCESS_LEVELS.map((a) => (
        <option key={a} value={a}>
          {ACCESS_NAMES[a]}
        </option>
      ))}
    </select>
  );
}

function AccessEditor({ vault, members, locked, onChanged }: { vault: VaultEntry; members: MemberView[]; locked: boolean; onChanged: () => void }) {
  const [list, setList] = useState<VaultAccess[] | null>(null);
  const [add, setAdd] = useState("");
  const [addAccess, setAddAccess] = useState<Access>("write");
  const [revoked, setRevoked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    teams.access(vault.id).then(setList, (e) => setError(errorText(e)));
  }, [vault.id]);
  useEffect(load, [load]);

  const act = (p: Promise<void>, after?: () => void) => {
    setBusy(true);
    setError("");
    p.then(
      () => (after?.(), setBusy(false), load(), onChanged()),
      (e) => (setError(errorText(e)), setBusy(false)),
    );
  };
  const candidates = members.filter(
    (m) => m.status === "confirmed" && m.role === "member" && !list?.some((a) => a.accountId === m.accountId),
  );

  return (
    <div className="stack">
      {list === null && !error && <p className="hint">Loading…</p>}
      {list?.map((a) => (
        <div className="row access-row" key={a.accountId}>
          <span className="grow">{a.email || a.accountId}</span>
          {a.implicit ? (
            <span className="muted">{ACCESS_NAMES.manage} (owner or admin)</span>
          ) : (
            <>
              <AccessSelect value={a.access} label={`Access for ${a.email}`} disabled={locked} onChange={(x) => act(teams.setAccess(vault.id, a.accountId, x))} />
              <button
                type="button"
                className="ghost-danger small-button"
                disabled={busy}
                onClick={() => act(teams.revokeAccess(vault.id, a.accountId), () => setRevoked(true))}
              >
                Remove
              </button>
            </>
          )}
        </div>
      ))}
      {candidates.length > 0 && (
        <div className="row">
          <select className="grow" value={add} onChange={(e) => setAdd(e.target.value)} aria-label="Member to give access" disabled={locked}>
            <option value="">Give a member access…</option>
            {candidates.map((m) => (
              <option key={m.accountId} value={m.accountId}>
                {m.email}
              </option>
            ))}
          </select>
          <AccessSelect value={addAccess} onChange={setAddAccess} label="Access for the new member" disabled={locked} />
          <button
            type="button"
            className="secondary small-button"
            disabled={!add || busy || locked}
            onClick={() => act(teams.setAccess(vault.id, add, addAccess), () => setAdd(""))}
          >
            Add
          </button>
        </div>
      )}
      {revoked && (
        <p className="hint">
          They can't sync this vault anymore, but what they already had stays on their devices. Rotate the key (the button
          appears after the next sync) so they can't read anything added from now on, and change the passwords and keys they
          could see.
        </p>
      )}
      {members.some((m) => m.status === "accepted") && <p className="hint">Members waiting for confirmation can be added once confirmed.</p>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

/** New vault, as a bar (like New team): its name, Create vault or Cancel. */
function NewVault({ orgId, onCreated, onCancel }: { orgId: string; onCreated: () => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError("");
    teams.createVault(orgId, name.trim()).then(
      () => (setName(""), setBusy(false), onCreated()),
      (err) => (setError(errorText(err)), setBusy(false)),
    );
  };
  return (
    <form className="quick-bar" onSubmit={submit}>
      <span className="section-title">New vault</span>
      <input className="grow" value={name} onChange={(e) => setName(e.target.value)} placeholder="Staging" aria-label="Vault name" autoFocus />
      <button type="button" className="quiet" onClick={onCancel}>
        Cancel
      </button>
      <button type="submit" className="secondary" disabled={!name.trim() || busy}>
        Create vault
      </button>
      <small className="hint quick-hint">Then give members access to it (Access, on its row).</small>
      {error && <p className="error quick-hint">{error}</p>}
    </form>
  );
}

const day = (iso: string | null) => (iso ? dateText(iso) : "");

/** The organization's plan (hosted servers), and what it means for its vaults. */
function PlanLine({ plan, enforced, seatsUsed }: { plan: OrgPlan | null; enforced: boolean; seatsUsed: number | null }) {
  if (!plan) {
    return <p className={`plan-line ${enforced ? "warn" : "hint"}`}>{enforced ? "No plan: shared vaults can be read but not changed until the team has a plan." : "No plan"}</p>;
  }
  const name = plan.plan.charAt(0).toUpperCase() + plan.plan.slice(1);
  const seats = plan.seats != null ? ` · ${seatsUsed ?? "?"} of ${plan.seats} seats used` : "";
  const [text, tone] = (() => {
    switch (plan.status) {
      case "trialing":
        return [`${name} trial until ${day(plan.expiresAt)}${seats}`, "hint"];
      case "grace":
        return [
          `The ${name} plan ended ${day(plan.expiresAt)}. Shared vaults keep syncing ${plan.graceEndsAt ? `until ${day(plan.graceEndsAt)}` : "for a few more days"}.`,
          "warn",
        ];
      case "lapsed":
      case "canceled":
        return [`The ${name} plan has ended: shared vaults can be read but not changed until it's renewed.`, "error"];
      default:
        return [`${name} plan${plan.expiresAt ? `, renews ${day(plan.expiresAt)}` : ""}${seats}`, "hint"];
    }
  })();
  return <p className={`plan-line ${tone}`}>{text}</p>;
}

/** The organization's identity provider, and whether this device is signed in there. */
function SsoLine({ org, onSignIn }: { org: OrgInfo; onSignIn: () => void }) {
  const [sso, setSso] = useState<SsoView | null>(null);
  useEffect(() => {
    teams.ssoStatus(org.id).then(setSso, () => {});
  }, [org.id]);
  if (!sso?.configured) return null;
  const host = sso.issuer ? new URL(sso.issuer).host : "an identity provider";
  return (
    <div className="sso-line">
      <span>
        Single sign-on at <strong>{host}</strong>
        {sso.required ? ", required for its vaults" : ""}.
      </span>
      {sso.sessionExpiresAt ? (
        <span className="muted">This device is signed in until {dateTimeText(sso.sessionExpiresAt)}.</span>
      ) : (
        <button type="button" className="secondary small-button" onClick={onSignIn}>
          Sign in
        </button>
      )}
    </div>
  );
}

/** One audit event as a sentence. */
function describe(e: Activity["events"][number], names: Record<string, string>): string {
  const who = (id: string | null) => (id ? (names[id] ?? "a former member") : "someone");
  const vault = e.vaultId ? (names[e.vaultId] ?? "a vault you can't open") : "a vault";
  const actor = who(e.actorId);
  const target = who(e.targetId);
  const device = e.detail ? ` "${e.detail}"` : "";
  const access = e.detail && e.detail in ACCESS_NAMES ? ` (${ACCESS_NAMES[e.detail as Access].toLowerCase()})` : "";
  switch (e.kind) {
    case "org_created":
      return `${actor} created the team`;
    case "org_updated":
      return `${actor} changed the team's name or settings`;
    case "member_invited":
      return `${actor} invited ${e.detail ?? "someone"}`;
    case "invite_cancelled":
      return `${actor} cancelled an invite${e.detail ? ` for ${e.detail}` : ""}`;
    case "member_accepted":
      return `${target} joined`;
    case "member_confirmed":
      return `${actor} confirmed ${target}`;
    case "role_changed":
      return `${actor} made ${target} ${e.detail ? `${e.detail === "admin" ? "an" : "a"} ${e.detail}` : "something else"}`;
    case "member_removed":
      return `${actor} removed ${target}`;
    case "member_left":
      return `${actor} left`;
    case "ownership_transferred":
      return `${actor} handed ownership to ${target}`;
    case "vault_created":
      return `${actor} created ${vault}`;
    case "vault_deleted":
      return `${actor} deleted ${vault}`;
    case "vault_access_granted":
      return `${actor} gave ${target} access to ${vault}${access}`;
    case "vault_access_changed":
      return `${actor} changed ${target}'s access to ${vault}${access}`;
    case "vault_access_revoked":
      return `${actor} removed ${target}'s access to ${vault}`;
    case "vault_key_rotated":
      return `${actor} rotated the key of ${vault}`;
    case "member_recertified":
      return `${actor} certified ${target} again`;
    case "device_approval_requested":
      return `${target}'s new device${device} asked to open the vaults`;
    case "device_approved":
      return `${actor} approved ${e.targetId === e.actorId ? "their" : `${target}'s`} device${device}`;
    case "device_denied":
      return `${actor} denied ${e.targetId === e.actorId ? "their" : `${target}'s`} device${device}`;
    case "audit_stream_configured":
      return `${actor} set up the audit stream`;
    case "audit_stream_secret_rotated":
      return `${actor} rotated the audit stream's signing secret`;
    case "audit_stream_removed":
      return `${actor} removed the audit stream`;
    case "audit_stream_disabled":
      return "The audit stream was turned off: its endpoint kept failing";
    default:
      return `${actor}: ${e.kind.replace(/_/g, " ")}`;
  }
}

/** This account's SSH keys published to the organization's member key directory. */
function MyKeys({
  org,
  keys,
  published,
  ready,
  waiting,
  onChanged,
}: {
  org: OrgInfo;
  keys: KeyView[];
  published: MemberKeyView[];
  ready: boolean;
  /** The directory waits like the organization's vaults (two-step verification, said above). */
  waiting: boolean;
  onChanged: () => void;
}) {
  const [pick, setPick] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const unpublished = keys.filter((k) => !published.some((p) => k.publicKey.startsWith(p.publicKey)));
  const act = (p: Promise<unknown>) => {
    setBusy(true);
    setError("");
    p.then(
      () => (setBusy(false), setPick(""), onChanged()),
      (e) => (setError(errorText(e)), setBusy(false)),
    );
  };
  return (
    <div className="stack">
      <h2 className="section-title">Your SSH keys</h2>
      <p className="hint">
        Publish the public keys you use on {org.name}'s servers. If you leave, admins can then find and remove your access
        from those servers. Only the public half is shared.
      </p>
      {!ready && !waiting && <p className="hint">The organization's member key directory arrives with the next sync.</p>}
      {published.length > 0 && (
        <ul className="device-list">
          {published.map((k) => (
            <li key={k.id}>
              <div>
                <strong>{k.label || "SSH key"}</strong>
                <small className="mono">{k.fingerprint ?? k.publicKey}</small>
              </div>
              <button type="button" className="ghost-danger small-button" disabled={busy} onClick={() => act(teams.unpublishKey(k.id))}>
                Unpublish
              </button>
            </li>
          ))}
        </ul>
      )}
      {ready && unpublished.length > 0 && (
        <div className="row">
          <select className="grow" value={pick} onChange={(e) => setPick(e.target.value)} aria-label="Key to publish">
            <option value="">Publish one of your keys…</option>
            {unpublished.map((k) => (
              <option key={k.id} value={k.id}>
                {k.label} ({k.fingerprint})
              </option>
            ))}
          </select>
          <button type="button" className="secondary small-button" disabled={!pick || busy} onClick={() => act(teams.publishKey(org.id, pick))}>
            Publish
          </button>
        </div>
      )}
      {ready && keys.length === 0 && <p className="hint">Your personal vault has no SSH keys to publish.</p>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

/** Removing a confirmed member: what they could read, removal and key rotation, their SSH keys on
 * the organization's hosts, and the shared secrets to change. */
function Offboard({ org, member, onBack, onChanged }: { org: OrgInfo; member: MemberView; onBack: () => void; onChanged: () => void }) {
  const [summary, setSummary] = useState<OffboardSummary | null>(null);
  const [error, setError] = useState("");
  const [removed, setRemoved] = useState(false);
  const [rotation, setRotation] = useState<string[]>([]);
  const [busy, setBusy] = useState("");
  const [scan, setScan] = useState<HostResult[] | null>(null);
  const [cleaned, setCleaned] = useState<HostResult[] | null>(null);
  const [done, setDone] = useState<Set<string>>(new Set());
  const [replaced, setReplaced] = useState<Record<string, KeyReplaced | string>>({});

  useEffect(() => {
    offboard.summary(org.id, member.accountId).then(setSummary, (e) => setError(errorText(e)));
  }, [org.id, member.accountId]);

  const run = async (what: string, fn: () => Promise<void>) => {
    setBusy(what);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy("");
    }
  };
  const removeAndRotate = () =>
    run("remove", async () => {
      if (!removed) {
        await teams.remove(org.id, member.accountId);
        setRemoved(true);
        onChanged();
      }
      for (const v of summary?.vaults ?? []) {
        if (rotation.includes(v.name)) continue;
        await teams.rotate(v.vaultId);
        setRotation((r) => [...r, v.name]);
      }
      onChanged();
    });
  const found = scan?.filter((h) => (h.keys ?? 0) > 0) ?? [];
  const tick = (id: string) =>
    setDone((d) => {
      const next = new Set(d);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const replace = (keyId: string) =>
    run(`key:${keyId}`, async () => {
      try {
        const r = await offboard.replaceKey(keyId);
        setReplaced((x) => ({ ...x, [keyId]: r }));
        setDone((d) => new Set(d).add(keyId));
        onChanged();
      } catch (e) {
        setReplaced((x) => ({ ...x, [keyId]: errorText(e) }));
      }
    });
  const rotatedAll = !!summary && summary.vaults.every((v) => rotation.includes(v.name));

  return (
    <>
      <button type="button" className="link align-start" onClick={onBack}>
        ← {org.name}
      </button>
      <h1>Remove {member.email}</h1>
      {error && <p className="error">{error}</p>}
      {!summary && !error && <p className="hint">Loading…</p>}
      {summary && (
        <>
          <div className="stack">
            <h2 className="section-title">1. What they can open</h2>
            {summary.vaults.length === 0 && <p className="hint">No vaults of the organization.</p>}
            <ul className="device-list">
              {summary.vaults.map((v) => (
                <li key={v.vaultId}>
                  <div>
                    <strong>{v.name}</strong>
                    <span className="kind-badge">{ACCESS_NAMES[v.access]}</span>
                    <small>
                      {v.directory ? "Members' public SSH keys (nothing secret)" : [
                        [v.hosts, "host"],
                        [v.keys, "SSH key"],
                        [v.vpns, "VPN"],
                        [v.other, "other item"],
                      ]
                        .filter(([n]) => (n as number) > 0)
                        .map(([n, what]) => `${n} ${what}${n === 1 ? "" : "s"}`)
                        .join(", ") || "empty"}
                    </small>
                  </div>
                </li>
              ))}
            </ul>
            <p className="hint">Whatever they synced stays on their devices: removing them stops what comes next, not what they saw.</p>
          </div>

          <div className="stack">
            <h2 className="section-title">2. Remove and rotate</h2>
            <p className="hint">
              Removes them from {org.name} and gives {summary.vaults.length === 1 ? "that vault" : "those vaults"} new keys, so
              they can't read anything added from now on.
            </p>
            {rotation.length > 0 && <p className="ok">New keys: {rotation.join(", ")}</p>}
            {!rotatedAll || !removed ? (
              <button type="button" className="danger align-start" disabled={!!busy} onClick={() => void removeAndRotate()}>
                {busy === "remove" ? "Working…" : removed ? "Rotate the rest" : `Remove ${member.email} and rotate keys`}
              </button>
            ) : (
              <p className="ok">Removed; every vault they had has a new key.</p>
            )}
          </div>

          <div className="stack">
            <h2 className="section-title">3. Their SSH keys on your hosts</h2>
            {summary.keys.length === 0 ? (
              <p className="hint">
                They published no SSH keys, so the app can't tell which lines in authorized_keys are theirs. Check the hosts
                by hand.
              </p>
            ) : (
              <>
                <p className="hint">
                  Looks for {summary.keys.length === 1 ? "their published key" : `their ${summary.keys.length} published keys`} in
                  ~/.ssh/authorized_keys on every host of {org.name}, logging in as each host is saved.
                </p>
                <ul className="key-list mono">
                  {summary.keys.map((k) => (
                    <li key={k}>{k}</li>
                  ))}
                </ul>
                <div className="row">
                  <button type="button" className="secondary" disabled={!!busy} onClick={() => void run("scan", async () => setScan(await offboard.scan(org.id, member.accountId)))}>
                    {busy === "scan" ? "Checking hosts…" : scan ? "Check again" : "Check hosts"}
                  </button>
                  {found.length > 0 && !cleaned && (
                    <button
                      type="button"
                      className="danger"
                      disabled={!!busy}
                      onClick={() =>
                        void run("clean", async () =>
                          setCleaned(await offboard.clean(org.id, member.accountId, found.map((h) => h.hostId))),
                        )
                      }
                    >
                      {busy === "clean" ? "Removing…" : `Remove from ${found.length} host${found.length === 1 ? "" : "s"}`}
                    </button>
                  )}
                </div>
                {(cleaned ?? scan) && (
                  <ul className="device-list">
                    {(cleaned ?? scan)!.map((h) => (
                      <li key={h.hostId}>
                        <div>
                          <strong>{h.label}</strong>
                          <small className={h.problem ? "warn" : ""}>
                            {h.problem
                              ? h.problem
                              : cleaned
                                ? `${h.keys} line${h.keys === 1 ? "" : "s"} removed`
                                : h.keys
                                  ? `${h.keys} of their keys found`
                                  : "none of their keys"}
                          </small>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </>
            )}
          </div>

          <div className="stack">
            <h2 className="section-title">4. Change what they could see</h2>
            {summary.secrets.length === 0 && <p className="hint">No saved passwords, SSH keys or VPN profiles in those vaults.</p>}
            <ul className="device-list">
              {summary.secrets.map((s) => {
                const r = replaced[s.itemId];
                return (
                  <li key={s.itemId}>
                    <label className="check grow">
                      <input type="checkbox" checked={done.has(s.itemId)} onChange={() => tick(s.itemId)} />
                      <span>
                        {s.kind === "password" ? "Password of" : s.kind === "key" ? "SSH key" : "VPN profile"} <strong>{s.label}</strong>
                        <small>
                          {" "}
                          · {s.vaultName}
                          {s.kind === "key" && s.usedBy.length > 0 && ` · used by ${s.usedBy.join(", ")}`}
                          {typeof r === "string" && ` · ${r}`}
                          {r && typeof r !== "string" && ` · replaced (${r.fingerprint})`}
                          {r && typeof r !== "string" && r.oldKeyLeft.length > 0 && `; the old key is still on ${r.oldKeyLeft.join(", ")}`}
                        </small>
                      </span>
                    </label>
                    {s.kind === "key" && (!r || typeof r === "string") && (
                      <button type="button" className="secondary small-button" disabled={!!busy} onClick={() => void replace(s.itemId)}>
                        {busy === `key:${s.itemId}` ? "Replacing…" : "Replace key"}
                      </button>
                    )}
                  </li>
                );
              })}
            </ul>
            {summary.secrets.some((s) => s.kind === "key") && (
              <p className="hint">
                Replace key: a new key goes onto every host that logs in with it and is tried there first; then the vault switches
                to it and the old key is removed from those hosts. If any host fails, nothing changes.
              </p>
            )}
          </div>
        </>
      )}
    </>
  );
}
