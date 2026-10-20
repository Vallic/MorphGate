import { Fragment, useCallback, useEffect, useState, type FormEvent } from "react";
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
  type VaultAccess,
  type VaultEntry,
} from "./api";
import { Page } from "./Page";
import { mobileOs } from "./mobile/useMobile";

interface Props {
  vaults: VaultEntry[];
  orgs: OrgInfo[];
  /** SSH keys in the vault (the personal ones can be published to an organization). */
  keys: KeyView[];
  /** Reloads organizations, vaults and items. */
  onChanged: () => Promise<void>;
  onClose: () => void;
  /** Sign in at an organization's identity provider. */
  onSso: (orgId: string, orgName: string) => void;
  /** From a link: an invite to look up, or the team to open. */
  invite?: string;
  openOrg?: string;
}

const ACCESS_LEVELS: Access[] = ["read", "write", "manage"];

export function TeamsPanel({ vaults, orgs, keys, onChanged, onClose, onSso, invite, openOrg }: Props) {
  const personal = vaults.find((v) => v.personal)?.id;
  const personalKeys = keys.filter((k) => k.vaultId === personal);
  const [status, setStatus] = useState<SharingStatus | null>(null);
  const [error, setError] = useState("");
  const [open, setOpen] = useState<string | null>(openOrg ?? null);
  useEffect(() => {
    teams.status().then(setStatus, (e) => setError(errorText(e)));
  }, []);
  const org = orgs.find((o) => o.id === open);
  const opened = (id: string) => void onChanged().then(() => setOpen(id));

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
      />
    );
  }

  return (
    <Page
      title="Teams"
      lead="Share hosts, keys, tunnels and VPNs with your team through organization vaults. They stay end-to-end encrypted: the sync server can't read them either."
      onClose={onClose}
      aside={
        status?.available ? (
          <>
            {status.fingerprint && (
              <div className="stack">
                <h2 className="section-title">Your fingerprint</h2>
                <Fingerprint value={status.fingerprint} />
                <p className="hint">
                  Before an admin gives you access to a team's vaults, they compare this with you on a call or in person. It
                  proves that the keys the server showed them are really yours.
                </p>
              </div>
            )}
            <JoinOrg onJoined={opened} invite={invite} />
          </>
        ) : undefined
      }
    >
      {error && <p className="error">{error}</p>}
      {!status && !error && <p className="hint">Loading…</p>}
      {status && !status.available && <p className="warn">{status.reason}</p>}
      {(orgs.length > 0 || status?.available) && (
        <div className="stack">
          <h2 className="section-title">Organizations</h2>
          {orgs.length === 0 && <p className="hint">None yet. Create one, or join with an invite someone sent you.</p>}
          {orgs.length > 0 && (
            <ul className="device-list">
              {orgs.map((o) => {
                const count = vaults.filter((v) => v.orgId === o.id && !v.directory).length;
                return (
                  <li key={o.id}>
                    <div>
                      <strong>{o.name}</strong>
                      <span className="kind-badge">{ROLE_NAMES[o.role]}</span>
                      <small>
                        {o.status === "accepted"
                          ? "Waiting for an admin to confirm you"
                          : `${count} vault${count === 1 ? "" : "s"} you can open`}
                      </small>
                    </div>
                    <button type="button" className="secondary small-button" onClick={() => setOpen(o.id)}>
                      Open
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
      {status?.available && <CreateOrg onCreated={opened} />}
    </Page>
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

function CreateOrg({ onCreated }: { onCreated: (id: string) => void }) {
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
    <form className="stack" onSubmit={submit}>
      <h2 className="section-title">New organization</h2>
      <div className="row">
        <input className="grow" value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Ops" aria-label="Organization name" />
        <button type="submit" className="secondary" disabled={!name.trim() || busy}>
          Create
        </button>
      </div>
      <p className="hint">You'll be its owner. Then create vaults in it and invite people.</p>
      {error && <p className="error">{error}</p>}
      {limit && (
        <div className="notice-box stack team-limit">
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
}

function OrgView({ org, vaults, personalKeys, fingerprint, me, onBack, onClose, onChanged, onGone, onSso }: OrgProps) {
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
  const [offboarding, setOffboarding] = useState<MemberView | null>(null);
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

  const load = useCallback(() => {
    // Only confirmed members see the member list.
    if (!confirmed) return;
    teams.members(org.id).then(setMembers, (e) => setError(errorText(e)));
    teams.details(org.id).then(setDetails, (e) => setError(errorText(e)));
    if (admin) teams.invites(org.id).then(setInvites, (e) => setError(errorText(e)));
  }, [org.id, confirmed, admin]);
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

  const lead = (details?.plansOffered || (confirmed && details?.ssoOffered)) && (
    <>
      {details?.plansOffered && (
        <PlanLine
          org={org}
          plan={details.plan}
          enforced={details.plansEnforced}
          seatsUsed={members?.filter((m) => m.status === "confirmed").length ?? null}
          portal={owner && details.portal && !mobileOs}
        />
      )}
      {confirmed && details?.ssoOffered && <SsoLine org={org} onSignIn={onSso} />}
    </>
  );

  return (
    <Page
      back={{ label: "All organizations", onClick: onBack }}
      onClose={onClose}
      title={org.name}
      badge={<span className="kind-badge">{ROLE_NAMES[org.role]}</span>}
      lead={lead || undefined}
      aside={
        admin ? (
          <>
            <fieldset className="plain" disabled={locked}>
              <Invites
                org={org}
                owner={owner}
                vaults={shared}
                invites={invites}
                domains={details?.policies.allowedEmailDomains ?? []}
                onChanged={changed}
              />
            </fieldset>
            {details && (
              <fieldset className="plain" disabled={locked}>
                <PolicyEditor key={JSON.stringify(details.policies)} org={org} details={details} onChanged={changed} />
              </fieldset>
            )}
            <ActivityLog org={org} />
            {owner && <OwnerZone org={org} members={members ?? []} onChanged={changed} onGone={onGone} />}
          </>
        ) : undefined
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
      {/* Locked: giving access and new vaults wait for a plan; taking access away and rotating don't. */}
      <div className="stack">
        <h2 className="section-title">Vaults</h2>
        {shared.length === 0 && (
          <p className="hint">
            {canCreateVaults ? "No vaults yet. Create one, then give members access." : "You can't open any of its vaults yet."}
          </p>
        )}
        {vaults.length > 0 && (
          <ul className="device-list">
            {vaults.map((v) => (
              <VaultRow key={v.id} vault={v} members={members ?? []} locked={locked} onChanged={changed} />
            ))}
          </ul>
        )}
        {canCreateVaults && (
          <fieldset className="plain" disabled={locked}>
            <NewVault orgId={org.id} onCreated={changed} />
          </fieldset>
        )}
      </div>

      {confirmed && (
        <fieldset className="plain" disabled={locked}>
          <MyKeys org={org} keys={personalKeys} published={memberKeys.filter((k) => k.mine)} ready={hasDirectory} onChanged={loadKeys} />
        </fieldset>
      )}
      {confirmed && details && (
        <fieldset className="plain" disabled={locked}>
          <DeviceRequests org={org} admin={admin} required={details.policies.requireDeviceApproval} />
        </fieldset>
      )}
      {confirmed && (
        <Members
          org={org}
          keysRequired={details?.policies.requireMemberKeys === true}
          members={members}
          memberKeys={memberKeys}
          admin={admin}
          owner={owner}
          locked={locked}
          onChanged={changed}
          onGone={onGone}
          onOffboard={setOffboarding}
        />
      )}
    </Page>
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

function VaultRow({ vault, members, locked, onChanged }: { vault: VaultEntry; members: MemberView[]; locked: boolean; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const manage = vault.access === "manage";
  const rotate = () => {
    setBusy(true);
    setError("");
    teams.rotate(vault.id).then(
      () => (setBusy(false), onChanged()),
      (e) => (setError(errorText(e)), setBusy(false)),
    );
  };
  return (
    <>
      <li className={manage && vault.rotationDue ? "due" : ""}>
        <div>
          <strong>{vault.name ?? "Shared vault"}</strong>
          <span className="kind-badge">{vault.directory ? "Every member" : ACCESS_NAMES[vault.access]}</span>
          <small>
            {vault.directory
              ? `Members' SSH public keys: ${vault.items} published`
              : `${vault.items} item${vault.items === 1 ? "" : "s"}`}
            {vault.rotationDue && " · someone lost access since the key was made"}
          </small>
        </div>
        {manage && vault.rotationDue && (
          <button type="button" className="rotate small-button" disabled={busy} onClick={rotate} title="Seal a new key to everyone who still has access">
            {busy ? "Rotating…" : "Rotate key"}
          </button>
        )}
        {manage && !vault.directory && (
          <button type="button" className="secondary small-button" onClick={() => setEditing(!editing)}>
            {editing ? "Done" : "Access"}
          </button>
        )}
      </li>
      {error && (
        <li>
          <p className="error">{error}</p>
        </li>
      )}
      {editing && (
        <li className="nested">
          <AccessEditor vault={vault} members={members} locked={locked} onChanged={onChanged} />
        </li>
      )}
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

function NewVault({ orgId, onCreated }: { orgId: string; onCreated: () => void }) {
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
    <form className="stack" onSubmit={submit}>
      <div className="row">
        <input className="grow" value={name} onChange={(e) => setName(e.target.value)} placeholder="Staging" aria-label="New vault name" />
        <button type="submit" className="secondary" disabled={!name.trim() || busy}>
          New vault
        </button>
      </div>
      {error && <p className="error">{error}</p>}
    </form>
  );
}

interface MembersProps {
  org: OrgInfo;
  members: MemberView[] | null;
  /** Keys published in the directory, to show who published theirs. */
  memberKeys: MemberKeyView[];
  admin: boolean;
  owner: boolean;
  /** The organization asks members to publish their SSH keys. */
  keysRequired: boolean;
  onChanged: () => void;
  onGone: () => void;
  /** Removing a confirmed member goes through offboarding. */
  onOffboard: (m: MemberView) => void;
  /** The team has no usable plan: confirming people and changing roles wait for one. */
  locked: boolean;
}

function Members({ org, members, memberKeys, admin, owner, keysRequired, onChanged, onGone, onOffboard, locked }: MembersProps) {
  const published = (account: string) => memberKeys.filter((k) => k.accountId === account && k.verified).length;
  const [confirming, setConfirming] = useState<string | null>(null);
  const [matches, setMatches] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const act = (p: Promise<void>, then: () => void = onChanged) => {
    setBusy(true);
    setError("");
    p.then(
      () => (setBusy(false), setConfirming(null), setRemoving(null), then()),
      (e) => (setError(errorText(e)), setBusy(false)),
    );
  };

  return (
    <div className="stack">
      <h2 className="section-title">Members</h2>
      {members === null && !error && <p className="hint">Loading…</p>}
      {members && (
        <ul className="device-list">
          {members.map((m) => {
            const canRemove = !m.me && m.role !== "owner" && admin && (m.role === "member" || owner);
            return (
              <Fragment key={m.accountId}>
                <li>
                  <span className="member-initial" aria-hidden="true">
                    {(m.email[0] ?? "?").toUpperCase()}
                  </span>
                  <div>
                    <strong>{m.email}</strong>
                    {m.me && <span className="kind-badge me">you</span>}
                    <span className="kind-badge">{ROLE_NAMES[m.role]}</span>
                    <small>
                      {m.status === "accepted" ? "Waiting for confirmation" : m.verified ? "Keys verified" : "Keys not verified yet"}
                      {m.status === "confirmed" && ` · ${published(m.accountId)} SSH key${published(m.accountId) === 1 ? "" : "s"} published`}
                      {m.status === "confirmed" && keysRequired && published(m.accountId) === 0 && (
                        <span className="warn-text"> · none yet, and the organization asks for them</span>
                      )}
                      <span className="mono"> · {m.fingerprint}</span>
                    </small>
                  </div>
                  {admin && m.status === "confirmed" && !m.verified && !m.me && (
                    <button
                      type="button"
                      className="secondary small-button"
                      onClick={() => (setConfirming(confirming === m.accountId ? null : m.accountId), setMatches(false))}
                      title="The admin who confirmed them left: compare their fingerprint and certify them again"
                    >
                      Verify…
                    </button>
                  )}
                  {admin && m.status === "accepted" && (
                    <button
                      type="button"
                      className="primary small-button"
                      disabled={locked}
                      onClick={() => (setConfirming(confirming === m.accountId ? null : m.accountId), setMatches(false))}
                    >
                      Confirm…
                    </button>
                  )}
                  {owner && !m.me && m.status === "confirmed" && m.role !== "owner" && (
                    <button
                      type="button"
                      className="secondary small-button"
                      disabled={busy || locked}
                      onClick={() => act(teams.setRole(org.id, m.accountId, m.role === "admin" ? "member" : "admin"))}
                      title={m.role === "admin" ? "They keep only the vault access you give them" : "Admins manage every vault and member"}
                    >
                      {m.role === "admin" ? "Make member" : "Make admin"}
                    </button>
                  )}
                  {canRemove && m.status === "confirmed" && (
                    <button type="button" className="ghost-danger small-button" onClick={() => onOffboard(m)}>
                      Remove…
                    </button>
                  )}
                  {((canRemove && m.status === "accepted") || (m.me && m.role !== "owner")) &&
                    (removing === m.accountId ? (
                      <button
                        type="button"
                        className="danger small-button"
                        disabled={busy}
                        onClick={() => act(teams.remove(org.id, m.accountId), m.me ? onGone : onChanged)}
                      >
                        {m.me ? "Really leave?" : "Really remove?"}
                      </button>
                    ) : (
                      <button type="button" className="ghost-danger small-button" onClick={() => setRemoving(m.accountId)}>
                        {m.me ? "Leave" : "Remove"}
                      </button>
                    ))}
                </li>
                {confirming === m.accountId && (
                  <li className="nested">
                    <div className="stack">
                      <p className="hint">
                        Ask {m.email} to read you their fingerprint (Teams, on their device), on a call or in person. Confirm only
                        if it matches:
                      </p>
                      <Fingerprint value={m.fingerprint} />
                      {m.pendingVaults.length > 0 && (
                        <p className="hint">Confirming gives them the vault access their invite offered.</p>
                      )}
                      <label className="check">
                        <input type="checkbox" checked={matches} onChange={(e) => setMatches(e.target.checked)} />
                        <span>It matches what they read to me</span>
                      </label>
                      <button
                        type="button"
                        className="primary"
                        disabled={!matches || busy}
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
                  </li>
                )}
              </Fragment>
            );
          })}
        </ul>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

interface InvitesProps {
  org: OrgInfo;
  owner: boolean;
  vaults: VaultEntry[];
  invites: InviteView[];
  /** The organization only invites addresses at these domains (empty = any). */
  domains: string[];
  onChanged: () => void;
}

const domainOf = (email: string) => email.trim().split("@").pop()?.toLowerCase() ?? "";

function Invites({ org, owner, vaults, invites, domains, onChanged }: InvitesProps) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [grants, setGrants] = useState<Record<string, Access>>({});
  const [created, setCreated] = useState<InviteView | null>(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const wellFormed = /^[^@\s]+@[^@\s]+$/.test(email.trim());
  const domainOk = domains.length === 0 || domains.includes(domainOf(email));
  const valid = wellFormed && domainOk;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError("");
    const vaultGrants = role === "admin" ? [] : Object.entries(grants).map(([vaultId, access]) => ({ vaultId, access }));
    teams.invite(org.id, email.trim(), role, vaultGrants).then(
      (inv) => (setCreated(inv), setCopied(false), setEmail(""), setGrants({}), setBusy(false), onChanged()),
      (err) => (setError(errorText(err)), setBusy(false)),
    );
  };
  const cancel = (id: string) => {
    setError("");
    teams.cancelInvite(org.id, id).then(onChanged, (e) => setError(errorText(e)));
  };
  const toggle = (id: string, on: boolean) =>
    setGrants((g) => {
      const next = { ...g };
      if (on) next[id] = "write";
      else delete next[id];
      return next;
    });

  return (
    <div className="stack">
      <h2 className="section-title">Invites</h2>
      {invites.length > 0 && (
        <ul className="device-list">
          {invites.map((i) => (
            <li key={i.id}>
              <div>
                <strong>{i.email}</strong>
                <span className="kind-badge">{ROLE_NAMES[i.role]}</span>
                <small>Expires {dateText(i.expiresAt)}</small>
              </div>
              <button type="button" className="ghost-danger small-button" onClick={() => cancel(i.id)}>
                Cancel
              </button>
            </li>
          ))}
        </ul>
      )}
      {created?.token && (
        <div className="notice-box stack">
          <p>
            This server doesn't email invites. Send this code to {created.email} (it works once, for that address, for 7 days):
          </p>
          <code className="invite-code">{created.token}</code>
          <div className="row">
            <button
              type="button"
              className="secondary grow"
              onClick={() => void navigator.clipboard?.writeText(created.token ?? "").then(() => setCopied(true))}
            >
              {copied ? "Copied" : "Copy code"}
            </button>
            <button type="button" className="secondary grow" onClick={() => setCreated(null)}>
              Done
            </button>
          </div>
        </div>
      )}
      {created && !created.token && <p className="ok">Invite emailed to {created.email}.</p>}
      <form className="stack" onSubmit={submit}>
        <div className="row">
          <input
            className="grow"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="colleague@example.com"
            aria-label="Email to invite"
            autoCapitalize="off"
            spellCheck={false}
          />
          {owner && (
            <select className="compact" value={role} onChange={(e) => setRole(e.target.value as Role)} aria-label="Role">
              <option value="member">Member</option>
              <option value="admin">Admin</option>
            </select>
          )}
          <button type="submit" className="secondary" disabled={!valid || busy}>
            Invite
          </button>
        </div>
        {role === "member" && vaults.length > 0 && (
          <div className="stack grants">
            <span className="hint">Vaults they get once you confirm them:</span>
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
        {role === "admin" && <p className="hint">Admins open every vault of the organization and manage members.</p>}
        {domains.length > 0 && (
          <p className={wellFormed && !domainOk ? "warn" : "hint"}>Invites go only to {domains.map((d) => `@${d}`).join(", ")}.</p>
        )}
      </form>
      {error && <p className="error">{error}</p>}
    </div>
  );
}

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
      <h2 className="section-title">Ownership</h2>
      {!mode && (
        <div className="row">
          <button type="button" className="secondary grow" disabled={admins.length === 0} onClick={() => setMode("transfer")}>
            Transfer ownership
          </button>
          <button type="button" className="ghost-danger grow" onClick={() => setMode("delete")}>
            Delete organization
          </button>
        </div>
      )}
      {!mode && admins.length === 0 && <p className="hint">To hand the organization over, make someone an admin first.</p>}
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
              Deletes {org.name} and all its vaults for everyone. Items in them disappear from every member's devices on their next
              sync. This can't be undone.
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

const day = (iso: string | null) => (iso ? dateText(iso) : "");

/** The organization's plan (hosted servers), and what it means for its vaults. */
function PlanLine({
  org,
  plan,
  enforced,
  seatsUsed,
  portal,
}: {
  org: OrgInfo;
  plan: OrgPlan | null;
  enforced: boolean;
  seatsUsed: number | null;
  /** The owner can open the team's billing page. */
  portal: boolean;
}) {
  const [error, setError] = useState("");
  // The team's Billing tab in the account portal, signed in.
  const billing = () => sync.openPortal(`/account/team/${org.id}/billing`).catch((e) => setError(errorText(e)));
  if (!plan) {
    return (
      <div className="row access-row plan-line">
        <p className={`grow ${enforced ? "warn" : "hint"}`}>
          {enforced ? "No plan: shared vaults can be read but not changed until the team has a plan." : "No plan"}
        </p>
        {portal && (
          <button type="button" className="secondary small-button" onClick={billing}>
            Choose a plan ↗
          </button>
        )}
        {error && <p className="error">{error}</p>}
      </div>
    );
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
  return (
    <div className="row access-row plan-line">
      <p className={`grow ${tone}`}>{text}</p>
      {portal && (
        <button type="button" className="secondary small-button" onClick={billing}>
          Manage plan ↗
        </button>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

/** Devices waiting to open the organization's vaults, and the ones denied. */
function DeviceRequests({ org, admin, required }: { org: OrgInfo; admin: boolean; required: boolean }) {
  const [requests, setRequests] = useState<DeviceRequest[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(() => {
    teams.deviceRequests(org.id).then(setRequests, (e) => setError(errorText(e)));
  }, [org.id]);
  useEffect(load, [load]);
  if (!requests || (requests.length === 0 && !error)) {
    return required ? (
      <div className="stack">
        <h2 className="section-title">Devices</h2>
        <p className="hint">
          New devices wait for approval before they open the organization's vaults. None is waiting.
          {!admin && " When you sign in on a new device, approve it here, from this one."}
        </p>
      </div>
    ) : null;
  }
  const decide = (r: DeviceRequest, approve: boolean) => {
    setBusy(r.deviceId);
    setError("");
    teams.decideDevice(org.id, r.accountId, r.deviceId, approve).then(
      () => (setBusy(null), load()),
      (e) => (setError(errorText(e)), setBusy(null)),
    );
  };
  const pending = requests.filter((r) => r.status === "pending");
  return (
    <div className="stack device-requests">
      <h2 className="section-title">{pending.length > 0 ? "Waiting for approval" : "Devices"}</h2>
      <ul className="device-list">
        {requests.map((r) => (
          <li key={`${r.accountId}/${r.deviceId}`} className="device-row">
            <div className="grow">
              <strong>{r.name ?? "A device"}</strong>
              <div className="muted">
                {[
                  r.thisDevice ? "This device" : r.mine ? "Your device" : (r.email ?? "A member"),
                  r.platform && platformName(r.platform),
                  `asked ${dateTimeText(r.requestedAt)}`,
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </div>
            </div>
            <span className={`kind-badge ${r.status === "denied" ? "danger" : ""}`}>{r.status === "denied" ? "Denied" : "Waiting"}</span>
            {r.thisDevice ? (
              <span className="hint">Approve it from another of your devices</span>
            ) : (
              <>
                <button type="button" className="secondary small-button" disabled={busy !== null} onClick={() => decide(r, true)}>
                  Approve
                </button>
                {r.status === "pending" && (
                  <button type="button" className="ghost-danger small-button" disabled={busy !== null} onClick={() => decide(r, false)}>
                    Deny
                  </button>
                )}
              </>
            )}
          </li>
        ))}
      </ul>
      {error && <p className="error">{error}</p>}
    </div>
  );
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

function PolicyEditor({ org, details, onChanged }: { org: OrgInfo; details: OrgDetails; onChanged: () => void }) {
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
  return (
    <div className="stack">
      <h2 className="section-title">Policies</h2>
      <label className="check">
        <input
          type="checkbox"
          checked={p.requireTotp}
          disabled={!details.totpOffered && !p.requireTotp}
          onChange={(e) => setP({ ...p, requireTotp: e.target.checked })}
        />
        <span>
          Require two-step verification to open the organization's vaults
          {!details.totpOffered && " (this server doesn't offer two-step verification)"}
        </span>
      </label>
      <label className="check">
        <input type="checkbox" checked={p.membersCanCreateVaults} onChange={(e) => setP({ ...p, membersCanCreateVaults: e.target.checked })} />
        <span>Members can create vaults (they manage the ones they create)</span>
      </label>
      <label>
        <span>Invite only addresses at these domains (empty: any)</span>
        <input value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="example.com, example.org" spellCheck={false} autoCapitalize="off" />
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={p.requireDeviceApproval}
          disabled={!approvalOffered && !p.requireDeviceApproval}
          onChange={(e) => setP({ ...p, requireDeviceApproval: e.target.checked })}
        />
        <span>
          Owners and admins approve new devices before they open the organization's vaults (members can approve their own, from a device
          already approved). Devices in use now stay approved.
          {!approvalOffered && " Needs the Business plan."}
        </span>
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={p.requireMemberKeys === true}
          onChange={(e) => setP({ ...p, requireMemberKeys: e.target.checked })}
        />
        <span>
          Members publish the SSH keys they use on the organization's servers (so leaving can remove them); the app reminds those who
          haven't
        </span>
      </label>
      {details.sessionLogsOffered && (
        <label>
          <span>Delete the team's session logs after this many days (0 keeps them)</span>
          <input
            type="number"
            min={0}
            max={3650}
            value={p.sessionLogRetentionDays}
            onChange={(e) => setP({ ...p, sessionLogRetentionDays: Math.max(0, Math.min(3650, Math.floor(Number(e.target.value) || 0))) })}
          />
        </label>
      )}
      {p.requireSso && (
        <p className="hint">Single sign-on is required for the organization's vaults. It is set where the identity provider is, on the website.</p>
      )}
      {dirty && (
        <button type="button" className="primary align-start" disabled={busy} onClick={save}>
          Save policies
        </button>
      )}
      {error && <p className="error">{error}</p>}
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
      return `${actor} created the organization`;
    case "org_updated":
      return `${actor} changed the organization's name or policies`;
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

const PAGE = 50;

/** The audit log: what the server saw (owners and admins). */
function ActivityLog({ org }: { org: OrgInfo }) {
  const [log, setLog] = useState<Activity | null>(null);
  const [shown, setShown] = useState(PAGE);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const load = () => {
    setOpen(true);
    setError("");
    teams.activity(org.id).then(setLog, (e) => setError(errorText(e)));
  };
  const download = (format: "csv" | "jsonl") => {
    setError("");
    setSaved("");
    teams.exportActivity(org.id, format).then(setSaved, (e) => setError(errorText(e)));
  };
  return (
    <div className="stack">
      <h2 className="section-title">Activity</h2>
      {!open && (
        <button type="button" className="secondary align-start" onClick={load}>
          Show activity
        </button>
      )}
      {open && !log && !error && <p className="hint">Loading…</p>}
      {log && (
        <>
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
          <p className="hint">
            The server records what it sees: membership, access, keys and policy changes. It can't see which hosts anyone
            opened or what they ran.
          </p>
          <div className="row wrap">
            <button type="button" className="secondary small-button" onClick={() => download("csv")}>
              Download CSV
            </button>
            <button type="button" className="secondary small-button" onClick={() => download("jsonl")}>
              Download JSON lines
            </button>
          </div>
          {saved && <p className="ok">Saved {saved}</p>}
        </>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

/** This account's SSH keys published to the organization's member key directory. */
function MyKeys({
  org,
  keys,
  published,
  ready,
  onChanged,
}: {
  org: OrgInfo;
  keys: KeyView[];
  published: MemberKeyView[];
  ready: boolean;
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
      {!ready && <p className="hint">The organization's member key directory arrives with the next sync.</p>}
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
