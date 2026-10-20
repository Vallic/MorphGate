import { useState, type FormEvent } from "react";
import {
  errorText,
  groups as groupsApi,
  identities as identitiesApi,
  vpnKindName,
  type GroupView,
  type HostAuthInput,
  type HostAuthView,
  type HostView,
  type IdentityView,
  type KeyView,
  type VaultEntry,
  type VaultTheme,
  type VpnView,
} from "./api";
import { AgentField, agentOf } from "./AgentField";
import { BUILTIN_THEMES } from "./themes";
import { isReadOnly, personalVault, sameVault, VaultField } from "./VaultField";
import { mobileOs } from "./mobile/useMobile";

type Kind = HostAuthView["kind"];
const LABELS: Record<Kind, string> = { password: "Password", key: "SSH key", agent: "SSH agent" };

/** A user and how to sign in: what a host or an identity carries. */
export function useCredentials(initialUser: string, initial: HostAuthView | undefined, keys: KeyView[]) {
  const [user, setUser] = useState(initialUser);
  const [kind, setKind] = useState<Kind>(initial?.kind ?? "password");
  const [password, setPassword] = useState("");
  const [forget, setForget] = useState(false);
  const [keyId, setKeyId] = useState(initial?.kind === "key" ? initial.keyId : (keys[0]?.id ?? ""));
  const [agent, setAgent] = useState(agentOf(initial));
  const hasSaved = initial?.kind === "password" && initial.saved;
  const auth = (): HostAuthInput =>
    kind === "password" ? { kind, password: forget ? "" : password || null } : kind === "key" ? { kind, keyId } : { kind, ...agent };
  const complete = user.trim() !== "" && (kind !== "key" || keyId !== "");
  const fields = (onNewKey?: () => void) => (
    <>
      <label>
        <span>User</span>
        <input value={user} onChange={(e) => setUser(e.target.value)} placeholder="root" spellCheck={false} autoCapitalize="off" />
      </label>
      <div className="segmented" role="radiogroup" aria-label="Authentication">
        {(Object.keys(LABELS) as Kind[]).filter((k) => k !== "agent" || !mobileOs || kind === "agent").map((k) => (
          <button type="button" key={k} role="radio" aria-checked={kind === k} className={kind === k ? "on" : ""} onClick={() => setKind(k)}>
            {LABELS[k]}
          </button>
        ))}
      </div>
      {kind === "password" && (
        <>
          <label>
            <span>{hasSaved ? "Password (saved — type to replace)" : "Password"}</span>
            <input
              type="password"
              value={password}
              disabled={forget}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={hasSaved ? "••••••••" : "Leave empty to be asked when connecting"}
              autoComplete="off"
            />
          </label>
          {hasSaved && (
            <label className="check">
              <input type="checkbox" checked={forget} onChange={(e) => setForget(e.target.checked)} />
              <span>Forget the saved password and ask every time</span>
            </label>
          )}
        </>
      )}
      {kind === "key" &&
        (keys.length ? (
          <label>
            <span>Key</span>
            <select value={keyId} onChange={(e) => setKeyId(e.target.value)}>
              {keys.map((k) => (
                <option key={k.id} value={k.id}>
                  {k.label} ({k.algorithm.replace(/^ssh-/, "")})
                </option>
              ))}
            </select>
          </label>
        ) : (
          <p className="hint">
            No keys in the vault yet.
            {onNewKey && (
              <>
                {" "}
                <button type="button" className="link inline" onClick={onNewKey}>
                  Generate or import one
                </button>
              </>
            )}
          </p>
        ))}
      {kind === "agent" && <AgentField value={agent} onChange={setAgent} />}
    </>
  );
  return { user, kind, auth, complete, fields, resetKey: (id: string) => setKeyId(id) };
}

/** Credentials several hosts share: changing them here changes them for every host using them. */
export function IdentityEditor({
  identity,
  hosts,
  groups,
  keys: everyKey,
  vaults,
  onSaved,
  onDeleted,
  onCancel,
  onNewKey,
}: {
  identity?: IdentityView;
  hosts: HostView[];
  groups: GroupView[];
  keys: KeyView[];
  vaults: VaultEntry[];
  onSaved: (identity: IdentityView) => void;
  onDeleted: () => void;
  onCancel: () => void;
  onNewKey: () => void;
}) {
  const [vaultId, setVaultId] = useState(identity?.vaultId ?? personalVault(vaults));
  const keys = everyKey.filter(sameVault(vaultId));
  const [label, setLabel] = useState(identity?.label ?? "");
  const creds = useCredentials(identity?.user ?? "", identity?.auth, keys);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const readOnly = isReadOnly(vaults, identity?.vaultId);
  const users = identity
    ? [
        ...hosts.filter((h) => h.identityId === identity.id).map((h) => h.label),
        ...groups.filter((g) => g.identityId === identity.id).map((g) => `group ${g.name}`),
      ]
    : [];

  const save = (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    identitiesApi
      .save({ id: identity?.id, vaultId: identity ? undefined : vaultId, label, user: creds.user, auth: creds.auth() })
      .then(onSaved, (err) => (setError(errorText(err)), setBusy(false)));
  };
  const remove = () => {
    if (!identity) return;
    identitiesApi.remove(identity.id).then(onDeleted, (err) => setError(errorText(err)));
  };

  return (
    <div className="panel editor-layout">
      <form className="editor-form" onSubmit={save}>
        <div className="editor-head">
          <h1>{identity ? "Edit identity" : "New identity"}</h1>
          {identity && <span className="mono muted">{identity.label}</span>}
        </div>
        <p className="hint">
          A user and how to sign in, shared by hosts. Change it here and every host using it signs in the new way.
        </p>
        <VaultField
          vaults={vaults}
          itemVault={identity?.vaultId}
          item={identity && { id: identity.id, label: identity.label }}
          value={vaultId}
          onChange={(id) => (setVaultId(id), creds.resetKey(everyKey.find((k) => k.vaultId === id)?.id ?? ""))}
        />
        <label>
          <span>Name</span>
          <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="ops on production" autoFocus={!identity} />
        </label>
        {creds.fields(onNewKey)}
        {error && <p className="error">{error}</p>}
        <div className="actions">
          {identity &&
            !readOnly &&
            (confirmDelete ? (
              <button type="button" className="danger" onClick={remove}>
                Really delete?
              </button>
            ) : (
              <button type="button" className="ghost-danger" onClick={() => setConfirmDelete(true)}>
                Delete identity
              </button>
            ))}
          <span className="spacer" />
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={readOnly || busy || !label.trim() || !creds.complete}>
            Save
          </button>
        </div>
      </form>
      <aside className="editor-aside">
        <section className="aside-card">
          <h2 className="section-title">Used by</h2>
          {users.length > 0 ? (
            <ul className="aside-list">
              {users.map((u) => (
                <li key={u}>{u}</li>
              ))}
            </ul>
          ) : (
            <p className="hint">No host or group yet. Pick it under "Sign in as" in a host's editor, or as a group's identity.</p>
          )}
        </section>
      </aside>
    </div>
  );
}

/** A group of hosts and the defaults they share: each host takes what it leaves empty from here. */
export function GroupEditor({
  group,
  hosts: everyHost,
  identities: everyIdentity,
  vpns: everyVpn,
  themes: everyTheme,
  vaults,
  onSaved,
  onDeleted,
  onCancel,
}: {
  group?: GroupView;
  hosts: HostView[];
  identities: IdentityView[];
  vpns: VpnView[];
  themes: VaultTheme[];
  vaults: VaultEntry[];
  onSaved: (group: GroupView) => void;
  onDeleted: () => void;
  onCancel: () => void;
}) {
  const [vaultId, setVaultId] = useState(group?.vaultId ?? personalVault(vaults));
  const inVault = sameVault(vaultId);
  const [name, setName] = useState(group?.name ?? "");
  const [identityId, setIdentityId] = useState(group?.identityId ?? "");
  const [jumpId, setJumpId] = useState(group?.jumpId ?? "");
  const [vpnId, setVpnId] = useState(group?.vpnId ?? "");
  const [themeId, setThemeId] = useState(group?.themeId ?? "");
  const [keepSession, setKeepSession] = useState(group?.keepSession ?? false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const readOnly = isReadOnly(vaults, group?.vaultId);
  const members = group ? everyHost.filter((h) => h.groupId === group.id) : [];

  const pickVault = (id: string) => {
    setVaultId(id);
    setIdentityId("");
    setJumpId("");
    setVpnId("");
    if (!themeId.startsWith("builtin:")) setThemeId("");
  };
  const save = (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    groupsApi
      .save({
        id: group?.id,
        vaultId: group ? undefined : vaultId,
        name,
        identityId: identityId || null,
        jumpId: jumpId || null,
        vpnId: vpnId || null,
        themeId: themeId || null,
        keepSession,
      })
      .then(onSaved, (err) => (setError(errorText(err)), setBusy(false)));
  };
  const remove = () => {
    if (!group?.id) return;
    groupsApi.remove(group.id).then(onDeleted, (err) => setError(errorText(err)));
  };

  return (
    <div className="panel editor-layout">
      <form className="editor-form" onSubmit={save}>
        <div className="editor-head">
          <h1>{group ? "Edit group" : "New group"}</h1>
          {group && <span className="mono muted">{group.name}</span>}
        </div>
        <p className="hint">Hosts in the group take what they leave empty from here: credentials, jump host, VPN, terminal scheme.</p>
        <VaultField
          vaults={vaults}
          itemVault={group?.vaultId}
          item={group?.id ? { id: group.id, label: group.name } : undefined}
          value={vaultId}
          onChange={pickVault}
        />
        <label>
          <span>Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Production" autoFocus={!group} />
        </label>
        <label>
          <span>Identity</span>
          <select value={identityId} onChange={(e) => setIdentityId(e.target.value)}>
            <option value="">None: each host signs in its own way</option>
            {everyIdentity.filter(inVault).map((i) => (
              <option key={i.id} value={i.id}>
                {i.label} ({i.user})
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Connect via</span>
          <select value={jumpId} onChange={(e) => setJumpId(e.target.value)}>
            <option value="">Direct connection</option>
            {everyHost.filter(inVault).map((h) => (
              <option key={h.id} value={h.id}>
                Jump host: {h.label} ({h.user}@{h.hostname})
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>VPN</span>
          <select value={vpnId} onChange={(e) => setVpnId(e.target.value)}>
            <option value="">None (your normal network)</option>
            {everyVpn.filter(inVault).map((v) => (
              <option key={v.id} value={v.id}>
                {v.label} ({vpnKindName(v.kind)} · {v.server})
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Terminal scheme</span>
          <select value={themeId} onChange={(e) => setThemeId(e.target.value)}>
            <option value="">This device's scheme</option>
            {BUILTIN_THEMES.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
            {everyTheme.filter(inVault).map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={keepSession} onChange={(e) => setKeepSession(e.target.checked)} />
          <span>Keep sessions on the server (tmux)</span>
        </label>
        {error && <p className="error">{error}</p>}
        <div className="actions">
          {group &&
            !readOnly &&
            (confirmDelete ? (
              <button type="button" className="danger" onClick={remove}>
                Really delete?
              </button>
            ) : (
              <button type="button" className="ghost-danger" onClick={() => setConfirmDelete(true)}>
                Delete group
              </button>
            ))}
          <span className="spacer" />
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={readOnly || busy || !name.trim()}>
            Save
          </button>
        </div>
      </form>
      <aside className="editor-aside">
        <section className="aside-card">
          <h2 className="section-title">Hosts in the group</h2>
          {members.length > 0 ? (
            <>
              <ul className="aside-list">
                {members.map((h) => (
                  <li key={h.id}>
                    <strong>{h.label}</strong>
                    <span className="mono muted">
                      {h.user}@{h.hostname}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="hint">Deleting the group keeps them, with what they took from it.</p>
            </>
          ) : (
            <p className="hint">None yet. Pick the group in a host's editor.</p>
          )}
        </section>
      </aside>
    </div>
  );
}
