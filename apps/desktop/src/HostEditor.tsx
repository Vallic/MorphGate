import { useEffect, useState, type FormEvent } from "react";
import { errorText, hosts, teams, vpnKindName, type GroupView, type HostInput, type IdentityView, type HostView, type KeyView, type VaultEntry, type VaultTheme, type VpnView } from "./api";
import { AgentField, agentOf } from "./AgentField";
import { HostAttachments } from "./Attachments";
import { mobileOs } from "./mobile/useMobile";
import { jumpChain } from "./RouteBar";
import { BUILTIN_THEMES, PRODUCTION_THEME, findTheme, type ThemeColors } from "./themes";
import { isReadOnly, personalVault, sameVault, VaultField } from "./VaultField";

type Kind = "password" | "key" | "agent";
const LABELS: Record<Kind, string> = { password: "Password", key: "SSH key", agent: "SSH agent" };

interface Props {
  host?: HostView;
  hosts: HostView[];
  groups: GroupView[];
  identities: IdentityView[];
  keys: KeyView[];
  vpns: VpnView[];
  vaults: VaultEntry[];
  /** Vault themes (the host can only use one from its own vault). */
  themes: VaultTheme[];
  /** The scheme this device uses when a host has none of its own. */
  deviceTheme: string;
  onSaved: (host: HostView, connect: boolean) => void;
  onDeleted: () => void;
  onCancel: () => void;
  onNewKey: () => void;
  /** Opens this host's session logs. */
  onLogs?: (hostId: string) => void;
}

export function HostEditor({
  host,
  hosts: everyHost,
  groups: everyGroup,
  identities: everyIdentity,
  keys: everyKey,
  vpns: everyVpn,
  vaults,
  themes: everyTheme,
  deviceTheme,
  onSaved,
  onDeleted,
  onCancel,
  onNewKey,
  onLogs,
}: Props) {
  const [vaultId, setVaultId] = useState(host?.vaultId ?? personalVault(vaults));
  // A host's key, jump host and VPN come from its own vault.
  const keys = everyKey.filter(sameVault(vaultId));
  const allHosts = everyHost.filter(sameVault(vaultId));
  const vpns = everyVpn.filter(sameVault(vaultId));
  const themes = everyTheme.filter(sameVault(vaultId));
  const groupsHere = everyGroup.filter((g) => g.vaultId === vaultId);
  const identitiesHere = everyIdentity.filter(sameVault(vaultId));
  const [themeId, setThemeId] = useState(host?.own.themeId ?? "");
  const [groupId, setGroupId] = useState(host?.groupId ?? "");
  const group = groupsHere.find((g) => g.id === groupId);
  const groupIdentity = identitiesHere.find((i) => i.id === group?.identityId);
  // "own": this host's user and sign-in; "group": the group's identity; else an identity's id.
  const [cred, setCred] = useState(host?.identityId ?? (host && host.own.user === "" ? "group" : "own"));
  const credential = cred === "group" && !groupIdentity ? "own" : cred;
  const [keepSession, setKeepSession] = useState(host?.own.keepSession ?? false);
  const [record, setRecord] = useState(host?.recordSessions ?? false);
  const orgId = vaults.find((v) => v.id === vaultId)?.orgId ?? null;
  // Whether the team's server and plan keep recordings, asked when they're turned on.
  const [teamKeeps, setTeamKeeps] = useState<{ orgId: string; problem: string | null } | null>(null);
  useEffect(() => {
    if (!record || !orgId) return;
    let live = true;
    teams.details(orgId).then(
      (d) =>
        live &&
        setTeamKeeps({
          orgId,
          problem: !d.sessionLogsOffered
            ? "This sync server doesn't store session logs: recordings stay on this device."
            : d.features && !d.features.includes("session_logs")
              ? "The team's plan doesn't include session logs: recordings stay on this device until it is on the Business plan, then upload."
              : null,
        }),
      () => {},
    );
    return () => {
      live = false;
    };
  }, [record, orgId]);
  const recordProblem = record && teamKeeps?.orgId === orgId ? teamKeeps.problem : null;
  const readOnly = isReadOnly(vaults, host?.vaultId);
  const [label, setLabel] = useState(host?.label ?? "");
  const [hostname, setHostname] = useState(host?.hostname ?? "");
  const [port, setPort] = useState(String(host?.port ?? 22));
  const [user, setUser] = useState(host?.own.user ?? "");
  const [kind, setKind] = useState<Kind>(host?.own.auth.kind ?? "password");
  const [password, setPassword] = useState("");
  const [forget, setForget] = useState(false);
  const [keyId, setKeyId] = useState(host?.own.auth.kind === "key" ? host.own.auth.keyId : (keys[0]?.id ?? ""));
  const [agent, setAgent] = useState(agentOf(host?.own.auth));
  const [forwardAgent, setForwardAgent] = useState(host?.forwardAgent ?? false);
  const [loginCommand, setLoginCommand] = useState(host?.loginCommand ?? "");
  const [jumpCommand, setJumpCommand] = useState(host?.jumpCommand ?? "");
  // Connected by a command on this computer (OpenSSH's ProxyCommand) instead of a jump host.
  const [proxy, setProxy] = useState(!!host?.proxyCommand);
  const [proxyCommand, setProxyCommand] = useState(host?.proxyCommand ?? "");
  const [proxyAllowed, setProxyAllowed] = useState(host?.proxyAllowed ?? false);
  const [jumpId, setJumpId] = useState(host?.own.jumpId ?? "");
  const [vpnId, setVpnId] = useState(host?.own.vpnId ?? "");
  const [tags, setTags] = useState(host?.tags.join(", ") ?? "");
  const [notes, setNotes] = useState(host?.notes ?? "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [pinned, setPinned] = useState(false);

  useEffect(() => {
    if (host) hosts.pinnedKey(host.hostname, host.port).then((k) => setPinned(k !== null), () => {});
  }, [host]);

  const pickVault = (id: string) => {
    setVaultId(id);
    setKeyId(everyKey.find((k) => k.vaultId === id)?.id ?? "");
    setJumpId("");
    setVpnId("");
    setGroupId("");
    setCred("own");
    if (!themeId.startsWith("builtin:")) setThemeId("");
  };

  const hasSaved = host?.own.auth.kind === "password" && host.own.auth.saved;
  const own = credential === "own";
  const portNum = Number(port);
  const valid =
    !readOnly &&
    hostname.trim() !== "" &&
    (!own || user.trim() !== "") &&
    Number.isInteger(portNum) &&
    portNum > 0 &&
    portNum < 65536 &&
    (!own || kind !== "key" || keyId !== "") &&
    (!proxy || proxyCommand.trim() !== "");

  const save = async (connect: boolean, e?: FormEvent) => {
    e?.preventDefault();
    if (!valid) return;
    const auth: HostInput["auth"] =
      kind === "password" ? { kind, password: forget ? "" : password || null } : kind === "key" ? { kind, keyId } : { kind, ...agent };
    setBusy(true);
    setError("");
    try {
      const saved = await hosts.save({
        id: host?.id,
        vaultId: host ? undefined : vaultId || undefined,
        label,
        hostname,
        port: portNum,
        user: own ? user : "",
        auth,
        jumpId: proxy ? null : jumpId || null,
        vpnId: proxy ? null : vpnId || null,
        themeId: themeId || null,
        recordSessions: record,
        keepSession,
        forwardAgent,
        loginCommand: loginCommand.trim() || null,
        jumpCommand: jumpCommand.trim() || null,
        proxyCommand: proxy ? proxyCommand.trim() || null : null,
        groupId: groupId || null,
        identityId: own || credential === "group" ? null : credential,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
        notes,
      });
      onSaved(saved, connect);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!host) return;
    try {
      await hosts.remove(host.id);
      onDeleted();
    } catch (err) {
      setError(errorText(err));
    }
  };

  // What the group fills in where this host leaves a field empty.
  const groupJump = group?.jumpId && group.jumpId !== host?.id ? allHosts.find((h) => h.id === group.jumpId) : undefined;
  const groupVpn = vpns.find((v) => v.id === group?.vpnId);
  const groupTheme = group?.themeId ? findTheme(group.themeId, themes) : undefined;
  // With a jump host, the VPN is the first hop's.
  const jump = proxy ? undefined : allHosts.find((h) => h.id === (jumpId || groupJump?.id));
  // A command that came with the vault, unchanged here: it runs once this device allows it.
  const proxyWaits = proxy && !!host?.proxyCommand && proxyCommand.trim() === host.proxyCommand && !proxyAllowed;
  const hops = jump ? [...jumpChain(jump, allHosts), jump] : [];
  const routeVpnId = hops.length ? hops[0].vpnId : vpnId || group?.vpnId;
  const routeVpn = vpns.find((v) => v.id === routeVpnId);
  const schemeId = themeId || group?.themeId || deviceTheme;
  const prod = schemeId === PRODUCTION_THEME;

  return (
    <div className="panel editor-layout">
      <form className="editor-form" onSubmit={(e) => void save(false, e)}>
        <div className="editor-head">
          <h1>{host ? "Edit host" : "New host"}</h1>
          {host && <span className="mono muted">{host.label}</span>}
        </div>
        <VaultField vaults={vaults} itemVault={host?.vaultId} item={host && { id: host.id, label: host.label }} value={vaultId} onChange={pickVault} />

        <label>
          <span>Label</span>
          <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder={hostname || "Production DB"} autoFocus={!host} />
        </label>
        <div className="row">
          <label className="grow">
            <span>Hostname or IP</span>
            <input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="db1.example.com" spellCheck={false} autoCapitalize="off" />
          </label>
          <label className="port">
            <span>Port</span>
            <input value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" />
          </label>
        </div>
        {groupsHere.length > 0 && (
          <label>
            <span>Group</span>
            <select value={groupId} onChange={(e) => setGroupId(e.target.value)}>
              <option value="">No group</option>
              {groupsHere.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {(identitiesHere.length > 0 || groupIdentity) && (
          <label>
            <span>Sign in as</span>
            <select value={credential} onChange={(e) => setCred(e.target.value)}>
              <option value="own">This host's own user and sign-in</option>
              {groupIdentity && (
                <option value="group">
                  From the group: {groupIdentity.label} ({groupIdentity.user})
                </option>
              )}
              {identitiesHere.map((i) => (
                <option key={i.id} value={i.id}>
                  Identity: {i.label} ({i.user})
                </option>
              ))}
            </select>
          </label>
        )}
        {own && (
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
                  No keys in the vault yet.{" "}
                  <button type="button" className="link inline" onClick={onNewKey}>
                    Generate or import one
                  </button>
                </p>
              ))}
            {kind === "agent" && <AgentField value={agent} onChange={setAgent} disabled={readOnly} />}
          </>
        )}

        <label>
          <span>Connect via</span>
          <select
            value={proxy ? "proxy" : jumpId}
            onChange={(e) => (e.target.value === "proxy" ? (setProxy(true), setJumpId("")) : (setProxy(false), setJumpId(e.target.value)))}
          >
            <option value="">{groupJump ? `From the group: jump host ${groupJump.label}` : "Direct connection"}</option>
            {allHosts
              .filter((h) => h.id !== host?.id)
              .map((h) => (
                <option key={h.id} value={h.id}>
                  Jump host: {h.label} ({h.user}@{h.hostname})
                </option>
              ))}
            {(!mobileOs || proxy) && (
              <option value="proxy" disabled={!!groupJump || !!groupVpn}>
                A command on this computer (proxy command){groupJump || groupVpn ? ": not with the group's jump host or VPN" : ""}
              </option>
            )}
          </select>
        </label>
        {proxy && (
          <label>
            <span>Proxy command</span>
            <input
              className="mono"
              value={proxyCommand}
              onChange={(e) => setProxyCommand(e.target.value)}
              placeholder="aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p"
              spellCheck={false}
              disabled={readOnly}
            />
            <small className="hint">
              Runs on this computer when it connects; its input and output are the connection (OpenSSH's <span className="mono">ProxyCommand</span>). %h,
              %p and %r are this host's address, port and user. {mobileOs && "Phones and tablets can't run it: connect to this host from the desktop app."}
            </small>
            {proxyWaits && host && (
              <div className="notice-box stack">
                <p>
                  This command came with the vault. It runs on this computer only once you allow it here, after reading it: <span className="mono">{host.proxyCommand}</span>
                </p>
                {!mobileOs && (
                  <div className="row">
                    <button
                      type="button"
                      className="secondary small-button"
                      onClick={() => hosts.allowProxy(host.id).then((h) => setProxyAllowed(h.proxyAllowed), (e) => setError(errorText(e)))}
                    >
                      Allow on this device
                    </button>
                  </div>
                )}
              </div>
            )}
          </label>
        )}
        {jump && (
          <label>
            <span>Through the jump host by a command (optional)</span>
            <input className="mono" value={jumpCommand} onChange={(e) => setJumpCommand(e.target.value)} placeholder="nc %h %p" spellCheck={false} disabled={readOnly} />
            <small className="hint">
              For jump hosts that hand a connection on instead of forwarding it: the jump host runs this command, and its input and output carry
              the connection (OpenSSH's <span className="mono">ProxyCommand ssh jump-host …</span>). %h, %p and %r are this host's address, port
              and user.
            </small>
          </label>
        )}

        <label>
          <span>VPN</span>
          {proxy ? (
            <select disabled value="">
              <option value="">None: the proxy command connects it</option>
            </select>
          ) : jump ? (
            <select disabled value="">
              <option value="">
                {routeVpn ? `From the jump host: ${routeVpn.label} (${vpnKindName(routeVpn.kind)} · ${routeVpn.server})` : "From the jump host: none"}
              </option>
            </select>
          ) : (
            <select value={vpnId} onChange={(e) => setVpnId(e.target.value)}>
              <option value="">{groupVpn ? `From the group: ${groupVpn.label}` : "None (your normal network)"}</option>
              {vpns.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.label} ({vpnKindName(v.kind)} · {v.server})
                </option>
              ))}
            </select>
          )}
          {jump && (
            <small className="hint">
              With a jump host, MorphGate dials the jump host first; it uses the jump host's VPN setting, and this host is reached from there.
            </small>
          )}
        </label>

        <label>
          <span>Terminal scheme</span>
          <div className="row align-center">
            <select className={`grow ${themeId === PRODUCTION_THEME ? "prod-select" : ""}`} value={themeId} onChange={(e) => setThemeId(e.target.value)}>
              <option value="">{groupTheme ? `From the group: ${groupTheme.name}` : "This device's scheme"}</option>
              {BUILTIN_THEMES.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
              {themes.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
            {(themeId || groupTheme) && <SchemeStrip theme={findTheme(themeId || group!.themeId!, themes)} />}
          </div>
          {themeId === PRODUCTION_THEME && (
            <small className="hint">Tabs for this host also get a red marker and a PROD label, so the color is never the only signal.</small>
          )}
        </label>
        <label>
          <span>Login command (optional)</span>
          <input className="mono" value={loginCommand} onChange={(e) => setLoginCommand(e.target.value)} placeholder="tmux attach" spellCheck={false} disabled={readOnly} />
          <small className="hint">Runs with a terminal instead of the login shell, as ssh -t host &lt;command&gt; does.</small>
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={!loginCommand.trim() && (keepSession || !!group?.keepSession)}
            onChange={(e) => setKeepSession(e.target.checked)}
            disabled={readOnly || !!group?.keepSession || !!loginCommand.trim()}
          />
          <span>Keep the session on the server (tmux){group?.keepSession ? ": the group keeps its sessions" : ""}</span>
        </label>
        {(keepSession || group?.keepSession) && (
          <p className="hint">
            Each tab attaches to its own tmux session on the host (created when missing), so a dropped connection, a restart or another device
            picks up where it was. Where tmux isn't installed, you get a normal shell.
          </p>
        )}
        {/* Phones and tablets have no agent to forward, and some clouds' SSH (Vallic Cloud's) forwards
            nothing: only where it's already on, so it can be turned off. */}
        {((!mobileOs && !host?.source?.noForwarding) || forwardAgent) && (
          <label className="check">
            <input type="checkbox" checked={forwardAgent} onChange={(e) => setForwardAgent(e.target.checked)} disabled={readOnly} />
            <span>Forward the SSH agent</span>
          </label>
        )}
        {forwardAgent && (
          <p className="warn">
            While you're connected, programs on this host can use your agent's keys to sign in elsewhere as you (git, other servers), and so can
            anyone with root there. Only for hosts you trust.
          </p>
        )}
        <label className="check">
          <input type="checkbox" checked={record} onChange={(e) => setRecord(e.target.checked)} disabled={readOnly} />
          <span>Record sessions into the vault</span>
        </label>
        {record && (
          <p className="hint">
            What each session prints is saved, encrypted with the vault's key, and synced with it. In a team's vault, everyone who can open
            the vault can play it back; hosted MorphGate keeps team recordings on the Business plan.
          </p>
        )}
        {recordProblem && <p className="warn">{recordProblem}</p>}
        <label>
          <span>Tags</span>
          <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="prod, db" spellCheck={false} />
        </label>
        <label>
          <span>Notes</span>
          <textarea rows={2} value={notes} onChange={(e) => setNotes(e.target.value)} />
        </label>
        <div className="stack">
          <span className="field-label">Attachments</span>
          <HostAttachments hostId={host?.id ?? null} readOnly={readOnly} />
        </div>

        {error && <p className="error">{error}</p>}

        <div className="actions">
          {host &&
            !readOnly &&
            (confirmDelete ? (
              <button type="button" className="danger" onClick={() => void remove()}>
                Really delete?
              </button>
            ) : (
              <button type="button" className="ghost-danger" onClick={() => setConfirmDelete(true)}>
                Delete host
              </button>
            ))}
          <span className="spacer" />
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="strong" disabled={!valid || busy}>
            Save
          </button>
          <button type="button" className="primary" disabled={!valid || busy} onClick={() => void save(true)}>
            Save & connect
          </button>
        </div>
      </form>

      <aside className="editor-aside">
        <section className="aside-card" aria-label="Connection path">
          <h2 className="section-title">Connection path</h2>
          <ol className="path">
            <PathStep state="origin" title="This device" sub="your normal network" />
            {routeVpn && (
              <PathStep
                state="hop"
                title={routeVpn.label}
                kind={vpnKindName(routeVpn.kind)}
                sub={routeVpn.active ? `${routeVpn.address ?? "connected"}, connected` : `${routeVpn.server}, comes up with the session`}
                live={routeVpn.active}
              />
            )}
            {hops.map((h) => (
              <PathStep key={h.id} state="hop" title={h.label} kind="jump host" sub={`${h.user}@${h.hostname}:${h.port}`} />
            ))}
            <PathStep
              state={prod ? "prod" : "target"}
              title={label || hostname || "This host"}
              sub={`${user || "user"}@${hostname || "host"}:${port || 22}${pinned ? " · key pinned" : ""}`}
            />
          </ol>
        </section>
        <TerminalPreview theme={findTheme(schemeId, themes)} prod={prod} title={label || hostname || "new host"} user={user || "user"} />
        {host && onLogs && (
          <button type="button" className="secondary" onClick={() => onLogs(host.id)}>
            Session logs…
          </button>
        )}
      </aside>
    </div>
  );
}

function PathStep({ state, title, kind, sub, live }: { state: "origin" | "hop" | "target" | "prod"; title: string; kind?: string; sub: string; live?: boolean }) {
  return (
    <li className={`path-step ${state}`}>
      <i className="status-square" aria-hidden="true" />
      <div className="path-info">
        <div className="path-title">
          {title}
          {kind && <span className="muted"> · {kind}</span>}
        </div>
        <div className={`path-sub mono ${live ? "live" : ""}`}>{sub}</div>
      </div>
    </li>
  );
}

/** A few lines of a session in the host's scheme. */
function TerminalPreview({ theme, prod, title, user }: { theme: ThemeColors; prod: boolean; title: string; user: string }) {
  const [, , green, yellow, blue] = theme.ansi;
  const prompt = (
    <>
      <span style={{ color: green, fontWeight: 600 }}>
        {user}@{title}
      </span>
      :<span style={{ color: blue, fontWeight: 600 }}>~</span>$
    </>
  );
  return (
    <section className={`aside-card preview-card ${prod ? "prod" : ""}`} aria-label="Terminal preview">
      <div className="preview-title">
        <i className="status-square connected" aria-hidden="true" />
        {prod && <span className="tab-marker">PROD</span>}
        <span>{title}</span>
      </div>
      <div className="preview-term mono" style={{ background: theme.background, color: theme.foreground }}>
        <div>
          {prompt} sudo systemctl restart pgbouncer
        </div>
        <div style={{ color: yellow }}>[sudo] password for {user}:</div>
        <div>
          {prompt} <span style={{ background: theme.cursor, color: theme.cursorAccent }}> </span>
        </div>
      </div>
    </section>
  );
}

/** The scheme's background and its normal colors, at a glance. */
function SchemeStrip({ theme }: { theme: { background: string; ansi: string[] } }) {
  return (
    <span className="scheme-strip" aria-hidden="true">
      <i style={{ background: theme.background, width: 22 }} />
      {theme.ansi.slice(1, 8).map((c, i) => (
        <i key={i} style={{ background: c }} />
      ))}
    </span>
  );
}
