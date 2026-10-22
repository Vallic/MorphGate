import { useCallback, useEffect, useRef, useState } from "react";
import {
  cloud,
  dateText,
  errorText,
  openLink,
  PROVIDERS,
  REACH_NAMES,
  type CloudProvider,
  type CloudReachKind,
  type CloudRefresh,
  type CloudSource,
  type DeviceAuth,
  type FeedInput,
  type HostView,
  type KeyView,
  type SourceSettings,
  type VaultEntry,
} from "./api";
import { mobileOs } from "./mobile/useMobile";
import { Page } from "./Page";
import { personalVault, VaultField } from "./VaultField";

const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? "" : "s"}`;

/** "just now", "12 min ago", "3 h ago", a date. */
function ago(seconds: number, now = Date.now() / 1000) {
  const d = now - seconds;
  if (d < 60) return "just now";
  if (d < 3600) return `${Math.round(d / 60)} min ago`;
  if (d < 86400) return `${Math.round(d / 3600)} h ago`;
  return dateText(seconds * 1000);
}

const refreshed = (r: CloudRefresh, feed: boolean) =>
  [
    r.added && `${plural(r.added, "host")} added`,
    r.updated && `${r.updated} updated`,
    r.gone && `${r.gone} gone from the ${feed ? "feed" : "cloud"}`,
    r.snippetsAdded && `${plural(r.snippetsAdded, "snippet")} added`,
    r.snippetsUpdated && `${plural(r.snippetsUpdated, "snippet")} changed`,
    r.snippetsRemoved && `${plural(r.snippetsRemoved, "snippet")} removed`,
  ]
    .filter(Boolean)
    .join(", ") || "Nothing changed";

interface Note {
  sourceId: string;
  text: string;
  skipped?: string[];
  withoutAddress?: string[];
  couldNot?: string[];
  /** A feed's entries left out (what `couldNot` holds for a cloud). */
  feed?: boolean;
}

const noteOf = (sourceId: string, r: CloudRefresh, feed = false): Note => ({
  sourceId,
  text: refreshed(r, feed),
  skipped: r.withoutShell,
  withoutAddress: r.withoutAddress,
  couldNot: r.skipped,
  feed,
});

/** A sign-in in progress: the code, the page to type it at, until it's approved. */
interface Flow {
  device: DeviceAuth;
  /** Signing this device in to a source; null for a new one. */
  sourceId: string | null;
  error?: string;
}

/** What each CLI provider lists by (none: one context is one project or account), the profile or
 * context it signs in with, who its machines log in as by default, and how it groups them. */
const SCOPES: Record<string, { label: string | null; placeholder: string; user: string; profile: string | null; group: string }> = {
  aws: { label: "Regions (optional)", placeholder: "eu-central-1, us-east-1: every enabled region when empty", user: "ec2-user", profile: "Profile (optional)", group: "by region" },
  gcp: { label: "Projects (optional)", placeholder: "shop-prod, shop-staging: every project when empty", user: "your OS Login user", profile: null, group: "by project" },
  azure: { label: "Subscription ids (optional)", placeholder: "every enabled subscription when empty", user: "the VM's admin user", profile: null, group: "by resource group" },
  hetzner: { label: null, placeholder: "", user: "root", profile: "Context (optional: hcloud's active one)", group: "by location" },
  digitalocean: { label: null, placeholder: "", user: "root", profile: "Context (optional: doctl's default)", group: "by region" },
};

/** A CLI source's settings, for adding one or changing it. */
function SettingsForm({
  provider,
  source,
  hosts,
  keys,
  vaultId,
  busy,
  submit,
  onSubmit,
  onCancel,
}: {
  provider: CloudProvider;
  source?: CloudSource;
  hosts: HostView[];
  keys: KeyView[];
  vaultId: string;
  busy: boolean;
  submit: string;
  onSubmit: (settings: SourceSettings, keyId: string | null) => void;
  onCancel: () => void;
}) {
  const scope = SCOPES[provider];
  const cli = PROVIDERS[provider].cli!;
  const [profile, setProfile] = useState(source?.profile ?? "");
  const [scopes, setScopes] = useState(source?.scopes.join(", ") ?? "");
  const [reach, setReach] = useState<SourceSettings["reach"]>(source?.reach ?? "public");
  const [jumpId, setJumpId] = useState(source?.jumpId ?? "");
  const [user, setUser] = useState(source?.user ?? "");
  const [groupTag, setGroupTag] = useState(source?.groupTag ?? "");
  const [keyId, setKeyId] = useState(source?.keyId ?? "");
  // The CLI on this device: who it's signed in as, or why not.
  const [check, setCheck] = useState<{ ok: boolean; text: string; missing?: boolean } | null>(null);
  const [cliPath, setCliPath] = useState(source?.cliPath ?? "");
  const checking = useRef(0);
  const runCheck = useCallback(() => {
    const run = ++checking.current;
    setCheck(null);
    cloud.check(provider, scope.profile ? profile : null).then(
      (c) => run === checking.current && setCheck({ ok: true, text: `${cli} (${c.path}) is signed in as ${c.account}` }),
      (e) => run === checking.current && setCheck({ ok: false, text: errorText(e), missing: errorText(e).includes("isn't installed") }),
    );
  }, [provider, profile, cli, scope.profile]);
  useEffect(() => {
    const t = window.setTimeout(runCheck, 400);
    return () => window.clearTimeout(t);
  }, [runCheck]);
  const vaultHosts = hosts.filter((h) => h.vaultId === vaultId && !h.source);
  const vaultKeys = keys.filter((k) => k.vaultId === vaultId);
  const valid = reach !== "private" || jumpId !== "";

  return (
    <form
      className="stack cloud-settings"
      onSubmit={(e) => {
        e.preventDefault();
        if (!valid) return;
        onSubmit(
          {
            profile: scope.profile ? profile : null,
            scopes: scopes.split(",").map((s) => s.trim()).filter(Boolean),
            reach,
            jumpId: reach === "private" ? jumpId : null,
            user,
            groupTag,
          },
          keyId || null,
        );
      }}
    >
      {check ? <p className={check.ok ? "hint" : "error"}>{check.text}</p> : <p className="hint">Asking {cli} who it's signed in as…</p>}
      {check?.missing && (
        <div className="row">
          <input className="mono grow" value={cliPath} onChange={(e) => setCliPath(e.target.value)} placeholder={`Where ${cli} is on this computer`} aria-label={`Path to ${cli}`} spellCheck={false} />
          <button type="button" className="secondary small-button" onClick={() => cloud.cliPath(provider, cliPath.trim() || null).then(runCheck, (e) => setCheck({ ok: false, text: errorText(e) }))}>
            Use it
          </button>
        </div>
      )}
      {scope.profile && (
        <label>
          <span>{scope.profile}</span>
          <input value={profile} onChange={(e) => setProfile(e.target.value)} placeholder="default" spellCheck={false} />
        </label>
      )}
      {scope.label && (
        <label>
          <span>{scope.label}</span>
          <input value={scopes} onChange={(e) => setScopes(e.target.value)} placeholder={scope.placeholder} spellCheck={false} />
        </label>
      )}
      <label>
        <span>Reach its machines by</span>
        <select value={reach} onChange={(e) => setReach(e.target.value as SourceSettings["reach"])}>
          <option value="public">Their public address (machines without one are left out)</option>
          <option value="private">Their private address, through a jump host</option>
          {provider === "aws" && <option value="aws-ssm">AWS Session Manager (needs AWS's session-manager-plugin)</option>}
          {provider === "aws" && <option value="aws-eice">An EC2 Instance Connect Endpoint</option>}
          {provider === "gcp" && <option value="gcp-iap">IAP (Identity-Aware Proxy)</option>}
        </select>
        {reach !== "public" && reach !== "private" && (
          <small className="hint">
            Every machine is reached through {REACH_NAMES[reach]}, addresses or not: MorphGate runs {cli} for it when it connects, as it's signed in on that
            computer.
          </small>
        )}
      </label>
      {reach === "private" && (
        <label>
          <span>Jump host</span>
          <select value={jumpId} onChange={(e) => setJumpId(e.target.value)}>
            <option value="">Choose a host…</option>
            {vaultHosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.label} ({h.user}@{h.hostname})
              </option>
            ))}
          </select>
        </label>
      )}
      <label>
        <span>Log in as (where a machine doesn't say)</span>
        <input value={user} onChange={(e) => setUser(e.target.value)} placeholder={scope.user} spellCheck={false} />
        <small className="hint">
          A machine's own wins: its{" "}
          {provider === "aws" ? "morphgate:user tag" : provider === "digitalocean" ? "morphgate-user:<name> tag" : "morphgate-user tag or label"}.
        </small>
      </label>
      <label>
        <span>Group by tag (optional)</span>
        <input value={groupTag} onChange={(e) => setGroupTag(e.target.value)} placeholder={`${scope.group} when empty`} spellCheck={false} />
      </label>
      {!source && (
        <label>
          <span>Its hosts sign in with</span>
          <select value={keyId} onChange={(e) => setKeyId(e.target.value)}>
            <option value="">The SSH agent</option>
            {vaultKeys.map((k) => (
              <option key={k.id} value={k.id}>
                {k.label} ({k.algorithm.replace(/^ssh-/, "")})
              </option>
            ))}
          </select>
          {provider === "aws" && <small className="hint">A machine started with a key pair signs in with the vault's key of that name.</small>}
        </label>
      )}
      <div className="row">
        <button type="submit" className="primary" disabled={busy || !valid}>
          {busy ? "Listing…" : submit}
        </button>
        <button type="button" className="link" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** A feed's name, address and token, for adding one or changing it. */
function FeedForm({
  source,
  keys,
  vaultId,
  busy,
  submit,
  onSubmit,
  onCancel,
}: {
  source?: CloudSource;
  keys: KeyView[];
  vaultId: string;
  busy: boolean;
  submit: string;
  onSubmit: (input: FeedInput, keyId: string | null) => void;
  onCancel: () => void;
}) {
  const [label, setLabel] = useState(source?.label ?? "");
  const [url, setUrl] = useState(source?.url ?? "");
  const [token, setToken] = useState("");
  const [keyId, setKeyId] = useState("");
  const vaultKeys = keys.filter((k) => k.vaultId === vaultId);
  const valid = /^https:\/\/\S+$|^http:\/\/(localhost|127\.0\.0\.1|\[::1\])([:/]\S*)?$/.test(url.trim()) && (!!source || token.trim() !== "");
  return (
    <form
      className="stack cloud-settings"
      onSubmit={(e) => {
        e.preventDefault();
        if (valid) onSubmit({ label: label.trim() || null, url: url.trim(), token: token.trim() || null }, keyId || null);
      }}
    >
      <label>
        <span>Address</span>
        <input className="mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://ops.example.com/morphgate.json" spellCheck={false} autoFocus={!source} />
      </label>
      <label>
        <span>Token</span>
        <input
          type="password"
          className="mono"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder={source ? `Leave empty to keep it (${source.tokenEnd ?? "…"})` : "Sent as Authorization: Bearer"}
          autoComplete="off"
          spellCheck={false}
        />
        <small className="hint">Kept in the vault, so every device that can open it refreshes the feed. Use a token that only reads the feed.</small>
      </label>
      <label>
        <span>Name (optional)</span>
        <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="What the feed calls itself" />
      </label>
      {!source && (
        <label>
          <span>Its hosts sign in with</span>
          <select value={keyId} onChange={(e) => setKeyId(e.target.value)}>
            <option value="">The SSH agent</option>
            {vaultKeys.map((k) => (
              <option key={k.id} value={k.id}>
                {k.label} ({k.algorithm.replace(/^ssh-/, "")})
              </option>
            ))}
          </select>
          <small className="hint">A host the feed gives a key name signs in with the vault's key of that name.</small>
        </label>
      )}
      <div className="row">
        <button type="submit" className="primary" disabled={busy || !valid}>
          {busy ? "Reading…" : submit}
        </button>
        <button type="button" className="link" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** Clouds: their machines and environments as hosts, kept in step. Vallic Cloud signs in on each
 * device (a code typed in the browser); AWS, Google Cloud and Azure list with their CLI on this
 * device. The hosts sync like any others. */
export function CloudPage({
  vaults,
  keys,
  hosts,
  adding: addingFirst,
  onChanged,
  onClose,
}: {
  vaults: VaultEntry[];
  keys: KeyView[];
  hosts: HostView[];
  /** Opened to add this (Add from… → Feed URL…). */
  adding?: CloudProvider;
  onChanged: () => void;
  onClose: () => void;
}) {
  const [sources, setSources] = useState<CloudSource[] | null>(null);
  const [flow, setFlow] = useState<Flow | null>(null);
  const [vaultId, setVaultId] = useState(personalVault(vaults));
  const [error, setError] = useState("");
  const [note, setNote] = useState<Note | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const [adding, setAdding] = useState<CloudProvider | null>(addingFirst ?? null);
  const [editing, setEditing] = useState<string | null>(null);
  // The poll of the sign-in on screen (a new sign-in or Cancel ends it).
  const polling = useRef(0);

  const load = useCallback(() => {
    cloud.sources().then(setSources, (e) => setError(errorText(e)));
  }, []);
  useEffect(load, [load]);
  useEffect(() => () => void (polling.current += 1), []);

  const signIn = async (sourceId: string | null) => {
    setError("");
    setNote(null);
    try {
      const device = await cloud.signIn();
      const run = ++polling.current;
      setFlow({ device, sourceId });
      void openLink(device.verificationUri).catch(() => {});
      let wait = (device.interval ?? 5) * 1000;
      const poll = async () => {
        if (polling.current !== run) return;
        try {
          const s = await cloud.poll(device.deviceCode, { sourceId, vaultId });
          if (polling.current !== run) return;
          if (s.status === "pending") {
            if (s.slower) wait += 5000;
            window.setTimeout(() => void poll(), wait);
          } else if (s.status === "done") {
            setFlow(null);
            setNote(noteOf(s.source.id, s.refresh));
            load();
            onChanged();
          } else {
            setFlow((f) => f && { ...f, error: s.status === "denied" ? "The sign-in was declined in the browser." : "The code ran out before it was used." });
          }
        } catch (e) {
          setFlow((f) => f && { ...f, error: errorText(e) });
        }
      };
      window.setTimeout(() => void poll(), wait);
    } catch (e) {
      setError(errorText(e));
    }
  };

  const act = (sourceId: string, p: Promise<unknown>, after?: (r: unknown) => void) => {
    setBusy(sourceId);
    setError("");
    setNote(null);
    p.then(
      (r) => (setBusy(null), after?.(r), load(), onChanged()),
      (e) => (setBusy(null), setError(errorText(e)), load()),
    );
  };

  const addFeed = (input: FeedInput, keyId: string | null) => {
    setBusy("adding");
    setError("");
    setNote(null);
    cloud.addFeed(input, { vaultId, keyId }).then(
      (r) => (setBusy(null), setAdding(null), setNote(noteOf(r.source.id, r.refresh, true)), load(), onChanged()),
      (e) => (setBusy(null), setError(errorText(e)), load()),
    );
  };

  const add = (provider: CloudProvider, settings: SourceSettings, keyId: string | null) => {
    setBusy("adding");
    setError("");
    setNote(null);
    cloud.add(provider, settings, { vaultId, keyId }).then(
      (r) => (setBusy(null), setAdding(null), setNote(noteOf(r.source.id, r.refresh)), load(), onChanged()),
      (e) => (setBusy(null), setError(errorText(e)), load()),
    );
  };

  return (
    <Page
      title="Clouds"
      lead="Your clouds' machines and environments as hosts, kept in step: a refresh brings what the cloud decides, and your renames, keys and notes stay. Vallic Cloud signs in on each device; AWS, Google Cloud, Azure, Hetzner Cloud and DigitalOcean list with their own CLI on this computer; a feed is a list of hosts and snippets your team publishes at an address."
      onClose={onClose}
    >
      <div className="stack cloud-page">
        {error && <p className="error">{error}</p>}

        {flow && (
          <div className="notice-box stack cloud-sign-in">
            <p>Type this code at Vallic Cloud's sign-in page, then approve:</p>
            <p className="mono cloud-code" aria-label="Sign-in code">
              {flow.device.userCode}
            </p>
            <div className="row">
              <button type="button" className="secondary" onClick={() => void openLink(flow.device.verificationUri)}>
                Open {flow.device.verificationUri.replace(/^https?:\/\//, "")} ↗
              </button>
              <button type="button" className="link" onClick={() => ((polling.current += 1), setFlow(null))}>
                Cancel
              </button>
            </div>
            {flow.error ? <p className="error">{flow.error}</p> : <p className="hint">Waiting for you to approve it…</p>}
          </div>
        )}

        {sources?.map((s) => {
          const vaultKeys = keys.filter((k) => k.vaultId === s.vaultId);
          const key = vaultKeys.find((k) => k.id === s.keyId);
          const vallic = s.provider === "vallic";
          const feed = s.provider === "feed";
          const provider = PROVIDERS[s.provider]?.name ?? s.provider;
          const how = vallic
            ? null
            : feed
              ? `${s.url ?? ""} · token ${s.tokenEnd ?? "…"}`
              : [
                s.profile && `${s.provider === "aws" ? "profile" : "context"} ${s.profile}`,
                s.scopes.length
                  ? s.scopes.join(", ")
                  : s.provider === "aws"
                    ? "every region"
                    : s.provider === "gcp"
                      ? "every project"
                      : s.provider === "azure"
                        ? "every subscription"
                        : null,
                s.reach === "private"
                  ? `private addresses through ${hosts.find((h) => h.id === s.jumpId)?.label ?? "a jump host"}`
                  : s.reach
                    ? `through ${REACH_NAMES[s.reach as CloudReachKind]}`
                    : "public addresses",
                s.user && `as ${s.user}`,
                s.groupTag && `grouped by ${s.groupTag}`,
              ]
                .filter(Boolean)
                .join(" · ");
          return (
            <section key={s.id} className="aside-card stack cloud-source">
              <div className="row">
                <div className="grow">
                  <h2 className="section-title">
                    {s.label}
                    {s.label !== provider && <span className="kind-badge">{provider}</span>}
                  </h2>
                  <p className="hint">
                    {s.account && `${s.account} · `}
                    {plural(s.hosts, "host")}
                    {s.gone > 0 && ` (${s.gone} gone)`}
                    {s.snippets > 0 && ` · ${plural(s.snippets, "snippet")}`}
                    {s.refreshedAt > 0 && ` · refreshed ${ago(s.refreshedAt)}`}
                  </p>
                  {how && <p className={`hint ${feed ? "mono cloud-url" : ""}`}>{how}</p>}
                </div>
                {s.signedIn ? (
                  <button type="button" className="primary small-button" disabled={busy === s.id} onClick={() => act(s.id, cloud.refresh(s.id), (r) => setNote(noteOf(s.id, r as CloudRefresh, feed)))}>
                    {busy === s.id ? "Refreshing…" : "Refresh"}
                  </button>
                ) : (
                  <button type="button" className="primary small-button" disabled={!!flow} onClick={() => void signIn(s.id)}>
                    Sign in on this device
                  </button>
                )}
              </div>
              {note?.sourceId === s.id && (
                <>
                  <p className="ok">{note.text}.</p>
                  {note.skipped && note.skipped.length > 0 && <p className="hint">No shell for you (your role), or not running yet: {note.skipped.join(", ")}.</p>}
                  {note.withoutAddress && note.withoutAddress.length > 0 && (
                    <p className="hint">
                      Without {s.reach === "private" ? "a private" : "a public"} address: {note.withoutAddress.join(", ")}.
                    </p>
                  )}
                  {note.couldNot && note.couldNot.length > 0 && (
                    <p className="hint">
                      {note.feed ? "Skipped" : "Couldn't list"}: {note.couldNot.join("; ")}
                    </p>
                  )}
                </>
              )}
              {s.failed && note?.sourceId !== s.id && busy !== s.id && <p className="error">The last refresh failed: {s.failed}</p>}
              {editing === s.id && feed ? (
                <FeedForm
                  source={s}
                  keys={keys}
                  vaultId={s.vaultId}
                  busy={busy === s.id}
                  submit="Save and refresh"
                  onCancel={() => setEditing(null)}
                  onSubmit={(input) =>
                    act(
                      s.id,
                      cloud.feedSettings(s.id, input).then(() => cloud.refresh(s.id)),
                      (r) => (setEditing(null), setNote(noteOf(s.id, r as CloudRefresh, true))),
                    )
                  }
                />
              ) : editing === s.id && !vallic ? (
                <SettingsForm
                  provider={s.provider}
                  source={s}
                  hosts={hosts}
                  keys={keys}
                  vaultId={s.vaultId}
                  busy={busy === s.id}
                  submit="Save and refresh"
                  onCancel={() => setEditing(null)}
                  onSubmit={(settings) =>
                    act(
                      s.id,
                      cloud.settings(s.id, settings).then(() => cloud.refresh(s.id)),
                      (r) => (setEditing(null), setNote(noteOf(s.id, r as CloudRefresh))),
                    )
                  }
                />
              ) : (
                <>
                  <label>
                    <span>Its hosts sign in with</span>
                    <select value={s.keyId ?? ""} onChange={(e) => act(s.id, cloud.setKey(s.id, e.target.value || null))} disabled={busy === s.id}>
                      <option value="">The SSH agent</option>
                      {vaultKeys.map((k) => (
                        <option key={k.id} value={k.id}>
                          {k.label} ({k.algorithm.replace(/^ssh-/, "")})
                        </option>
                      ))}
                    </select>
                  </label>
                  {vallic && key && s.signedIn && (
                    <div className="row">
                      <button
                        type="button"
                        className="secondary small-button"
                        disabled={busy === s.id || key.algorithm.startsWith("sk-")}
                        onClick={() => act(s.id, cloud.addKey(s.id, key.id), () => setNote({ sourceId: s.id, text: `${key.label} is on your Vallic account now` }))}
                      >
                        Add {key.label} to your Vallic account
                      </button>
                      {key.algorithm.startsWith("sk-") && <small className="hint">Vallic Cloud doesn't take security keys: choose an Ed25519 key.</small>}
                    </div>
                  )}
                </>
              )}
              <div className="row">
                {vallic && s.signedIn && (
                  <button type="button" className="link" disabled={busy === s.id} onClick={() => act(s.id, cloud.signOut(s.id))}>
                    Sign out on this device
                  </button>
                )}
                {!vallic && editing !== s.id && (
                  <button type="button" className="link" onClick={() => setEditing(s.id)}>
                    Settings…
                  </button>
                )}
                <span className="spacer" />
                {removing === s.id ? (
                  <>
                    <button type="button" className="ghost-danger small-button" onClick={() => (setRemoving(null), act(s.id, cloud.remove(s.id, true)))}>
                      {s.snippets > 0 ? "Remove it, its hosts and snippets" : "Remove it and its hosts"}
                    </button>
                    <button type="button" className="secondary small-button" onClick={() => (setRemoving(null), act(s.id, cloud.remove(s.id, false)))}>
                      {s.snippets > 0 ? "Remove it, keep the hosts and snippets" : "Remove it, keep the hosts"}
                    </button>
                    <button type="button" className="link" onClick={() => setRemoving(null)}>
                      Cancel
                    </button>
                  </>
                ) : (
                  <button type="button" className="ghost-danger small-button" onClick={() => setRemoving(s.id)}>
                    Remove…
                  </button>
                )}
              </div>
            </section>
          );
        })}

        {adding === "feed" && (
          <section className="aside-card stack cloud-adding">
            <h2 className="section-title">Add a feed</h2>
            <p className="hint">
              Hosts and snippets from a JSON document at an address, read with a token: from Terraform output, a CMDB or an internal endpoint. Its hosts and
              snippets stay in step with it; your renames, keys, tags and notes stay yours.
            </p>
            <VaultField vaults={vaults} value={vaultId} onChange={setVaultId} />
            <FeedForm
              key={vaultId}
              keys={keys}
              vaultId={vaultId}
              busy={busy === "adding"}
              submit="Add and read the feed"
              onCancel={() => setAdding(null)}
              onSubmit={addFeed}
            />
          </section>
        )}

        {adding && adding !== "feed" && (
          <section className="aside-card stack cloud-adding">
            <h2 className="section-title">Add {PROVIDERS[adding].name}</h2>
            <VaultField vaults={vaults} value={vaultId} onChange={setVaultId} />
            <SettingsForm
              key={`${adding}-${vaultId}`}
              provider={adding}
              hosts={hosts}
              keys={keys}
              vaultId={vaultId}
              busy={busy === "adding"}
              submit="Add and list machines"
              onCancel={() => setAdding(null)}
              onSubmit={(settings, keyId) => add(adding, settings, keyId)}
            />
          </section>
        )}

        {sources && !flow && !adding && (
          <div className="stack">
            {sources.length === 0 && <p className="hint">Not connected yet.</p>}
            <VaultField vaults={vaults} value={vaultId} onChange={setVaultId} />
            <div className="row wrap">
              <button type="button" className={sources.length === 0 ? "primary" : "secondary"} onClick={() => void signIn(null)}>
                {sources.some((s) => s.provider === "vallic") ? "Connect another Vallic account" : "Connect Vallic Cloud"}
              </button>
              {!mobileOs &&
                (["aws", "gcp", "azure", "hetzner", "digitalocean"] as const).map((p) => (
                  <button key={p} type="button" className="secondary" onClick={() => (setError(""), setNote(null), setAdding(p))}>
                    Add {PROVIDERS[p].name}
                  </button>
                ))}
              <button type="button" className="secondary" onClick={() => (setError(""), setNote(null), setAdding("feed"))}>
                Add a feed
              </button>
            </div>
          </div>
        )}
      </div>
    </Page>
  );
}
