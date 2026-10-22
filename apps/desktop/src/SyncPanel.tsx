import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import {
  ago,
  dateText,
  platformName,
  errorText,
  isTotpRequired,
  ownsTeam,
  sync,
  totpTitle,
  type OrgInfo,
  type SsoNeed,
  type SyncAccount,
  type SyncDevice,
  type SyncPlan,
  type SyncServer,
  type SyncStatus,
  type SyncTerms,
  type TotpSetup,
} from "./api";
import { Page } from "./Page";
import { HOSTED_SERVER, SyncServerField } from "./SyncServerField";
import { isTotpCode, TotpCode } from "./TotpCode";
import { TermsCheck, TermsLinks } from "./Terms";
import { RecoveryCode } from "./VaultGate";
import { mobileOs } from "./mobile/useMobile";

interface Props {
  status: SyncStatus;
  /** The teams this account is in (deleting it needs the ones it owns gone first). */
  orgs: OrgInfo[];
  onChanged: () => void;
  onClose: () => void;
  onOpenTeams: () => void;
  /** Opened to turn on two-step verification (teams wait for it). */
  startTotp?: boolean;
}

export function SyncPanel({ status, orgs, onChanged, onClose, onOpenTeams, startTotp }: Props) {
  // The address of the account just deleted from here.
  const [deleted, setDeleted] = useState("");
  // The account this device just joined: what that did to its master password is said once more.
  const [joinedAs, setJoinedAs] = useState("");
  const onDeleted = (email: string) => {
    setDeleted(email);
    onChanged();
  };
  return (
    <Page
      title="Sync"
      onClose={onClose}
      aside={
        status.enabled ? (
          !status.signedOut && (
            <Account
              round={status.lastSyncAt}
              totpRequired={status.totpRequired}
              startTotp={startTotp}
              owned={orgs.filter((o) => o.role === "owner")}
              onChanged={onChanged}
              onDeleted={onDeleted}
              onOpenTeams={onOpenTeams}
            />
          )
        ) : (
          <ServerSees />
        )
      }
    >
      {!status.enabled && deleted && (
        <p className="ok">Your account {deleted} is deleted. This device keeps its vault, with sync off.</p>
      )}
      {status.enabled && joinedAs && <Joined email={joinedAs} onDone={() => setJoinedAs("")} />}
      {status.enabled ? (
        <Enabled status={status} onChanged={onChanged} />
      ) : (
        <Setup onChanged={onChanged} onJoined={(email) => (setJoinedAs(email), onChanged())} />
      )}
    </Page>
  );
}

// A vault created without sync gets the offer once, a week on (the first screen had New account
// and Sign in already): when, on this device.
const OFFER_AT = "morphgate.sync-offer-at";
const WEEK = 7 * 24 * 60 * 60 * 1000;

/** When `SyncOffer` shows: a week after a vault was created without sync, then never again. */
export const syncOfferTime = {
  /** A vault without sync, created just now. */
  schedule() {
    try {
      localStorage.setItem(OFFER_AT, String(Date.now() + WEEK));
    } catch {
      // No offer, then: Sync stays in the sidebar.
    }
  },
  /** Whether its week is up. */
  due() {
    try {
      const at = Number(localStorage.getItem(OFFER_AT));
      return at > 0 && at <= Date.now();
    } catch {
      return false;
    }
  },
  /** Answered, or not wanted any more (sync is on, or the device started with an account). */
  forget() {
    try {
      localStorage.removeItem(OFFER_AT);
    } catch {
      // Nothing to forget.
    }
  },
};

/** The same setup in a dialog, offered once a week after a vault was created without sync
 * (`syncOfferTime`). `later` says where Sync is found afterwards. */
export function SyncOffer({ later, onDone }: { later: string; onDone: (enabled: boolean) => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [joinedAs, setJoinedAs] = useState("");
  useEffect(() => {
    ref.current?.showModal();
  }, []);
  if (joinedAs) {
    return (
      <dialog ref={ref} open className="sheet sync-offer" onCancel={(e) => (e.preventDefault(), onDone(true))}>
        <h1>Signed in</h1>
        <Joined email={joinedAs} onDone={() => onDone(true)} />
      </dialog>
    );
  }
  return (
    <dialog ref={ref} className="sheet sync-offer" onCancel={(e) => (e.preventDefault(), onDone(false))}>
      <h1>Sync this vault?</h1>
      <Setup onChanged={() => onDone(true)} onJoined={setJoinedAs} />
      <div className="actions">
        <p className="hint grow">You can turn it on later from {later}.</p>
        <button type="button" onClick={() => onDone(false)}>
          Not now
        </button>
      </div>
    </dialog>
  );
}

/** Beside the setup form: what turning sync on shares with the server. */
function ServerSees() {
  return (
    <div className="stack">
      <h2 className="section-title">What the server stores</h2>
      <ul className="plain-list">
        <li>Your email address, and the devices you sign in on.</li>
        <li>Your items, encrypted on this device: it can count them and see when they change, not what is in them.</li>
        <li>Never your master password: only a key derived from it.</li>
      </ul>
    </div>
  );
}

function Enabled({ status, onChanged }: { status: SyncStatus; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [confirm, setConfirm] = useState(false);

  const act = (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    fn()
      .then(onChanged, (e) => setError(errorText(e)))
      .finally(() => setBusy(false));
  };

  return (
    <>
      <dl className="facts">
        <dt>Server</dt>
        <dd className="mono">{status.server}</dd>
        <dt>Account</dt>
        <dd>{status.email}</dd>
        <dt>Last sync</dt>
        <dd>{status.syncing ? "Syncing…" : status.lastSyncAt ? ago(status.lastSyncAt) : "Not yet"}</dd>
      </dl>
      {status.signedOut ? (
        <SignInAgain onChanged={onChanged} />
      ) : (
        status.lastError && <p className="error">{status.lastError}</p>
      )}
      {error && error !== status.lastError && <p className="error">{error}</p>}
      <p className="hint">
        Changes sync within seconds, and the vault checks for others' every minute while you use the app (every 5 while
        you don't, and at once when you're back). The server only ever stores encrypted items; it cannot read hosts,
        passwords or keys.
      </p>
      <div className="row">
        <button type="button" className="secondary grow" disabled={busy || status.syncing || status.signedOut} onClick={() => act(sync.now)}>
          Sync now
        </button>
        <button type="button" className="secondary grow" disabled={confirm} onClick={() => setConfirm(true)}>
          Disconnect this device
        </button>
      </div>
      {confirm && (
        <div className="notice-box stack disconnect">
          <p>
            Disconnect this device from {status.email}? Your other devices keep syncing, and the account keeps everything that has synced.
          </p>
          <div className="row wrap">
            <button type="button" className="danger" disabled={busy} onClick={() => act(() => sync.disable(true))}>
              Remove everything from this device
            </button>
            <button type="button" className="secondary" disabled={busy} onClick={() => act(() => sync.disable(false))}>
              Keep a copy here
            </button>
            <button type="button" className="link" disabled={busy} onClick={() => setConfirm(false)}>
              Cancel
            </button>
          </div>
          <p className="hint">
            Removing takes this device back to the start; signing in again brings it all back. Keeping a copy leaves your personal vault here,
            no longer syncing; team vaults go either way.
          </p>
        </div>
      )}
      {!status.signedOut && <Devices round={status.lastSyncAt} />}
    </>
  );
}

function SignInAgain({ onChanged }: { onChanged: () => void }) {
  const [password, setPassword] = useState("");
  // Set once the server asks for an authenticator code.
  const [totp, setTotp] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const ok = password !== "" && (totp === null || isTotpCode(totp));
  return (
    <form
      className="stack notice-box"
      onSubmit={(e) => {
        e.preventDefault();
        if (!ok) return;
        setBusy(true);
        setError("");
        sync.signInAgain(password, totp ?? undefined).then(
          () => (setPassword(""), setTotp(null), setBusy(false), onChanged()),
          (err) => {
            if (isTotpRequired(err)) setTotp("");
            else setError(errorText(err));
            setBusy(false);
          },
        );
      }}
    >
      <p className="warn">
        This device was signed out of sync. If the master password was changed on another device, sign in with the new one: this
        vault then opens with it too.
      </p>
      <label>
        <span>Master password of the sync account</span>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus />
      </label>
      {totp !== null && <TotpCode value={totp} onChange={setTotp} />}
      {error && <p className="error">{error}</p>}
      <button className="primary" type="submit" disabled={!ok || busy}>
        {busy ? "Signing in…" : "Sign in again"}
      </button>
    </form>
  );
}

/** `round`: the last sync's time; the list loads again after each (a device signed in meanwhile). */
function Devices({ round }: { round: number | null }) {
  const [devices, setDevices] = useState<SyncDevice[] | null>(null);
  const [error, setError] = useState("");
  const [confirm, setConfirm] = useState<string | null>(null);

  const load = useCallback(() => {
    sync.devices().then(setDevices, (e) => setError(errorText(e)));
  }, []);
  useEffect(load, [load, round]);

  const revoke = (id: string) => {
    setError("");
    sync.revokeDevice(id).then(
      () => (setConfirm(null), load()),
      (e) => (setConfirm(null), setError(errorText(e))),
    );
  };

  return (
    <div className="stack">
      <h2 className="section-title">Devices</h2>
      {error && <p className="error">{error}</p>}
      {devices === null && !error && <p className="hint">Loading…</p>}
      {devices && (
        <ul className="device-list">
          {devices.map((d) => (
            <li key={d.id}>
              <div>
                <strong>{d.name}</strong>
                {d.current && <span className="kind-badge">this device</span>}
                <small>
                  {platformName(d.platform)} · {d.lastSeenAt ? `last seen ${ago(Date.parse(d.lastSeenAt))}` : `added ${ago(Date.parse(d.createdAt))}`}
                </small>
              </div>
              {!d.current &&
                (confirm === d.id ? (
                  <button type="button" className="danger small-button" onClick={() => revoke(d.id)}>
                    Really sign out?
                  </button>
                ) : (
                  <button type="button" className="ghost-danger small-button" onClick={() => setConfirm(d.id)}>
                    Sign out
                  </button>
                ))}
            </li>
          ))}
        </ul>
      )}
      <p className="hint">
        Signing a device out stops it syncing and, the next time it connects, removes everything MorphGate keeps on it. Changes it hadn't synced
        yet are lost.
      </p>
    </div>
  );
}

/** After joining an account: the password chosen on this device stopped working. */
function Joined({ email, onDone }: { email: string; onDone: () => void }) {
  return (
    <div className="stack joined">
      <p className="ok">This device is signed in to {email}, and its hosts and keys are merged with the account's.</p>
      <p className="warn">
        From now on it opens with the account's master password. The password you chose on this device no longer works,
        and the account's recovery key replaces this device's.
      </p>
      <div className="row">
        <button className="primary" type="button" onClick={onDone}>
          OK
        </button>
      </div>
    </div>
  );
}

function Setup({ onChanged, onJoined }: { onChanged: () => void; onJoined: (email: string) => void }) {
  // A new account from this vault, or the account already used on another device.
  const [join, setJoin] = useState(false);
  const [server, setServer] = useState(HOSTED_SERVER);
  const [checked, setChecked] = useState<SyncServer | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [code, setCode] = useState<string | null>(null);
  // Servers that verify addresses mail a code first; null until it was sent.
  const [emailCode, setEmailCode] = useState<string | null>(null);
  const [accepted, setAccepted] = useState(false);
  const terms = checked?.terms ?? null;

  // MorphGate's server is known: what it asks for (its terms) shows before anything is typed.
  useEffect(() => {
    if (server !== HOSTED_SERVER) return;
    let live = true;
    sync.check(server).then(
      (caps) => live && setChecked(caps),
      () => {},
    );
    return () => {
      live = false;
    };
  }, [server]);

  const check = () => {
    setError("");
    setChecked(null);
    sync.check(server).then(setChecked, (e) => setError(errorText(e)));
  };

  const sendCode = async () => {
    await sync.startRegistration(server, email);
    setEmailCode("");
  };

  const enable = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const caps = checked ?? (await sync.check(server));
      setChecked(caps);
      if (caps.terms && !accepted) {
        setError("Accept the terms of use and the privacy policy first.");
        return;
      }
      if (emailCode === null && caps.emailVerification) {
        await sendCode();
        return;
      }
      const r = await sync.enable(server, email, password, emailCode ?? undefined, caps.terms && accepted ? caps.terms.version : undefined);
      setPassword("");
      if (r.recoveryCode) setCode(r.recoveryCode);
      else onChanged();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  if (code) {
    return (
      <>
        <p className="hint">
          This vault predates stored recovery keys, so a new recovery key was created for your sync account. The old one
          no longer works.
        </p>
        <RecoveryCode code={code} action="Done" onDone={onChanged} />
      </>
    );
  }

  const choice = (
    <div className="segmented two" role="radiogroup" aria-label="Which account">
      <button type="button" role="radio" aria-checked={!join} className={join ? "" : "on"} onClick={() => (setJoin(false), setError(""))}>
        New account
      </button>
      <button type="button" role="radio" aria-checked={join} className={join ? "on" : ""} onClick={() => (setJoin(true), setError(""))}>
        I have an account
      </button>
    </div>
  );
  if (join) {
    return (
      <div className="stack sync-setup">
        {choice}
        <Join server={server} setServer={setServer} email={email} setEmail={setEmail} onJoined={onJoined} />
      </div>
    );
  }

  return (
    <form className="stack sync-setup" onSubmit={(e) => void enable(e)}>
      {choice}
      <p className="hint">
        Sync keeps this vault on your other devices. Everything is encrypted here before upload; the server stores only
        ciphertext. Use MorphGate's, or run your own with <span className="mono">vault-sync-server</span>.
      </p>
      <SyncServerField
        value={server}
        onChange={(s) => (setServer(s), setChecked(null), setEmailCode(null), setAccepted(false))}
        action={
          <button type="button" className="secondary" disabled={!server.trim()} onClick={check}>
            Check
          </button>
        }
      />
      {checked && (
        <p className={checked.registrationOpen ? "ok" : "warn"}>
          {/* The version only when it's a release's ("dev": a server built from source). */}
          {checked.name || "vault-sync server"}
          {/^\d/.test(checked.version ?? "") && ` ${checked.version}`}
          {checked.registrationOpen ? " — accepts new accounts" : " — not accepting new accounts"}
        </p>
      )}
      <label>
        <span>Email</span>
        <input type="email" value={email} onChange={(e) => (setEmail(e.target.value), setEmailCode(null))} autoComplete="username" />
      </label>
      <label>
        <span>Master password (to confirm)</span>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
      </label>
      <p className="hint">Your master password becomes the sync account password. It is never sent; only a key derived from it is.</p>
      {emailCode !== null && (
        <>
          <TotpCode value={emailCode} onChange={setEmailCode} label={`Code sent to ${email}`} />
          <p className="hint">
            Didn't get it? Check spam, or{" "}
            <button type="button" className="link inline" onClick={() => sendCode().catch((err) => setError(errorText(err)))}>
              send a new code
            </button>
            . If this address already has an account, you got an email saying so instead:{" "}
            <button type="button" className="link inline" onClick={() => (setJoin(true), setEmailCode(null), setError(""))}>
              sign in to it
            </button>
            .
          </p>
        </>
      )}
      {terms && <TermsCheck terms={terms} accepted={accepted} onChange={setAccepted} />}
      {error && <p className="error">{error}</p>}
      <button
        className="primary"
        type="submit"
        disabled={
          busy || !server.trim() || !email.includes("@") || !password || (emailCode !== null && !isTotpCode(emailCode)) || (terms !== null && !accepted)
        }
      >
        {busy ? (emailCode === null ? "Checking…" : "Creating account and uploading…") : "Enable sync"}
      </button>
    </form>
  );
}

/** The server's terms changed since this account accepted them. */
function TermsUpdate({ terms, onDone }: { terms: SyncTerms; onDone: () => void }) {
  const { busy, error, run } = useStep();
  return (
    <div className="stack notice-box terms-update">
      <p>
        The <TermsLinks terms={terms} /> are new or have changed since you accepted them: please review and accept them.
      </p>
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button
          type="button"
          className="primary"
          disabled={busy}
          onClick={() =>
            run(async () => {
              await sync.acceptTerms(terms.version);
              onDone();
            })
          }
        >
          Accept
        </button>
      </div>
    </div>
  );
}

/** Signs this device in to the account already used elsewhere: what this vault holds goes into the
 * account's, and it opens with the account's master password from now on. */
function Join({
  server,
  setServer,
  email,
  setEmail,
  onJoined,
}: {
  server: string;
  setServer: (s: string) => void;
  email: string;
  setEmail: (s: string) => void;
  onJoined: (email: string) => void;
}) {
  const [password, setPassword] = useState("");
  // Set once the server asks for an authenticator code.
  const [totp, setTotp] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const ok = server.trim() !== "" && email.includes("@") && password !== "" && (totp === null || isTotpCode(totp));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!ok) return;
    setBusy(true);
    setError("");
    sync.join(server, email, password, totp ?? undefined).then(
      () => (setPassword(""), onJoined(email)),
      (err) => {
        if (isTotpRequired(err)) setTotp("");
        else setError(errorText(err));
        setBusy(false);
      },
    );
  };

  return (
    <form className="stack" onSubmit={submit}>
      <p className="hint">
        Sign in with the account you use on your other devices. What this vault holds goes into that account, and its
        hosts and keys come here.
      </p>
      <p className="warn">
        This device's master password stops working: it opens with the account's master password from then on, and the
        account's recovery key applies instead of this device's.
      </p>
      <SyncServerField value={server} onChange={setServer} />
      <label>
        <span>Email</span>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
      </label>
      <label>
        <span>The account's master password</span>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
      </label>
      {totp !== null && <TotpCode value={totp} onChange={setTotp} />}
      {error && <p className="error">{error}</p>}
      <button className="primary" type="submit" disabled={!ok || busy}>
        {busy ? "Signing in and merging…" : "Sign in"}
      </button>
    </form>
  );
}

const day = (iso: string | null) => (iso ? dateText(iso) : "");

function planText(p: SyncPlan): string {
  const name = p.plan === "personal" ? "Hosted sync" : p.plan;
  switch (p.status) {
    case "trialing":
      return `Free trial until ${day(p.expiresAt)}`;
    case "active":
      return `${name}, renews ${day(p.expiresAt)}`;
    case "grace": {
      const until = p.graceEndsAt ? `until ${day(p.graceEndsAt)}` : "for a few days";
      return p.seatTeam
        ? `Your seat in ${p.seatTeam} ended ${day(p.expiresAt)}; hosted sync keeps working ${until}`
        : `${name} ended ${day(p.expiresAt)}; still syncing ${until}`;
    }
    case "lapsed":
    case "canceled":
      return `${name} ended ${day(p.expiresAt)}`;
    default:
      return name;
  }
}

/** Plan, two-step verification, email and the account portal: whatever the server offers. Loads
 * again after each sync round (`round`): a plan bought or ended meanwhile shows. */
function Account({
  round,
  totpRequired,
  startTotp,
  owned,
  onChanged,
  onDeleted,
  onOpenTeams,
}: {
  round: number | null;
  /** Teams whose vaults wait until the account has two-step verification. */
  totpRequired: SsoNeed[];
  startTotp?: boolean;
  owned: OrgInfo[];
  onChanged: () => void;
  onDeleted: (email: string) => void;
  onOpenTeams: () => void;
}) {
  const [account, setAccount] = useState<SyncAccount | null>(null);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const [mode, setMode] = useState<"" | "totp-on" | "totp-off" | "email" | "delete">(startTotp ? "totp-on" : "");
  const exportData = () => {
    setError("");
    setSaved("");
    sync.exportAccount().then(setSaved, (e) => setError(errorText(e)));
  };

  const load = useCallback(() => {
    sync.account().then(setAccount, (e) => setError(errorText(e)));
  }, []);
  useEffect(load, [load, round]);

  const done = () => {
    setMode("");
    load();
    onChanged();
  };
  const cancel = () => setMode("");

  if (!account) return error ? <p className="error">{error}</p> : null;
  // Asked to turn it on, but it's on already (from another device, say).
  const shown = mode === "totp-on" && account.totpEnabled ? "" : mode;
  const facts = account.plan || account.emailVerified === false || account.totp;
  return (
    <div className="stack">
      <h2 className="section-title">Account</h2>
      {facts && (
        <dl className="facts">
          {account.plan && (
            <>
              <dt>Plan</dt>
              <dd>{planText(account.plan)}</dd>
            </>
          )}
          {account.emailVerified === false && (
            <>
              <dt>Email</dt>
              <dd>Not verified</dd>
            </>
          )}
          {account.totp && (
            <>
              <dt>Two-step verification</dt>
              <dd>{account.totpEnabled ? "On" : "Off"}</dd>
            </>
          )}
        </dl>
      )}
      {error && <p className="error">{error}</p>}
      {account.termsToAccept && shown === "" && <TermsUpdate terms={account.termsToAccept} onDone={done} />}
      {saved && (
        <p className="ok">
          Saved {saved}: what the server keeps about your account. Your hosts and keys aren't in it; the server can't read them.
        </p>
      )}
      {totpRequired.length > 0 && !account.totpEnabled && <p className="notice-box warn">{totpTitle(totpRequired)}.</p>}
      {shown === "totp-on" && <TotpOn onDone={done} onCancel={cancel} />}
      {shown === "totp-off" && <TotpOff onDone={done} onCancel={cancel} />}
      {shown === "email" && <EmailChange onDone={done} onCancel={cancel} />}
      {shown === "delete" && (
        <DeleteAccount email={account.email} owned={owned} onDone={() => onDeleted(account.email)} onCancel={cancel} onOpenTeams={onOpenTeams} />
      )}
      {shown === "" && (
        <div className="row wrap">
          {account.totp && (
            <button type="button" className="secondary" onClick={() => setMode(account.totpEnabled ? "totp-off" : "totp-on")}>
              {account.totpEnabled ? "Turn off two-step verification" : "Turn on two-step verification"}
            </button>
          )}
          {account.emailChange && (
            <button type="button" className="secondary" onClick={() => setMode("email")}>
              Change email
            </button>
          )}
          {account.portal && !mobileOs && (
            <button type="button" className="secondary" onClick={() => sync.openPortal().catch((e) => setError(errorText(e)))}>
              Manage account ↗
            </button>
          )}
          <button type="button" className="secondary" onClick={exportData}>
            Download your data
          </button>
          <button type="button" className="ghost-danger" onClick={() => (setSaved(""), setMode("delete"))}>
            Delete account…
          </button>
        </div>
      )}
      {shown === "" && account.totp && !account.totpEnabled && (
        <p className="hint">With two-step verification, signing in on a new device also needs a code from an authenticator app.</p>
      )}
    </div>
  );
}

/** Runs one async step with busy and error state. */
function useStep() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const run = (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    fn()
      .catch((e) => setError(errorText(e)))
      .finally(() => setBusy(false));
  };
  return { busy, error, run };
}

function PasswordField({ value, onChange, autoFocus = false }: { value: string; onChange: (v: string) => void; autoFocus?: boolean }) {
  return (
    <label>
      <span>Master password</span>
      <input type="password" value={value} onChange={(e) => onChange(e.target.value)} autoComplete="current-password" autoFocus={autoFocus} />
    </label>
  );
}

/** "ABCD EFGH …", easier to type than one long run. */
const groups = (secret: string) => secret.replace(/(.{4})(?=.)/g, "$1 ");

function TotpOn({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [password, setPassword] = useState("");
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [code, setCode] = useState("");
  const { busy, error, run } = useStep();

  if (!setup) {
    return (
      <form
        className="stack notice-box"
        onSubmit={(e) => {
          e.preventDefault();
          run(async () => {
            setSetup(await sync.totpStart(password));
            setPassword("");
          });
        }}
      >
        <p>Confirm with your master password to set up an authenticator app.</p>
        <PasswordField value={password} onChange={setPassword} autoFocus />
        {error && <p className="error">{error}</p>}
        <div className="row">
          <button type="button" className="secondary" onClick={onCancel}>
            Cancel
          </button>
          <button className="primary grow" type="submit" disabled={!password || busy}>
            {busy ? "Checking…" : "Continue"}
          </button>
        </div>
      </form>
    );
  }
  return (
    <form
      className="stack notice-box"
      onSubmit={(e) => {
        e.preventDefault();
        run(async () => {
          await sync.totpEnable(code);
          onDone();
        });
      }}
    >
      <p>Scan this with an authenticator app (1Password, Aegis, Google Authenticator, …), then enter the code it shows.</p>
      <img className="qr" src={`data:image/svg+xml;utf8,${encodeURIComponent(setup.qrSvg)}`} alt="QR code for the authenticator app" />
      <p className="hint">
        Can't scan it? Enter this key instead: <span className="mono">{groups(setup.secret)}</span>
      </p>
      <TotpCode value={code} onChange={setCode} autoFocus={false} />
      <p className="hint">If you lose the authenticator, your recovery key still gets you in (and turns two-step verification off).</p>
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button type="button" className="secondary" onClick={onCancel}>
          Cancel
        </button>
        <button className="primary grow" type="submit" disabled={!isTotpCode(code) || busy}>
          {busy ? "Turning on…" : "Turn on"}
        </button>
      </div>
    </form>
  );
}

function TotpOff({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const { busy, error, run } = useStep();
  return (
    <form
      className="stack notice-box"
      onSubmit={(e) => {
        e.preventDefault();
        run(async () => {
          await sync.totpDisable(password, code);
          onDone();
        });
      }}
    >
      <p>New devices will sign in with the master password alone.</p>
      <PasswordField value={password} onChange={setPassword} autoFocus />
      <TotpCode value={code} onChange={setCode} autoFocus={false} />
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button type="button" className="secondary" onClick={onCancel}>
          Cancel
        </button>
        <button className="danger grow" type="submit" disabled={!password || !isTotpCode(code) || busy}>
          {busy ? "Turning off…" : "Turn off"}
        </button>
      </div>
    </form>
  );
}

/** Deletes the sync account (the master password proves it's the holder). An owner hands their
 * teams over or deletes them first. */
function DeleteAccount({
  email,
  owned,
  onDone,
  onCancel,
  onOpenTeams,
}: {
  email: string;
  owned: OrgInfo[];
  onDone: () => void;
  onCancel: () => void;
  onOpenTeams: () => void;
}) {
  const [password, setPassword] = useState("");
  const [failure, setFailure] = useState<unknown>(null);
  const { busy, error, run } = useStep();
  if (owned.length > 0) {
    return (
      <div className="stack notice-box">
        <p className="warn">
          You own {owned.map((o) => o.name).join(", ")}. Transfer {owned.length === 1 ? "it" : "each"} to an admin or delete{" "}
          {owned.length === 1 ? "it" : "them"} in Teams first: an account that owns a team can't be deleted.
        </p>
        <div className="row">
          <button type="button" className="secondary" onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="primary grow" onClick={onOpenTeams}>
            Open Teams
          </button>
        </div>
      </div>
    );
  }
  return (
    <form
      className="stack notice-box"
      onSubmit={(e) => {
        e.preventDefault();
        setFailure(null);
        run(async () => {
          try {
            await sync.deleteAccount(password);
          } catch (err) {
            setFailure(err);
            throw err;
          }
          onDone();
        });
      }}
    >
      <p className="warn">
        Deletes {email} from the sync server with everything it keeps for it: the synced copy of your vault, your devices, your
        team memberships and any subscription. This can't be undone.
      </p>
      <p className="hint">
        This device keeps its vault, with sync off; items from team vaults leave it. Your other devices stop syncing and keep what
        they have. A team you own has to be transferred or deleted first.
      </p>
      <PasswordField value={password} onChange={setPassword} autoFocus />
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button type="button" className="secondary" onClick={onCancel}>
          Cancel
        </button>
        {ownsTeam(failure) ? (
          <button type="button" className="primary grow" onClick={onOpenTeams}>
            Open Teams
          </button>
        ) : (
          <button className="danger grow" type="submit" disabled={!password || busy}>
            {busy ? "Deleting…" : "Delete account"}
          </button>
        )}
      </div>
    </form>
  );
}

function EmailChange({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const { busy, error, run } = useStep();

  if (!sent) {
    return (
      <form
        className="stack notice-box"
        onSubmit={(e) => {
          e.preventDefault();
          run(async () => {
            await sync.emailStart(email);
            setSent(true);
          });
        }}
      >
        <label>
          <span>New email</span>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" autoFocus />
        </label>
        {error && <p className="error">{error}</p>}
        <div className="row">
          <button type="button" className="secondary" onClick={onCancel}>
            Cancel
          </button>
          <button className="primary grow" type="submit" disabled={!email.includes("@") || busy}>
            {busy ? "Sending…" : "Send code"}
          </button>
        </div>
      </form>
    );
  }
  return (
    <form
      className="stack notice-box"
      onSubmit={(e) => {
        e.preventDefault();
        run(async () => {
          await sync.emailChange(password, email, code);
          onDone();
        });
      }}
    >
      <TotpCode value={code} onChange={setCode} label={`Code sent to ${email}`} />
      <PasswordField value={password} onChange={setPassword} />
      <p className="hint">Your other devices pick up the new address on their own. The old address gets a notice.</p>
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button type="button" className="secondary" onClick={onCancel}>
          Cancel
        </button>
        <button className="primary grow" type="submit" disabled={!isTotpCode(code) || !password || busy}>
          {busy ? "Changing…" : "Change email"}
        </button>
      </div>
    </form>
  );
}
