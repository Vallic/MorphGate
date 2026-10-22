import { listen } from "@tauri-apps/api/event";
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  device,
  errorText,
  isCancelled,
  isTotpRequired,
  links,
  presenceName,
  sync,
  teams,
  vault,
  type InvitePreview,
  type PasswordStrength,
  type PresenceKind,
  type SyncServer,
} from "./api";
import { HOSTED_SERVER, SyncServerField } from "./SyncServerField";
import { TermsCheck } from "./Terms";
import { isTotpCode, TotpCode } from "./TotpCode";
import appIcon from "./assets/brand/app-icon.svg";
import { MobileUnlock } from "./mobile/MobileUnlock";
import { onPhone, useMobile } from "./mobile/useMobile";

const MIN_CHARS = 10;

/** How the first screen starts: a vault on this device only, a vault with an account that syncs
 * it, or signing in to the account already used on another device. */
type Start = "vault" | "account" | "signIn";

const STARTS: [Start, string][] = [
  ["vault", "New vault"],
  ["account", "New account"],
  ["signIn", "Sign in"],
];

function StartChoice({ value, onChange }: { value: Start; onChange: (s: Start) => void }) {
  return (
    <div className="segmented gate-choice" role="radiogroup" aria-label="How to start">
      {STARTS.map(([s, label]) => (
        <button key={s} type="button" role="radio" aria-checked={value === s} className={value === s ? "on" : ""} onClick={() => onChange(s)}>
          {label}
        </button>
      ))}
    </div>
  );
}

/** The app icon over a card; `footnote` explains the screen's circumstances under it. */
function Card({
  title,
  lead,
  footnote,
  choice,
  notice,
  invite,
  after,
  children,
}: {
  title: string;
  lead: ReactNode;
  footnote?: ReactNode;
  choice?: ReactNode;
  /** Above everything: why the app is back at the start (the device was erased). */
  notice?: ReactNode;
  /** An invite waiting for an account (`InviteNote`). */
  invite?: ReactNode;
  /** Under the form. */
  after?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="gate">
      <img className="gate-icon" src={appIcon} alt="MorphGate" width={56} height={56} />
      <div className="gate-card">
        {notice && <p className="notice-box warn gate-notice">{notice}</p>}
        {invite}
        {choice}
        <div className="gate-head">
          <h1>{title}</h1>
          <p className="lead">{lead}</p>
        </div>
        {children}
        {after}
      </div>
      {footnote && <p className="gate-footnote">{footnote}</p>}
    </div>
  );
}

/** An invite to a team that waits for an account: from a link opened before there was a vault,
 * or pasted on this screen. It stays waiting until the workspace opens Teams with it. */
interface PendingInvite {
  token: string;
  /** The server the link names; none for a bare code (MorphGate's is asked). */
  server: string | null;
  preview: InvitePreview | null;
  /** Why it couldn't be looked up (only said when the link named its server). */
  error: string;
}

function usePendingInvite(): PendingInvite | null {
  const [invite, setInvite] = useState<PendingInvite | null>(null);
  useEffect(() => {
    let live = true;
    const look = () =>
      void links.peek().then((all) => {
        const found = [...all].reverse().find((r) => r.link?.kind === "invite")?.link;
        if (!live || found?.kind !== "invite") return;
        const { token, server } = found;
        setInvite((cur) => (cur?.token === token ? cur : { token, server, preview: null, error: "" }));
        const same = (cur: PendingInvite | null) => cur?.token === token;
        teams.peek(server ?? HOSTED_SERVER, token).then(
          (preview) => live && setInvite((cur) => (same(cur) ? { ...cur!, preview } : cur)),
          (e) => live && server && setInvite((cur) => (same(cur) ? { ...cur!, error: errorText(e) } : cur)),
        );
      }, () => {});
    look();
    const unlisten = listen("links-pending", look);
    return () => {
      live = false;
      void unlisten.then((f) => f());
    };
  }, []);
  return invite;
}

function InviteNote({ invite }: { invite: PendingInvite }) {
  const p = invite.preview;
  if (invite.error) return <p className="notice-box warn gate-invite">This invite can't be opened: {invite.error}</p>;
  return (
    <p className="notice-box gate-invite">
      {p ? (
        <>
          {p.inviterEmail || "An admin"} invited <strong>{p.email}</strong> to join <strong>{p.orgName}</strong> as {p.role === "admin" ? "an admin" : "a member"}.
        </>
      ) : (
        "You have an invite to a team."
      )}{" "}
      Create your account{p ? " with that address" : ""}, or sign in if you have one: Teams then opens with the invite.
    </p>
  );
}

/** "Joining a team?": the invite's code, or its link, pasted in. */
function PasteInvite() {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [error, setError] = useState("");
  if (!open) {
    return (
      <button type="button" className="link align-start" onClick={() => setOpen(true)}>
        Joining a team? Paste your invite
      </button>
    );
  }
  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        setError("");
        links.addInvite(text).catch((err) => setError(errorText(err)));
      }}
    >
      <label>
        <span>Invite code or link</span>
        <input value={text} onChange={(e) => setText(e.target.value)} autoFocus spellCheck={false} autoComplete="off" />
      </label>
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button type="button" className="secondary" onClick={() => (setOpen(false), setError(""))}>
          Cancel
        </button>
        <button type="submit" className="primary grow" disabled={!text.trim()}>
          Use this invite
        </button>
      </div>
    </form>
  );
}

const PresenceIcon = () => (
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
    <path d="M5 11a7 7 0 0 1 14 0v2" />
    <path d="M8.5 20c.9-1.8 1.5-4 1.5-7v-2a2 2 0 0 1 4 0v2c0 3-.6 5.6-1.8 8" />
    <path d="M5 15v-1M17.5 17c-.2 1.2-.5 2.3-1 3.3" />
  </svg>
);

/** The app's estimate of a master password (zxcvbn, as it's checked when set), shortly after
 * typing stops; null until there's one for this very password. */
export function usePasswordStrength(password: string): PasswordStrength | null {
  const [s, setS] = useState<{ for: string; strength: PasswordStrength } | null>(null);
  useEffect(() => {
    if (!password) return;
    let live = true;
    const t = setTimeout(() => vault.strength(password).then((r) => live && setS({ for: password, strength: r }), () => {}), 120);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [password]);
  return s && s.for === password ? s.strength : null;
}

/** The meter: too short, then by how many guesses it would take (10^10 is the bar). */
function meter(password: string, s: PasswordStrength | null): { label: string; level: 0 | 1 | 2 | 3 } {
  if (password.length < MIN_CHARS) return { level: 0, label: `Too short: at least ${MIN_CHARS} characters` };
  if (!s) return { level: 0, label: "Checking…" };
  if (s.ok) return { level: 3, label: "Strong" };
  const why = s.warning ?? s.suggestions[0] ?? "It follows a pattern cracking tools try early.";
  return { level: s.guessesLog10 >= 8 ? 2 : 1, label: `Too easy to guess. ${why}` };
}

export function NewPasswordFields({
  password,
  confirm,
  setPassword,
  setConfirm,
  label = "Master password",
  autoFocus = true,
  strength,
}: {
  password: string;
  confirm: string;
  setPassword: (s: string) => void;
  setConfirm: (s: string) => void;
  label?: string;
  autoFocus?: boolean;
  strength: PasswordStrength | null;
}) {
  const s = meter(password, strength);
  // A suggestion is shown, in the clear, while both fields still hold it.
  const [suggested, setSuggested] = useState("");
  const [error, setError] = useState("");
  const suggest = () => {
    setError("");
    vault.suggest().then(
      (p) => (setSuggested(p), setPassword(p), setConfirm(p)),
      (e) => setError(errorText(e)),
    );
  };
  const showing = suggested !== "" && password === suggested && confirm === suggested;
  return (
    <>
      <label>
        <span>{label}</span>
        <input
          type="password"
          autoFocus={autoFocus}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
        />
      </label>
      <div className={`meter l${s.level}`} aria-label={`Password strength: ${s.label}`}>
        <i />
        <i />
        <i />
        <small>{password ? s.label : `At least ${MIN_CHARS} characters, not easy to guess: a few unrelated words make a strong one.`}</small>
      </div>
      {showing ? (
        <div className="notice-box stack suggested-password">
          <span className="mono" aria-label="Suggested password">
            {suggested}
          </span>
          <small className="hint">Five random words. Write them down, or save them in a password manager: you'll need them to unlock MorphGate.</small>
          <button type="button" className="link align-start" onClick={suggest}>
            Suggest another
          </button>
        </div>
      ) : (
        <button type="button" className="link align-start" onClick={suggest}>
          Suggest a strong password
        </button>
      )}
      {error && <p className="error">{error}</p>}
      <label>
        <span>Repeat password</span>
        <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
      </label>
    </>
  );
}

/** Shows a recovery code once, with copy and an explicit "I saved it" acknowledgement. */
/** How long a copied recovery key stays on the clipboard, at most, where the webview allows
 * clearing it without a click (WebKit lets pages write the clipboard only right after one). */
const CLIPBOARD_SECONDS = 60;

export function RecoveryCode({ code, action, onDone }: { code: string; action: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  // Copied: cleared on leaving this screen (a click, so it works everywhere), or after a minute.
  const clear = () => {
    if (copied) void navigator.clipboard?.writeText("").catch(() => {});
  };
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => void navigator.clipboard?.writeText("").catch(() => {}), CLIPBOARD_SECONDS * 1000);
    return () => clearTimeout(t);
  }, [copied]);
  return (
    <>
      <div className="recovery-code" aria-label="Recovery key">
        {code.split("-").map((group, i) => (
          <span key={i}>{group}</span>
        ))}
      </div>
      <button type="button" className="secondary" onClick={() => void navigator.clipboard?.writeText(code).then(() => setCopied(true))}>
        {copied ? "Copied" : "Copy to clipboard"}
      </button>
      {copied && <p className="hint">MorphGate clears the clipboard when you continue, so the key doesn't stay there.</p>}
      <label className="check">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        <span>I stored it somewhere safe, away from this device</span>
      </label>
      <button type="button" className="primary large" disabled={!saved} onClick={() => (clear(), onDone())}>
        {action}
      </button>
    </>
  );
}

/** What the first screen's forms share: the choice, its notes, and what an invite fills in. */
interface StartProps {
  choice: ReactNode;
  notice?: ReactNode;
  invite: PendingInvite | null;
  after?: ReactNode;
}

/** The server and address an invite names, once known (unless already typed in). */
function useInviteFill(invite: PendingInvite | null, setServer: (s: string) => void, setEmail: (f: (e: string) => string) => void) {
  const server = invite?.server;
  const email = invite?.preview?.email;
  useEffect(() => {
    if (server) setServer(server);
  }, [server]);
  useEffect(() => {
    if (email) setEmail((e) => e || email);
  }, [email]);
}

function SignIn({ onDone, choice, notice, invite, after }: StartProps & { onDone: () => void }) {
  const [recover, setRecover] = useState(false);
  const [server, setServer] = useState(invite?.server ?? HOSTED_SERVER);
  const [email, setEmail] = useState(invite?.preview?.email ?? "");
  useInviteFill(invite, setServer, setEmail);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // Set once the server asks for an authenticator code.
  const [totp, setTotp] = useState<string | null>(null);
  const base = server.trim() !== "" && email.includes("@");
  const newStrength = usePasswordStrength(recover ? password : "");
  const ok = recover
    ? base && code.trim() !== "" && !!newStrength?.ok && password === confirm
    : base && password !== "" && (totp === null || isTotpCode(totp));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!ok) return;
    setBusy(true);
    setError("");
    const call = recover ? sync.recoverSignIn(server, email, code, password) : sync.signIn(server, email, password, totp ?? undefined);
    call.then(onDone, (err) => {
      if (isTotpRequired(err)) setTotp("");
      else setError(errorText(err));
      setBusy(false);
    });
  };

  return (
    <Card
      notice={notice}
      invite={invite && <InviteNote invite={invite} />}
      choice={choice}
      after={after}
      title={recover ? "Reset password and sign in" : "Sign in to sync"}
      lead={
        recover
          ? "Use the recovery key of your sync account to choose a new master password. Your other devices are signed out and ask for the new one."
          : "Join the vault you already use on another device. Hosts and keys download encrypted and are decrypted here."
      }
    >
      <form className="stack" onSubmit={submit}>
        <SyncServerField value={server} onChange={setServer} />
        <label>
          <span>Email</span>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" autoFocus={!onPhone} />
        </label>
        {recover ? (
          <>
            <label>
              <span>Recovery key</span>
              <textarea className="mono" rows={3} value={code} onChange={(e) => setCode(e.target.value)} spellCheck={false} placeholder="XXXX-XXXX-XXXX-…" />
            </label>
            <NewPasswordFields
              password={password}
              confirm={confirm}
              setPassword={setPassword}
              setConfirm={setConfirm}
              label="New master password"
              autoFocus={false}
              strength={newStrength}
            />
          </>
        ) : (
          <>
            <label>
              <span>Master password</span>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
            </label>
            {totp !== null && (
              <>
                <TotpCode value={totp} onChange={setTotp} />
                <p className="hint">This account has two-step verification. Lost the authenticator? Use your recovery key below.</p>
              </>
            )}
          </>
        )}
        {error && <p className="error">{error}</p>}
        <button className="primary" type="submit" disabled={!ok || busy}>
          {busy ? (recover ? "Resetting…" : "Signing in…") : recover ? "Reset and sign in" : "Sign in"}
        </button>
        <button type="button" className="link" onClick={() => (setRecover(!recover), setError(""), setPassword(""), setConfirm(""), setTotp(null))}>
          {recover ? "Back to sign in" : "Forgot the master password? Use your recovery key"}
        </button>
      </form>
    </Card>
  );
}

/** Why this device was erased (`device-erased`): it's back at the start. */
export interface Erased {
  reason: "signedOut" | "disconnected";
  email: string | null;
}

function erasedNotice(e: Erased): string {
  const account = e.email ?? "its sync account";
  return e.reason === "signedOut"
    ? `This device was signed out of ${account} from another device, so MorphGate removed everything it kept here. To use the account again, choose “Sign in”.`
    : `MorphGate removed everything it kept on this device. Your vaults are still in ${e.email ?? "your sync account"}: choose “Sign in” to get them back.`;
}

/** A new vault and the account that syncs it, in one go: the vault is created here, then the
 * account with the same master password (after the emailed code, on servers that check). */
function NewAccount({
  onDone,
  onSignIn,
  choice,
  notice,
  invite,
  after,
}: StartProps & { onDone: (created: boolean) => void; onSignIn: () => void }) {
  const [server, setServer] = useState(invite?.server ?? HOSTED_SERVER);
  const [checked, setChecked] = useState<SyncServer | null>(null);
  const [email, setEmail] = useState(invite?.preview?.email ?? "");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [accepted, setAccepted] = useState(false);
  // Servers that verify addresses mail a code first; null until it was sent.
  const [emailCode, setEmailCode] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // The vault's recovery key once it's created (before the account, which may still fail).
  const [created, setCreated] = useState<string | null>(null);
  // Shown once everything is done (or the account is skipped).
  const [recovery, setRecovery] = useState<{ code: string; account: boolean } | null>(null);
  useInviteFill(invite, setServer, setEmail);
  const strength = usePasswordStrength(password);
  const terms = checked?.terms ?? null;

  // What the server asks for (its terms, a mailed code) shows before anything is typed.
  useEffect(() => {
    let live = true;
    setChecked(null);
    const t = setTimeout(() => void sync.check(server).then((c) => live && setChecked(c), () => {}), server === HOSTED_SERVER ? 0 : 600);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [server]);

  const ok =
    server.trim() !== "" &&
    email.includes("@") &&
    (created !== null || (!!strength?.ok && password === confirm)) &&
    (terms === null || accepted) &&
    (emailCode === null || isTotpCode(emailCode));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ok) return;
    setBusy(true);
    setError("");
    try {
      const caps = checked ?? (await sync.check(server));
      setChecked(caps);
      if (caps.terms && !accepted) return setError("Accept the terms of use and the privacy policy first.");
      if (emailCode === null && caps.emailVerification) {
        await sync.startRegistration(server, email);
        setEmailCode("");
        return;
      }
      const code = created ?? (await vault.create(password));
      setCreated(code);
      const r = await sync.enable(server, email, password, emailCode ?? undefined, caps.terms && accepted ? caps.terms.version : undefined);
      setPassword("");
      setConfirm("");
      setRecovery({ code: r.recoveryCode ?? code, account: true });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  if (recovery) {
    return (
      <Card
        title="Save your recovery key"
        lead={
          recovery.account
            ? "It is the only way back in if you forget your master password, here and for your account. MorphGate cannot reset it for you, and it will not be shown again."
            : "It is the only way back in if you forget your master password. MorphGate cannot reset it for you, and it will not be shown again."
        }
        footnote="Hosts, keys and passwords are encrypted on this device with your master password. It never leaves this device."
      >
        <RecoveryCode code={recovery.code} action="Open my vault" onDone={() => onDone(!recovery.account)} />
      </Card>
    );
  }

  const asking = emailCode === null && !!checked?.emailVerification;
  return (
    <Card
      notice={notice}
      invite={invite && <InviteNote invite={invite} />}
      choice={choice}
      after={after}
      title="Create your account"
      lead="A vault encrypted on this device with your master password, kept on your other devices through sync. The server stores only ciphertext."
    >
      <form className="stack" onSubmit={(e) => void submit(e)}>
        <SyncServerField value={server} onChange={(v) => (setServer(v), setEmailCode(null), setAccepted(false))} />
        {checked && !checked.registrationOpen && <p className="warn">This server isn't accepting new accounts.</p>}
        <label>
          <span>Email</span>
          <input
            type="email"
            value={email}
            onChange={(e) => (setEmail(e.target.value), setEmailCode(null))}
            autoComplete="username"
            autoFocus={!onPhone && !invite}
          />
        </label>
        {!created && (
          <NewPasswordFields password={password} confirm={confirm} setPassword={setPassword} setConfirm={setConfirm} autoFocus={false} strength={strength} />
        )}
        <p className="hint">
          {created
            ? "Your vault is ready, with the master password you chose. The account gets the same one."
            : "Your master password also signs you in to your account. It never leaves this device: only a key derived from it does."}
        </p>
        {confirm && password !== confirm && !created && <p className="error">Passwords don't match.</p>}
        {emailCode !== null && (
          <>
            <TotpCode value={emailCode} onChange={setEmailCode} label={`Code sent to ${email}`} />
            <p className="hint">
              Didn't get it? Check spam, or{" "}
              <button
                type="button"
                className="link inline"
                onClick={() => sync.startRegistration(server, email).catch((err) => setError(errorText(err)))}
              >
                send a new code
              </button>
              . If this address already has an account, you got an email saying so instead
              {created ? (
                "."
              ) : (
                <>
                  :{" "}
                  <button type="button" className="link inline" onClick={onSignIn}>
                    sign in to it
                  </button>
                  .
                </>
              )}
            </p>
          </>
        )}
        {terms && <TermsCheck terms={terms} accepted={accepted} onChange={setAccepted} />}
        {error && <p className="error">{error}</p>}
        <button className="primary large" type="submit" disabled={!ok || busy}>
          {busy ? (asking ? "Sending code…" : created ? "Creating account…" : "Creating vault and account…") : asking ? "Continue" : "Create account"}
        </button>
        {created && (
          <button type="button" className="link" onClick={() => setRecovery({ code: created, account: false })}>
            Use the vault without an account for now
          </button>
        )}
      </form>
    </Card>
  );
}

/** `onDone(true)`: a new vault without sync (sync is offered next); `onDone(false)`: sync is on. */
export function SetupScreen({ onDone, erased }: { onDone: (created: boolean) => void; erased?: Erased | null }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [code, setCode] = useState<string | null>(null);
  const invite = usePendingInvite();
  const [start, setStart] = useState<Start>("vault");
  // An invite needs an account: it's what the screen offers first, until something is chosen.
  const chose = useRef(false);
  useEffect(() => {
    if (invite && !chose.current) setStart("account");
  }, [invite?.token]);

  const strength = usePasswordStrength(password);
  const ok = !!strength?.ok && password === confirm;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ok) return;
    setBusy(true);
    setError("");
    try {
      setCode(await vault.create(password));
      setPassword("");
      setConfirm("");
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const notice = erased ? erasedNotice(erased) : undefined;
  const choice = <StartChoice value={start} onChange={(s) => ((chose.current = true), setStart(s))} />;
  const after = invite ? undefined : <PasteInvite />;
  if (start === "signIn") return <SignIn onDone={() => onDone(false)} choice={choice} notice={notice} invite={invite} after={after} />;
  if (start === "account") {
    return (
      <NewAccount
        onDone={onDone}
        onSignIn={() => ((chose.current = true), setStart("signIn"))}
        choice={choice}
        notice={notice}
        invite={invite}
        after={after}
      />
    );
  }

  if (code) {
    return (
      <Card
        title="Save your recovery key"
        lead="It is the only way back in if you forget your master password. MorphGate cannot reset it for you, and it will not be shown again."
        footnote="Hosts, keys and passwords are encrypted on this device with your master password. It never leaves this device."
      >
        <RecoveryCode code={code} action="Open my vault" onDone={() => onDone(true)} />
      </Card>
    );
  }

  return (
    <Card
      notice={notice}
      invite={invite && <InviteNote invite={invite} />}
      choice={choice}
      after={after}
      title="Create your vault"
      lead="Hosts, keys and passwords are encrypted on this device with your master password. It never leaves this device."
    >
      <form className="stack" onSubmit={submit}>
        <NewPasswordFields password={password} confirm={confirm} setPassword={setPassword} setConfirm={setConfirm} autoFocus={!onPhone} strength={strength} />
        {confirm && password !== confirm && <p className="error">Passwords don't match.</p>}
        {error && <p className="error">{error}</p>}
        <button className="primary large" type="submit" disabled={!ok || busy}>
          {busy ? "Deriving keys…" : "Create vault"}
        </button>
      </form>
    </Card>
  );
}

/** Keychain unlock is tried by itself only at app launch; after any lock it takes a click. */
let triedKeychain = false;

/** Called once the workspace is open: from now on, locking means locked. */
export function noKeychainAutoUnlock() {
  triedKeychain = true;
}

export function UnlockScreen({ onUnlocked }: { onUnlocked: () => void }) {
  const [mode, setMode] = useState<"unlock" | "recover">("unlock");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [synced, setSynced] = useState(false);
  const [keychain, setKeychain] = useState(false);
  /** Set when keychain unlock first asks for Touch ID / Windows Hello / polkit. */
  const [presence, setPresence] = useState<PresenceKind | null>(null);
  const [autoLock, setAutoLock] = useState<number | null>(null);
  const mobile = useMobile();

  useEffect(() => {
    sync.status().then((s) => setSynced(s.enabled), () => {});
    device.status().then(
      (d) => {
        setKeychain(d.keychainEnabled);
        setAutoLock(d.autoLockMinutes);
        setPresence(d.presenceRequired ? d.presence.kind : null);
        if (d.keychainEnabled && !triedKeychain) {
          triedKeychain = true;
          void run(device.unlockWithKeychain);
        }
      },
      () => {},
    );
  }, []);

  // The new password's estimate, while recovering (the field unlocks too).
  const recoverStrength = usePasswordStrength(mode === "recover" ? password : "");

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
      onUnlocked();
    } catch (err) {
      setError(isCancelled(err) ? "" : errorText(err));
      setBusy(false);
    }
  };

  if (mode === "recover") {
    const ok = code.trim() !== "" && !!recoverStrength?.ok && password === confirm;
    return (
      <Card
        title="Use your recovery key"
        lead="Enter the recovery key you saved when you created the vault, then choose a new master password."
        footnote={
          synced
            ? "Sync is on, so the new password is set on the sync server too (this needs a connection) and your other devices ask for it."
            : "Sync is off on this device, so only this vault changes."
        }
      >
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (ok) void run(() => vault.recover(code, password));
          }}
        >
          <label>
            <span>Recovery key</span>
            <textarea className="mono" rows={3} value={code} onChange={(e) => setCode(e.target.value)} spellCheck={false} placeholder="XXXX-XXXX-XXXX-…" autoFocus />
          </label>
          <NewPasswordFields password={password} confirm={confirm} setPassword={setPassword} setConfirm={setConfirm} strength={recoverStrength} />
          {error && <p className="error">{error}</p>}
          <button className="primary large" type="submit" disabled={!ok || busy}>
            {busy ? "Re-encrypting…" : "Set new password"}
          </button>
          <button type="button" className="link" onClick={() => (setMode("unlock"), setError(""), setPassword(""), setConfirm(""))}>
            Back to unlock
          </button>
        </form>
      </Card>
    );
  }

  const lockNote = autoLock
    ? `Locks after ${autoLock} minute${autoLock === 1 ? "" : "s"} without use. Locking closes open sessions.`
    : "Locking closes open sessions.";

  if (mobile) {
    return (
      <MobileUnlock
        presence={keychain ? (presence ? presenceName(presence) : "the system keychain") : null}
        busy={busy}
        error={error}
        footnote={lockNote}
        onPresence={() => void run(device.unlockWithKeychain)}
        onPassword={(pw) => void run(() => vault.unlock(pw))}
        onRecover={() => (setMode("recover"), setError(""), setPassword(""))}
      />
    );
  }

  return (
    <Card
      title="Unlock MorphGate"
      lead={
        keychain
          ? `Unlock with ${presence ? presenceName(presence) : "the system keychain"} or your master password.`
          : "Enter your master password."
      }
      footnote={lockNote}
    >
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (password) void run(() => vault.unlock(password));
        }}
      >
        {keychain && (
          <>
            <button type="button" className="primary large with-icon" disabled={busy} onClick={() => void run(device.unlockWithKeychain)}>
              <PresenceIcon />
              {presence ? `Unlock with ${presenceName(presence)}` : "Unlock with system keychain"}
            </button>
            <p className="divider-text">or with the master password</p>
          </>
        )}
        <label>
          <span>Master password</span>
          <input type="password" autoFocus={!keychain} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
        </label>
        {error && <p className="error">{error}</p>}
        <button className={keychain ? "secondary strong" : "primary large"} type="submit" disabled={!password || busy}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
        <button type="button" className="link" onClick={() => (setMode("recover"), setError(""), setPassword(""))}>
          Forgot password? Use your recovery key
        </button>
      </form>
    </Card>
  );
}
