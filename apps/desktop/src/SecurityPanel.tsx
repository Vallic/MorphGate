import { useEffect, useState, type FormEvent } from "react";
import { onIos, onPhone } from "./mobile/useMobile";
import { device, errorText, isCancelled, presenceName, vault, type DeviceStatus, type PresenceKind, type SyncStatus } from "./api";
import { NewPasswordFields, RecoveryCode, usePasswordStrength } from "./VaultGate";

interface Props {
  sync: SyncStatus | null;
  onChanged: () => void;
  /** Auto-lock or keychain settings changed. */
  onDeviceChanged: (d: DeviceStatus) => void;
  onClose: () => void;
}


/** Master password and recovery key. With sync on, both change on the server first. */
export function SecurityPanel({ sync, onChanged, onDeviceChanged, onClose }: Props) {
  const synced = !!sync?.enabled;
  return (
    <div className="panel">
      <div className="panel-card">
        <h1>Security</h1>
        <ThisDevice onChanged={onDeviceChanged} />
        <hr className="divider" />
        <h2 className="section-title">Master password</h2>
        <ChangePassword synced={synced} signedOut={!!sync?.signedOut} onChanged={onChanged} />
        <hr className="divider" />
        <h2 className="section-title">Recovery key</h2>
        <NewRecoveryKey synced={synced} signedOut={!!sync?.signedOut} />
        <hr className="divider" />
        <h2 className="section-title">Export</h2>
        <ExportVault />
        <div className="actions">
          <span className="spacer" />
          <button type="button" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function ChangePassword({ synced, signedOut, onChanged }: { synced: boolean; signedOut: boolean; onChanged: () => void }) {
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);
  const strength = usePasswordStrength(password);
  const ok = current !== "" && !!strength?.ok && password === confirm && password !== current;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ok) return;
    setBusy(true);
    setError("");
    setDone(false);
    try {
      await vault.changePassword(current, password);
      setCurrent("");
      setPassword("");
      setConfirm("");
      setDone(true);
      onChanged();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="stack" onSubmit={(e) => void submit(e)}>
      <p className="hint">
        {synced
          ? "The new password is set on the sync server first, then here. Your other devices are signed out of sync and ask for the new password; until then they still open with the old one."
          : "Only the key that protects your vault is re-encrypted; hosts and keys stay as they are."}
      </p>
      {signedOut && <p className="warn">This device is signed out of sync. Sign in again in the Sync panel first.</p>}
      <label>
        <span>Current master password</span>
        <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" autoFocus={!onPhone} />
      </label>
      <NewPasswordFields
        password={password}
        confirm={confirm}
        setPassword={setPassword}
        setConfirm={setConfirm}
        label="New master password"
        autoFocus={false}
        strength={strength}
      />
      {confirm && password !== confirm && <p className="error">Passwords don't match.</p>}
      {error && <p className="error">{error}</p>}
      {done && <p className="ok">Master password changed{synced ? " here and on the sync server" : ""}.</p>}
      <button className="primary" type="submit" disabled={!ok || busy || signedOut}>
        {busy ? "Re-encrypting…" : "Change master password"}
      </button>
    </form>
  );
}

/** A readable copy of the vault, for moving elsewhere or keeping. */
function ExportVault() {
  const [password, setPassword] = useState("");
  const [secrets, setSecrets] = useState(false);
  const [teamVaults, setTeamVaults] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    setSaved("");
    vault.export(password, secrets, teamVaults).then(
      (path) => (setSaved(path), setPassword(""), setBusy(false)),
      (err) => (setError(errorText(err)), setBusy(false)),
    );
  };

  return (
    <form className="stack export-vault" onSubmit={submit}>
      <p className="hint">
        Saves your hosts, keys, snippets, tunnels, VPNs and themes as a readable JSON file in Downloads. Session logs and attachments are
        listed, not included: save those one by one.
      </p>
      <label className="check">
        <input type="checkbox" checked={secrets} onChange={(e) => setSecrets(e.target.checked)} />
        <span>Include passwords, private keys and VPN credentials</span>
      </label>
      <label className="check">
        <input type="checkbox" checked={teamVaults} onChange={(e) => setTeamVaults(e.target.checked)} />
        <span>Include the team vaults you can open</span>
      </label>
      {secrets && <p className="warn">Anyone with the file can then use your keys and passwords. Keep it safe, and delete it when you're done.</p>}
      <label>
        <span>Master password (to confirm)</span>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
      </label>
      {error && <p className="error">{error}</p>}
      {saved && <p className="ok">Saved {saved}</p>}
      <button type="submit" className="secondary align-start" disabled={busy || !password}>
        {busy ? "Exporting…" : "Export vault"}
      </button>
    </form>
  );
}

function NewRecoveryKey({ synced, signedOut }: { synced: boolean; signedOut: boolean }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [code, setCode] = useState<string | null>(null);

  if (code) {
    return (
      <div className="stack">
        <p className="hint">Your new recovery key. The old one no longer works{synced ? ", on this device or on the sync server" : ""}.</p>
        <RecoveryCode code={code} action="Done" onDone={() => setCode(null)} />
      </div>
    );
  }

  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        if (!password) return;
        setBusy(true);
        setError("");
        vault.newRecoveryCode(password).then(
          (c) => (setCode(c), setPassword(""), setBusy(false)),
          (err) => (setError(errorText(err)), setBusy(false)),
        );
      }}
    >
      <p className="hint">
        The recovery key resets a forgotten master password. Lost it, or think someone saw it? Make a new one; the old one stops
        working{synced ? " everywhere" : ""}. Nobody is signed out.
      </p>
      <label>
        <span>Master password</span>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
      </label>
      {error && <p className="error">{error}</p>}
      <button className="secondary" type="submit" disabled={!password || busy || signedOut}>
        {busy ? "Creating…" : "Create a new recovery key"}
      </button>
    </form>
  );
}

const AUTO_LOCK = [
  { minutes: 0, label: "Never" },
  { minutes: 5, label: "After 5 minutes" },
  { minutes: 15, label: "After 15 minutes" },
  { minutes: 30, label: "After 30 minutes" },
  { minutes: 60, label: "After 1 hour" },
  { minutes: 240, label: "After 4 hours" },
];

const PRESENCE_HINT: Record<PresenceKind, string> = {
  biometric: "Android checks your fingerprint or face before it releases the key.",
  touchId: "MorphGate asks for Touch ID (or your Mac's password) before it uses the key in the keychain.",
  faceId: "MorphGate asks for Face ID before it uses the key in the keychain.",
  passcode: "MorphGate asks for your passcode before it uses the key in the keychain.",
  windowsHello: "MorphGate asks for your face, fingerprint or Windows Hello PIN before it uses the key in the keychain.",
  system:
    "MorphGate asks the system to confirm it's you before it uses the key in the keychain: your fingerprint where the system is set up for it, otherwise your login password.",
};

/** Keychain unlock only after Touch ID / Windows Hello / polkit. */
function PresenceOption({ status, busy, act }: { status: DeviceStatus; busy: boolean; act: (fn: () => Promise<void>) => void }) {
  const { presence, presenceRequired } = status;
  const name = presenceName(presence.kind);
  const toggle = (
    <label className="check">
      <input type="checkbox" checked={presenceRequired} disabled={busy} onChange={(e) => act(() => device.requirePresence(e.target.checked))} />
      <span>Ask for {name} before unlocking</span>
    </label>
  );
  if (presence.status === "setup") {
    return (
      <div className="row">
        <p className="hint grow">
          To ask for your fingerprint or login password before unlocking, MorphGate needs to add a polkit rule to the system. Setting it up asks
          for an administrator password once.
        </p>
        <button type="button" className="secondary" disabled={busy} onClick={() => act(device.setupPresence)}>
          Set up
        </button>
      </div>
    );
  }
  if (presence.status === "unavailable") {
    return (
      <>
        {presenceRequired && toggle}
        <p className="hint">
          {name[0].toUpperCase() + name.slice(1)} can't be used here{presence.detail ? `: ${presence.detail.replace(/[^.]$/, "$&.")}` : "."}
          {presenceRequired && " Until it works again, unlock with the master password."}
        </p>
      </>
    );
  }
  return (
    <>
      {toggle}
      <p className="hint">
        {PRESENCE_HINT[presence.kind]} That keeps out someone at your unlocked computer, not programs running as you.
      </p>
    </>
  );
}

/** Android: a fingerprint or face instead of the master password. The key that opens the vault is
 * sealed in the phone's Keystore and only a biometric check releases it. */
function BiometricOption({
  status,
  password,
  setPassword,
  busy,
  act,
}: {
  status: DeviceStatus;
  password: string;
  setPassword: (p: string) => void;
  busy: boolean;
  act: (fn: () => Promise<void>) => void;
}) {
  if (status.keychainEnabled) {
    return (
      <div className="row">
        <p className="ok grow">Unlocks with your fingerprint or face on this phone.</p>
        <button type="button" className="secondary" disabled={busy} onClick={() => act(device.disableKeychain)}>
          Turn off
        </button>
      </div>
    );
  }
  if (status.presence.status !== "ready") {
    return (
      <p className="hint">
        Unlocking with a fingerprint or face isn't possible: {status.presence.detail ?? "Android doesn't allow it here"}. The master
        password is needed.
      </p>
    );
  }
  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        if (password) act(() => device.enableKeychain(password));
      }}
    >
      <p className="hint">
        Unlock with your fingerprint or face instead of typing the master password. The key that opens this vault is kept in
        your phone's secure hardware, which releases it only after Android checks your fingerprint or face. If you add or
        remove one in Android's settings, unlock once with the master password and turn this on again. The master password
        keeps working.
      </p>
      <label>
        <span>Master password (to confirm)</span>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
      </label>
      <button type="submit" className="secondary" disabled={!password || busy}>
        {busy ? "Turning on…" : "Unlock with fingerprint or face"}
      </button>
    </form>
  );
}

/** iPhones and iPads: Face ID (or Touch ID, or the passcode) instead of the master password. The
 * key that opens the vault is in the device's keychain, which releases it only after Face ID. */
function IosUnlockOption({
  status,
  password,
  setPassword,
  busy,
  act,
}: {
  status: DeviceStatus;
  password: string;
  setPassword: (p: string) => void;
  busy: boolean;
  act: (fn: () => Promise<void>) => void;
}) {
  const name = presenceName(status.presence.kind);
  if (status.keychainEnabled) {
    return (
      <div className="row">
        <p className="ok grow">Unlocks with {name} on this device.</p>
        <button type="button" className="secondary" disabled={busy} onClick={() => act(device.disableKeychain)}>
          Turn off
        </button>
      </div>
    );
  }
  if (status.presence.status !== "ready" || !status.keychainAvailable) {
    return (
      <p className="hint">
        Unlocking with {name} isn't possible: {status.presence.detail?.replace(/\.$/, "") ?? "the keychain can't be used"}. The master password is
        needed.
      </p>
    );
  }
  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        if (password) act(() => device.enableKeychain(password));
      }}
    >
      <p className="hint">
        Unlock with {name} instead of typing the master password. The key that opens this vault stays in this device's keychain,
        which releases it only after {name}. Removing the device's passcode removes the key too. The master password keeps working.
      </p>
      <label>
        <span>Master password (to confirm)</span>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
      </label>
      <button type="submit" className="secondary" disabled={!password || busy}>
        {busy ? "Turning on…" : `Unlock with ${name}`}
      </button>
    </form>
  );
}

function ThisDevice({ onChanged }: { onChanged: (d: DeviceStatus) => void }) {
  const [status, setStatus] = useState<DeviceStatus | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const reload = () =>
    device.status().then(
      (d) => (setStatus(d), onChanged(d)),
      (e) => setError(errorText(e)),
    );
  useEffect(() => void reload(), []);

  const act = (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    fn()
      .then(() => (setPassword(""), reload()))
      .catch((e) => !isCancelled(e) && setError(errorText(e)))
      .finally(() => setBusy(false));
  };

  if (!status) return <p className="hint">Loading…</p>;
  const biometric = status.presence.kind === "biometric";
  return (
    <div className="stack">
      <h2 className="section-title">This device</h2>
      <label>
        <span>Lock when idle</span>
        <select value={status.autoLockMinutes} onChange={(e) => act(() => device.setAutoLock(Number(e.target.value)))}>
          {AUTO_LOCK.map((o) => (
            <option key={o.minutes} value={o.minutes}>
              {o.label}
            </option>
          ))}
        </select>
      </label>
      <p className="hint">No keyboard or mouse use in MorphGate for that long locks the vault. Locking closes terminals, file browsers, tunnels and VPNs.</p>
      {onIos ? (
        <IosUnlockOption status={status} password={password} setPassword={setPassword} busy={busy} act={act} />
      ) : biometric ? (
        <BiometricOption status={status} password={password} setPassword={setPassword} busy={busy} act={act} />
      ) : status.keychainEnabled ? (
        <>
          <div className="row">
            <p className="ok grow">Unlocks with the system keychain on this device.</p>
            <button type="button" className="secondary" disabled={busy} onClick={() => act(device.disableKeychain)}>
              Turn off
            </button>
          </div>
          <PresenceOption status={status} busy={busy} act={act} />
        </>
      ) : status.keychainAvailable ? (
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (password) act(() => device.enableKeychain(password));
          }}
        >
          <p className="hint">
            Unlock without typing the master password: a key for this vault goes into the system keychain, which your login
            unlocks. Anyone who can use your logged-in account on this computer can then open MorphGate. The master password
            keeps working and is still needed on other devices.
          </p>
          <div className="row">
            <label className="grow">
              <span>Master password (to confirm)</span>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
            </label>
            <button type="submit" className="secondary align-end" disabled={!password || busy}>
              {busy ? "Turning on…" : "Unlock with system keychain"}
            </button>
          </div>
        </form>
      ) : (
        <p className="hint">No system keychain is available here (on Linux, GNOME Keyring or KWallet must be running), so the master password is always needed.</p>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
