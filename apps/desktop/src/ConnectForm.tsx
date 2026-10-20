import { useState, type FormEvent } from "react";
import { errorText, keys as keysApi, type AuthRequest, type ConnectTarget, type HostInput } from "./api";
import { FilePick, type PickedFile } from "./FilePick";
import { mobileOs } from "./mobile/useMobile";

type AuthKind = AuthRequest["kind"];

const AUTH_LABELS: Record<AuthKind, string> = { password: "Password", key: "Key", agent: "SSH agent" };

/** Remembered between connections; never includes secrets (so no key). */
const LAST_KEY = "morphgate.lastTarget";

interface Remembered {
  host: string;
  port: number;
  user: string;
  authKind: AuthKind;
}

function loadRemembered(): Remembered {
  const fallback: Remembered = { host: "", port: 22, user: "", authKind: "password" };
  try {
    return { ...fallback, ...JSON.parse(localStorage.getItem(LAST_KEY) ?? "{}") };
  } catch {
    return fallback;
  }
}

/** What a `morphgate://connect` link fills in. */
export interface ConnectPrefill {
  host: string;
  port: number | null;
  user: string | null;
  label: string | null;
}

interface Props {
  onConnect: (target: ConnectTarget, title: string) => void;
  /** Saves the target as a vault host before connecting. */
  onSaveHost: (input: HostInput) => Promise<void>;
  /** Filled in from a link: shown, never connected to until Connect. */
  prefill?: ConnectPrefill;
}

export function ConnectForm({ onConnect, onSaveHost, prefill }: Props) {
  const initial = loadRemembered();
  const [host, setHost] = useState(prefill?.host ?? initial.host);
  const [port, setPort] = useState(String(prefill?.port ?? (prefill ? 22 : initial.port)));
  const [user, setUser] = useState(prefill ? (prefill.user ?? "") : initial.user);
  const label = prefill?.label?.trim() || host.trim();
  const [authKind, setAuthKind] = useState<AuthKind>(initial.authKind);
  const [password, setPassword] = useState("");
  const [keyFrom, setKeyFrom] = useState<"file" | "text">("file");
  const [keyFile, setKeyFile] = useState<PickedFile | null>(null);
  const [keyText, setKeyText] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [save, setSave] = useState(false);
  const [error, setError] = useState("");

  const portNum = Number(port);
  const privateKey = keyFrom === "file" ? (keyFile?.text ?? "") : keyText;
  const valid =
    host.trim() !== "" &&
    user.trim() !== "" &&
    Number.isInteger(portNum) &&
    portNum > 0 &&
    portNum < 65536 &&
    (authKind !== "key" || privateKey.trim() !== "");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    const auth: AuthRequest =
      authKind === "password"
        ? { kind: "password", password }
        : authKind === "key"
          ? { kind: "key", privateKey, passphrase: passphrase || undefined }
          : { kind: "agent" };
    try {
      localStorage.setItem(LAST_KEY, JSON.stringify({ host, port: portNum, user, authKind }));
    } catch {
      /* storage unavailable: nothing to remember */
    }
    if (save) {
      try {
        // A saved host signs in with a key from the vault: the key goes in first, named after
        // its file (or the host).
        const key =
          authKind === "key"
            ? await keysApi.import(keyFrom === "file" && keyFile ? keyFile.name : `${label} key`, { kind: "text", text: privateKey }, passphrase || undefined)
            : null;
        await onSaveHost({
          label,
          hostname: host.trim(),
          port: portNum,
          user: user.trim(),
          auth: key
            ? { kind: "key", keyId: key.id }
            : authKind === "password"
              ? { kind: "password", password: password || null }
              : { kind: "agent", agent: null, path: null, key: null },
          tags: [],
          notes: "",
        });
      } catch (err) {
        setError(errorText(err));
        return;
      }
    }
    setPassword("");
    setPassphrase("");
    setKeyText("");
    setKeyFile(null);
    onConnect({ kind: "adhoc", host: host.trim(), port: portNum, user: user.trim(), auth }, prefill?.label?.trim() || `${user.trim()}@${host.trim()}`);
  };

  return (
    <div className="panel">
      <form className="panel-card" onSubmit={(e) => void submit(e)}>
        <h1>Quick connect</h1>
        <p className="muted">Connect once, or save the host to your vault.</p>
        {prefill && (
          <p className="notice-box link-notice">
            Filled in from a link{prefill.label ? ` for ${prefill.label}` : ""}. Check the address before you connect.
          </p>
        )}

        <div className="row">
          <label className="grow">
            <span>Host</span>
            <input autoFocus value={host} onChange={(e) => setHost(e.target.value)} placeholder="db1.example.com" spellCheck={false} autoCapitalize="off" />
          </label>
          <label className="port">
            <span>Port</span>
            <input value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" />
          </label>
        </div>

        <label>
          <span>User</span>
          <input value={user} onChange={(e) => setUser(e.target.value)} placeholder="root" spellCheck={false} autoCapitalize="off" />
        </label>

        <div className="segmented" role="radiogroup" aria-label="Authentication">
          {(Object.keys(AUTH_LABELS) as AuthKind[]).filter((k) => k !== "agent" || !mobileOs || authKind === "agent").map((k) => (
            <button type="button" key={k} role="radio" aria-checked={authKind === k} className={authKind === k ? "on" : ""} onClick={() => setAuthKind(k)}>
              {AUTH_LABELS[k]}
            </button>
          ))}
        </div>

        {authKind === "password" && (
          <label>
            <span>Password</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" />
          </label>
        )}
        {authKind === "key" && (
          <>
            <div className="segmented two small" role="radiogroup" aria-label="Key from">
              <button type="button" role="radio" aria-checked={keyFrom === "file"} className={keyFrom === "file" ? "on" : ""} onClick={() => setKeyFrom("file")}>
                From file
              </button>
              <button type="button" role="radio" aria-checked={keyFrom === "text"} className={keyFrom === "text" ? "on" : ""} onClick={() => setKeyFrom("text")}>
                Paste
              </button>
            </div>
            {keyFrom === "file" ? (
              <FilePick label="Private key file (id_ed25519, a .pem or PuTTY's .ppk)" picked={keyFile ? [keyFile] : []} onPick={(f) => setKeyFile(f[0] ?? null)} />
            ) : (
              <label>
                <span>Private key</span>
                <textarea className="mono" rows={5} value={keyText} onChange={(e) => setKeyText(e.target.value)} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" spellCheck={false} />
              </label>
            )}
            <label>
              <span>Passphrase (if encrypted)</span>
              <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoComplete="off" />
            </label>
            <p className="hint">The key is used for this connection only, unless you save the host: then it's imported into the vault too.</p>
          </>
        )}
        {authKind === "agent" && <p className="hint">Uses the identities loaded in $SSH_AUTH_SOCK.</p>}

        <label className="check">
          <input type="checkbox" checked={save} onChange={(e) => setSave(e.target.checked)} />
          <span>Save to vault{authKind === "password" ? " (including the password)" : authKind === "key" ? " (with the key)" : ""}</span>
        </label>

        {error && <p className="error">{error}</p>}

        <button className="primary" type="submit" disabled={!valid}>
          Connect
        </button>
      </form>
    </div>
  );
}
