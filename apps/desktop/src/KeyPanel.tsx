import { useState, type FormEvent } from "react";
import { errorText, keys as keysApi, type CertInfo, type KeySource, type KeyView, type VaultEntry } from "./api";
import { FilePick, type PickedFile } from "./FilePick";
import { isReadOnly, personalVault, VaultField } from "./VaultField";
import { copyText } from "./clipboard";

/** A certificate's validity now, as a line and a tone. */
export function certificateValidity(c: CertInfo, now = Date.now() / 1000): { text: string; tone: "ok" | "warn" | "error" } {
  const when = (t: number) => new Date(t * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  const hours = (s: number) => Math.max(1, Math.round(s / 3600));
  if (c.validAfter > now) return { text: `Valid from ${when(c.validAfter)}`, tone: "warn" };
  if (c.validBefore >= 2 ** 63) return { text: "Never expires", tone: "ok" };
  if (c.validBefore <= now) return { text: `Expired ${when(c.validBefore)}: get a new one from its CA`, tone: "error" };
  const left = c.validBefore - now;
  if (left < 24 * 3600) {
    const h = hours(left);
    return { text: `Expires in ${h} hour${h === 1 ? "" : "s"} (${when(c.validBefore)})`, tone: "warn" };
  }
  return { text: `Valid until ${when(c.validBefore)}`, tone: "ok" };
}

/** Renewing the certificate with a command: what it runs, allowing it here, renewing now. */
function Renewal({ k, readOnly, onChanged }: { k: KeyView; readOnly: boolean; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [command, setCommand] = useState(k.renew?.command ?? "");
  const [file, setFile] = useState(k.renew?.file ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const act = (p: Promise<unknown>, done?: string) => {
    setBusy(true);
    setError("");
    setNote("");
    p.then(
      () => (setBusy(false), setEditing(false), done && setNote(done), onChanged()),
      (e) => (setBusy(false), setError(errorText(e))),
    );
  };
  return (
    <div className="stack key-renewal">
      <h3 className="section-title">Renewal</h3>
      {editing ? (
        <form
          className="stack"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            act(keysApi.renewal(k.id, command.trim() ? { command, file: file.trim() || null } : null));
          }}
        >
          <label>
            <span>Renew with a command</span>
            <input
              className="mono"
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              placeholder="vault write -field=signed_key ssh/sign/deploy public_key=-"
              spellCheck={false}
            />
            <small className="hint">
              Runs on this computer before connecting when the certificate is missing or runs out within 5 minutes. It gets the public key on its input
              (and as a file: %k), and prints the new certificate, or leaves it in the file below.
            </small>
          </label>
          <label>
            <span>Certificate file (optional)</span>
            <input className="mono" value={file} onChange={(e) => setFile(e.target.value)} placeholder="~/.ssh/id_ed25519-cert.pub" spellCheck={false} />
          </label>
          <div className="row">
            <button type="button" onClick={() => setEditing(false)}>
              Cancel
            </button>
            <button type="submit" className="primary" disabled={busy}>
              {busy ? "Saving…" : command.trim() ? "Save renewal" : "Don't renew"}
            </button>
          </div>
        </form>
      ) : k.renew ? (
        <>
          <p className="mono">{k.renew.command}</p>
          {k.renew.file && <p className="hint mono">Leaves it in {k.renew.file}</p>}
          {!k.renewAllowed && (
            <div className="notice-box stack">
              <p>This command came with the vault. It runs on this computer only once you allow it here, after reading it.</p>
              {!readOnly && (
                <div className="row">
                  <button type="button" className="secondary small-button" disabled={busy} onClick={() => act(keysApi.allowRenewal(k.id))}>
                    Allow on this device
                  </button>
                </div>
              )}
            </div>
          )}
        </>
      ) : (
        <p className="hint">Short-lived certificates can be renewed by a command (HashiCorp Vault, step-ca, ssh-keygen -s) before they run out.</p>
      )}
      {error && <p className="error">{error}</p>}
      {note && <p className="ok">{note}</p>}
      {!readOnly && !editing && (
        <div className="row">
          {k.renew && k.renewAllowed && (
            <button type="button" className="secondary small-button" disabled={busy} onClick={() => act(keysApi.renew(k.id), "Renewed.")}>
              {busy ? "Renewing…" : "Renew now"}
            </button>
          )}
          <button type="button" className="link" onClick={() => setEditing(true)}>
            {k.renew ? "Change renewal" : "Renew with a command…"}
          </button>
        </div>
      )}
    </div>
  );
}

/** The key's OpenSSH certificate: what it says, and adding, replacing or removing it. */
function Certificate({ k, readOnly, onChanged }: { k: KeyView; readOnly: boolean; onChanged: () => void }) {
  const [adding, setAdding] = useState(false);
  const [from, setFrom] = useState<"file" | "text">("file");
  const [file, setFile] = useState<PickedFile | null>(null);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const c = k.certificate;
  const save = (source: KeySource | null) => {
    setBusy(true);
    setError("");
    keysApi.certificate(k.id, source).then(
      () => (setBusy(false), setAdding(false), setText(""), setFile(null), onChanged()),
      (e) => (setError(errorText(e)), setBusy(false)),
    );
  };
  const valid = c && certificateValidity(c);
  return (
    <div className="stack key-certificate">
      <h2 className="section-title">Certificate</h2>
      {c && valid ? (
        <dl className="facts">
          <dt>Validity</dt>
          <dd className={valid.tone === "ok" ? undefined : valid.tone}>{valid.text}</dd>
          <dt>Signs in as</dt>
          <dd>{c.principals.length > 0 ? c.principals.join(", ") : "Any user the server allows"}</dd>
          <dt>Issued by</dt>
          <dd className="mono">{c.ca}</dd>
          {c.keyId && (
            <>
              <dt>Key ID</dt>
              <dd className="mono">{c.keyId}</dd>
            </>
          )}
        </dl>
      ) : k.certificateError ? (
        <p className="error">The certificate stored with this key can't be used: {k.certificateError}.</p>
      ) : (
        <p className="hint">
          None. Servers that trust a certificate authority (step-ca, HashiCorp Vault, Teleport) take this key with a certificate the CA issued for
          it: add it here, and signing in presents it.
        </p>
      )}
      {error && <p className="error">{error}</p>}
      {!readOnly && adding && (
        <form
          className="stack"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            save({ kind: "text", text: from === "file" ? (file?.text ?? "") : text });
          }}
        >
          <div className="segmented two small" role="radiogroup">
            <button type="button" role="radio" aria-checked={from === "file"} className={from === "file" ? "on" : ""} onClick={() => setFrom("file")}>
              From file
            </button>
            <button type="button" role="radio" aria-checked={from === "text"} className={from === "text" ? "on" : ""} onClick={() => setFrom("text")}>
              Paste
            </button>
          </div>
          {from === "file" ? (
            <FilePick label="Certificate file (id_ed25519-cert.pub, say)" picked={file ? [file] : []} onPick={(f) => setFile(f[0] ?? null)} />
          ) : (
            <label>
              <span>Certificate</span>
              <textarea className="mono" rows={4} value={text} onChange={(e) => setText(e.target.value)} placeholder="ssh-ed25519-cert-v01@openssh.com AAAA…" spellCheck={false} />
            </label>
          )}
          <div className="row">
            <button type="button" onClick={() => setAdding(false)}>
              Cancel
            </button>
            <button type="submit" className="primary" disabled={busy || (from === "file" ? !file : !text.trim())}>
              {busy ? "Saving…" : "Save certificate"}
            </button>
          </div>
        </form>
      )}
      {!readOnly && !adding && (
        <div className="row">
          <button type="button" className="secondary small-button" onClick={() => setAdding(true)}>
            {c || k.certificateError ? "Replace certificate" : "Add certificate"}
          </button>
          {(c || k.certificateError) && (
            <button type="button" className="ghost-danger small-button" disabled={busy} onClick={() => save(null)}>
              Remove certificate
            </button>
          )}
        </div>
      )}
      <Renewal k={k} readOnly={readOnly} onChanged={onChanged} />
    </div>
  );
}

export function KeyDetail({
  k,
  vaults,
  onChanged,
  onDeleted,
  onClose,
}: {
  k: KeyView;
  vaults: VaultEntry[];
  onChanged: () => void;
  onDeleted: () => void;
  onClose: () => void;
}) {
  const readOnly = isReadOnly(vaults, k.vaultId);
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const [error, setError] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);

  return (
    <div className="panel">
      <div className="panel-card">
        <h1>{k.label}</h1>
        <VaultField vaults={vaults} itemVault={k.vaultId} item={{ id: k.id, label: k.label }} value={k.vaultId} onChange={() => {}} />
        <dl className="facts">
          <dt>Type</dt>
          <dd>{k.algorithm}</dd>
          <dt>Fingerprint</dt>
          <dd className="mono">{k.fingerprint}</dd>
          {k.encrypted && (
            <>
              <dt>Passphrase</dt>
              <dd>Saved in the vault</dd>
            </>
          )}
        </dl>
        <label>
          <span>Public key — add it to ~/.ssh/authorized_keys on your servers</span>
          <textarea className="mono" rows={4} readOnly value={k.publicKey} onFocus={(e) => e.currentTarget.select()} />
        </label>
        <Certificate k={k} readOnly={readOnly} onChanged={onChanged} />
        {error && <p className="error">{error}</p>}
        <div className="actions">
          {readOnly ? null : confirmDelete ? (
            <button
              type="button"
              className="danger"
              onClick={() =>
                void keysApi
                  .remove(k.id)
                  .then(onDeleted)
                  .catch((e) => (setError(errorText(e)), setConfirmDelete(false)))
              }
            >
              Really delete?
            </button>
          ) : (
            <button type="button" className="ghost-danger" onClick={() => setConfirmDelete(true)}>
              Delete
            </button>
          )}
          <span className="spacer" />
          <button type="button" onClick={onClose}>
            Close
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => void copyText(k.publicKey).then((ok) => (ok ? setCopied(true) : setCopyFailed(true)))}
          >
            {copied ? "Copied" : copyFailed ? "Couldn't copy" : "Copy public key"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function NewKey({ vaults, onCreated, onCancel }: { vaults: VaultEntry[]; onCreated: (k: KeyView) => void; onCancel: () => void }) {
  const [vaultId, setVaultId] = useState(personalVault(vaults));
  const [mode, setMode] = useState<"generate" | "import">("generate");
  const [label, setLabel] = useState("");
  const [from, setFrom] = useState<"file" | "text">("file");
  const [file, setFile] = useState<PickedFile | null>(null);
  const [text, setText] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const valid = mode === "generate" || (from === "file" ? file !== null : text.trim() !== "");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError("");
    try {
      const k =
        mode === "generate"
          ? await keysApi.generate(label, vaultId || undefined)
          : await keysApi.import(
              // Named after its file unless given a label.
              label.trim() || (from === "file" && file ? file.name : ""),
              { kind: "text", text: from === "file" ? (file?.text ?? "") : text },
              passphrase || undefined,
              vaultId || undefined,
            );
      onCreated(k);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  return (
    <div className="panel">
      <form className="panel-card" onSubmit={submit}>
        <h1>New SSH key</h1>
        <VaultField vaults={vaults} value={vaultId} onChange={setVaultId} />
        <div className="segmented two" role="radiogroup">
          <button type="button" role="radio" aria-checked={mode === "generate"} className={mode === "generate" ? "on" : ""} onClick={() => setMode("generate")}>
            Generate
          </button>
          <button type="button" role="radio" aria-checked={mode === "import"} className={mode === "import" ? "on" : ""} onClick={() => setMode("import")}>
            Import
          </button>
        </div>

        <label>
          <span>Label</span>
          <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder={mode === "generate" ? "MorphGate key" : "Defaults to the file name"} autoFocus />
        </label>

        {mode === "generate" && <p className="hint">Creates a new Ed25519 key. The private key is stored only in your encrypted vault.</p>}

        {mode === "import" && (
          <>
            <div className="segmented two small" role="radiogroup">
              <button type="button" role="radio" aria-checked={from === "file"} className={from === "file" ? "on" : ""} onClick={() => setFrom("file")}>
                From file
              </button>
              <button type="button" role="radio" aria-checked={from === "text"} className={from === "text" ? "on" : ""} onClick={() => setFrom("text")}>
                Paste
              </button>
            </div>
            {from === "file" ? (
              <FilePick label="Private key file (id_ed25519, a .pem or PuTTY's .ppk)" picked={file ? [file] : []} onPick={(f) => setFile(f[0] ?? null)} />
            ) : (
              <label>
                <span>Private key</span>
                <textarea className="mono" rows={6} value={text} onChange={(e) => setText(e.target.value)} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" spellCheck={false} />
              </label>
            )}
            <label>
              <span>Passphrase (only if the key is encrypted)</span>
              <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoComplete="off" />
            </label>
            <p className="hint">
              The key is copied into the vault; the original file is not changed. OpenSSH and PEM keys, and PuTTY's .ppk (kept as an OpenSSH
              key).
            </p>
          </>
        )}

        {error && <p className="error">{error}</p>}
        <div className="actions">
          <span className="spacer" />
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
          <button className="primary" type="submit" disabled={!valid || busy}>
            {mode === "generate" ? "Generate key" : "Import key"}
          </button>
        </div>
      </form>
    </div>
  );
}
