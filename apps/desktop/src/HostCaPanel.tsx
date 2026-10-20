import { useState, type FormEvent } from "react";
import { errorText, hostCas, keyType, type HostCaView, type VaultEntry } from "./api";
import { isReadOnly, personalVault, VaultField } from "./VaultField";

interface Props {
  ca?: HostCaView;
  vaults: VaultEntry[];
  onSaved: (ca: HostCaView) => void;
  onDeleted: () => void;
  onCancel: () => void;
}

/** A host CA: hosts whose keys it signed are trusted without pinning each one (OpenSSH's
 * `@cert-authority`). In a team's vault, for every member. */
export function HostCaPanel({ ca, vaults, onSaved, onDeleted, onCancel }: Props) {
  const [vaultId, setVaultId] = useState(ca?.vaultId ?? personalVault(vaults));
  const readOnly = isReadOnly(vaults, ca?.vaultId);
  const [label, setLabel] = useState(ca?.label ?? "");
  const [publicKey, setPublicKey] = useState(ca?.publicKey ?? "");
  const [hosts, setHosts] = useState(ca?.hosts.join(", ") ?? "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // A pasted `@cert-authority` line brings its hosts.
  const line = publicKey.trim().startsWith("@cert-authority");
  const valid = !readOnly && label.trim() !== "" && publicKey.trim() !== "" && (hosts.trim() !== "" || line);

  const save = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError("");
    try {
      onSaved(
        await hostCas.save({
          id: ca?.id,
          vaultId: ca ? undefined : vaultId || undefined,
          label,
          publicKey,
          hosts: hosts.split(",").map((h) => h.trim()).filter(Boolean),
        }),
      );
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  return (
    <div className="panel">
      <form className="panel-card wide" onSubmit={(e) => void save(e)}>
        <h1>{ca ? "Host CA" : "New host CA"}</h1>
        <p className="hint">
          Hosts whose keys this certificate authority signed are trusted without asking, instead of each key being pinned on first connect: what step-ca,
          HashiCorp Vault or Teleport issue, or <span className="mono">ssh-keygen -h -s</span>. In a team's vault it covers every member.
        </p>
        <VaultField vaults={vaults} itemVault={ca?.vaultId} item={ca && { id: ca.id, label: ca.label }} value={vaultId} onChange={setVaultId} />
        <label>
          <span>Name</span>
          <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Production host CA" autoFocus={!ca} disabled={readOnly} />
        </label>
        <label>
          <span>The CA's public key</span>
          <textarea
            className="mono"
            rows={3}
            value={publicKey}
            onChange={(e) => setPublicKey(e.target.value)}
            placeholder={"ssh-ed25519 AAAA… (or a whole @cert-authority line from a known_hosts file)"}
            spellCheck={false}
            disabled={readOnly}
          />
          {ca && (
            <small className="hint mono">
              {keyType(ca.algorithm)} {ca.fingerprint}
            </small>
          )}
        </label>
        <label>
          <span>For hosts</span>
          <input value={hosts} onChange={(e) => setHosts(e.target.value)} placeholder={line ? "the line's, or these" : "*.example.com, 10.0.*, !bastion.example.com"} spellCheck={false} disabled={readOnly} />
          <small className="hint">Patterns as in known_hosts: * and ? match, ! excludes. A host on any port; [host]:port for one port.</small>
        </label>

        {error && <p className="error">{error}</p>}
        <div className="actions">
          {ca &&
            !readOnly &&
            (confirmDelete ? (
              <button type="button" className="danger" onClick={() => void hostCas.remove(ca.id).then(onDeleted, (e) => setError(errorText(e)))}>
                Really delete?
              </button>
            ) : (
              <button type="button" className="ghost-danger" onClick={() => setConfirmDelete(true)}>
                Delete
              </button>
            ))}
          <span className="spacer" />
          <button type="button" onClick={onCancel}>
            Close
          </button>
          <button type="submit" className="primary" disabled={!valid || busy}>
            {busy ? "Saving…" : ca ? "Save changes" : "Save host CA"}
          </button>
        </div>
      </form>
    </div>
  );
}
