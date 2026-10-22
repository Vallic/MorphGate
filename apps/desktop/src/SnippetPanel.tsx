import { useState, type FormEvent } from "react";
import { errorText, snippets, type SnippetView, type VaultEntry } from "./api";
import { isReadOnly, personalVault, VaultField } from "./VaultField";

interface Props {
  snippet?: SnippetView;
  vaults: VaultEntry[];
  /** Title of the terminal the snippet would be sent to, if one is connected. */
  targetTitle: string | null;
  onSaved: (s: SnippetView) => void;
  onDeleted: () => void;
  onCancel: () => void;
  /** `snippet`: the saved one being sent (a feed's may ask first). */
  onSend: (body: string, run: boolean, snippet?: SnippetView) => void;
}

export function SnippetPanel({ snippet, vaults, targetTitle, onSaved, onDeleted, onCancel, onSend }: Props) {
  const [vaultId, setVaultId] = useState(snippet?.vaultId ?? personalVault(vaults));
  // A feed's snippet changes in the feed: here it's read, run or copied.
  const feed = snippet?.source ?? null;
  const readOnly = isReadOnly(vaults, snippet?.vaultId) || !!feed;
  const [name, setName] = useState(snippet?.name ?? "");
  const [body, setBody] = useState(snippet?.body ?? "");
  const [tags, setTags] = useState(snippet?.tags.join(", ") ?? "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const dirty = !snippet || name !== snippet.name || body !== snippet.body || tags !== snippet.tags.join(", ");
  const valid = !readOnly && name.trim() !== "" && body.trim() !== "";

  const save = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError("");
    try {
      onSaved(await snippets.save({ id: snippet?.id, vaultId: snippet ? undefined : vaultId || undefined, name, body, tags: tags.split(",").map((t) => t.trim()).filter(Boolean) }));
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  /** A snippet of one's own with the feed's commands, in the same vault where it can be written. */
  const copy = async () => {
    if (!snippet) return;
    setBusy(true);
    setError("");
    try {
      const into = isReadOnly(vaults, snippet.vaultId) ? personalVault(vaults) : snippet.vaultId;
      onSaved(await snippets.save({ vaultId: into || undefined, name: `${snippet.name} (copy)`, body: snippet.body, tags: snippet.tags }));
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel">
      <form className="panel-card wide" onSubmit={(e) => void save(e)}>
        <h1>{snippet ? "Snippet" : "New snippet"}</h1>
        {feed && (
          <div className="notice-box row">
            <span className="grow">
              From the feed <strong>{feed.label}</strong>: it changes there, and is read-only here.
            </span>
            <button type="button" className="secondary small-button" disabled={busy} onClick={() => void copy()}>
              Make a copy
            </button>
          </div>
        )}
        <VaultField vaults={vaults} itemVault={snippet?.vaultId} item={snippet && { id: snippet.id, label: snippet.name }} value={vaultId} onChange={setVaultId} />
        <label>
          <span>Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Disk usage" autoFocus={!snippet} readOnly={!!feed} />
        </label>
        <label>
          <span>Commands</span>
          <textarea
            className="mono"
            rows={7}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder={"df -h\ndu -sh /var/log/* | sort -h | tail"}
            spellCheck={false}
            readOnly={!!feed}
          />
        </label>
        <label>
          <span>Tags</span>
          <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="ops" spellCheck={false} readOnly={!!feed} />
        </label>

        <div className="send-row">
          {targetTitle ? (
            <>
              <span className="hint">
                Send to <strong>{targetTitle}</strong>
              </span>
              <span className="spacer" />
              <button type="button" disabled={!body} onClick={() => onSend(body, false, snippet)} title="Insert without pressing Enter">
                Paste
              </button>
              <button type="button" className="primary" disabled={!body} onClick={() => onSend(body, true, snippet)}>
                Run
              </button>
            </>
          ) : (
            <span className="hint">Open a connected terminal tab to paste or run this snippet.</span>
          )}
        </div>

        {error && <p className="error">{error}</p>}
        <div className="actions">
          {snippet &&
            !readOnly &&
            (confirmDelete ? (
              <button type="button" className="danger" onClick={() => void snippets.remove(snippet.id).then(onDeleted, (e) => setError(errorText(e)))}>
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
          {!feed && (
            <button type="submit" disabled={!valid || !dirty || busy}>
              {snippet ? "Save changes" : "Save snippet"}
            </button>
          )}
        </div>
      </form>
    </div>
  );
}
