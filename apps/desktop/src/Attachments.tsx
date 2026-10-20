import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { MAX_ATTACHMENT_BYTES, attachments, errorText, openLink, type AttachmentView } from "./api";
import { mobileOs } from "./mobile/useMobile";

const STATE: Record<AttachmentView["state"], string | null> = {
  local: null,
  uploading: "Uploading",
  remote: "On the server",
  failed: "Not uploaded",
};

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/** Files kept with a host, encrypted in its vault: add, save to Downloads, delete. */
export function HostAttachments({ hostId, readOnly }: { hostId: string | null; readOnly: boolean }) {
  const [list, setList] = useState<AttachmentView[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [deleting, setDeleting] = useState<string | null>(null);
  const picker = useRef<HTMLInputElement>(null);

  const load = useCallback(() => {
    if (hostId) attachments.list(hostId).then(setList, (e) => setError(errorText(e)));
  }, [hostId]);
  useEffect(() => {
    load();
    const off = [listen("session-logs-changed", load), listen("vault-changed", load)];
    return () => off.forEach((u) => void u.then((f) => f()));
  }, [load]);

  if (!hostId) {
    return <p className="hint">Save the host first, then attach files to it.</p>;
  }

  const add = async (files: FileList | null) => {
    if (!files?.length) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      for (const file of [...files]) {
        if (file.size > MAX_ATTACHMENT_BYTES) throw new Error(`${file.name} is larger than ${MAX_ATTACHMENT_BYTES / 1024 / 1024} MB`);
        await attachments.add(hostId, file);
      }
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
      if (picker.current) picker.current.value = "";
      load();
    }
  };
  const save = (a: AttachmentView) =>
    attachments.save(a.id).then(
      (path) => (setNotice(`Saved ${path}`), load()),
      (e) => setError(errorText(e)),
    );
  const remove = (a: AttachmentView) =>
    attachments.remove(a.id).then(
      () => (setDeleting(null), load()),
      (e) => setError(errorText(e)),
    );

  const refused = list?.find((a) => a.state === "failed");
  return (
    <div className="stack attachments">
      {list && list.length > 0 && (
        <ul className="device-list">
          {list.map((a) => (
            <li key={a.id} className="attachment-row">
              <div className="grow">
                <strong>{a.name}</strong>
                <div className="muted">
                  {size(a.size)}
                  {STATE[a.state] && ` · ${STATE[a.state]}`}
                </div>
              </div>
              <button type="button" className="secondary small-button" onClick={() => void save(a)}>
                Save
              </button>
              {!readOnly &&
                (deleting === a.id ? (
                  <button type="button" className="danger small-button" onClick={() => void remove(a)}>
                    Delete {a.name}?
                  </button>
                ) : (
                  <button type="button" className="ghost-danger small-button" onClick={() => setDeleting(a.id)}>
                    Delete
                  </button>
                ))}
            </li>
          ))}
        </ul>
      )}
      {refused && (
        <div className="row align-center">
          <p className="warn grow">
            {refused.name} wasn't uploaded: {refused.problem}
          </p>
          {refused.upgradeUrl && !mobileOs && (
            <button type="button" className="secondary small-button" onClick={() => void openLink(refused.upgradeUrl!).catch((e) => setError(errorText(e)))}>
              Upgrade
            </button>
          )}
        </div>
      )}
      {!readOnly && (
        <>
          <input ref={picker} type="file" multiple hidden aria-label="Files to attach" onChange={(e) => void add(e.target.files)} />
          <button type="button" className="secondary small-button align-start" disabled={busy} onClick={() => picker.current?.click()}>
            {busy ? "Attaching…" : "Attach files"}
          </button>
        </>
      )}
      <p className="hint">Encrypted with the vault's key and synced with it, up to {MAX_ATTACHMENT_BYTES / 1024 / 1024} MB each.</p>
      {notice && <p className="ok">{notice}</p>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
