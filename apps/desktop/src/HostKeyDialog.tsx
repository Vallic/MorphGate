import { useEffect, useRef, useState } from "react";
import { keyType, type ChangedHostKey, type HostKeyPrompt } from "./api";

const where = (host: string, port: number) => (port === 22 ? host : `[${host}]:${port}`);

/** A host seen for the first time: trust its key (pinned from then on) or not. */
export function HostKeyDialog({ prompt, onAnswer }: { prompt: HostKeyPrompt; onAnswer: (accept: boolean) => void }) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    ref.current?.showModal();
  }, []);

  return (
    <dialog ref={ref} className="modal hostkey" aria-labelledby="hk-title" onCancel={(e) => (e.preventDefault(), onAnswer(false))}>
      <div className="hostkey-head">
        <span className="hostkey-icon">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
            <circle cx="8" cy="15" r="4" />
            <path d="M11 12l8-8M16 7l2 2" />
          </svg>
        </span>
        <div>
          <h2 id="hk-title">Unknown host key</h2>
          <p>
            <strong className="mono">{where(prompt.host, prompt.port)}</strong> has not been seen before. Compare the fingerprint with the
            one your server admin gave you before trusting it.
          </p>
        </div>
      </div>
      <dl className="key-compare">
        <div>
          <dt>Presented</dt>
          <dd className="mono">
            <span className="muted">{keyType(prompt.algorithm)}</span> {prompt.fingerprint}
          </dd>
        </div>
      </dl>
      <p className="hint">Once trusted, the key is pinned: if the host ever answers with a different one, MorphGate won't connect.</p>
      <div className="actions">
        <button onClick={() => onAnswer(false)}>Cancel</button>
        <button className="primary" onClick={() => onAnswer(true)}>
          Trust and connect
        </button>
      </div>
    </dialog>
  );
}

/** A host answered with a different key than the one pinned: MorphGate didn't connect. */
export function HostKeyChangedDialog({ changed, label, onClose }: { changed: ChangedHostKey; label?: string; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    ref.current?.showModal();
  }, []);

  const address = `${changed.host}:${changed.port}`;
  const lineNote = changed.line ? `known_hosts line ${changed.line}` : "known_hosts";
  const details = [
    `Host key changed for ${label ? `${label} (${address})` : address}`,
    changed.pinnedFingerprint && `Pinned (${lineNote}${changed.file ? ` in ${changed.file}` : ""}): ${changed.pinnedAlgorithm} ${changed.pinnedFingerprint}`,
    `Presented now: ${changed.algorithm} ${changed.fingerprint}`,
  ]
    .filter(Boolean)
    .join("\n");

  const copy = () =>
    void navigator.clipboard.writeText(details).then(
      () => setCopied(true),
      () => {},
    );

  return (
    <dialog
      ref={ref}
      className="modal hostkey changed"
      role="alertdialog"
      aria-labelledby="hk-changed-title"
      aria-describedby="hk-changed-lead"
      onCancel={(e) => (e.preventDefault(), onClose())}
    >
      <div className="hostkey-head">
        <span className="hostkey-icon danger">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M12 4l9 16H3z" />
            <path d="M12 10v4M12 17h.01" />
          </svg>
        </span>
        <div>
          <h2 id="hk-changed-title">Host key changed</h2>
          <p id="hk-changed-lead">
            {label ? (
              <>
                {label} <span className="mono muted">{address}</span>
              </>
            ) : (
              <span className="mono">{address}</span>
            )}{" "}
            answered with a different key than the one pinned on first connect. Someone may be intercepting the connection, so MorphGate
            did not connect.
          </p>
        </div>
      </div>
      <dl className="key-compare">
        {changed.pinnedFingerprint && (
          <div>
            <dt>
              <span>Pinned</span>
              <span className="where mono">{lineNote}</span>
            </dt>
            <dd className="mono">
              <span className="muted">{keyType(changed.pinnedAlgorithm ?? "")}</span> {changed.pinnedFingerprint}
            </dd>
          </div>
        )}
        <div className="presented">
          <dt>Presented now</dt>
          <dd className="mono">
            <span className="alg">{keyType(changed.algorithm)}</span> {changed.fingerprint}
          </dd>
        </div>
      </dl>
      <div className="todo">
        <h3>What to do</h3>
        <ol>
          <li>Ask the server's admin whether the host key was rotated, and compare the new fingerprint with theirs.</li>
          <li>
            Only if it matches, remove {changed.line ? `line ${changed.line}` : "its line"} from{" "}
            <span className="mono muted">{changed.file ?? "known_hosts"}</span> and connect again.
          </li>
        </ol>
      </div>
      <div className="actions">
        <button onClick={copy}>{copied ? "Copied" : "Copy details"}</button>
        <button className="primary" autoFocus onClick={onClose}>
          Close
        </button>
      </div>
    </dialog>
  );
}
