import { useEffect, useRef, useState } from "react";
import { openLink, type VpnPrompt } from "./api";

interface Props {
  prompt: VpnPrompt;
  /** `null` = cancel; `[]` = trust the certificate. */
  onAnswer: (answers: string[] | null) => void;
}

/**
 * What a VPN needs while connecting: a password, a one-time code, trust in its certificate, or a
 * sign-in in the browser.
 */
export function VpnPromptDialog({ prompt, onAnswer }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const [values, setValues] = useState(prompt.kind === "fields" ? prompt.fields.map((f) => f.value) : []);

  useEffect(() => {
    ref.current?.showModal();
  }, []);

  if (prompt.kind === "browser") {
    // Closes by itself (vpn-prompt-closed) once the VPN server confirms the sign-in.
    return (
      <dialog ref={ref} className="modal" onCancel={(e) => (e.preventDefault(), onAnswer(null))}>
        <h2>{prompt.title}</h2>
        <p>
          Finish signing in in your browser. <strong>{prompt.vpn}</strong> connects as soon as the VPN server confirms it.
        </p>
        {prompt.error && <p className="error">The browser didn't open: {prompt.error}</p>}
        <dl>
          <dt>Sign-in page</dt>
          <dd className="mono">{prompt.url}</dd>
        </dl>
        <div className="actions">
          <button type="button" onClick={() => void openLink(prompt.url)}>
            Open again
          </button>
          <span className="spacer" />
          <button onClick={() => onAnswer(null)}>Cancel</button>
        </div>
      </dialog>
    );
  }

  if (prompt.kind === "certificate") {
    return (
      <dialog ref={ref} className="modal" onCancel={(e) => (e.preventDefault(), onAnswer(null))}>
        <h2>Untrusted VPN server</h2>
        <p>
          The certificate of <strong>{prompt.host}</strong> isn't trusted by this computer
          {prompt.reason ? ` (${prompt.reason})` : ""}. Compare the fingerprint with the one your VPN admin gave you
          before trusting it; MorphGate then remembers it for this VPN.
        </p>
        <dl>
          <dt>VPN</dt>
          <dd>{prompt.vpn}</dd>
          <dt>Fingerprint</dt>
          <dd className="mono">{prompt.fingerprint}</dd>
        </dl>
        <div className="actions">
          <button onClick={() => onAnswer(null)}>Cancel</button>
          <button className="primary" onClick={() => onAnswer([])}>
            Trust and connect
          </button>
        </div>
      </dialog>
    );
  }

  return (
    <dialog ref={ref} className="modal" onCancel={(e) => (e.preventDefault(), onAnswer(null))}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onAnswer(values);
        }}
      >
        <h2>{prompt.title}</h2>
        {prompt.message && <p className="pre-line">{prompt.message}</p>}
        {prompt.fields.map((f, i) => (
          <label key={i} className="modal-field">
            <span>{f.label}</span>
            <input
              type={f.secret ? "password" : "text"}
              autoFocus={i === (prompt.fields.findIndex((x) => !x.value) >= 0 ? prompt.fields.findIndex((x) => !x.value) : 0)}
              value={values[i] ?? ""}
              onChange={(e) => setValues((v) => v.map((x, j) => (j === i ? e.target.value : x)))}
              autoComplete={f.secret ? "one-time-code" : "off"}
              spellCheck={false}
            />
          </label>
        ))}
        <div className="actions">
          <span className="spacer" />
          <button type="button" onClick={() => onAnswer(null)}>
            Cancel
          </button>
          <button type="submit" className="primary">
            Continue
          </button>
        </div>
      </form>
    </dialog>
  );
}
