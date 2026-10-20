import { useEffect, useRef, useState } from "react";
import { errorText, openLink, sync, teams, type SsoView } from "./api";

interface Props {
  orgId: string;
  orgName: string;
  onDone: () => void;
  onClose: () => void;
}

const POLL_MS = 2000;

/**
 * Signs this device in at an organization's identity provider: the page opens in the browser,
 * and the dialog notices on its own when the provider sent the user back, then syncs.
 */
export function SsoSignIn({ orgId, orgName, onDone, onClose }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const [sso, setSso] = useState<SsoView | null>(null);
  const [waiting, setWaiting] = useState<{ until: number; url: string } | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    ref.current?.showModal();
    teams.ssoStatus(orgId).then(setSso, (e) => setError(errorText(e)));
  }, [orgId]);

  // While the browser is out: has the provider sent the user back yet?
  useEffect(() => {
    if (!waiting) return;
    let stopped = false;
    const timer = setInterval(() => {
      if (Date.now() > waiting.until) {
        setWaiting(null);
        setError("The sign-in expired. Start it again.");
        return;
      }
      teams.ssoStatus(orgId).then(
        (s) => {
          if (stopped || !s.sessionExpiresAt) return;
          setWaiting(null);
          void sync.now().catch(() => {});
          onDone();
        },
        () => {},
      );
    }, POLL_MS);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [waiting, orgId, onDone]);

  const start = () => {
    setError("");
    teams.ssoStart(orgId).then(
      (s) => setWaiting({ until: Date.now() + s.expiresIn * 1000, url: s.url }),
      (e) => setError(errorText(e)),
    );
  };

  const provider = sso?.issuer ? new URL(sso.issuer).host : "its identity provider";
  return (
    <dialog ref={ref} className="modal sso" aria-labelledby="sso-title" onCancel={(e) => (e.preventDefault(), onClose())}>
      <h2 id="sso-title">Sign in to {orgName}</h2>
      <p>
        {orgName} keeps its vaults behind single sign-on. Sign in at <strong>{provider}</strong> in your browser; its vaults sync on this
        device once you're back. Your master password still protects everything: single sign-on only adds to it.
      </p>
      {waiting ? (
        <div className="notice-box stack">
          <p className="hint">
            <span className="spinner" aria-hidden="true" /> Finish signing in in your browser. This updates by itself.
          </p>
          <p className="hint">
            The page didn't open?{" "}
            <button type="button" className="link" onClick={() => void openLink(waiting.url).catch((e) => setError(errorText(e)))}>
              Open it
            </button>
            .
          </p>
        </div>
      ) : null}
      {error && <p className="error">{error}</p>}
      <div className="actions">
        <span className="spacer" />
        <button type="button" onClick={onClose}>
          {waiting ? "Cancel" : "Not now"}
        </button>
        {!waiting && (
          <button type="button" className="primary" onClick={start} disabled={sso !== null && !sso.configured}>
            Sign in
          </button>
        )}
      </div>
    </dialog>
  );
}
