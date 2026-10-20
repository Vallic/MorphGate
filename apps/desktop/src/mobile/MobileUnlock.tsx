import { useState } from "react";
import appIcon from "../assets/brand/app-icon.svg";

interface Props {
  /** "Face ID", "fingerprint", … when the system keychain unlocks the vault; null without it. */
  presence: string | null;
  busy: boolean;
  error: string;
  footnote: string;
  onPresence: () => void;
  onPassword: (password: string) => void;
  onRecover: () => void;
}

const FaceIcon = () => (
  <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2" />
    <path d="M9 9.5v1.5M15 9.5v1.5M12 9.5v3.5h-1M9.5 16a4 4 0 0 0 5 0" />
  </svg>
);

const FingerIcon = () => (
  <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
    <path d="M5 11a7 7 0 0 1 14 0v2" />
    <path d="M8.5 20c.9-1.8 1.5-4 1.5-7v-2a2 2 0 0 1 4 0v2c0 3-.6 5.6-1.8 8" />
    <path d="M5 15v-1M17.5 17c-.2 1.2-.5 2.3-1 3.3" />
  </svg>
);

/** Unlock on a phone: the app icon, a big presence target, and the master password one tap away. */
export function MobileUnlock({ presence, busy, error, footnote, onPresence, onPassword, onRecover }: Props) {
  // Until the user picks, the password field only shows without a presence check (which may only
  // be known after the device's status loads).
  const [picked, setTyping] = useState<boolean | null>(null);
  const typing = picked ?? presence === null;
  const [password, setPassword] = useState("");

  return (
    <main className="m-unlock">
      <div className="m-unlock-hero">
        <img src={appIcon} alt="MorphGate" width={88} height={88} />
        <div className="m-unlock-text">
          <h1>Unlock MorphGate</h1>
          <p>{presence ? `Use your ${presence}, or your master password.` : "Enter your master password."}</p>
        </div>
        {presence && !typing && (
          <button type="button" className="m-presence" aria-label={`Unlock with ${presence}`} disabled={busy} onClick={onPresence}>
            {/face/i.test(presence) && !/finger/i.test(presence) ? <FaceIcon /> : <FingerIcon />}
          </button>
        )}
      </div>

      <form
        className="m-unlock-actions"
        onSubmit={(e) => {
          e.preventDefault();
          if (password) onPassword(password);
        }}
      >
        {error && <p className="error">{error}</p>}
        {typing ? (
          <>
            <label>
              <span>Master password</span>
              <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
            </label>
            <button type="submit" className="m-button primary" disabled={!password || busy}>
              {busy ? "Unlocking…" : "Unlock"}
            </button>
            {presence && (
              <button type="button" className="m-button" disabled={busy} onClick={() => (setTyping(false), onPresence())}>
                Unlock with {presence}
              </button>
            )}
          </>
        ) : (
          <>
            <button type="button" className="m-button primary" disabled={busy} onClick={onPresence}>
              Unlock with {presence}
            </button>
            <button type="button" className="m-button" onClick={() => setTyping(true)}>
              Use master password
            </button>
          </>
        )}
        <button type="button" className="m-link" onClick={onRecover}>
          Forgot password? Use your recovery key
        </button>
        <p className="m-footnote">{footnote}</p>
      </form>
    </main>
  );
}
