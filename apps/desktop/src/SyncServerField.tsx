import { useState, type ReactNode } from "react";

/** MorphGate's hosted sync service, the default choice. */
export const HOSTED_SERVER = "https://morphgate.com";

const isPlainHttp = (url: string) => {
  try {
    const u = new URL(url);
    return u.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  } catch {
    return false;
  }
};

interface Props {
  /** The server's address: `HOSTED_SERVER`, or what was typed for your own. */
  value: string;
  onChange: (server: string) => void;
  /** Beside the choice (the Sync panel's Check button). */
  action?: ReactNode;
}

/** Where a vault syncs: morphgate.com (prefilled) or your own vault-sync server. */
export function SyncServerField({ value, onChange, action }: Props) {
  const [own, setOwn] = useState(value !== "" && value !== HOSTED_SERVER);
  const [address, setAddress] = useState(own ? value : "");
  const pick = (mine: boolean) => {
    setOwn(mine);
    onChange(mine ? address : HOSTED_SERVER);
  };
  return (
    <div className="stack sync-server">
      <span className="field-label">Sync server</span>
      <div className="row">
        <div className="segmented two grow" role="radiogroup" aria-label="Sync server">
          <button type="button" role="radio" aria-checked={!own} className={own ? "" : "on"} onClick={() => pick(false)}>
            morphgate.com
          </button>
          <button type="button" role="radio" aria-checked={own} className={own ? "on" : ""} onClick={() => pick(true)}>
            Your own server
          </button>
        </div>
        {action}
      </div>
      {own ? (
        <label>
          <span>Server address</span>
          <input
            value={address}
            onChange={(e) => (setAddress(e.target.value), onChange(e.target.value))}
            placeholder="https://sync.example.com"
            spellCheck={false}
            autoCapitalize="off"
            autoFocus
          />
        </label>
      ) : (
        <p className="hint">MorphGate's hosted sync. Like any vault-sync server, it only ever stores what this device encrypted.</p>
      )}
      {own && isPlainHttp(address) && <p className="warn">Plain http:// sends tokens unencrypted over the network. Use https://.</p>}
    </div>
  );
}
