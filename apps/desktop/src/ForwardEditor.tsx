import { useState, type FormEvent } from "react";
import { errorText, forwards, isLoopback, type ForwardRule, type ForwardView, type HostView, type VaultEntry } from "./api";
import { isReadOnly, personalVault, sameVault, VaultField } from "./VaultField";

type Kind = ForwardRule["kind"];

const KINDS: Record<Kind, { label: string; help: string }> = {
  local: {
    label: "Local",
    help: "A port on this computer reaches a destination the server can see (ssh -L). Typical: a database behind the server.",
  },
  remote: {
    label: "Remote",
    help: "A port on the server reaches a destination this computer can see (ssh -R). Typical: show a local dev server to the server.",
  },
  dynamic: {
    label: "SOCKS proxy",
    help: "A SOCKS5 proxy on this computer; every connection leaves from the server (ssh -D). Point a browser at it.",
  },
};

interface Props {
  forward?: ForwardView;
  hosts: HostView[];
  vaults: VaultEntry[];
  onSaved: (f: ForwardView, start: boolean) => void;
  onDeleted: () => void;
  onCancel: () => void;
}

const portOk = (p: string, allowZero: boolean) => {
  const n = Number(p);
  return Number.isInteger(n) && n >= (allowZero ? 0 : 1) && n < 65536;
};

export function ForwardEditor({ forward, hosts: everyHost, vaults, onSaved, onDeleted, onCancel }: Props) {
  const r = forward?.rule;
  const [vaultId, setVaultId] = useState(forward?.vaultId ?? personalVault(vaults));
  // A tunnel runs through a host of its own vault, and not one whose cloud forwards no ports
  // (Vallic Cloud's): those stay listed only for a tunnel saved through one before.
  const carries = (h: HostView) => !h.source?.noForwarding || h.id === forward?.hostId;
  const hosts = everyHost.filter(sameVault(vaultId)).filter(carries);
  const readOnly = isReadOnly(vaults, forward?.vaultId);
  const [label, setLabel] = useState(forward?.label ?? "");
  const [hostId, setHostId] = useState(forward?.hostId ?? hosts[0]?.id ?? "");
  const pickVault = (id: string) => {
    setVaultId(id);
    setHostId(everyHost.find((h) => h.vaultId === id && carries(h))?.id ?? "");
  };
  const [kind, setKind] = useState<Kind>(r?.kind ?? "local");
  const [bindHost, setBindHost] = useState(r?.bindHost ?? "127.0.0.1");
  const [bindPort, setBindPort] = useState(String(r?.bindPort ?? ""));
  const [targetHost, setTargetHost] = useState(r && r.kind !== "dynamic" ? r.targetHost : "127.0.0.1");
  const [targetPort, setTargetPort] = useState(r && r.kind !== "dynamic" ? String(r.targetPort) : "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const needsTarget = kind !== "dynamic";
  const valid =
    !readOnly &&
    hostId !== "" &&
    bindHost.trim() !== "" &&
    portOk(bindPort, kind === "remote") &&
    (!needsTarget || (targetHost.trim() !== "" && portOk(targetPort, false)));
  const exposed = kind !== "remote" && bindHost.trim() !== "" && !isLoopback(bindHost);

  const save = async (start: boolean, e?: FormEvent) => {
    e?.preventDefault();
    if (!valid) return;
    const rule: ForwardRule = needsTarget
      ? { kind: kind as "local" | "remote", bindHost, bindPort: Number(bindPort), targetHost, targetPort: Number(targetPort) }
      : { kind: "dynamic", bindHost, bindPort: Number(bindPort) };
    const host = hosts.find((h) => h.id === hostId);
    const fallback = needsTarget ? `${host?.label ?? "host"} → ${targetHost}:${targetPort}` : `SOCKS via ${host?.label ?? "host"}`;
    setBusy(true);
    setError("");
    try {
      onSaved(
        await forwards.save({ id: forward?.id, vaultId: forward ? undefined : vaultId || undefined, label: label.trim() || fallback, hostId, rule }),
        start,
      );
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  if (!everyHost.some(carries)) {
    return (
      <div className="panel">
        <div className="panel-card">
          <h1>New tunnel</h1>
          <p className="hint">
            A tunnel runs through one of your saved hosts. Add a host first{everyHost.length > 0 ? " (hosts from Vallic Cloud don't forward ports)" : ""}.
          </p>
          <div className="actions">
            <span className="spacer" />
            <button type="button" onClick={onCancel}>
              Close
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="panel">
      <form className="panel-card" onSubmit={(e) => void save(false, e)}>
        <h1>{forward ? "Edit tunnel" : "New tunnel"}</h1>
        <VaultField vaults={vaults} itemVault={forward?.vaultId} item={forward && { id: forward.id, label: forward.label }} value={vaultId} onChange={pickVault} />
        {forward?.running && <p className="hint">This tunnel is running; saving changes stops it.</p>}

        <label>
          <span>Name</span>
          <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Postgres on prod" autoFocus={!forward} />
        </label>
        <label>
          <span>Through host</span>
          <select value={hostId} onChange={(e) => setHostId(e.target.value)}>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.label} ({h.user}@{h.hostname})
              </option>
            ))}
          </select>
        </label>
        {hosts.find((h) => h.id === hostId)?.source?.noForwarding && (
          <p className="warn">This host's cloud doesn't forward ports, so this tunnel can't start. Choose another host.</p>
        )}

        <div className="segmented" role="radiogroup" aria-label="Tunnel type">
          {(Object.keys(KINDS) as Kind[]).map((k) => (
            <button type="button" key={k} role="radio" aria-checked={kind === k} className={kind === k ? "on" : ""} onClick={() => setKind(k)}>
              {KINDS[k].label}
            </button>
          ))}
        </div>
        <p className="hint">{KINDS[kind].help}</p>

        <div className="row">
          <label className="grow">
            <span>{kind === "remote" ? "Listen on (server)" : "Listen on (this computer)"}</span>
            <input value={bindHost} onChange={(e) => setBindHost(e.target.value)} spellCheck={false} />
          </label>
          <label className="port">
            <span>Port</span>
            <input value={bindPort} onChange={(e) => setBindPort(e.target.value)} inputMode="numeric" placeholder={kind === "dynamic" ? "1080" : kind === "remote" ? "0 = any" : "15432"} />
          </label>
        </div>
        {exposed && <p className="warn">Listening on {bindHost} lets other machines on your network use this tunnel.</p>}

        {needsTarget && (
          <div className="row">
            <label className="grow">
              <span>{kind === "local" ? "Destination (as seen from the server)" : "Destination (as seen from this computer)"}</span>
              <input value={targetHost} onChange={(e) => setTargetHost(e.target.value)} spellCheck={false} placeholder="127.0.0.1" />
            </label>
            <label className="port">
              <span>Port</span>
              <input value={targetPort} onChange={(e) => setTargetPort(e.target.value)} inputMode="numeric" placeholder="5432" />
            </label>
          </div>
        )}

        {error && <p className="error">{error}</p>}
        <div className="actions">
          {forward &&
            !readOnly &&
            (confirmDelete ? (
              <button type="button" className="danger" onClick={() => void forwards.remove(forward.id).then(onDeleted, (e) => setError(errorText(e)))}>
                Really delete?
              </button>
            ) : (
              <button type="button" className="ghost-danger" onClick={() => setConfirmDelete(true)}>
                Delete
              </button>
            ))}
          <span className="spacer" />
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" disabled={!valid || busy}>
            Save
          </button>
          <button type="button" className="primary" disabled={!valid || busy} onClick={() => void save(true)}>
            Save & start
          </button>
        </div>
      </form>
    </div>
  );
}
