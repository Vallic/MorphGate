import { useState, type FormEvent } from "react";
import { errorText, OC_PROTOCOLS, VPN_KINDS, vpnKindName, vpns, type HostView, type VaultEntry, type VpnInput, type VpnKind, type VpnView } from "./api";
import { FilePick, type PickedFile } from "./FilePick";
import { isReadOnly, personalVault, VaultField } from "./VaultField";
import { mobileOs } from "./mobile/useMobile";

interface Props {
  vpn?: VpnView;
  hosts: HostView[];
  vaults: VaultEntry[];
  onSaved: (v: VpnView) => void;
  onChanged: () => void;
  onDeleted: () => void;
  onClose: () => void;
}

const INTRO: Record<VpnKind, string> = {
  wireguard:
    "WireGuard runs inside MorphGate, only for hosts that use this profile. Nothing on your system changes: no network interface, no routes, no admin rights, and several clients' VPNs can be up at once.",
  openvpn:
    "OpenVPN runs inside MorphGate, only for hosts that use this profile: no network interface, no routes, no admin rights. Import the .ovpn file your VPN admin gave you; the certificates and keys it refers to are embedded in your encrypted vault.",
  openconnect:
    "For Cisco AnyConnect, GlobalProtect, Fortinet, Pulse/Ivanti and F5 servers. MorphGate uses the openconnect program for the VPN protocol and keeps the traffic inside the app: no network interface, no routes, no admin rights.",
};

const WG_PLACEHOLDER = "[Interface]\nPrivateKey = …\nAddress = 10.8.0.2/32\nDNS = 10.8.0.1\n\n[Peer]\nPublicKey = …\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.8.0.0/24";
const OVPN_PLACEHOLDER = "client\ndev tun\nremote vpn.example.com 1194 udp\nauth-user-pass\n<ca>\n-----BEGIN CERTIFICATE-----\n…\n</ca>";

export function VpnPanel({ vpn, hosts, vaults, onSaved, onChanged, onDeleted, onClose }: Props) {
  const [vaultId, setVaultId] = useState(vpn?.vaultId ?? personalVault(vaults));
  const readOnly = isReadOnly(vaults, vpn?.vaultId);
  const [kind, setKind] = useState<VpnKind>(vpn?.kind ?? "wireguard");
  const [label, setLabel] = useState(vpn?.label ?? "");
  const [replace, setReplace] = useState(!vpn);
  const [from, setFrom] = useState<"paste" | "file">("file");
  const [config, setConfig] = useState("");
  // The profile, and for OpenVPN the files it refers to, picked together.
  const [files, setFiles] = useState<PickedFile[]>([]);
  const [username, setUsername] = useState(vpn?.username ?? "");
  const [password, setPassword] = useState("");
  const [editPassword, setEditPassword] = useState(!vpn?.hasPassword);
  const [clearPassword, setClearPassword] = useState(false);
  const [server, setServer] = useState(vpn?.kind === "openconnect" ? vpn.server : "");
  const [protocol, setProtocol] = useState(vpn?.protocol ?? "anyconnect");
  const [authgroup, setAuthgroup] = useState(vpn?.authgroup ?? "");
  const [forgetCert, setForgetCert] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [test, setTest] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const users = vpn ? hosts.filter((h) => h.vpnId === vpn.id) : [];
  const usesFile = kind !== "openconnect";
  const hasNewConfig = usesFile && replace && (from === "paste" ? config.trim() !== "" : files.length > 0);
  const valid =
    !readOnly && (kind === "openconnect" ? server.trim() !== "" : vpn ? label.trim() !== "" || hasNewConfig : hasNewConfig);

  const pickKind = (k: VpnKind) => {
    setKind(k);
    setFiles([]);
    setError("");
  };

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const input: VpnInput = { id: vpn?.id, vaultId: vpn ? undefined : vaultId || undefined, kind, label };
    if (hasNewConfig) {
      if (from === "paste") input.config = config;
      else {
        // The profile is the .ovpn or .conf among them (or the one file); the rest, what it names.
        const profile = files.find((f) => /\.(ovpn|conf)$/i.test(f.name)) ?? files[0];
        input.config = profile.text;
        input.configFiles = files.filter((f) => f !== profile).map((f) => ({ name: f.name, data: f.base64 }));
      }
    }
    if (kind !== "wireguard") {
      input.username = username;
      if (clearPassword) input.password = "";
      else if (password) input.password = password;
    }
    if (kind === "openconnect") {
      input.server = server;
      input.protocol = protocol;
      input.authgroup = authgroup;
      input.forgetServerCert = forgetCert;
    }
    try {
      const saved = await vpns.save(input);
      setConfig("");
      setPassword("");
      setClearPassword(false);
      setEditPassword(!saved.hasPassword);
      setForgetCert(false);
      onSaved(saved);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const runTest = () => {
    if (!vpn) return;
    setTest("Connecting…");
    setError("");
    vpns.test(vpn.id).then(
      (r) => {
        setTest(`Connected to ${r.server} as ${r.address} (${r.millis} ms).`);
        onChanged();
      },
      (e) => (setTest(null), setError(errorText(e))),
    );
  };

  return (
    <div className="panel">
      <form className="panel-card wide" onSubmit={(e) => void save(e)}>
        <h1>
          {vpn ? "VPN" : "New VPN"}
          {vpn && <span className="kind-badge">{vpnKindName(vpn.kind)}</span>}
        </h1>
        <VaultField vaults={vaults} itemVault={vpn?.vaultId} item={vpn && { id: vpn.id, label: vpn.label }} value={vaultId} onChange={setVaultId} />
        {!vpn && (
          <div className="segmented" role="radiogroup" aria-label="VPN type">
            {VPN_KINDS.filter((k) => !mobileOs || k.kind !== "openconnect").map((k) => (
              <button key={k.kind} type="button" role="radio" aria-checked={kind === k.kind} className={kind === k.kind ? "on" : ""} onClick={() => pickKind(k.kind)}>
                {k.name}
              </button>
            ))}
          </div>
        )}
        <p className="hint">{INTRO[kind]}</p>

        <label>
          <span>Name</span>
          <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Client A office" autoFocus={!vpn} />
        </label>

        {vpn && !vpn.problem && (
          <dl className="facts">
            {vpn.facts.map((f) => (
              <FactRow key={f.label} label={f.label} value={f.value} />
            ))}
            {vpn.publicKey && (
              <>
                <dt>Your key</dt>
                <dd className="mono key-line">
                  {vpn.publicKey}
                  <button type="button" className="icon small" title="Copy public key" onClick={() => void navigator.clipboard?.writeText(vpn.publicKey ?? "").then(() => setCopied(true))}>
                    {copied ? "✓" : "⧉"}
                  </button>
                </dd>
              </>
            )}
            <dt>Status</dt>
            <dd>{vpn.active ? `Connected as ${vpn.address}` : "Idle: starts when a host needs it"}</dd>
          </dl>
        )}
        {vpn?.problem && <p className="error">{vpn.kind === "openconnect" ? vpn.problem : `Stored configuration is invalid: ${vpn.problem}`}</p>}
        {vpn && (
          <p className="hint">
            {users.length ? `Used by: ${users.map((h) => h.label).join(", ")}.` : "No host uses this VPN yet: pick it in a host's settings."}
          </p>
        )}

        {kind === "openconnect" && (
          <>
            <label>
              <span>Server</span>
              <input value={server} onChange={(e) => setServer(e.target.value)} placeholder="vpn.example.com or https://vpn.example.com/group" spellCheck={false} />
            </label>
            <div className="row">
              <label className="grow">
                <span>Protocol</span>
                <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                  {OC_PROTOCOLS.map((p) => (
                    <option key={p.value} value={p.value}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className="grow">
                <span>Group (optional)</span>
                <input value={authgroup} onChange={(e) => setAuthgroup(e.target.value)} placeholder="Ask when connecting" spellCheck={false} />
              </label>
            </div>
            {vpn?.serverCert && !forgetCert && (
              <p className="hint">
                Server certificate pinned: <span className="mono">{vpn.serverCert}</span>{" "}
                <button type="button" className="link inline" onClick={() => setForgetCert(true)}>
                  Forget
                </button>
              </p>
            )}
            {forgetCert && <p className="hint">The pinned certificate is forgotten when you save; you'll be asked again on the next connect.</p>}
          </>
        )}

        {usesFile &&
          (vpn && !replace ? (
            <button type="button" className="link" onClick={() => setReplace(true)}>
              {kind === "openvpn" ? "Replace the profile" : "Replace the configuration"}
            </button>
          ) : (
            <>
              <div className="segmented two small" role="radiogroup">
                <button type="button" role="radio" aria-checked={from === "file"} className={from === "file" ? "on" : ""} onClick={() => setFrom("file")}>
                  {kind === "openvpn" ? "From .ovpn file" : "From .conf file"}
                </button>
                <button type="button" role="radio" aria-checked={from === "paste"} className={from === "paste" ? "on" : ""} onClick={() => setFrom("paste")}>
                  {kind === "openvpn" ? "Paste profile" : "Paste config"}
                </button>
              </div>
              {from === "paste" ? (
                <label>
                  <span>{kind === "openvpn" ? "OpenVPN profile (with inline <ca>, <cert>, <key> blocks)" : "WireGuard configuration (wg-quick format)"}</span>
                  <textarea
                    className="mono"
                    rows={9}
                    value={config}
                    onChange={(e) => setConfig(e.target.value)}
                    spellCheck={false}
                    placeholder={kind === "openvpn" ? OVPN_PLACEHOLDER : WG_PLACEHOLDER}
                  />
                </label>
              ) : kind === "openvpn" ? (
                <FilePick label="The .ovpn file, and the files it refers to if they're separate" picked={files} multiple onPick={setFiles} />
              ) : (
                <FilePick label="The .conf file" picked={files} onPick={setFiles} />
              )}
              <p className="hint">
                {kind === "openvpn"
                  ? "Files the profile refers to (ca, cert, key, pkcs12, tls-crypt…) are embedded: choose them with it, unless they're inline in the profile. Scripts and route settings are ignored."
                  : "The private key is stored only in your encrypted vault. PostUp/PostDown scripts are ignored."}
              </p>
            </>
          ))}

        {kind !== "wireguard" && (
          <>
            <div className="row">
              <label className="grow">
                <span>Username</span>
                <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Ask when connecting" spellCheck={false} autoComplete="off" />
              </label>
              <label className="grow">
                <span>Password</span>
                {editPassword || clearPassword ? (
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => (setPassword(e.target.value), setClearPassword(false))}
                    placeholder={clearPassword ? "Removed when you save" : "Ask when connecting"}
                    autoComplete="off"
                  />
                ) : (
                  <span className="saved-secret">
                    Saved in the vault
                    <button type="button" className="link inline" onClick={() => setEditPassword(true)}>
                      Change
                    </button>
                    <button type="button" className="link inline" onClick={() => setClearPassword(true)}>
                      Remove
                    </button>
                  </span>
                )}
              </label>
            </div>
            <p className="hint">
              {kind === "openvpn"
                ? "Only for profiles that sign in with a username and password (auth-user-pass). One-time codes, and the passphrase of a protected key, are asked when connecting."
                : "Leave the password empty to type it, and any one-time code, when connecting."}
            </p>
          </>
        )}

        {test && <p className="ok">{test}</p>}
        {error && <p className="error">{error}</p>}

        <div className="actions">
          {vpn &&
            !readOnly &&
            (confirmDelete ? (
              <button type="button" className="danger" onClick={() => void vpns.remove(vpn.id).then(onDeleted, (e) => (setError(errorText(e)), setConfirmDelete(false)))}>
                Really delete?
              </button>
            ) : (
              <button type="button" className="ghost-danger" onClick={() => setConfirmDelete(true)}>
                Delete
              </button>
            ))}
          <span className="spacer" />
          {vpn && (
            <button type="button" onClick={runTest} disabled={busy || test === "Connecting…"}>
              Test
            </button>
          )}
          <button type="button" onClick={onClose}>
            Close
          </button>
          <button type="submit" className="primary" disabled={!valid || busy}>
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </div>
  );
}

function FactRow({ label, value }: { label: string; value: string }) {
  const mono = !["Sign-in", "Protocol", "Certificate", "One-time code"].includes(label);
  return (
    <>
      <dt>{label}</dt>
      <dd className={mono ? "mono" : undefined}>{value}</dd>
    </>
  );
}
