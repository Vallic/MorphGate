import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { errorText, hostImport, type ImportHost, type ImportPreview, type ImportResult, type ImportSource, type VaultEntry } from "./api";
import { certificateValidity } from "./KeyPanel";
import { Page } from "./Page";
import { personalVault, VaultField } from "./VaultField";

const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? "" : "s"}`;

/** "1 host and 2 keys", "3 hosts, 1 key and 2 groups". */
const counts = (r: ImportResult) => {
  const parts = [plural(r.hosts, "host"), plural(r.keys, "key")];
  if (r.groups > 0) parts.push(plural(r.groups, "group"));
  if (r.certificates > 0) parts.push(plural(r.certificates, "certificate"));
  return parts.length === 2 ? parts.join(" and ") : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
};

type Kind = ImportSource["kind"];

const SOURCES: Record<Kind, { name: string; lead: string; file: string; placeholder: string; accept: string }> = {
  sshConfig: {
    name: "OpenSSH",
    lead: "From OpenSSH's configuration: each Host becomes a host, with the keys it names and its jump hosts. The file isn't changed.",
    file: "Configuration file",
    placeholder: "~/.ssh/config",
    accept: "",
  },
  putty: {
    name: "PuTTY",
    lead: "From PuTTY's saved sessions on this computer, or a .reg file exported from PuTTY on Windows: SSH sessions become hosts, with their keys (.ppk, kept as OpenSSH keys) and SSH proxies as jump hosts.",
    file: "A .reg file or PuTTY's sessions folder (empty: the sessions saved here)",
    placeholder: "PuTTY's saved sessions",
    accept: ".reg",
  },
  csv: {
    name: "CSV",
    lead: "From a CSV file: Termius' import template (Groups, Label, Tags, Hostname/IP, Protocol, Port, Username, Password) or another manager's export. Columns are found by their headers; groups and tags come along.",
    file: "CSV file",
    placeholder: "~/Downloads/hosts.csv",
    accept: ".csv,.tsv,.txt",
  },
  royal: {
    name: "Royal TS",
    lead: "From a Royal TS or Royal TSX document (.rtsz, .rtsx): SSH connections become hosts, their folders groups, and their credentials give the user and key. Passwords stay in Royal TS, which keeps them encrypted.",
    file: "Royal TS document",
    placeholder: "~/Documents/Connections.rtsz",
    accept: ".rtsz,.rtsx,.xml",
  },
};

/** A file's bytes as base64, for the import to read. */
const base64 = async (file: File) => {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
};

/** Hosts from other SSH clients: OpenSSH's configuration, PuTTY's sessions, a CSV file or a Royal
 * TS document. A preview of what the source holds, then the import of the hosts picked, with the
 * keys they use, their jump hosts and their groups. */
export function ImportHostsPage({ vaults, onImported, onClose }: { vaults: VaultEntry[]; onImported: () => void; onClose: () => void }) {
  const [kind, setKind] = useState<Kind>("sshConfig");
  const [path, setPath] = useState("~/.ssh/config");
  // The source the preview shows: the import reads the same one.
  const [source, setSource] = useState<ImportSource | null>(null);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [passphrases, setPassphrases] = useState<Record<string, string>>({});
  const [vaultId, setVaultId] = useState(personalVault(vaults));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);
  const chooser = useRef<HTMLInputElement>(null);

  const read = useCallback((from: ImportSource, keep = false) => {
    setError("");
    if (!keep) setResult(null);
    setSource(from);
    hostImport.preview(from).then(
      (p) => {
        setPreview(p);
        // What the vault has already starts unticked.
        setPicked(new Set(p.hosts.filter((h) => !h.exists).map((h) => h.id)));
      },
      (e) => (setPreview(null), setError(errorText(e))),
    );
  }, []);
  useEffect(() => read({ kind: "sshConfig", path: "~/.ssh/config" }), [read]);

  const pick = (next: Kind) => {
    if (next === kind) return;
    setKind(next);
    setPreview(null);
    setSource(null);
    setError("");
    setResult(null);
    setPassphrases({});
    const start = next === "sshConfig" ? "~/.ssh/config" : "";
    setPath(start);
    // OpenSSH and PuTTY have a usual place; a CSV file or a document is chosen first.
    if (next === "sshConfig" || next === "putty") read({ kind: next, path: start });
  };

  const choose = async (file: File | undefined) => {
    if (!file) return;
    setPath("");
    try {
      read({ kind, data: await base64(file), name: file.name });
    } catch (e) {
      setError(errorText(e));
    }
  };

  const toggle = (id: string) =>
    setPicked((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!source) return;
    setBusy(true);
    setError("");
    hostImport.run({ source, ids: [...picked], vaultId: vaultId || null, passphrases }).then(
      (r) => {
        setResult(r);
        setBusy(false);
        setPassphrases({});
        onImported();
        read(source, true);
      },
      (err) => (setError(errorText(err)), setBusy(false)),
    );
  };

  const about = SOURCES[kind];
  const hosts = preview?.hosts ?? [];
  // The keys the picked hosts sign in with.
  const keys = (preview?.keys ?? []).filter((k) => k.usedBy.some((id) => picked.has(id)));

  return (
    <Page title="Import hosts" lead={about.lead} onClose={onClose}>
      <form className="stack import-hosts" onSubmit={submit}>
        <div className="segmented four" role="radiogroup" aria-label="Import from">
          {(Object.keys(SOURCES) as Kind[]).map((k) => (
            <button key={k} type="button" role="radio" aria-checked={kind === k} className={kind === k ? "on" : ""} onClick={() => pick(k)}>
              {SOURCES[k].name}
            </button>
          ))}
        </div>
        <div className="row">
          <label className="grow">
            <span>{about.file}</span>
            <input value={path} onChange={(e) => setPath(e.target.value)} placeholder={about.placeholder} spellCheck={false} />
          </label>
          <button type="button" className="secondary align-end" onClick={() => read({ kind, path })} disabled={(kind === "csv" || kind === "royal") && path.trim() === ""}>
            Read
          </button>
          {kind !== "sshConfig" && (
            <button type="button" className="secondary align-end" onClick={() => chooser.current?.click()}>
              Choose…
            </button>
          )}
          <input
            ref={chooser}
            type="file"
            accept={about.accept}
            hidden
            onChange={(e) => {
              void choose(e.target.files?.[0]);
              e.target.value = "";
            }}
          />
        </div>
        {error && <p className="error">{error}</p>}
        {result && (
          <div className="notice-box stack import-result">
            <p className="ok">Imported {counts(result)}.</p>
            {result.notes.map((n) => (
              <p key={n} className="hint">
                {n}
              </p>
            ))}
          </div>
        )}
        {preview && preview.warnings.map((w) => <p key={w} className="warn">{w}</p>)}
        {preview && hosts.length === 0 && <p className="hint">{preview.source} has no hosts to import.</p>}
        {hosts.length > 0 && (
          <>
            <div className="row">
              <h2 className="section-title grow">
                {plural(hosts.length, "host")} in {preview!.source}
              </h2>
              <button type="button" className="link" onClick={() => setPicked(new Set(hosts.map((h) => h.id)))}>
                All
              </button>
              <button type="button" className="link" onClick={() => setPicked(new Set())}>
                None
              </button>
            </div>
            <ul className="device-list import-list">
              {hosts.map((h) => (
                <HostRow key={h.id} host={h} on={picked.has(h.id)} onToggle={() => toggle(h.id)} />
              ))}
            </ul>
          </>
        )}
        {keys.length > 0 && (
          <>
            <h2 className="section-title">Keys</h2>
            <ul className="device-list import-keys">
              {keys.map((k) => (
                <li key={k.path}>
                  <div>
                    <strong className="mono">{k.path}</strong>
                    {k.algorithm && <span className="kind-badge">{k.algorithm.replace(/^ssh-/, "")}</span>}
                    {k.inVault && <span className="kind-badge me">in the vault</span>}
                    {k.certificate && <span className="kind-badge">certificate</span>}
                    <small>
                      {k.error
                        ? `Can't be read: ${k.error}. Its hosts ${k.fallback === "agent" ? "use the SSH agent" : "ask for a password"}.`
                        : k.inVault
                          ? "The vault has this key: the hosts use that one."
                          : k.encrypted
                            ? `Encrypted: give its passphrase to copy it into the vault, or leave it empty for its hosts to ${k.fallback === "agent" ? "use the SSH agent" : "ask for a password"}.`
                            : `Copied into the vault${k.fingerprint ? ` (${k.fingerprint})` : ""}.`}
                    </small>
                    {k.certificate && (
                      <small>
                        With its certificate: signs in as {k.certificate.principals.join(", ") || "any user"}; {certificateValidity(k.certificate).text.toLowerCase()}.
                      </small>
                    )}
                  </div>
                  {k.encrypted && !k.inVault && !k.error && (
                    <input
                      type="password"
                      className="passphrase"
                      aria-label={`Passphrase for ${k.path}`}
                      placeholder="Passphrase"
                      value={passphrases[k.path] ?? ""}
                      onChange={(e) => setPassphrases((p) => ({ ...p, [k.path]: e.target.value }))}
                      autoComplete="off"
                    />
                  )}
                </li>
              ))}
            </ul>
          </>
        )}
        {hosts.length > 0 && (
          <>
            <VaultField vaults={vaults} value={vaultId} onChange={setVaultId} />
            <div className="row">
              <button type="submit" className="primary" disabled={busy || picked.size === 0}>
                {busy ? "Importing…" : `Import ${plural(picked.size, "host")}`}
              </button>
            </div>
          </>
        )}
      </form>
    </Page>
  );
}

function HostRow({ host: h, on, onToggle }: { host: ImportHost; on: boolean; onToggle: () => void }) {
  const port = h.port === 22 ? "" : `:${h.port}`;
  const auth =
    h.auth === "key"
      ? `key ${h.key?.split(/[/\\]/).pop()}`
      : h.auth === "agent"
        ? `${h.agent ? `${h.agent} agent` : "SSH agent"}${h.agentKey ? ", one key" : ""}`
        : h.password
          ? "saved password"
          : "password";
  return (
    <li>
      <label className="check">
        <input type="checkbox" checked={on} onChange={onToggle} aria-label={`Import ${h.label}`} />
      </label>
      <div>
        <strong>{h.label}</strong>
        <span className="kind-badge">{auth}</span>
        {h.group && <span className="kind-badge">group {h.group}</span>}
        {h.forwardAgent && <span className="kind-badge">forwards the agent</span>}
        {h.exists && <span className="kind-badge me">in the vault</span>}
        <small className="mono">
          {h.user}@{h.hostname}
          {port}
          {h.jumps.length > 0 && ` via ${h.jumps.join(" → ")}`}
        </small>
        {h.proxyCommand && <small className="mono">Connects by running on this computer: {h.proxyCommand}</small>}
        {h.tags.length > 0 && <small>Tags: {h.tags.join(", ")}</small>}
        {h.unsupported.length > 0 && <small>Not imported: {h.unsupported.join("; ")}</small>}
      </div>
    </li>
  );
}
