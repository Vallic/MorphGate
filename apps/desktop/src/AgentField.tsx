import { useEffect, useState } from "react";
import { agents, errorText, type AgentChoice, type AgentInfo, type HostAuthView } from "./api";

export const SYSTEM_AGENT: AgentChoice = { agent: null, path: null, key: null };

const NAMES: Record<string, string> = {
  system: "the system's SSH agent",
  "1password": "1Password",
  bitwarden: "Bitwarden",
  secretive: "Secretive",
  pageant: "Pageant",
  custom: "an SSH agent",
};

/** "SSH agent" as lists describe a host's sign-in: which agent, and one key or all of them. */
export function agentDescription(auth: AgentChoice): string {
  const which =
    !auth.agent || auth.agent === "system" ? "SSH agent" : auth.agent === "custom" ? "SSH agent (own socket)" : `${NAMES[auth.agent] ?? auth.agent} agent`;
  return auth.key ? `${which}, one key` : which;
}

/** The agent choice an auth view holds (the system's for anything else). */
export const agentOf = (auth: HostAuthView | undefined): AgentChoice =>
  auth?.kind === "agent" ? { agent: auth.agent, path: auth.path, key: auth.key } : SYSTEM_AGENT;

const short = (fp: string) => (fp.length > 22 ? `${fp.slice(0, 14)}…${fp.slice(-6)}` : fp);

/** Which SSH agent signs in, and which of its keys: the agents this device has, running or not,
 * with the keys they hold now. Keys never leave the agent; the vault keeps the agent's name and
 * the key's fingerprint. */
export function AgentField({ value, onChange, disabled }: { value: AgentChoice; onChange: (v: AgentChoice) => void; disabled?: boolean }) {
  const [list, setList] = useState<AgentInfo[] | null>(null);
  const [error, setError] = useState("");
  const [path, setPath] = useState(value.path ?? "");
  const id = value.agent ?? "system";

  const look = (p: string | null) => {
    setError("");
    agents.list(p).then(setList, (e) => setError(errorText(e)));
  };
  useEffect(() => look(value.path), []);

  const current = list?.find((a) => a.id === id);
  const keys = current?.keys ?? [];
  const saved = value.key && !keys.some((k) => k.fingerprint === value.key) ? value.key : null;
  const chosen = keys.find((k) => k.fingerprint === value.key);
  const pick = (agent: string) => onChange({ agent: agent === "system" ? null : agent, path: agent === "custom" ? path || null : null, key: null });

  return (
    <div className="stack agent-field">
      <label>
        <span>Agent</span>
        <select value={id} onChange={(e) => pick(e.target.value)} disabled={disabled} aria-label="SSH agent">
          {(list ?? [{ id: "system", name: "System agent", running: false, keys: [] } as unknown as AgentInfo]).map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
              {a.id === "custom" ? "" : a.running ? ` · ${a.keys.length} key${a.keys.length === 1 ? "" : "s"}` : " · not running here"}
            </option>
          ))}
          {list && !list.some((a) => a.id === id) && <option value={id}>{NAMES[id] ?? id} (not on this device)</option>}
        </select>
      </label>
      {id === "custom" && (
        <div className="row">
          <label className="grow">
            <span>Socket or pipe</span>
            <input
              value={path}
              onChange={(e) => setPath(e.target.value)}
              onBlur={() => onChange({ ...value, path: path.trim() || null })}
              placeholder={navigator.userAgent.includes("Windows") ? "\\\\.\\pipe\\my-agent" : "~/.ssh/agent.sock"}
              spellCheck={false}
              disabled={disabled}
            />
          </label>
          <button type="button" className="secondary align-end" disabled={disabled || !path.trim()} onClick={() => (onChange({ ...value, path: path.trim() }), look(path.trim()))}>
            Look
          </button>
        </div>
      )}
      <label>
        <span>Key</span>
        <select value={value.key ?? ""} onChange={(e) => onChange({ ...value, key: e.target.value || null })} disabled={disabled} aria-label="Agent key">
          <option value="">Any key it holds</option>
          {keys.map((k) => (
            <option key={k.fingerprint} value={k.fingerprint}>
              {k.comment || short(k.fingerprint)} ({k.algorithm.replace(/^ssh-/, "").replace(/@openssh\.com$/, "")}
              {k.certificate ? ", certificate" : ""})
            </option>
          ))}
          {saved && <option value={saved}>{short(saved)} (not held here now)</option>}
        </select>
      </label>
      {error && <p className="error">{error}</p>}
      {current && (
        <p className={current.running || id === "custom" ? "hint" : "warn"}>
          {current.running
            ? `${current.location}. ${value.key ? "Only this key is offered" : "Every key it holds is offered, in turn"}: the keys stay in the agent.`
            : id === "custom" && !path.trim()
              ? "The socket (or, on Windows, the named pipe) the agent listens on, on this device."
              : `Not running here${current.error ? `: ${current.error}` : ""}. Hosts can still name it; it signs in on devices where it runs.`}
        </p>
      )}
      {chosen?.securityKey && <p className="hint">A security key: MorphGate asks you to touch it when it signs in.</p>}
    </div>
  );
}
