// Moving items to another vault: "Move to…" opens a dialog with the plan (what moves, what rides
// along, what is copied because something staying still uses it), where each item that has a
// choice can be switched, then moves everything at once.

import { createContext, useContext, useEffect, useRef, useState } from "react";
import { errorText, moving, type Carry, type MovePlan, type Moved, type PlannedItem, type VaultEntry } from "./api";

/** What the app gives every "Move to…": the vaults, and what to do once something moved. */
export const MoveContext = createContext<{ vaults: VaultEntry[]; onMoved: (moved: Moved) => void } | null>(null);

/** Vaults an item in `from` can go to. */
export const moveTargets = (vaults: VaultEntry[], from: string) =>
  vaults.filter((v) => v.id !== from && v.access !== "read" && !v.directory);

const KINDS: Record<string, string> = {
  host: "Host",
  host_group: "Group",
  ssh_key: "Key",
  identity: "Identity",
  port_forward: "Tunnel",
  vpn: "VPN",
  snippet: "Snippet",
  attachment: "File",
  terminal_theme: "Theme",
};

const CARRY: Record<Carry, string> = { move: "Move", copy: "Copy", leave: "Leave out" };

const vaultName = (v: VaultEntry) => (v.personal ? "Personal (only you)" : v.label);

/** "Move to…", where there is another vault to move to. `onMoved`: after the app has. */
export function MoveButton({
  ids,
  label,
  from,
  className = "secondary",
  onMoved,
}: {
  ids: string[];
  label: string;
  from: string;
  className?: string;
  onMoved?: () => void;
}) {
  const ctx = useContext(MoveContext);
  const [open, setOpen] = useState(false);
  if (!ctx || moveTargets(ctx.vaults, from).length === 0) return null;
  return (
    <>
      <button type="button" className={className} onClick={() => setOpen(true)}>
        Move to…
      </button>
      {open && (
        <MoveDialog
          ids={ids}
          label={label}
          from={from}
          vaults={ctx.vaults}
          onMoved={(m) => (setOpen(false), ctx.onMoved(m), onMoved?.())}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}

function why(p: PlannedItem): string {
  switch (p.why.kind) {
    case "chosen":
      return "";
    case "rides":
      return `Goes with ${p.why.with}`;
    case "used":
      return `Used by ${p.why.by.join(", ")}`;
  }
}

function MoveDialog({
  ids,
  label,
  from,
  vaults,
  onMoved,
  onClose,
}: {
  ids: string[];
  label: string;
  from: string;
  vaults: VaultEntry[];
  onMoved: (moved: Moved) => void;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const targets = moveTargets(vaults, from);
  const source = vaults.find((v) => v.id === from);
  // From the personal vault, a team's is the likely target; from a team's, the personal one.
  const [to, setTo] = useState((source?.personal ? targets.find((v) => !v.personal) : targets.find((v) => v.personal))?.id ?? targets[0]?.id ?? "");
  const [choices, setChoices] = useState<Record<string, Carry>>({});
  const [plan, setPlan] = useState<MovePlan | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    ref.current?.showModal();
  }, []);
  useEffect(() => {
    if (!to) return;
    setError("");
    moving.plan(ids, to, choices).then(setPlan, (e) => (setPlan(null), setError(errorText(e))));
  }, [to, choices]);

  const go = () => {
    setBusy(true);
    setError("");
    moving.move(ids, to, choices).then(onMoved, (e) => (setError(errorText(e)), setBusy(false)));
  };
  const copiesOnly = plan !== null && plan.items.every((p) => p.carry !== "move");

  return (
    <dialog ref={ref} className="sheet move-dialog" onCancel={(e) => (e.preventDefault(), onClose())}>
      <h1>Move {label}</h1>
      <label>
        <span>To</span>
        <select value={to} onChange={(e) => (setTo(e.target.value), setChoices({}))}>
          {targets.map((v) => (
            <option key={v.id} value={v.id}>
              {vaultName(v)}
            </option>
          ))}
        </select>
      </label>
      {plan && (
        <ul className="device-list move-plan">
          {plan.items.map((p) => (
            <li key={p.id}>
              <div>
                <span className="kind-badge">{KINDS[p.kind] ?? p.kind}</span>
                <strong>{p.label}</strong>
                {why(p) && <small>{why(p)}</small>}
                {p.keptBy.length > 0 && <small>Still used here by {p.keptBy.join(", ")}: a copy goes, this one stays.</small>}
              </div>
              {p.choices.length > 0 ? (
                <div
                  className="segmented small"
                  role="radiogroup"
                  aria-label={`What happens to ${p.label}`}
                  style={{ "--choices": p.choices.length } as React.CSSProperties}
                >
                  {p.choices.map((c) => (
                    <button
                      type="button"
                      key={c}
                      role="radio"
                      aria-checked={p.carry === c}
                      className={p.carry === c ? "on" : ""}
                      onClick={() => setChoices({ ...choices, [p.id]: c })}
                    >
                      {CARRY[c]}
                    </button>
                  ))}
                </div>
              ) : (
                <span className="carry">{p.carry === "move" ? "Moves" : p.carry === "copy" ? "Copied" : "Left out"}</span>
              )}
            </li>
          ))}
        </ul>
      )}
      {source?.personal && targets.find((v) => v.id === to)?.personal === false && (
        <p className="hint">
          In a team's vault it is the team's: if you leave the team or are removed from it, it stays with the team and leaves your
          devices.
        </p>
      )}
      {plan?.notes.map((n) => (
        <p key={n} className="hint">
          {n}
        </p>
      ))}
      {error && <p className="error">{error}</p>}
      <div className="actions">
        <span className="spacer" />
        <button type="button" onClick={onClose}>
          Cancel
        </button>
        <button type="button" className="primary" disabled={!plan || busy} onClick={go}>
          {busy ? "Moving…" : copiesOnly ? "Copy" : "Move"}
        </button>
      </div>
    </dialog>
  );
}
