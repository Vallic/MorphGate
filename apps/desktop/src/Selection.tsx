// Several items of a list page at once: "Select" turns the rows into checkboxes, and a bar says how
// many are chosen and what can be done to them (delete them, move them to another vault, and
// what the page adds: a group for hosts).

import { useState, type ReactNode } from "react";
import { errorText, type BulkResult } from "./api";
import { MoveButton } from "./Move";

const count = (n: number, [one, many]: [string, string]) => `${n} ${n === 1 ? one : many}`;

/** A list's selection; `ids` is null while the list isn't selecting. */
export function useSelection() {
  const [ids, setIds] = useState<Set<string> | null>(null);
  return {
    on: ids !== null,
    has: (id: string) => !!ids?.has(id),
    start: () => setIds(new Set()),
    stop: () => setIds(null),
    set: (all: string[]) => setIds(new Set(all)),
    toggle: (id: string) =>
      setIds((s) => {
        if (!s) return s;
        const next = new Set(s);
        if (!next.delete(id)) next.add(id);
        return next;
      }),
    /** The chosen ones the list still shows (a deleted or filtered-out item drops out). */
    chosen: <T extends { id: string }>(shown: T[]) => shown.filter((x) => ids?.has(x.id)),
  };
}

export type Selection = ReturnType<typeof useSelection>;

/** What a row needs to be picked. */
export const pickOf = (sel: Selection, id: string, label: string) => (sel.on ? { on: sel.has(id), toggle: () => sel.toggle(id), label } : undefined);

/** Deletes one by one, for what has its own delete (tunnels, VPNs). */
export async function eachOf(ids: string[], remove: (id: string) => Promise<void>): Promise<BulkResult> {
  const result: BulkResult = { done: 0, refused: [] };
  for (const id of ids) {
    try {
      await remove(id);
      result.done += 1;
    } catch (e) {
      result.refused.push(errorText(e));
    }
  }
  return result;
}

/** What happened, in a line: what changed, and why the rest didn't. */
export function outcome(r: BulkResult, verb: string, noun: [string, string]) {
  const done = r.done > 0 ? `${verb} ${count(r.done, noun)}.` : "";
  return { ok: r.refused.length === 0, text: [done, ...r.refused].filter(Boolean).join(" ") };
}

interface BarProps {
  sel: Selection;
  /** What the list shows, for "Select all" and moving (one vault at a time). */
  shown: { id: string; vaultId: string }[];
  /** "host", "hosts". */
  noun: [string, string];
  onDelete: (ids: string[]) => Promise<BulkResult>;
  onChanged: () => void;
  /** More to do with the chosen ones (a group for hosts); `report` shows its outcome. */
  more?: (ids: string[], vaultId: string | null, report: (r: { ok: boolean; text: string }) => void) => ReactNode;
}

/** The bar over a selecting list. */
export function SelectBar({ sel, shown, noun, onDelete, onChanged, more }: BarProps) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  if (!sel.on) return null;
  const chosen = sel.chosen(shown);
  const ids = chosen.map((x) => x.id);
  const vaults = new Set(chosen.map((x) => x.vaultId));
  const vaultId = vaults.size === 1 ? [...vaults][0] : null;
  const all = chosen.length === shown.length && shown.length > 0;
  const what = count(ids.length, noun);

  const remove = () => {
    setBusy(true);
    setNote(null);
    onDelete(ids).then(
      (r) => (setBusy(false), setConfirming(false), setNote(outcome(r, "Deleted", noun)), onChanged()),
      (e) => (setBusy(false), setConfirming(false), setNote({ ok: false, text: errorText(e) })),
    );
  };

  return (
    <div className="select-bar-wrap">
      <div className="select-bar" role="toolbar" aria-label={`Selected ${noun[1]}`}>
        <strong className="select-count">{ids.length ? `${what} selected` : `Select ${noun[1]}`}</strong>
        <button type="button" className="link" onClick={() => (all ? sel.set([]) : sel.set(shown.map((x) => x.id)))}>
          {all ? "Select none" : "Select all"}
        </button>
        <span className="spacer" />
        {ids.length > 0 && !confirming && (
          <>
            {more?.(ids, vaultId, setNote)}
            {vaultId && <MoveButton ids={ids} label={what} from={vaultId} className="secondary small-button" onMoved={() => sel.set([])} />}
            <button type="button" className="ghost-danger small-button" onClick={() => (setNote(null), setConfirming(true))}>
              Delete…
            </button>
          </>
        )}
        {confirming && (
          <>
            <span className="select-confirm">Delete {what}?</span>
            <button type="button" className="danger small-button" disabled={busy} onClick={remove}>
              {busy ? "Deleting…" : "Delete"}
            </button>
            <button type="button" className="link" disabled={busy} onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </>
        )}
        <button type="button" className="secondary small-button" onClick={sel.stop}>
          Done
        </button>
      </div>
      {note && <p className={note.ok ? "ok" : "error"}>{note.text}</p>}
    </div>
  );
}
