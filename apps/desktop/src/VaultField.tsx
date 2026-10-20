import { useContext } from "react";
import type { VaultEntry } from "./api";
import { MoveButton, MoveContext, moveTargets } from "./Move";

export const personalVault = (vaults: VaultEntry[]) => vaults.find((v) => v.personal)?.id ?? "";

/** Items can only refer to items in the same vault (a host's key, jump host, VPN). */
export const sameVault = (vaultId: string) => (x: { vaultId: string }) => !vaultId || x.vaultId === vaultId;

interface Props {
  vaults: VaultEntry[];
  /** An existing item's vault; a new item picks one. */
  itemVault?: string;
  /** The existing item, to offer moving it to another vault. */
  item?: { id: string; label: string };
  value: string;
  onChange: (vaultId: string) => void;
}

/** Where a new item goes, once there are shared vaults to choose from; where an existing one lives
 * (and "Move to…" another). */
export function VaultField({ vaults, itemVault, item, value, onChange }: Props) {
  const moves = useContext(MoveContext);
  if (itemVault !== undefined) {
    const v = vaults.find((x) => x.id === itemVault);
    const movable = !!item && !!moves && moveTargets(moves.vaults, itemVault).length > 0;
    if (!v || (v.personal && !movable)) return null;
    return (
      <div className="vault-line">
        <p className="hint grow">
          {v.personal ? (
            "In your personal vault."
          ) : (
            <>
              In the shared vault <strong>{v.label}</strong>.
              {v.locked
                ? " Its team has no plan: it can be read, not changed, until it has one."
                : v.access === "read" && " You can use it but not change it."}
            </>
          )}
        </p>
        {movable && <MoveButton ids={[item.id]} label={item.label} from={itemVault} className="secondary small-button" />}
      </div>
    );
  }
  // The member key directory only holds members' public keys.
  const writable = vaults.filter((v) => v.access !== "read" && !v.directory);
  if (writable.length < 2) return null;
  return (
    <label>
      <span>Vault</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {writable.map((v) => (
          <option key={v.id} value={v.id}>
            {v.personal ? "Personal (only you)" : v.label}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Read-only for this account: editors show it without letting changes through. */
export const isReadOnly = (vaults: VaultEntry[], vaultId: string | undefined) =>
  vaultId !== undefined && vaults.find((v) => v.id === vaultId)?.access === "read";
