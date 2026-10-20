import { useEffect, useRef } from "react";
import { sync, type ApprovalNeed } from "./api";

/** Why an organization's vaults don't open on this device yet: it waits for approval, or was denied. */
export function ApprovalWait({ need, onClose }: { need: ApprovalNeed; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    ref.current?.showModal();
  }, []);
  return (
    <dialog ref={ref} className="modal approval" aria-labelledby="approval-title" onCancel={(e) => (e.preventDefault(), onClose())}>
      <h2 id="approval-title">{need.denied ? `${need.orgName} denied this device` : `Waiting for ${need.orgName}`}</h2>
      {need.denied ? (
        <p>
          Its vaults stay closed on this device. If that's a mistake, ask an owner or admin of {need.orgName} to approve it, or approve it
          yourself from another of your devices that the team approved: Teams › {need.orgName} there.
        </p>
      ) : (
        <p>
          {need.orgName} approves new devices before they open its vaults. An owner or admin can approve this one, or you can, from another
          of your devices that the team approved: Teams › {need.orgName} there. Its vaults sync here once it's approved.
        </p>
      )}
      <div className="actions">
        <span className="spacer" />
        <button type="button" onClick={onClose}>
          Close
        </button>
        <button type="button" className="primary" onClick={() => void sync.now().catch(() => {}).then(onClose)}>
          Check again
        </button>
      </div>
    </dialog>
  );
}
