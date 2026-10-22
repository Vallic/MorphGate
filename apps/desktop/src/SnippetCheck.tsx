import { useEffect, useRef } from "react";
import { dateText, type SnippetView } from "./api";

/** A feed's snippet changed since this device last pasted or ran it: what it is now, before it
 * goes to the terminal. */
export function SnippetCheckDialog({ snippet, run, onAnswer }: { snippet: SnippetView; run: boolean; onAnswer: (send: boolean) => void }) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    ref.current?.showModal();
  }, []);

  return (
    <dialog ref={ref} className="modal snippet-check" aria-labelledby="sc-title" onCancel={(e) => (e.preventDefault(), onAnswer(false))}>
      <h2 id="sc-title">{snippet.name} changed</h2>
      <p>
        Changed by <strong>{snippet.source?.label ?? "its feed"}</strong> on {dateText(snippet.updatedAt)}, since you last {run ? "ran" : "pasted"} it on this
        device. It now {run ? "runs" : "pastes"}:
      </p>
      <pre className="mono snippet-body">{snippet.body}</pre>
      <div className="actions">
        <button type="button" onClick={() => onAnswer(false)}>
          Cancel
        </button>
        <button type="button" className="primary" onClick={() => onAnswer(true)}>
          {run ? "Run it" : "Paste it"}
        </button>
      </div>
    </dialog>
  );
}
