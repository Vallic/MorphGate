import { useEffect, useRef, useState } from "react";

interface Props {
  title: string;
  message: string;
  onSubmit: (password: string) => void;
  onCancel: () => void;
}

export function PasswordDialog({ title, message, onSubmit, onCancel }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const [value, setValue] = useState("");

  useEffect(() => {
    ref.current?.showModal();
  }, []);

  return (
    <dialog ref={ref} className="modal" onCancel={(e) => (e.preventDefault(), onCancel())}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (value) onSubmit(value);
        }}
      >
        <h2>{title}</h2>
        <p>{message}</p>
        <input type="password" autoFocus value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" />
        <div className="actions">
          <span className="spacer" />
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={!value}>
            Connect
          </button>
        </div>
      </form>
    </dialog>
  );
}
