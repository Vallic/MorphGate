import { useId, useRef, useState } from "react";

/** A small file the person picked: its name, its text, and its bytes as base64 (for a binary
 * one, a PKCS#12 bundle say). */
export interface PickedFile {
  name: string;
  text: string;
  base64: string;
}

/** Keys, certificates, profiles and CSV files are small: anything bigger was picked by mistake. */
const MAX_BYTES = 1024 * 1024;

const base64 = (bytes: Uint8Array) => {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
};

/** "Choose file…" and the chosen files' names. The files are read here, in the page, so it works
 * the same on phones (where there's no path to type) as on computers. */
export function FilePick({
  label,
  picked,
  accept,
  multiple,
  onPick,
}: {
  label: string;
  picked: PickedFile[];
  /** The input's `accept`: extensions or types the system's picker shows first. */
  accept?: string;
  /** Several files at once (a profile and the files it refers to). */
  multiple?: boolean;
  onPick: (files: PickedFile[]) => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [error, setError] = useState("");
  const id = useId();
  const read = async (list: FileList | null) => {
    const files = [...(list ?? [])];
    if (files.length === 0) return;
    setError("");
    const big = files.find((f) => f.size > MAX_BYTES);
    if (big) {
      onPick([]);
      setError(`${big.name} is ${Math.round(big.size / 1024)} KB: more than 1 MB, so not what this needs.`);
      return;
    }
    try {
      onPick(
        await Promise.all(
          files.map(async (f) => {
            const bytes = new Uint8Array(await f.arrayBuffer());
            return { name: f.name, text: new TextDecoder().decode(bytes), base64: base64(bytes) };
          }),
        ),
      );
    } catch {
      onPick([]);
      setError("The file couldn't be read.");
    }
  };
  const names = picked.map((f) => f.name).join(", ");
  return (
    <div className="file-pick">
      <span id={id}>{label}</span>
      <div className="row align-center">
        <button type="button" className="secondary" aria-describedby={id} onClick={() => input.current?.click()}>
          {picked.length > 0 ? "Choose another…" : multiple ? "Choose files…" : "Choose file…"}
        </button>
        <span className={`grow file-pick-name ${picked.length > 0 ? "mono" : "muted"}`} title={names}>
          {picked.length > 0 ? names : multiple ? "No files chosen" : "No file chosen"}
        </span>
      </div>
      {error && <p className="error">{error}</p>}
      <input
        ref={input}
        type="file"
        accept={accept}
        multiple={multiple}
        hidden
        aria-labelledby={id}
        onChange={(e) => {
          void read(e.target.files);
          e.target.value = "";
        }}
      />
    </div>
  );
}
