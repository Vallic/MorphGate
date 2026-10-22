import { useEffect, useMemo, useState } from "react";

interface Component {
  name: string;
  version?: string;
  /** SPDX expression, as the package declares it. */
  license: string;
  kind: "crate" | "npm" | "font" | "data" | "android";
  url?: string;
  /** Indexes into `texts`. */
  texts: number[];
}

interface Notices {
  target: string;
  components: Component[];
  texts: string[];
}

// Written by scripts/licenses.mjs in `npm run build` (every Tauri build), for the platform built;
// missing under `npm run dev`. Loaded when this opens: it's most of a megabyte.
const generated = import.meta.glob<Notices>("./generated/licenses.json", { import: "default" });

const KINDS: Record<Component["kind"], string> = { crate: "Rust crate", npm: "npm package", font: "font", data: "word list", android: "Android library" };

/** About → Open-source licenses: the third-party components in this build, with their notices. */
export function Licenses({ onBack }: { onBack: () => void }) {
  // undefined: loading; null: not in this build.
  const [notices, setNotices] = useState<Notices | null | undefined>(undefined);
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<Component | null>(null);

  useEffect(() => {
    const load = generated["./generated/licenses.json"];
    if (!load) return setNotices(null);
    load().then(setNotices, () => setNotices(null));
  }, []);

  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return notices?.components.filter((c) => !f || c.name.toLowerCase().includes(f) || c.license.toLowerCase().includes(f)) ?? [];
  }, [notices, filter]);

  if (open && notices) {
    return (
      <div className="stack">
        <p className="license-name">
          <strong>{open.name}</strong> {open.version}
        </p>
        <p className="hint">
          {KINDS[open.kind]} · {open.license || "license not stated"}
          {open.url && (
            <>
              {" · "}
              <span className="mono">{open.url.replace(/^git\+/, "")}</span>
            </>
          )}
        </p>
        {open.texts.map((t) => (
          <pre key={t} className="license-text">
            {notices.texts[t]}
          </pre>
        ))}
        <div className="actions">
          <button type="button" className="secondary" onClick={() => setOpen(null)}>
            All components
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="stack">
      <h2 className="section-title">Open-source licenses</h2>
      <p className="hint">
        MorphGate is free software under the Mozilla Public License 2.0. It's built with these components, whose licenses ask for their notices to come
        with it.
      </p>
      {notices === undefined && <p className="hint">Loading…</p>}
      {notices === null && <p className="hint">This build has no list: it's made when the app is built for release.</p>}
      {notices && (
        <>
          <input type="search" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={`Search ${notices.components.length} components`} aria-label="Search components" />
          <ul className="list licenses-list">
            {shown.map((c) => (
              <li key={`${c.kind}:${c.name}:${c.version ?? ""}`}>
                <button type="button" className="license-row" onClick={() => setOpen(c)}>
                  <span className="grow">
                    {c.name} <span className="hint">{c.version}</span>
                  </span>
                  <span className="hint">{c.license}</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
      <div className="actions">
        <button type="button" className="secondary" onClick={onBack}>
          Back
        </button>
      </div>
    </div>
  );
}
