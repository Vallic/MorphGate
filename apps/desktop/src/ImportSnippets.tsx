import { useState, type FormEvent } from "react";
import { errorText, snippets as snippetsApi, type CsvSnippet, type SnippetCsv, type SnippetView, type VaultEntry } from "./api";
import { FilePick, type PickedFile } from "./FilePick";
import { mobileOs, onIos } from "./mobile/useMobile";
import { Page } from "./Page";
import { personalVault, VaultField } from "./VaultField";

const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? "" : "s"}`;

/** Snippets from a CSV file: what it holds, ticked, then saved into the vault picked. One named
 * like a snippet that vault has replaces it, if ticked (it starts unticked). */
export function ImportSnippetsPage({
  snippets,
  vaults,
  onImported,
  onClose,
}: {
  snippets: SnippetView[];
  vaults: VaultEntry[];
  onImported: () => void;
  onClose: () => void;
}) {
  const [vaultId, setVaultId] = useState(personalVault(vaults));
  const [file, setFile] = useState<PickedFile | null>(null);
  const [csv, setCsv] = useState<SnippetCsv | null>(null);
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");
  const [example, setExample] = useState("");

  // The snippet of that name the vault has (any vault's, when there is no list of vaults).
  const saved = (s: CsvSnippet, vault = vaultId) => snippets.find((x) => x.name === s.name && (!vault || x.vaultId === vault));

  const choose = (f: PickedFile | null) => {
    setFile(f);
    setCsv(null);
    setError("");
    setDone("");
    if (!f) return;
    snippetsApi.readCsv(f.name, f.text).then(
      (c) => {
        setCsv(c);
        setPicked(new Set(c.snippets.flatMap((s, i) => (saved(s) ? [] : [i]))));
      },
      (e) => setError(errorText(e)),
    );
  };

  const toggle = (i: number) =>
    setPicked((s) => {
      const next = new Set(s);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!csv) return;
    setBusy(true);
    setError("");
    let added = 0;
    let replaced = 0;
    try {
      for (const i of [...picked].sort((a, b) => a - b)) {
        const s = csv.snippets[i];
        const old = saved(s);
        await snippetsApi.save({ id: old?.id, vaultId: old ? undefined : vaultId || undefined, name: s.name, body: s.body, tags: s.tags });
        if (old) replaced++;
        else added++;
      }
      setDone(`Imported ${plural(added + replaced, "snippet")}${replaced ? ` (${replaced} replaced one the vault had)` : ""}.`);
      setPicked(new Set());
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
      onImported();
    }
  };

  const list = csv?.snippets ?? [];
  return (
    <Page
      title="Import snippets"
      lead="From a CSV file: a first line naming the columns (Name, Command, Tags), then a snippet a line. Spreadsheets save it that way; a command of several lines stays one value."
      onClose={onClose}
    >
      <form className="stack import-hosts" onSubmit={submit}>
        {/* Android's picker filters by MIME type, and names CSV files more than one way: there, any file. */}
        <FilePick label="CSV file" accept={mobileOs && !onIos ? undefined : ".csv,.tsv,.txt"} picked={file ? [file] : []} onPick={(f) => choose(f[0] ?? null)} />
        <p className="hint">
          Not sure of the format?{" "}
          <button
            type="button"
            className="link"
            onClick={() => snippetsApi.saveCsvExample().then((where) => setExample(`Saved ${where}: open it in a spreadsheet, or pick it above.`), (e) => setError(errorText(e)))}
          >
            Download an example
          </button>
          {example ? ` ${example}` : " with a few snippets, one of several lines."}
        </p>
        {error && <p className="error">{error}</p>}
        {done && <p className="ok">{done}</p>}
        {csv?.warnings.map((w) => (
          <p key={w} className="warn">
            {w}
          </p>
        ))}
        {csv && list.length === 0 && <p className="hint">{file?.name} has no snippets to import.</p>}
        {list.length > 0 && (
          <>
            <div className="row">
              <h2 className="section-title grow">
                {plural(list.length, "snippet")} in {file?.name}
              </h2>
              <button type="button" className="link" onClick={() => setPicked(new Set(list.map((_, i) => i)))}>
                All
              </button>
              <button type="button" className="link" onClick={() => setPicked(new Set())}>
                None
              </button>
            </div>
            {list.some((s) => saved(s)) && <p className="hint">One the vault has already starts unticked; ticked, it replaces the vault's.</p>}
            <ul className="device-list import-list">
              {list.map((s, i) => {
                const lines = s.body.split("\n");
                return (
                  <li key={i}>
                    <label className="check">
                      <input type="checkbox" checked={picked.has(i)} onChange={() => toggle(i)} aria-label={`Import ${s.name}`} />
                    </label>
                    <div>
                      <strong>{s.name}</strong>
                      {lines.length > 1 && <span className="kind-badge">{plural(lines.length, "line")}</span>}
                      {saved(s) && <span className="kind-badge me">in the vault</span>}
                      <small className="mono">{lines[0]}</small>
                      {s.tags.length > 0 && <small>Tags: {s.tags.join(", ")}</small>}
                    </div>
                  </li>
                );
              })}
            </ul>
            <VaultField vaults={vaults} value={vaultId} onChange={setVaultId} />
            <div className="row">
              <button type="submit" className="primary" disabled={busy || picked.size === 0}>
                {busy ? "Importing…" : `Import ${plural(picked.size, "snippet")}`}
              </button>
            </div>
          </>
        )}
      </form>
    </Page>
  );
}
