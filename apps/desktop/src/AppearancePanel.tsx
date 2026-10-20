import { useState, type FormEvent } from "react";
import {
  appearance,
  errorText,
  type AppTheme,
  type CursorStyle,
  type TerminalSettings,
  type ThemeSource,
  type VaultEntry,
  type VaultTheme,
} from "./api";
import { APP_THEME_SCHEMES, BUILTIN_THEMES, DEFAULT_FONT, DEFAULT_THEME, findTheme, type ThemeColors } from "./themes";
import { personalVault, VaultField } from "./VaultField";

interface Props {
  settings: TerminalSettings;
  themes: VaultTheme[];
  vaults: VaultEntry[];
  /** The app theme in effect ("system" resolved). */
  appTheme: "dark" | "light";
  /** Reloads settings and themes. */
  onChanged: () => void;
  onClose: () => void;
}

const DEFAULTS: TerminalSettings = {
  appTheme: "dark",
  theme: DEFAULT_THEME,
  followAppTheme: false,
  fontFamily: "",
  fontSize: 14,
  cursorStyle: "block",
  cursorBlink: true,
  boldBright: false,
  minimumContrast: null,
};

const APP_THEMES: { id: AppTheme; name: string }[] = [
  { id: "dark", name: "Console" },
  { id: "light", name: "Greenbar" },
  { id: "system", name: "Like the system" },
];

const FONTS: { css: string; name: string }[] = [
  { css: "", name: "Atkinson Hyperlegible Mono (default)" },
  { css: '"JetBrains Mono", monospace', name: "JetBrains Mono" },
  { css: '"Fira Code", monospace', name: "Fira Code" },
  { css: "ui-monospace, monospace", name: "System monospace" },
];

const CURSORS: { style: CursorStyle; name: string }[] = [
  { style: "block", name: "Block" },
  { style: "bar", name: "Bar" },
  { style: "underline", name: "Underline" },
];

type Scheme = ThemeColors & { id: string; style?: string; mood?: string; minimumContrast?: number };

export function AppearancePanel({ settings, themes, vaults, appTheme, onChanged, onClose }: Props) {
  const [error, setError] = useState("");
  const save = (next: TerminalSettings) => {
    setError("");
    appearance.setSettings(next).then(onChanged, (e) => setError(errorText(e)));
  };
  const schemes: Scheme[] = [...BUILTIN_THEMES, ...themes];
  const chosen = settings.followAppTheme ? APP_THEME_SCHEMES[appTheme] : settings.theme;
  // A scheme deleted elsewhere falls back to the default.
  const currentId = schemes.some((t) => t.id === chosen) ? chosen : DEFAULT_THEME;
  const current = findTheme(currentId, themes) as Scheme;
  const schemeContrast = BUILTIN_THEMES.find((b) => b.id === currentId)?.minimumContrast ?? 1;
  const contrast = settings.minimumContrast ?? schemeContrast;
  const vaultOf = (id: string) => vaults.find((v) => v.id === id);

  return (
    <div className="panel">
      <div className="settings-page">
        <header className="settings-head">
          <span className="hint">Settings</span>
          <h1>Terminal appearance</h1>
          <p className="hint">Applies to every host without its own scheme. A host can set one in its editor.</p>
        </header>
        {error && <p className="error">{error}</p>}

        <div className="settings-columns">
          <div className="settings-form">
            <fieldset>
              <legend className="section-title">App theme</legend>
              <div className="segmented" role="radiogroup" aria-label="App theme">
                {APP_THEMES.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    role="radio"
                    aria-checked={settings.appTheme === t.id}
                    className={settings.appTheme === t.id ? "on" : ""}
                    onClick={() => save({ ...settings, appTheme: t.id })}
                  >
                    {t.name}
                  </button>
                ))}
              </div>
            </fieldset>

            <fieldset>
              <legend className="section-title">Scheme</legend>
              <label className="check align-start">
                <input
                  type="checkbox"
                  checked={settings.followAppTheme}
                  onChange={(e) => save({ ...settings, followAppTheme: e.target.checked, minimumContrast: null })}
                />
                <span>
                  Follow the app theme
                  <small className="hint block">Console while the app is dark, Greenbar while it is light.</small>
                </span>
              </label>
              <div className={`scheme-grid ${settings.followAppTheme ? "following" : ""}`} role="radiogroup" aria-label="Scheme">
                {schemes.map((t) => (
                  <SchemeCard
                    key={t.id}
                    scheme={t}
                    selected={t.id === currentId}
                    vault={"vaultId" in t ? vaultOf((t as VaultTheme).vaultId) : undefined}
                    // Picking a scheme also takes its own minimum contrast.
                    onPick={() => save({ ...settings, theme: t.id, followAppTheme: false, minimumContrast: null })}
                    onDelete={
                      "vaultId" in t && vaultOf((t as VaultTheme).vaultId)?.access !== "read"
                        ? () =>
                            appearance.deleteTheme(t.id).then(
                              () => (t.id === settings.theme ? save({ ...settings, theme: DEFAULT_THEME }) : onChanged()),
                              (e) => setError(errorText(e)),
                            )
                        : undefined
                    }
                  />
                ))}
              </div>
            </fieldset>

            <fieldset>
              <legend className="section-title">Font</legend>
              <FontFields settings={settings} onSave={save} />
            </fieldset>

            <fieldset>
              <legend className="section-title">Cursor and text</legend>
              <div className="row wrap align-center">
                <div className="segmented grow" role="radiogroup" aria-label="Cursor style">
                  {CURSORS.map((c) => (
                    <button
                      key={c.style}
                      type="button"
                      role="radio"
                      aria-checked={settings.cursorStyle === c.style}
                      className={settings.cursorStyle === c.style ? "on" : ""}
                      onClick={() => save({ ...settings, cursorStyle: c.style })}
                    >
                      <span className={`cursor-glyph ${c.style}`} aria-hidden="true" />
                      {c.name}
                    </button>
                  ))}
                </div>
                <Toggle on={settings.cursorBlink} onChange={(v) => save({ ...settings, cursorBlink: v })}>
                  Blink
                </Toggle>
              </div>
              <Toggle on={settings.boldBright} onChange={(v) => save({ ...settings, boldBright: v })}>
                Draw bold text in bright colors
              </Toggle>
            </fieldset>

            <fieldset>
              <legend className="section-title">Minimum contrast</legend>
              <div className="row align-center">
                <input
                  className="grow contrast"
                  type="range"
                  min={1}
                  max={7}
                  step={0.5}
                  value={contrast}
                  aria-label="Minimum contrast ratio"
                  onChange={(e) => save({ ...settings, minimumContrast: Number(e.target.value) })}
                />
                <output className="contrast-value">{contrast}:1</output>
              </div>
              <div className="contrast-scale" aria-hidden="true">
                <span>1 off</span>
                <span>4.5 AA</span>
                <span>7 AAA</span>
              </div>
              <p className="hint">
                When a program draws a color too close to its background, the terminal lightens or darkens it until it reaches
                this ratio. {contrastNote(contrast)}
                {settings.minimumContrast !== null && (
                  <>
                    {" "}
                    <button type="button" className="link inline" onClick={() => save({ ...settings, minimumContrast: null })}>
                      Use the scheme's own ({schemeContrast}:1)
                    </button>
                  </>
                )}
              </p>
            </fieldset>

            <ImportScheme vaults={vaults} onImported={(t) => save({ ...settings, theme: t.id, followAppTheme: false, minimumContrast: null })} />

            <div className="row">
              <button type="button" className="secondary" onClick={() => save({ ...DEFAULTS, appTheme: settings.appTheme })}>
                Reset to defaults
              </button>
              <span className="spacer" />
              <button type="button" className="secondary" onClick={onClose}>
                Close
              </button>
            </div>
          </div>

          <aside className="settings-preview" aria-label="Preview">
            <span className="section-title">Preview · {current.name}</span>
            <Preview scheme={current} settings={settings} contrast={contrast} />
            {current.mood && <p className="hint">{current.mood}</p>}
          </aside>
        </div>
      </div>
    </div>
  );
}

function contrastNote(c: number): string {
  if (c <= 1) return "Off: colors are drawn exactly as the program asks.";
  if (c >= 7) return "At 7:1 every color meets WCAG AAA, which may shift a scheme's hues.";
  if (c >= 4.5) return "At 4.5:1 text meets WCAG AA.";
  return "Below 4.5:1 some colored text will not meet WCAG AA.";
}

function Toggle({ on, onChange, children }: { on: boolean; onChange: (on: boolean) => void; children: React.ReactNode }) {
  return (
    <button type="button" role="switch" aria-checked={on} className="toggle" onClick={() => onChange(!on)}>
      <span className={`switch-track ${on ? "on" : ""}`} aria-hidden="true">
        <i />
      </span>
      {children}
    </button>
  );
}

function FontFields({ settings, onSave }: { settings: TerminalSettings; onSave: (s: TerminalSettings) => void }) {
  const known = FONTS.some((f) => f.css === settings.fontFamily);
  const [custom, setCustom] = useState(known ? "" : settings.fontFamily);
  const [customMode, setCustomMode] = useState(!known);
  const size = settings.fontSize;
  return (
    <>
      <div className="row align-end">
        <label className="grow">
          <span>Family</span>
          <select
            value={customMode ? "custom" : settings.fontFamily}
            onChange={(e) => {
              if (e.target.value === "custom") {
                setCustomMode(true);
              } else {
                setCustomMode(false);
                onSave({ ...settings, fontFamily: e.target.value });
              }
            }}
          >
            {FONTS.map((f) => (
              <option key={f.name} value={f.css}>
                {f.name}
              </option>
            ))}
            <option value="custom">Another installed font…</option>
          </select>
        </label>
        <div className="stepper-field">
          <span id="font-size-label">Size</span>
          <div className="stepper" role="group" aria-labelledby="font-size-label">
            <button type="button" aria-label="Smaller" disabled={size <= 10} onClick={() => onSave({ ...settings, fontSize: size - 1 })}>
              −
            </button>
            <output>{size} px</output>
            <button type="button" aria-label="Larger" disabled={size >= 24} onClick={() => onSave({ ...settings, fontSize: size + 1 })}>
              +
            </button>
          </div>
        </div>
      </div>
      {customMode && (
        <form
          className="row"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            onSave({ ...settings, fontFamily: custom.trim() ? `"${custom.trim().replace(/"/g, "")}", monospace` : "" });
          }}
        >
          <input className="grow" value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="Cascadia Code" aria-label="Font name" spellCheck={false} />
          <button type="submit" className="secondary">
            Use font
          </button>
        </form>
      )}
    </>
  );
}

/** A few lines of a session in the scheme, font, cursor and bold setting. */
function Preview({ scheme, settings, contrast }: { scheme: Scheme; settings: TerminalSettings; contrast: number }) {
  const a = scheme.ansi;
  const bold = (normal: number) => (settings.boldBright ? a[normal + 8] : a[normal]);
  const prompt = (
    <>
      <b style={{ color: bold(2) }}>deploy@prod-db-02</b>:<b style={{ color: bold(4) }}>~/app</b>$
    </>
  );
  const cursor =
    settings.cursorStyle === "block"
      ? { background: scheme.cursor }
      : settings.cursorStyle === "bar"
        ? { borderLeft: `2px solid ${scheme.cursor}` }
        : { borderBottom: `2px solid ${scheme.cursor}` };
  return (
    <div className="preview-window">
      <div className="preview-bar">
        <span className="status-square connected" aria-hidden="true" />
        <strong>prod-db-02</strong>
        <span className="preview-style">{scheme.style ?? "Imported"}</span>
      </div>
      <div
        className="preview-body"
        style={{
          background: scheme.background,
          color: scheme.foreground,
          fontFamily: settings.fontFamily || DEFAULT_FONT,
          fontSize: settings.fontSize,
        }}
        data-contrast={contrast}
      >
        <div>{prompt} ls --color</div>
        <div>
          <b style={{ color: bold(4) }}>bin</b> <b style={{ color: bold(4) }}>config</b> <b style={{ color: bold(2) }}>deploy.sh</b>{" "}
          <span style={{ color: a[5] }}>pg.sock</span> <span style={{ color: a[1] }}>release.tar.gz</span>
        </div>
        <div>{prompt} git diff --stat</div>
        <div>
          {" "}config/pool.yml | 4 <span style={{ color: a[2] }}>++</span>
          <span style={{ color: a[1] }}>--</span>
        </div>
        <div style={{ color: a[8] }}># replica lag 2.4s, below the 5s alert</div>
        <div>
          <span style={{ color: a[3] }}>WARN</span> pgbouncer reload pending
        </div>
        <div>
          {prompt} <span className={`preview-cursor ${settings.cursorBlink ? "blink" : ""}`} style={cursor} />
        </div>
      </div>
    </div>
  );
}

function SchemeCard({
  scheme,
  selected,
  vault,
  onPick,
  onDelete,
}: {
  scheme: Scheme;
  selected: boolean;
  vault?: VaultEntry;
  onPick: () => void;
  onDelete?: () => void;
}) {
  const [sure, setSure] = useState(false);
  const a = scheme.ansi;
  return (
    <div className={`scheme-card ${selected ? "selected" : ""}`}>
      <button type="button" role="radio" aria-checked={selected} className="scheme-pick" onClick={onPick} title={scheme.mood ?? scheme.name}>
        <span className="scheme-mini" style={{ background: scheme.background, color: scheme.foreground }} aria-hidden="true">
          <span>
            <b style={{ color: a[2] }}>ops@db</b>:<span style={{ color: a[4] }}>~</span>$ ls
          </span>
          <span>
            <span style={{ color: a[4] }}>bin</span> <span style={{ color: a[2] }}>run.sh</span> <span style={{ color: a[1] }}>a.tgz</span>{" "}
            <span style={{ color: a[3] }}>!</span>
          </span>
          <span>
            <b style={{ color: a[2] }}>ops@db</b>:<span style={{ color: a[4] }}>~</span>$ <span style={{ background: scheme.cursor }}> </span>
          </span>
        </span>
        <span className="scheme-name">
          {selected && (
            <svg viewBox="0 0 24 24" width="12" height="12" aria-hidden="true">
              <path d="M5 12l5 5 9-10" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          )}
          {scheme.name}
        </span>
        {vault && <span className="scheme-tag">{vault.personal ? "Imported" : vault.label}</span>}
      </button>
      {onDelete &&
        (sure ? (
          <button type="button" className="danger small-button" onClick={onDelete}>
            Delete?
          </button>
        ) : (
          <button type="button" className="icon small scheme-delete" aria-label={`Delete ${scheme.name}`} title="Delete scheme" onClick={() => setSure(true)}>
            ×
          </button>
        ))}
    </div>
  );
}

function ImportScheme({ vaults, onImported }: { vaults: VaultEntry[]; onImported: (t: VaultTheme) => void }) {
  const [open, setOpen] = useState(false);
  const [from, setFrom] = useState<ThemeSource["kind"]>("file");
  const [path, setPath] = useState("");
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const [vaultId, setVaultId] = useState(personalVault(vaults));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const ready = from === "file" ? path.trim() !== "" : text.trim() !== "";

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError("");
    const source: ThemeSource = from === "file" ? { kind: "file", path } : { kind: "text", text };
    appearance.importTheme(source, name, vaultId || undefined).then(
      (t) => (setPath(""), setText(""), setName(""), setBusy(false), setOpen(false), onImported(t)),
      (err) => (setError(errorText(err)), setBusy(false)),
    );
  };

  if (!open) {
    return (
      <button type="button" className="secondary align-start" onClick={() => setOpen(true)}>
        Import a scheme…
      </button>
    );
  }
  return (
    <form className="stack import-scheme" onSubmit={submit}>
      <span className="section-title">Import a scheme</span>
      <p className="hint">
        From another terminal's theme file: Ghostty, Alacritty (.toml), iTerm2 (.itermcolors) or Windows Terminal (JSON).
        Collections like terminalcolors.com and iTerm2-Color-Schemes offer these. Imported schemes live in the vault and sync.
      </p>
      <div className="segmented two small" role="radiogroup">
        <button type="button" role="radio" aria-checked={from === "file"} className={from === "file" ? "on" : ""} onClick={() => setFrom("file")}>
          From file
        </button>
        <button type="button" role="radio" aria-checked={from === "text"} className={from === "text" ? "on" : ""} onClick={() => setFrom("text")}>
          Paste
        </button>
      </div>
      {from === "file" ? (
        <label>
          <span>Theme file</span>
          <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="~/Downloads/catppuccin-mocha.itermcolors" spellCheck={false} />
        </label>
      ) : (
        <label>
          <span>Theme</span>
          <textarea className="mono" rows={6} value={text} onChange={(e) => setText(e.target.value)} placeholder={"background = #1e1e2e\nforeground = #cdd6f4\npalette = 0=#45475a\n…"} spellCheck={false} />
        </label>
      )}
      <label>
        <span>Name</span>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="From the file" />
      </label>
      <VaultField vaults={vaults} value={vaultId} onChange={setVaultId} />
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button type="button" className="secondary" onClick={() => setOpen(false)}>
          Cancel
        </button>
        <button type="submit" className="primary" disabled={!ready || busy}>
          {busy ? "Importing…" : "Import and use"}
        </button>
      </div>
    </form>
  );
}
