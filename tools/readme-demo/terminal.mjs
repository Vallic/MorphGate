// A session MorphGate recorded (asciicast v2), replayed by xterm.js (headless) and drawn as SVG:
// each terminal row is a strip of the states it went through, and a CSS animation steps through
// them, so the file stays small and plays wherever SVG does (GitHub's README too).

import headless from "@xterm/headless";

const { Terminal } = headless;

// The Console theme (apps/desktop/src/themes.ts).
export const THEME = {
  background: "#0a1113",
  foreground: "#dce6e3",
  cursor: "#ffb547",
  ansi: ["#0a1113", "#ff6b6b", "#3ddbb6", "#ffb547", "#6cb6ff", "#d59cff", "#4fd1e8", "#dce6e3", "#5e7072", "#ff9494", "#7bebd0", "#ffcc80", "#9dcfff", "#e6c2ff", "#8ae4f2", "#ffffff"],
};

// Pauses longer than this are cut short.
const MAX_IDLE = 1.4;

const rgb = (n) => `#${n.toString(16).padStart(6, "0")}`;

/** xterm's 256 colors: the theme's 16, the 6×6×6 cube, 24 grays. */
function color256(n) {
  if (n < 16) return THEME.ansi[n];
  if (n < 232) {
    const c = n - 16;
    const v = (x) => (x === 0 ? 0 : 55 + x * 40);
    return rgb((v(Math.floor(c / 36)) << 16) | (v(Math.floor(c / 6) % 6) << 8) | v(c % 6));
  }
  const g = 8 + (n - 232) * 10;
  return rgb((g << 16) | (g << 8) | g);
}

/** A cell's look, as a key: foreground, background, bold, italic, underline. */
function styleOf(cell) {
  let fg = null;
  let bg = null;
  if (cell.isFgPalette()) {
    let n = cell.getFgColor();
    // Bold in bright colors, as xterm.js does by default.
    if (cell.isBold() && n < 8) n += 8;
    fg = color256(n);
  } else if (cell.isFgRGB()) fg = rgb(cell.getFgColor());
  if (cell.isBgPalette()) bg = color256(cell.getBgColor());
  else if (cell.isBgRGB()) bg = rgb(cell.getBgColor());
  if (cell.isInverse()) [fg, bg] = [bg ?? THEME.background, fg ?? THEME.foreground];
  if (cell.isDim() && fg) fg = `${fg}aa`;
  return [fg ?? "", bg ?? "", cell.isBold() ? 1 : 0, cell.isItalic() ? 1 : 0, cell.isUnderline() ? 1 : 0].join("|");
}

/** Replays `castText`: the screens it went through (a frame wherever the output pauses), with
 * long pauses cut short. `duration` is the last frame's time. */
export async function replay(castText) {
  const lines = castText.split("\n").filter((l) => l.trim());
  const header = JSON.parse(lines[0]);
  const events = lines.slice(1).map((l) => JSON.parse(l));
  const term = new Terminal({ cols: header.width, rows: header.height, allowProposedApi: true, scrollback: 0 });
  const write = (data) => new Promise((resolve) => term.write(data, resolve));
  const snapshot = () => {
    const b = term.buffer.active;
    const rows = [];
    for (let y = 0; y < term.rows; y++) {
      const line = b.getLine(b.viewportY + y);
      const runs = [];
      let run = null;
      for (let x = 0; line && x < term.cols; x++) {
        const cell = line.getCell(x);
        if (!cell || cell.getWidth() === 0) continue;
        const style = styleOf(cell);
        const ch = cell.getChars() || " ";
        if (run && run.style === style) run.text += ch;
        else runs.push((run = { x, style, text: ch }));
      }
      // Trailing blanks in the default look draw nothing.
      while (runs.length) {
        const last = runs[runs.length - 1];
        if (last.style.split("|")[1] !== "") break;
        last.text = last.text.replace(/ +$/, "");
        if (last.text) break;
        runs.pop();
      }
      rows.push(runs);
    }
    return { rows, cursor: [b.cursorX, b.cursorY] };
  };
  const frames = [];
  let clock = 0;
  let last = 0;
  for (let i = 0; i < events.length; i++) {
    const [t, kind, data] = events[i];
    if (kind === "o") await write(data);
    else if (kind === "r") term.resize(...data.split("x").map(Number));
    const next = events[i + 1]?.[0];
    if (next !== undefined && next - t < 0.02) continue;
    clock += Math.min(t - last, MAX_IDLE);
    last = t;
    frames.push({ at: clock, ...snapshot() });
  }
  return { title: header.title || "session", cols: header.width, rows: header.height, frames, duration: clock };
}

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** A row's runs: backgrounds, then a word at a time on its cells (renderers collapse runs of
 * spaces; `textLength` keeps any monospace font on the grid). */
function drawRow(runs, cw, lh) {
  let out = "";
  for (const r of runs) {
    const [fg, bg, bold, italic, underline] = r.style.split("|");
    if (bg) out += `<rect x="${(r.x * cw).toFixed(1)}" y="0" width="${(r.text.length * cw).toFixed(1)}" height="${lh}" fill="${bg}"/>`;
    for (const word of r.text.matchAll(/\S+/g)) {
      const attrs = [
        `x="${((r.x + word.index) * cw).toFixed(1)}"`,
        `y="${(lh / 2).toFixed(1)}"`,
        fg && `fill="${fg}"`,
        word[0].length > 1 && `textLength="${(word[0].length * cw).toFixed(1)}"`,
        +bold && `font-weight="700"`,
        +italic && `font-style="italic"`,
        +underline && `text-decoration="underline"`,
      ].filter(Boolean);
      out += `<text ${attrs.join(" ")}>${esc(word[0])}</text>`;
    }
  }
  return out;
}

/** The replay drawn on a grid of `cw` × `lh` cells: its SVG (rows from the top left, text
 * vertically centered in its row) and the CSS that animates it. The session starts `start`
 * seconds into an animation of `total` seconds; `id` keeps its class names apart. */
export function draw(r, { cw, lh, start, total, id = "t" }) {
  const pct = (t) => `${(((start + t) / total) * 100).toFixed(3)}%`;
  const strip = r.cols * cw;
  let css = "";
  let svg = "";
  for (let y = 0; y < r.rows; y++) {
    const states = [];
    const changes = [];
    for (const f of r.frames) {
      const key = JSON.stringify(f.rows[y]);
      let i = states.findIndex((s) => s.key === key);
      if (i < 0) i = states.push({ key, runs: f.rows[y] }) - 1;
      if (changes.length === 0 || changes[changes.length - 1].i !== i) changes.push({ at: f.at, i });
    }
    if (states.every((s) => s.runs.length === 0)) continue;
    const cells = states.map((s, i) => `<g transform="translate(${(i * strip).toFixed(1)} 0)">${drawRow(s.runs, cw, lh)}</g>`).join("");
    // Until the session starts (and once it's over) the row shows its first state.
    css += `.${id}${y}{animation:${id}${y} ${total.toFixed(2)}s steps(1,end) infinite}@keyframes ${id}${y}{0%{transform:translateX(0)}`;
    for (const c of changes) css += `${pct(c.at)}{transform:translateX(${(-c.i * strip).toFixed(1)}px)}`;
    css += "}";
    svg += `<g transform="translate(0 ${(y * lh).toFixed(1)})"><g class="${id}${y}">${cells}</g></g>`;
  }
  // The cursor: the theme's amber block, blinking, where each frame left it; hidden until the
  // session starts.
  css += `.${id}c{animation:${id}c ${total.toFixed(2)}s steps(1,end) infinite}@keyframes ${id}c{0%{opacity:0}`;
  let before = "";
  for (const f of r.frames) {
    const at = `translate(${(f.cursor[0] * cw).toFixed(1)}px,${(f.cursor[1] * lh).toFixed(1)}px)`;
    if (at !== before) css += `${pct(f.at)}{opacity:1;transform:${at}}`;
    before = at;
  }
  css += `}.${id}b{animation:${id}b 1.1s steps(1,end) infinite}@keyframes ${id}b{50%{opacity:0}}`;
  svg += `<g class="${id}c"><rect class="${id}b" x="0" y="${(lh * 0.1).toFixed(1)}" width="${cw.toFixed(1)}" height="${(lh * 0.8).toFixed(1)}" fill="${THEME.cursor}"/></g>`;
  return { css, svg };
}
