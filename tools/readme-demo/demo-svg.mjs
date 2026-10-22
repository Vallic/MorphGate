// The README's demo: MorphGate as the AppImage showed it, drawn as an animated SVG. Scene one is
// the Hosts page (the sidebar and the list of hosts); a pointer clicks a host; scene two is its
// session in a tab, the recording replayed in the app's own terminal area. The scenes are what
// demo.mjs captured from the app (snapshot.js: boxes, text and icons where the layout put them),
// drawn in the app's fonts, embedded (SIL Open Font License, apps/desktop/src/assets/fonts).
//
//   node demo-svg.mjs <demo.json> <out.svg>

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { draw, replay, THEME } from "./terminal.mjs";

const [input, output] = process.argv.slice(2);
if (!input || !output) {
  console.error("usage: node demo-svg.mjs <demo.json> <out.svg>");
  process.exit(2);
}
const demo = JSON.parse(readFileSync(input, "utf8"));
const fonts = join(dirname(fileURLToPath(import.meta.url)), "../../apps/desktop/src/assets/fonts");

// The story, in seconds: the Hosts page, the pointer moving to the host, the click; then the
// session from its start; the last screen held before it all starts over.
const MOVE_FROM = 0.7;
const MOVE_TO = 1.8;
const CLICK = 2.0;
const CONNECT = 2.4;
const HOLD = 3.5;

const session = await replay(demo.cast);
const total = CONNECT + session.duration + HOLD;
const pct = (t) => `${((t / total) * 100).toFixed(3)}%`;
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const n = (v) => +v.toFixed(1);
const W = demo.s1.width;
const H = demo.s1.height;

// Font families as classes (the computed ones, each a long list).
const families = new Map();
const familyClass = (f) => {
  if (!families.has(f)) families.set(f, `f${families.size}`);
  return families.get(f);
};
// Clips as clip paths, the whole window needing none.
const clips = new Map();
const clipAttr = (c) => {
  if (!c || (c.x <= 0 && c.y <= 0 && c.x + c.w >= W && c.y + c.h >= H)) return "";
  const key = [c.x, c.y, c.w, c.h].map((v) => Math.round(v)).join(",");
  if (!clips.has(key)) clips.set(key, `c${clips.size}`);
  return ` clip-path="url(#${clips.get(key)})"`;
};

/** A captured screen: its boxes, then icons and text. */
function scene(s) {
  let out = `<rect width="${W}" height="${H}" fill="${s.background}"/>`;
  for (const b of s.boxes) {
    const shape = `x="${n(b.x)}" y="${n(b.y)}" width="${n(b.w)}" height="${n(b.h)}"${b.radius ? ` rx="${n(Math.min(b.radius, b.w / 2, b.h / 2))}"` : ""}`;
    const paint = b.stroke
      ? `fill="none" stroke="${b.stroke}" stroke-width="${b.strokeWidth}" transform="translate(${b.strokeWidth / 2} ${b.strokeWidth / 2})"`
      : `fill="${b.fill}"`;
    const inset = b.stroke ? shape.replace(/width="([\d.]+)" height="([\d.]+)"/, (_, w, h) => `width="${n(w - b.strokeWidth)}" height="${n(h - b.strokeWidth)}"`) : shape;
    out += `<rect ${inset} ${paint}${b.opacity < 1 ? ` opacity="${n(b.opacity)}"` : ""}${clipAttr(b.clip)}/>`;
  }
  for (const i of s.icons) {
    // The page's own SVG, placed where it was, its currentColor the element's color.
    const svg = i.svg.replace(/^<svg\b([^>]*)>/, (_, attrs) => {
      const kept = attrs.replace(/\s(width|height|class|style|x|y|aria-hidden)="[^"]*"/g, "");
      return `<svg${kept} x="${n(i.x)}" y="${n(i.y)}" width="${n(i.w)}" height="${n(i.h)}" color="${i.color}"${i.opacity < 1 ? ` opacity="${n(i.opacity)}"` : ""}>`;
    });
    const cx = n(i.x + i.w / 2);
    const cy = n(i.y + i.h / 2);
    const turned = (i.turns ?? []).reduceRight(
      (inner, m) => `<g transform="translate(${cx} ${cy}) ${m.replace(/,/g, "")} translate(${-cx} ${-cy})">${inner}</g>`,
      svg,
    );
    const clip = clipAttr(i.clip);
    out += clip ? `<g${clip}>${turned}</g>` : turned;
  }
  for (const t of s.texts) {
    const attrs = [
      `x="${n(t.x)}"`,
      `y="${n(t.y + t.h / 2)}"`,
      `class="${familyClass(t.family)}"`,
      `font-size="${t.size}"`,
      t.weight !== "400" && `font-weight="${t.weight}"`,
      t.style === "italic" && `font-style="italic"`,
      t.spacing && `letter-spacing="${t.spacing}"`,
      `fill="${t.color}"`,
      t.text.length > 3 && `textLength="${n(t.w)}"`,
    ].filter(Boolean);
    out += `<text ${attrs.join(" ")}${clipAttr(t.clip)}>${esc(t.text)}</text>`;
  }
  return out;
}

const one = scene(demo.s1);
const two = scene(demo.s2);

// The session in the terminal area of scene two, on the grid the app laid it out on.
const area = demo.s2.terminal;
const cw = area.w / session.cols;
const lh = area.h / session.rows;
const term = draw(session, { cw, lh, start: CONNECT, total });

// The pointer: from below right of the host to it, a click, then gone with scene one.
const { target } = demo;
const tx = target.x + Math.min(40, target.w / 2);
const ty = target.y + target.h / 2;
const fx = tx + 260;
const fy = ty + 170;
const pointer = `<g class="ptr"><path d="M0 0v17l4.2-4.1 3 6.9 3.1-1.3-3-6.8H13z" fill="#ffffff" stroke="#0a1113" stroke-width="1.2" stroke-linejoin="round"/></g>`;
const ripple = `<circle class="rip" cx="${n(tx)}" cy="${n(ty)}" r="14" fill="none" stroke="${THEME.ansi[2]}" stroke-width="2"/>`;

const font = (family, file, weight, style = "normal") =>
  `@font-face{font-family:"${family}";src:url(data:font/woff2;base64,${readFileSync(join(fonts, file)).toString("base64")}) format("woff2");font-weight:${weight};font-style:${style}}`;
const t = () => `${total.toFixed(2)}s`;
const css = [
  font("Atkinson Hyperlegible Next", "AtkinsonHyperlegibleNext-Variable.woff2", "200 800"),
  font("Atkinson Hyperlegible Mono", "AtkinsonHyperlegibleMono-Variable.woff2", "200 800"),
  font("Martian Mono", "MartianMono-Variable.woff2", "100 800"),
  [...families].map(([f, c]) => `.${c}{font-family:${f}}`).join(""),
  `text{dominant-baseline:central;white-space:pre}`,
  `.term text{font-family:${area.family}}`,
  `.s1{animation:s1 ${t()} steps(1,end) infinite}@keyframes s1{0%{opacity:1}${pct(CONNECT)}{opacity:0}}`,
  `.s2{animation:s2 ${t()} steps(1,end) infinite}@keyframes s2{0%{opacity:0}${pct(CONNECT)}{opacity:1}}`,
  `.ptr{animation:ptr ${t()} infinite}@keyframes ptr{0%{transform:translate(${n(fx)}px,${n(fy)}px);opacity:1}` +
    `${pct(MOVE_FROM)}{transform:translate(${n(fx)}px,${n(fy)}px);animation-timing-function:ease-in-out}` +
    `${pct(MOVE_TO)}{transform:translate(${n(tx)}px,${n(ty)}px)}${pct(CONNECT + 0.4)}{transform:translate(${n(tx)}px,${n(ty)}px);opacity:1}` +
    `${pct(CONNECT + 0.7)}{transform:translate(${n(tx)}px,${n(ty)}px);opacity:0}100%{transform:translate(${n(tx)}px,${n(ty)}px);opacity:0}}`,
  `.rip{transform-box:fill-box;transform-origin:center;animation:rip ${t()} infinite}@keyframes rip{0%{opacity:0;transform:scale(.3)}` +
    `${pct(CLICK)}{opacity:0;transform:scale(.3)}${pct(CLICK + 0.05)}{opacity:.9;transform:scale(.4)}${pct(CLICK + 0.5)}{opacity:0;transform:scale(1.4)}100%{opacity:0}}`,
  term.css,
].join("");

const defs = [...clips]
  .map(([key, id]) => {
    const [x, y, w, h] = key.split(",");
    return `<clipPath id="${id}"><rect x="${x}" y="${y}" width="${w}" height="${h}"/></clipPath>`;
  })
  .join("");

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="MorphGate: the Hosts page, then a click on ${esc(session.title)} opens its session">
<title>MorphGate: connecting to ${esc(session.title)}</title>
<!-- Drawn by tools/readme-demo from the MorphGate AppImage. Fonts: Atkinson Hyperlegible Next and Mono (Braille Institute of America), Martian Mono (The Martian Mono Project Authors), under the SIL Open Font License 1.1. -->
<style>${css}</style>
<defs>${defs}<clipPath id="window"><rect width="${W}" height="${H}" rx="10"/></clipPath><clipPath id="screen"><rect width="${n(area.w)}" height="${n(area.h)}"/></clipPath></defs>
<g clip-path="url(#window)">
<g class="s2">${two}<g class="term" transform="translate(${n(area.x)} ${n(area.y)})" clip-path="url(#screen)" font-size="${area.size}" fill="${THEME.foreground}">${term.svg}</g></g>
<g class="s1">${one}${ripple}</g>
${pointer}
</g>
<rect x="0.5" y="0.5" width="${W - 1}" height="${H - 1}" rx="10" fill="none" stroke="#24343a"/>
</svg>
`;
writeFileSync(output, svg);
console.log(`${output}: ${W}×${H}, ${session.frames.length} frames, ${total.toFixed(1)} s, ${(svg.length / 1024).toFixed(0)} KiB`);
