// A monkey test of a packaged build: a vault with hosts, groups, keys and snippets, then a seeded
// random walk through the app (clicks on whatever is there, typing, keys, selects, the window
// resized), checking after every step that the page threw nothing, still renders and still
// answers. A failure names the seed, the step and the last steps taken, with a screenshot.
//
//   node monkey.mjs <binary> <out dir> <label>
//
// MONKEY_STEPS (500) and MONKEY_SEED (random, printed) repeat a run. Its hosts point where
// nothing listens (no server a random walk could change files on), and what would end the walk
// or leave the window (locking, installing an update, native file dialogs, erasing the device)
// isn't clicked.

import { mkdirSync, writeFileSync } from "node:fs";
import { createVault, session } from "./webdriver.mjs";

const [app, out, label] = process.argv.slice(2);
const STEPS = Number(process.env.MONKEY_STEPS || 500);
const SEED = Number(process.env.MONKEY_SEED || Math.floor(Math.random() * 2 ** 31));
const PASSWORD = "correct horse battery staple";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
mkdirSync(out, { recursive: true });

// mulberry32: the same seed, the same walk.
let state = SEED >>> 0;
const random = () => {
  state = (state + 0x6d2b79f5) >>> 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = (list) => list[Math.floor(random() * list.length)];
const between = (lo, hi) => lo + Math.floor(random() * (hi - lo + 1));

/** Something a person might type, or a cat walking over the keyboard. */
function gibberish() {
  return pick([
    () => Array.from({ length: between(1, 12) }, () => pick("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")).join(""),
    () => String(between(-99999, 99999)),
    () => pick(["web-1", "db.example.com", "10.0.0.1", "::1", "user@host", "~/.ssh/id_ed25519", "https://x.example/feed", "*.example.com", "0", "-1", "65536"]),
    () => Array.from({ length: between(1, 20) }, () => String.fromCharCode(between(32, 126))).join(""),
    () => pick(["čćžšđ", "日本語のホスト", "émoji 🚀🔑", "‮RTL", "a\u0000b", "<b>bold</b>", "' OR 1=1 --", "${HOME}", "%s%n", "\\\\server\\share"]),
    () => "x".repeat(between(200, 2000)),
    () => "",
  ])();
}

// Clicked: anything that takes a click, unless it ends the walk or leaves the window.
const CLICKABLE = "button, a[href], [role=tab], [role=menuitem], [role=radio], input[type=checkbox], summary, .lrow, .row-main, label.check";
const AVOID =
  /^(Lock|Install and restart|Quit)\b|lock (now|the vault)|erase|reset (this|the) (device|app)|delete (my|this|your) account|delete account|sign out everywhere|export|save \.cast|save .*csv|example csv|choose (a )?file|choose…|browse…|upload|download|open file|pick a file/i;

const PAGE_HOOKS = `
  if (!window.__monkey) {
    window.__monkey = [];
    window.addEventListener("error", (e) => window.__monkey.push("error: " + (e.message || e.error)));
    window.addEventListener("unhandledrejection", (e) => window.__monkey.push("unhandled rejection: " + (e.reason?.message ?? e.reason)));
  }
  return true;`;

const s = await session(app);
const trail = [];
const counts = {};
let step = 0;

/** What the walk does next, and what it did. */
async function act() {
  const roll = random();
  if (roll < 0.56) {
    // Something visible and enabled to click, by its index among them.
    const n = await s.exec(
      `const avoid = new RegExp(arguments[1], "i");
       window.__targets = [...document.querySelectorAll(arguments[0])].filter((e) => {
         const r = e.getBoundingClientRect();
         if (!r.width || !r.height || e.disabled || e.closest("[inert], [aria-hidden=true]")) return false;
         if (e.matches("input[type=file]") || e.closest("label")?.querySelector("input[type=file]")) return false;
         const text = (e.getAttribute("aria-label") || e.innerText || e.title || "").trim();
         return !avoid.test(text);
       });
       return window.__targets.length`,
      CLICKABLE,
      AVOID.source,
    );
    if (!n) return "click: nothing to click";
    const i = Math.floor(random() * n);
    return s.exec(
      `const e = window.__targets[arguments[0]];
       const what = (e.getAttribute("aria-label") || e.innerText || e.title || e.tagName).trim().replace(/\\s+/g, " ").slice(0, 60);
       e.scrollIntoView({ block: "nearest" }); e.click(); return "click: " + what`,
      i,
    );
  }
  if (roll < 0.76) {
    const text = gibberish();
    const typed = await s.exec(
      `const fields = [...document.querySelectorAll("input:not([type=checkbox]):not([type=radio]):not([type=file]), textarea")]
         .filter((e) => { const r = e.getBoundingClientRect(); return r.width && r.height && !e.disabled && !e.readOnly; });
       if (!fields.length) return null;
       const e = fields[Math.floor(arguments[1] * fields.length)];
       const proto = e instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
       const value = arguments[2] ? e.value + arguments[0] : arguments[0];
       e.focus();
       Object.getOwnPropertyDescriptor(proto, "value").set.call(e, value);
       e.dispatchEvent(new Event("input", { bubbles: true }));
       return (e.getAttribute("aria-label") || e.placeholder || e.name || e.type).slice(0, 40)`,
      text,
      random(),
      random() < 0.3,
    );
    return typed === null ? "type: no field" : `type into ${typed}: ${JSON.stringify(text.slice(0, 40))}`;
  }
  if (roll < 0.84) {
    const key = pick(["Escape", "Enter", "Tab", "ArrowDown", "ArrowUp", "Backspace", " "]);
    return s.exec(
      `const e = document.activeElement || document.body;
       const init = { key: arguments[0], bubbles: true, cancelable: true };
       e.dispatchEvent(new KeyboardEvent("keydown", init));
       e.dispatchEvent(new KeyboardEvent("keyup", init));
       // Enter in a form submits it, as a browser would.
       if (arguments[0] === "Enter" && e.form && e.tagName !== "TEXTAREA") e.form.requestSubmit();
       return "key: " + arguments[0] + " on " + (e.getAttribute?.("aria-label") || e.tagName)`,
      key,
    );
  }
  if (roll < 0.9) {
    return s.exec(
      `const all = [...document.querySelectorAll("select")].filter((e) => e.getBoundingClientRect().width && !e.disabled && e.options.length);
       if (!all.length) return "select: none";
       const e = all[Math.floor(arguments[0] * all.length)];
       const o = e.options[Math.floor(arguments[1] * e.options.length)];
       Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(e, o.value);
       e.dispatchEvent(new Event("change", { bubbles: true }));
       return "select: " + o.text.slice(0, 40)`,
      random(),
      random(),
    );
  }
  if (roll < 0.95) {
    // Typing into a session (never Enter: no command runs).
    const text = gibberish().replace(/[\r\n]/g, "").slice(0, 80) || "\u0003";
    const sent = await s.exec(
      `const t = document.querySelector(".terminal:not([hidden]) .xterm-helper-textarea");
       if (!t) return false;
       t.focus(); t.dispatchEvent(new InputEvent("input", { data: arguments[0], inputType: "insertText", bubbles: true })); return true`,
      text,
    );
    return sent ? `terminal: ${JSON.stringify(text.slice(0, 30))}` : "terminal: none open";
  }
  if (roll < 0.98) {
    return s.exec(
      `const items = [...document.querySelectorAll(".sidebar-nav button, .m-tabbar button, nav button")].filter((b) => b.getBoundingClientRect().width);
       if (!items.length) return "nav: none";
       const b = items[Math.floor(arguments[0] * items.length)]; b.click(); return "nav: " + b.innerText.trim().split("\\n")[0]`,
      random(),
    );
  }
  const [w, h] = pick([
    [390, 844],
    [640, 800],
    [860, 700],
    [1024, 700],
    [1280, 800],
    [1600, 900],
  ]);
  await s.resize(w, h);
  return `resize: ${w}×${h}`;
}

async function fail(why) {
  const report = [
    `${label}: ${why}`,
    `seed ${SEED}, step ${step} of ${STEPS} (MONKEY_SEED=${SEED} repeats it)`,
    "last steps:",
    ...trail.slice(-25).map((t) => `  ${t}`),
  ].join("\n");
  writeFileSync(`${out}/failure.txt`, `${report}\n`);
  await s.screenshot(`${out}/failure.png`).catch(() => {});
  throw new Error(report);
}

try {
  await createVault(s, PASSWORD);
  await s.resize(1280, 800);
  const invoke = (cmd, args) => s.exec(`return window.__TAURI_INTERNALS__.invoke(arguments[0], arguments[1])`, cmd, args);
  // Something on every page: a key, groups, hosts (where nothing listens), a snippet, a tunnel.
  const key = await invoke("key_generate", { label: "monkey", vaultId: null });
  const prod = (await invoke("group_save", { input: { name: "Production" } })).id;
  await invoke("group_save", { input: { name: "Staging" } });
  const auth = { kind: "key", keyId: key.id };
  for (const [name, addr, groupId] of [
    ["web-1", "127.0.0.9", prod],
    ["web-2", "127.0.0.10", prod],
    ["db-1", "127.0.0.11", null],
  ]) {
    await invoke("host_save", { input: { label: name, hostname: addr, port: 1, user: "deploy", auth, groupId, tags: ["monkey"] } });
  }
  await invoke("snippet_save", { input: { name: "Disk", body: "df -h", tags: ["ops"] } });
  await invoke("plugin:event|emit", { event: "vault-changed", payload: null });
  await sleep(500);
  console.log(`  ${label}: seed ${SEED}, ${STEPS} steps`);

  for (step = 1; step <= STEPS; step++) {
    await s.exec(PAGE_HOOKS);
    let did;
    try {
      did = await act();
    } catch (e) {
      // The page went away under a script (a click that closed what it was in): note it, go on.
      did = `(${String(e.message).slice(0, 80)})`;
    }
    trail.push(`${step}. ${did}`);
    const kind = did.split(/[: ]/)[0];
    counts[kind] = (counts[kind] ?? 0) + 1;
    await sleep(between(40, 220));
    let health;
    try {
      health = await s.exec(
        `const errors = (window.__monkey || []).splice(0);
         const root = document.getElementById("root");
         return { errors, rendered: !!root && root.childElementCount > 0 }`,
      );
    } catch (e) {
      await fail(`the app stopped answering: ${e.message}`);
    }
    if (health.errors.length) await fail(`the page threw: ${health.errors.join(" | ")}`);
    if (!health.rendered) await fail("the page went blank (a render crashed)");
  }
  console.log(`  ✓ ${label}: ${STEPS} random steps, nothing thrown (${Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(", ")}), seed ${SEED}`);
} finally {
  await s.close();
}
