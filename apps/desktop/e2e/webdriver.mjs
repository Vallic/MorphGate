// A minimal W3C WebDriver client for tauri-driver.
//
// WebKitGTK's automation can't synthesize keyboard or mouse input on Wayland ("unsupported
// operation"), so clicks and typing go through the DOM: React sees the same events.

import { writeFileSync } from "node:fs";

const BASE = process.env.WD_URL || "http://127.0.0.1:4444";
const ELEMENT = "element-6066-11e4-a52e-4f735466cecf";

async function call(method, path, body, base = BASE) {
  const res = await fetch(base + path, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${JSON.stringify(json.value ?? json).slice(0, 400)}`);
  return json.value;
}

/** Starts the app at `application` and returns helpers bound to its window. `base`: the
 * tauri-driver to use (one per person when a scenario runs several apps). */
export async function session(application, base = BASE) {
  const { sessionId: id } = await call("POST", "/session", { capabilities: { alwaysMatch: { "tauri:options": { application } } } }, base);
  const wd = (method, path, body) => call(method, path, body, base);
  const s = {
    id,
    exec: (script, ...args) => wd("POST", `/session/${id}/execute/sync`, { script, args }),
    find: async (css) => (await wd("POST", `/session/${id}/element`, { using: "css selector", value: css }))[ELEMENT],

    /** Polls `fn` until it returns something truthy. */
    async wait(fn, what, ms = 20000) {
      const end = Date.now() + ms;
      let last;
      while (Date.now() < end) {
        try {
          last = await fn();
          if (last) return last;
        } catch (e) {
          last = e;
        }
        await new Promise((r) => setTimeout(r, 200));
      }
      throw new Error(`timed out waiting for ${what}: ${last}`);
    },

    /** Waits until some element matching `css` contains `text`; returns the page text. */
    waitText: (text, css = "body", ms) =>
      s.wait(
        // Case-insensitive: innerText applies text-transform (section labels are uppercase).
        () => s.exec(`return [...document.querySelectorAll(arguments[0])].some((e) => e.innerText.toLowerCase().includes(arguments[1].toLowerCase())) ? document.body.innerText : null`, css, text),
        `"${text}"`,
        ms,
      ),

    click: (css) => s.exec(`const e = document.querySelector(arguments[0]); if (!e) throw new Error("no " + arguments[0]); e.click(); return true`, css),

    /** Clicks the first enabled button whose text contains `text`. */
    clickButton: (text) =>
      s.exec(
        `const b = [...document.querySelectorAll("button")].find((b) => b.innerText.includes(arguments[0]) && !b.disabled);
         if (!b) throw new Error("no enabled button " + arguments[0]); b.click(); return true`,
        text,
      ),

    /** "Add from…" on a list page, then one of its items ("Import…", "Clouds…"). */
    addFrom: async (item) => {
      await s.clickButton("Add from…");
      await s.wait(() => s.exec(`return document.querySelector(".add-from .menu") ? true : null`), "the Add from menu");
      await s.exec(
        `const b = [...document.querySelectorAll(".add-from .menu button")].find((b) => b.innerText.startsWith(arguments[0]));
         if (!b) throw new Error("no menu item " + arguments[0]); b.click(); return true`,
        item,
      );
    },

    /** One of a page's tabs ("Identities", "Host CAs"). */
    pageTab: (label) =>
      s.exec(
        `const b = [...document.querySelectorAll(".page-tabs button")].find((b) => b.innerText.startsWith(arguments[0]));
         if (!b) throw new Error("no tab " + arguments[0]); b.click(); return true`,
        label,
      ),

    /** Sets an input's value the way React notices. */
    type: (css, text) =>
      s.exec(
        `const e = document.querySelector(arguments[0]); if (!e) throw new Error("no " + arguments[0]);
         const proto = e instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
         Object.getOwnPropertyDescriptor(proto, "value").set.call(e, arguments[1]);
         e.dispatchEvent(new Event("input", { bubbles: true })); return true`,
        css,
        text,
      ),

    /** Sets the input inside the label whose text contains `label`. */
    typeLabelled: async (label, text) => {
      await s.exec(
        `const l = [...document.querySelectorAll("label")].find((l) => l.innerText.includes(arguments[0]));
         if (!l) throw new Error("no label " + arguments[0]); l.querySelector("input, textarea").setAttribute("data-e2e", "target"); return true`,
        label,
      );
      await s.type("[data-e2e=target]", text);
      await s.exec(`document.querySelector("[data-e2e=target]").removeAttribute("data-e2e"); return true`);
    },

    /** Gives the file input `css` a file, as choosing it in the system's dialog does; waits until
     * the page shows its name (FilePick.tsx). */
    pickFile: async (css, name, text) => {
      await s.exec(
        `const i = document.querySelector(arguments[0]); if (!i) throw new Error("no " + arguments[0]);
         const dt = new DataTransfer(); dt.items.add(new File([arguments[2]], arguments[1])); i.files = dt.files;
         i.dispatchEvent(new Event("change", { bubbles: true })); return true`,
        css,
        name,
        text,
      );
      await s.wait(
        () => s.exec(`return [...document.querySelectorAll(".file-pick-name")].some((e) => e.innerText === arguments[0]) || null`, name),
        `${name}, chosen`,
      );
    },

    /** Picks the option whose text contains `text` in a select, the way React notices. */
    choose: (css, text) =>
      s.exec(
        `const e = document.querySelector(arguments[0]); if (!e) throw new Error("no " + arguments[0]);
         const o = [...e.options].find((o) => o.text.includes(arguments[1])); if (!o) throw new Error("no option " + arguments[1]);
         Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(e, o.value);
         e.dispatchEvent(new Event("change", { bubbles: true })); return true`,
        css,
        text,
      ),

    /** Whether an element matching `css` has exactly the text `text`. */
    hasText: (css, text) =>
      s.exec(`return [...document.querySelectorAll(arguments[0])].some((e) => e.innerText.trim() === arguments[1])`, css, text),

    /** Types into the terminal through xterm's input-event path (as an input method would). */
    typeTerminal: (text) =>
      s.exec(
        `const t = document.querySelector(".xterm-helper-textarea"); t.focus();
         t.dispatchEvent(new InputEvent("input", { data: arguments[0], inputType: "insertText", bubbles: true })); return true`,
        text,
      ),

    /** Text of the error message in the open panel, if any. */
    panelError: () => s.exec(`const e = document.querySelector(".panel .error"); return e ? e.innerText : null`),

    /** Resizes the window (CSS pixels), e.g. to a phone's 390 × 844. */
    resize: (width, height) => wd("POST", `/session/${id}/window/rect`, { width, height }),
    screenshot: async (path) => writeFileSync(path, Buffer.from(await wd("GET", `/session/${id}/screenshot`), "base64")),
    close: () => wd("DELETE", `/session/${id}`).catch(() => {}),
  };
  return s;
}

/** First launch: creates a vault with `password` and waits for the workspace. A new vault is
 * offered sync in a dialog: "Not now", unless `keepOffer` (the caller turns sync on in it). */
export async function createVault(s, password, shots, { keepOffer = false } = {}) {
  await s.waitText("Create vault", "body", 60000);
  await s.typeLabelled("Master password", password);
  await s.typeLabelled("Repeat password", password);
  // Enabled once the app has judged the password strong enough.
  await s.wait(
    () => s.exec(`return [...document.querySelectorAll("button")].some((b) => b.innerText.includes("Create vault") && !b.disabled) || null`),
    "the password judged strong enough",
  );
  await s.clickButton("Create vault");
  await s.waitText("I stored it somewhere safe", "body", 60000);
  if (shots) await s.screenshot(`${shots}/recovery-key.png`);
  await s.click("label.check input");
  await s.exec(`[...document.querySelectorAll("button.primary")].find((b) => !b.disabled).click(); return true`);
  // The desktop layout, or the phone one.
  await s.wait(() => s.exec(`return document.querySelector("button.brand, .m-home") ? true : null`), "the workspace", 30000);
  await s.wait(() => s.exec(`return document.querySelector("dialog.sync-offer[open]") ? true : null`), "the offer to turn sync on");
  if (shots) await s.screenshot(`${shots}/sync-offer.png`);
  if (keepOffer) return;
  await s.exec(`[...document.querySelectorAll("dialog.sync-offer button")].find((b) => b.innerText === "Not now").click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector("dialog.sync-offer") ? null : true`), "the offer to close");
}

/** Opens About and returns the "Version …" line. */
export async function openAbout(s) {
  await s.click("button.brand");
  const text = await s.waitText("Version");
  return text.match(/Version [^\n]*/)[0];
}
