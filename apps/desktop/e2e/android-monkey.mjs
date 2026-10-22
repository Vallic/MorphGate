// Android's monkey on the Android app: random touches, swipes, rotations and keys, from the
// platform's own tool (`adb shell monkey`), on an emulator or a phone that adb reaches. The app is
// a debug build, whose WebView answers DevTools: through it the first screen creates a vault (then
// a key, groups, hosts where nothing listens and a snippet go in), the unlock screen opens it, and
// every error the page throws is heard. The walk runs
// in rounds, each from a fresh start with the app unlocked and its task pinned (so Back and swipes
// stay in it). A crash, a hang (ANR), a Rust panic, an uncaught error or a blank page fails it.
//
//   node android-monkey.mjs <debug apk> <out dir>
//
// MONKEY_ROUNDS (5) of MONKEY_EVENTS (1000) each; MONKEY_SEED (random, printed) seeds round n
// with seed + n. A seed repeats the walk's events, though not always what they hit: the app's
// timing differs from run to run.

import { execFileSync, spawn } from "node:child_process";
import { createWriteStream, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const [apk, out] = process.argv.slice(2);
const PKG = process.env.MONKEY_PACKAGE || "com.morphgate.app";
const ROUNDS = Number(process.env.MONKEY_ROUNDS || 5);
const EVENTS = Number(process.env.MONKEY_EVENTS || 1000);
const SEED = Number(process.env.MONKEY_SEED || Math.floor(Math.random() * 2 ** 31));
const PASSWORD = "correct horse battery staple";
const ADB = process.env.ADB || "adb";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
mkdirSync(out, { recursive: true });

const adb = (...args) => execFileSync(ADB, args, { encoding: "utf8", maxBuffer: 64 << 20 }).trim();
/** As `adb`, "" when it fails (`pidof` of a process that isn't running, say). */
const tryAdb = (...args) => {
  try {
    return adb(...args);
  } catch {
    return "";
  }
};

async function until(what, fn, ms = 90000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** The app's page over the DevTools protocol: `evaluate` runs an expression (awaiting a promise),
 * `thrown` collects what the page throws (during `phase`: the app's start, the setup, the walk),
 * `gone` says why the connection ended. */
async function devtools(pid) {
  const socket = `webview_devtools_remote_${pid}`;
  await until("the WebView's DevTools socket", () => new RegExp(`@${socket}$`, "m").test(tryAdb("shell", "cat", "/proc/net/unix")));
  const port = adb("forward", "tcp:0", `localabstract:${socket}`);
  const page = await until("the app's page", async () => {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
      return list.find((p) => p.type === "page" && p.webSocketDebuggerUrl);
    } catch {
      return null;
    }
  });
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((ok, fail) => {
    ws.onopen = ok;
    ws.onerror = () => fail(new Error("DevTools didn't connect"));
  });
  const waiting = new Map();
  const d = { thrown: [], gone: null, phase: "start" };
  let next = 1;
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && waiting.has(msg.id)) {
      const w = waiting.get(msg.id);
      waiting.delete(msg.id);
      if (msg.error) w.fail(new Error(msg.error.message));
      else w.ok(msg.result);
    } else if (msg.method === "Runtime.exceptionThrown") {
      const e = msg.params.exceptionDetails;
      d.thrown.push(`${d.phase}: ${(e.exception?.description ?? e.text).split("\n")[0]}`);
    } else if (msg.method === "Inspector.targetCrashed") {
      d.gone = "the page crashed";
    } else if (msg.method === "Inspector.detached") {
      d.gone = `the page went away (${msg.params.reason})`;
    }
  };
  ws.onclose = () => {
    d.gone ??= "DevTools disconnected";
    for (const w of waiting.values()) w.fail(new Error(d.gone));
    waiting.clear();
  };
  const send = (method, params = {}) =>
    new Promise((ok, fail) => {
      if (d.gone) return fail(new Error(d.gone));
      const id = next++;
      waiting.set(id, { ok, fail });
      ws.send(JSON.stringify({ id, method, params }));
    });
  d.evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error((r.exceptionDetails.exception?.description ?? r.exceptionDetails.text).split("\n")[0]);
    return r.result.value;
  };
  d.close = () => {
    ws.close();
    tryAdb("forward", "--remove", `tcp:${port}`);
  };
  await send("Inspector.enable");
  await send("Runtime.enable");
  return d;
}

// In the page: typing into the field a label names, clicking a button by its text (as a person
// would, through the app's own screens: the page is never reloaded, which would drop the app's
// calls still under way).
const PAGE = `
  const type = (label, value) => {
    const e = [...document.querySelectorAll("label")].find((l) => l.innerText.includes(label))?.querySelector("input");
    if (!e) return false;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(e, value);
    e.dispatchEvent(new Event("input", { bubbles: true }));
    return true;
  };
  const click = (text, css = "button") => {
    const b = [...document.querySelectorAll(css)].find((b) => b.innerText.trim() === text && !b.disabled);
    b?.click();
    return !!b;
  };`;
const inPage = (d, body) => d.evaluate(`(() => { ${PAGE}\n${body} })()`).catch(() => null);
const WORKSPACE = `return document.querySelector(".m-home, button.brand") ? true : null`;

/** The vault unlocked (created, with something on every page, the first time) through the app's
 * first screen or its unlock screen, the workspace showing. */
async function unlock(d) {
  const status = await until("the app's script", () =>
    d.evaluate(`window.__TAURI_INTERNALS__ ? window.__TAURI_INTERNALS__.invoke("vault_status") : null`).catch(() => null),
  );
  if (status === "uninitialized") {
    await until("the first screen", () => inPage(d, `return type("Master password", ${JSON.stringify(PASSWORD)}) && type("Repeat password", ${JSON.stringify(PASSWORD)})`));
    await until("Create vault", () => inPage(d, `return click("Create vault")`));
    await until("the recovery key", () => inPage(d, `const c = document.querySelector("label.check input"); if (!c) return null; if (!c.checked) c.click(); return true`));
    await until("Open my vault", () => inPage(d, `return click("Open my vault")`));
    await until("the workspace", () => inPage(d, WORKSPACE));
    await d.evaluate(`(async () => {
      const invoke = window.__TAURI_INTERNALS__.invoke;
      const key = await invoke("key_generate", { label: "monkey", vaultId: null });
      const prod = (await invoke("group_save", { input: { name: "Production" } })).id;
      await invoke("group_save", { input: { name: "Staging" } });
      const auth = { kind: "key", keyId: key.id };
      for (const [label, hostname, groupId] of [["web-1", "127.0.0.9", prod], ["web-2", "127.0.0.10", prod], ["db-1", "127.0.0.11", null]]) {
        await invoke("host_save", { input: { label, hostname, port: 1, user: "deploy", auth, groupId, tags: ["monkey"] } });
      }
      await invoke("snippet_save", { input: { name: "Disk", body: "df -h", tags: ["ops"] } });
      await invoke("plugin:event|emit", { event: "vault-changed", payload: null });
      return true;
    })()`);
  } else if (status === "locked") {
    await until("the unlock screen", () => inPage(d, `click("Use master password"); return type("Master password", ${JSON.stringify(PASSWORD)})`));
    await until("Unlock", () => inPage(d, `return click("Unlock", "button[type=submit]")`));
  }
  await until("the workspace", () => inPage(d, WORKSPACE));
}

/** The app's task, pinned: the monkey's Back and swipes can't take it out of the app. */
function pin() {
  const stacks = tryAdb("shell", "am", "stack", "list");
  const recents = stacks ? "" : tryAdb("shell", "dumpsys", "activity", "recents");
  const id =
    stacks.split("\n").find((l) => l.includes(`${PKG}/`))?.match(/taskId=(\d+)/)?.[1] ??
    recents.match(new RegExp(`#(\\d+) type=standard A=\\d+:${PKG.replace(/\./g, "\\.")}\\b`))?.[1];
  if (id) tryAdb("shell", "am", "task", "lock", id);
  return !!id;
}

/** What went wrong in a round's logcat (lines "date time pid tid level tag: message"): a Rust
 * panic, a Java exception or a fatal signal in the app's process, or a native crash's report. */
function logProblems(log, pid) {
  return log
    .split("\n")
    .filter((l) => (l.split(/\s+/)[2] === pid && / panicked at |FATAL EXCEPTION|Fatal signal/.test(l)) || l.includes(`>>> ${PKG} <<<`))
    .slice(0, 10);
}

async function fail(dir, round, why, extra = []) {
  const report = [`Android monkey: ${why}`, `seed ${SEED}, round ${round} of ${ROUNDS} (MONKEY_SEED=${SEED} repeats it)`, ...extra].join("\n");
  writeFileSync(`${out}/failure.txt`, `${report}\n`);
  writeFileSync(`${dir}/end.png`, execFileSync(ADB, ["exec-out", "screencap", "-p"], { maxBuffer: 64 << 20 }));
  throw new Error(report);
}

// From no data: round 1 creates the vault (so not a phone whose MorphGate you use).
tryAdb("shell", "am", "task", "lock", "stop");
adb("install", "-r", apk);
adb("shell", "pm", "clear", PKG);
console.log(`  Android monkey: seed ${SEED}, ${ROUNDS} rounds of ${EVENTS} events`);
const totals = { rejected: 0, pins: 0 };

for (let round = 1; round <= ROUNDS; round++) {
  const dir = `${out}/round-${round}`;
  mkdirSync(dir, { recursive: true });
  tryAdb("shell", "am", "task", "lock", "stop");
  tryAdb("shell", "am", "force-stop", PKG);
  tryAdb("logcat", "-c");
  const logcat = spawn(ADB, ["logcat", "-v", "threadtime"], { stdio: ["ignore", "pipe", "ignore"] });
  logcat.stdout.pipe(createWriteStream(`${dir}/logcat.txt`));
  let d = null;
  try {
    adb("shell", "monkey", "-p", PKG, "-c", "android.intent.category.LAUNCHER", "1");
    const pid = await until("the app's process", () => tryAdb("shell", "pidof", PKG));
    d = await devtools(pid);
    d.phase = "setup";
    await unlock(d);
    if (pin()) totals.pins++;
    await sleep(1000);
    d.phase = "walk";

    // The walk: mostly touches and swipes, some turns of the screen. No system keys or app
    // switches (they'd only leave the app), no random key codes (some sleep the device); typing
    // happens on the on-screen keyboard.
    const walk = spawn(
      ADB,
      [
        "shell", "monkey", "-p", PKG, "-s", String(SEED + round), "--throttle", "100",
        "--pct-syskeys", "0", "--pct-appswitch", "0", "--pct-anyevent", "0", "--pct-trackball", "0",
        "--pct-touch", "45", "--pct-motion", "20", "--pct-rotation", "3",
        "--ignore-security-exceptions", "-v", "-v", String(EVENTS),
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let text = "";
    walk.stdout.on("data", (b) => (text += b));
    walk.stderr.on("data", (b) => (text += b));
    await new Promise((r) => walk.on("close", r));
    writeFileSync(`${dir}/monkey.txt`, text);
    await sleep(2000);

    const after = tryAdb("shell", "pidof", PKG);
    const crash = text.match(/^\/\/ (CRASH|NOT RESPONDING): .*$/m);
    const rendered = !d.gone && (await d.evaluate(`(document.getElementById("root")?.childElementCount ?? 0) > 0`).catch(() => false));
    const focus = tryAdb("shell", "dumpsys", "window").match(/mCurrentFocus=Window\{\S+ \S+ ([^}]+)\}/)?.[1] ?? "?";
    const injected = text.match(/Events injected: (\d+)/)?.[1] ?? "0";
    totals.rejected += (text.match(/\/\/ Rejecting start of Intent/g) ?? []).length;
    logcat.kill();
    await sleep(500);
    const problems = logProblems(readFileSync(`${dir}/logcat.txt`, "utf8"), pid);

    if (crash) await fail(dir, round, `the app ${crash[1] === "CRASH" ? "crashed" : "stopped responding"}`, text.split("\n").filter((l) => l.startsWith("// ")).slice(0, 20));
    if (problems.length) await fail(dir, round, "the app's log has a crash or a panic", problems);
    if (d.thrown.length) await fail(dir, round, `the page threw: ${d.thrown.join(" | ")}`);
    if (after !== pid) await fail(dir, round, `the app's process ${after ? `restarted (${pid} → ${after})` : "ended"}`);
    if (d.gone) await fail(dir, round, d.gone);
    if (!rendered) await fail(dir, round, "the page went blank (a render crashed)");
    writeFileSync(`${dir}/end.png`, execFileSync(ADB, ["exec-out", "screencap", "-p"], { maxBuffer: 64 << 20 }));
    console.log(`  round ${round}: ${injected} events, nothing crashed or threw; in front: ${focus}`);
  } finally {
    logcat.kill();
    d?.close();
  }
}
tryAdb("shell", "am", "task", "lock", "stop");
console.log(
  `  ✓ Android monkey: ${ROUNDS} rounds of ${EVENTS} events, nothing crashed, hung, panicked or threw (pinned ${totals.pins} of ${ROUNDS}; ` +
    `${totals.rejected} starts of other apps refused), seed ${SEED}`,
);
