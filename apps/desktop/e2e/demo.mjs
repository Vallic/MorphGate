// The README's demo: the packaged AppImage with a few hosts in groups. Its Hosts page is captured,
// web-1 (the test sshd) is clicked, and its session view is captured and recorded with the app's
// own session recording; tools/readme-demo/demo-svg.mjs draws it all (demo.json) as an animated
// SVG. The host's login command runs a clean bash with a demo prompt in a demo home (a small git
// repository); this machine's user and loopback address are swapped for demo ones in the captured
// text, and nothing is saved that still shows them or this computer's home folder.
//
//   node demo.mjs <AppImage> <out dir> <ssh key> <ssh port> <user>

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { userInfo } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createVault, session } from "./webdriver.mjs";

const [app, out, key, port, user] = process.argv.slice(2);
const PASSWORD = "correct horse battery staple";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const snapshotJs = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../../tools/readme-demo/snapshot.js"), "utf8");

// The demo home: an app with a few releases.
const home = `${out}/home-demo`;
const repo = `${home}/shop`;
mkdirSync(`${repo}/config`, { recursive: true });
const git = (...args) =>
  execFileSync("git", ["-C", repo, ...args], {
    env: { ...process.env, GIT_AUTHOR_NAME: "Ana", GIT_AUTHOR_EMAIL: "ana@example.com", GIT_COMMITTER_NAME: "Ana", GIT_COMMITTER_EMAIL: "ana@example.com" },
  });
git("init", "-q", "-b", "main");
for (const [file, text, message] of [
  ["README.md", "# shop\n", "Start the shop"],
  ["config/nginx.conf", "server { listen 80; }\n", "Serve it with nginx"],
  ["Dockerfile", "FROM php:8.4-fpm\n", "Run in a container"],
  ["config/nginx.conf", "server { listen 443 ssl; }\n", "TLS everywhere"],
]) {
  writeFileSync(`${repo}/${file}`, text);
  git("add", "-A");
  git("commit", "-q", "-m", message);
}
git("tag", "v2.4.1");

// sshd starts it in the real home: it moves to the demo's first. A clean bash: no rc files, a
// demo prompt (the theme's green and blue), this home.
const login =
  `cd '${home}' && exec env -i TERM=xterm-256color LANG=C.UTF-8 HOME='${home}' PATH=/usr/local/bin:/usr/bin:/bin GIT_PAGER=cat ` +
  `PS1='\\[\\e[32m\\]deploy@web-1\\[\\e[0m\\]:\\[\\e[34m\\]\\w\\[\\e[0m\\]$ ' bash --norc --noprofile -i`;
// What the captured text shows instead of this machine's.
const mask = [[`${user}@127.0.0.1:${port}`, "deploy@10.0.12.34:22"]];

let s = await session(app);
try {
  await createVault(s, PASSWORD);
  await s.resize(1024, 600);
  const invoke = (cmd, args) => s.exec(`return window.__TAURI_INTERNALS__.invoke(arguments[0], arguments[1])`, cmd, args);
  const capture = () => s.exec(`${snapshotJs}; return snapshot(arguments[0]);`, mask);
  const k = await invoke("key_import", { input: { label: "deploy", source: { kind: "file", path: key }, passphrase: null } });
  const group = async (name) => (await invoke("group_save", { input: { name } })).id;
  const production = await group("Production");
  const staging = await group("Staging");
  const host = (label, hostname, groupId, tags, extra = {}) =>
    invoke("host_save", { input: { label, hostname, port: 22, user: "deploy", auth: { kind: "key", keyId: k.id }, groupId, tags, ...extra } });
  await host("web-1", "127.0.0.1", production, ["shop"], { port: Number(port), user, recordSessions: true, loginCommand: login });
  await host("web-2", "10.0.12.35", production, ["shop"]);
  await host("db-1", "10.0.12.40", production, ["postgres"]);
  await host("staging", "10.0.20.11", staging, ["shop"]);
  await host("bastion", "bastion.shop.example", null, []);
  // Made behind the page's back: it reloads its lists on vault-changed.
  await invoke("plugin:event|emit", { event: "vault-changed", payload: null });
  const sidebarHost = (label) =>
    `[...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === ${JSON.stringify(label)})`;
  await s.wait(() => s.exec(`return ${sidebarHost("web-1")} ? true : null`), "web-1 listed");

  // Its host key, pinned once beforehand: the demo's connection asks nothing.
  const rows = () => s.exec(`return document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows")?.innerText ?? ""`);
  const prompts = async () => ((await rows()).match(/deploy@web-1:/g) ?? []).length;
  await s.exec(`${sidebarHost("web-1")}.querySelector(".row-main").click(); return true`);
  await s.waitText("Trust and connect", "body", 60000);
  await s.clickButton("Trust and connect");
  await s.wait(async () => ((await prompts()) >= 1 ? true : null), "the demo prompt", 60000);
  await s.click(".tab.active .close");

  // Scene one: the Hosts page.
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await sleep(800);
  const row = `[...document.querySelectorAll(".panel.page .lrow")].find((r) => r.querySelector(".lname")?.innerText === "web-1").querySelector(".lnamebtn")`;
  const target = await s.exec(`const r = ${row}.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }`);
  const s1 = await capture();
  await s.screenshot(`${out}/scene1.png`);

  // Scene two: the click, and the session.
  await s.exec(`${row}.click(); return true`);
  await s.wait(async () => ((await prompts()) >= 1 ? true : null), "the demo prompt", 60000);
  await sleep(600);
  const s2 = await capture();
  await s.screenshot(`${out}/scene2.png`);
  if (!s2.terminal) throw new Error("no terminal in the session view");
  await sleep(600);
  // Typed as a person would: a key at a time, a pause before Enter.
  for (const command of ["uptime", "cd shop && git log --oneline --decorate -4", "ls"]) {
    const before = await prompts();
    for (const ch of command) {
      await s.typeTerminal(ch);
      await sleep(45 + Math.round(Math.random() * 70));
    }
    await sleep(450);
    await s.typeTerminal("\r");
    await s.wait(async () => ((await prompts()) > before ? true : null), `the prompt after ${command}`, 30000);
    await sleep(1400);
  }
  await sleep(1500);
  // Closing the tab ends the session and its recording.
  await s.click(".tab.active .close");
  const log = await s.wait(async () => {
    const logs = (await invoke("session_logs", { hostId: null })).filter((l) => l.endedAt);
    return logs.length >= 2 ? logs.sort((a, b) => b.startedAt - a.startedAt)[0] : null;
  }, "the recording, ended", 30000);
  const cast = await invoke("session_log_cast", { id: log.id });
  const demo = JSON.stringify({ s1, s2, target, cast });
  // It goes in a public README: nothing of this computer's.
  for (const leak of [userInfo().homedir, "127.0.0.1", `${user}@`]) {
    if (demo.includes(leak)) throw new Error(`the demo shows ${leak}: not saved`);
  }
  writeFileSync(`${out}/demo.json`, demo);
  console.log(`  ✓ captured the demo: ${out}/demo.json`);
} catch (e) {
  await s.screenshot(`${out}/failed.png`).catch(() => {});
  throw e;
} finally {
  await s.close();
}
