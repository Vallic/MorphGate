// The phone layout, in the real app at a phone's size (390 × 844): import a key and save a
// host on the phone screens, connect from the host's sheet, use the extra-key row (Ctrl+C, ↑),
// browse and download over SFTP, then lock and unlock.
//
//   node mobile.mjs <app> <screenshots> <ssh key> <ssh port> <user>

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createVault, session } from "./webdriver.mjs";

const [app, shots, key, port, user] = process.argv.slice(2);
const PASSWORD = "correct horse battery staple";
const ok = (...a) => console.log("  ✓", ...a);

// Downloads land in the XDG download folder.
const downloads = `${process.env.HOME}/Downloads`;
mkdirSync(downloads, { recursive: true });
mkdirSync(process.env.XDG_CONFIG_HOME, { recursive: true });
writeFileSync(`${process.env.XDG_CONFIG_HOME}/user-dirs.dirs`, `XDG_DOWNLOAD_DIR="${downloads}"\n`);

const s = await session(app);
const rows = () => s.exec(`const r = document.querySelector(".m-term:not([hidden]) .xterm-rows"); return r ? r.innerText : ""`);
const prompt = () => s.wait(async () => /[$#]\s*$/m.test(await rows()) || null, "a shell prompt", 30000);
const tap = (css) => s.click(css);
const tapText = (css, text) =>
  s.exec(
    `const b = [...document.querySelectorAll(arguments[0])].find((e) => e.innerText.includes(arguments[1]));
     if (!b) throw new Error("nothing like " + arguments[1]); b.click(); return true`,
    css,
    text,
  );

try {
  await s.resize(390, 844);
  // The first screen's three choices fit a phone.
  await s.wait(() => s.exec(`return document.querySelector(".gate-choice") ? true : null`), "the first screen", 60000);
  assert.ok(
    await s.exec(`return [...document.querySelectorAll(".gate-choice button")].every((b) => b.scrollWidth <= b.clientWidth && b.getBoundingClientRect().height < 40)`),
    "the choices fit on one line",
  );
  await s.screenshot(`${shots}/first-screen.png`);
  await createVault(s, PASSWORD, shots);
  await s.wait(() => s.exec(`return document.querySelector(".m-home") ? true : null`), "the phone layout");
  ok("a phone-sized window gets the phone layout");

  // A key, then a host that uses it: the desktop editors, full screen under a back bar.
  await tapText(".m-nav button", "Keys");
  await tap('button[aria-label="New key"]');
  await s.waitText("New key", ".m-bar");
  await s.clickButton("Import");
  await s.typeLabelled("Label", "phone");
  await s.pickFile(".m-panel input[type=file]", "id_ed25519", readFileSync(key, "utf8"));
  await s.clickButton("Import key");
  await s.waitText("Public key", ".m-panel");
  await tap('.m-bar button[aria-label="Back"]');
  await tapText(".m-nav button", "Hosts");
  await tap('button[aria-label="New host"]');
  await s.waitText("New host", ".m-bar");
  await s.typeLabelled("Label", "box");
  await s.typeLabelled("Hostname or IP", "127.0.0.1");
  await s.typeLabelled("Port", port);
  await s.typeLabelled("User", user);
  await s.clickButton("SSH key");
  await s.exec(
    `[...document.querySelectorAll("label.check")].find((l) => l.innerText.includes("Record sessions")).querySelector("input").click(); return true`,
  );
  await s.screenshot(`${shots}/host-editor.png`);
  await s.click(".m-panel form button[type=submit]");
  await s.waitText("Edit host", ".m-bar");
  await tap('.m-bar button[aria-label="Back"]');
  await s.wait(() => s.hasText(".m-row-title .m-ellipsis", "box"), "box in the host list");
  await s.screenshot(`${shots}/hosts.png`);
  ok("imported a key and saved a host on the phone screens");

  // A host that signs in with an SSH agent, which phones don't have: marked desktop only, its
  // sheet says why and doesn't offer to connect.
  await tap('button[aria-label="New host"]');
  await s.waitText("New host", ".m-bar");
  await s.typeLabelled("Label", "agent-host");
  await s.typeLabelled("Hostname or IP", "127.0.0.1");
  await s.typeLabelled("Port", port);
  await s.typeLabelled("User", user);
  await s.clickButton("SSH agent");
  await s.click(".m-panel form button[type=submit]");
  await s.waitText("Edit host", ".m-bar");
  await tap('.m-bar button[aria-label="Back"]');
  await s.wait(
    () => s.exec(`const li = [...document.querySelectorAll(".m-row")].find((r) => r.innerText.includes("agent-host")); return li?.innerText.includes("desktop") || null`),
    "agent-host marked desktop only",
  );
  await tapText(".m-row", "agent-host");
  await s.waitText("Desktop only", ".m-sheet");
  assert.match(await s.exec(`return document.querySelector(".m-sheet").innerText`), /signs in with an SSH agent, which phones don't have/);
  assert.equal(await s.exec(`return [...document.querySelectorAll(".m-sheet button")].find((b) => b.innerText.trim() === "Connect").disabled`), true);
  await s.screenshot(`${shots}/desktop-only.png`);
  await s.exec(`document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" })); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".m-sheet") ? null : true`), "the sheet closed");
  ok("a host that needs a computer (an SSH agent here) is marked desktop only, and its sheet says why");

  // A snippet, for the terminal's menu below.
  await tapText(".m-nav button", "Snippets");
  await tap('button[aria-label="New snippet"]');
  await s.waitText("New snippet", ".m-bar");
  await s.typeLabelled("Name", "answer");
  await s.typeLabelled("Commands", "echo snippet-$((40+2))");
  await s.click(".m-panel form button[type=submit]");
  // Saved: the bar says "Snippet", no longer "New snippet".
  await s.wait(() => s.exec(`const t = document.querySelector(".m-bar")?.innerText ?? ""; return (t.includes("Snippet") && !t.includes("New snippet")) || null`), "the saved snippet");
  await tap('.m-bar button[aria-label="Back"]');

  // More, from a CSV file: the example the app saves to Downloads, chosen back.
  await tapText("button.m-link", "Import from a CSV file");
  await s.waitText("Import snippets", ".m-bar");
  await s.clickButton("Download an example");
  const example = `${downloads}/morphgate-snippets-example.csv`;
  await s.wait(() => existsSync(example) || null, "the example in Downloads");
  await s.pickFile(".m-panel input[type=file]", "morphgate-snippets-example.csv", readFileSync(example, "utf8"));
  await s.waitText("Import 5 snippets", ".m-panel");
  await s.screenshot(`${shots}/import-snippets.png`);
  await s.clickButton("Import 5 snippets");
  await s.waitText("Imported 5 snippets", ".m-panel");
  await tap('.m-bar button[aria-label="Back"]');
  await s.wait(() => s.hasText(".m-row-title .m-ellipsis", "Deploy"), "the imported snippets in the list");
  ok("imported snippets from the example CSV the app saves");

  // A VPN from its file: a WireGuard .conf, chosen; saving goes back to the list, which has it.
  await tapText(".m-nav button", "VPNs");
  await tap('button[aria-label="New VPN"]');
  await s.waitText("New VPN", ".m-bar");
  const wgKey = () => randomBytes(32).toString("base64");
  await s.pickFile(
    ".m-panel input[type=file]",
    "office.conf",
    `[Interface]\nPrivateKey = ${wgKey()}\nAddress = 10.8.0.2/32\n\n[Peer]\nPublicKey = ${wgKey()}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.8.0.0/24\n`,
  );
  await s.click(".m-panel form button[type=submit]");
  await s.wait(() => s.hasText(".m-row-title .m-ellipsis", "WireGuard vpn.example.com"), "the VPN from its file in the list");
  ok("added a WireGuard VPN from its .conf file");
  await tapText(".m-nav button", "Hosts");

  // The host's sheet: its route, how it signs in, Connect.
  await tapText(".m-row", "box");
  await s.waitText("Connect", ".m-sheet");
  assert.ok(await s.hasText(".m-auth strong", "phone"), "the sheet names the key");
  await s.screenshot(`${shots}/host-sheet.png`);
  await tapText(".m-sheet button", "Connect");
  await s.waitText("Trust and connect");
  await s.clickButton("Trust and connect");
  await prompt();
  ok("connected from the host's sheet");

  // Ctrl from the extra-key row interrupts a command; it lets go once used.
  await s.typeTerminal("sleep 30\r");
  await s.wait(async () => (await rows()).includes("sleep 30") || null, "the command");
  await tap('.m-keys button[aria-label="Control"]');
  assert.equal(await s.exec(`return document.querySelector('.m-keys button[aria-label="Control"]').getAttribute("aria-pressed")`), "true");
  await s.typeTerminal("c");
  await s.wait(async () => (await rows()).includes("^C") || null, "Ctrl+C to reach the shell", 10000);
  await prompt();
  assert.equal(await s.exec(`return document.querySelector('.m-keys button[aria-label="Control"]').getAttribute("aria-pressed")`), "false");
  // ↑ brings the last command back.
  await s.typeTerminal("echo arrow-$((20+22))\r");
  await s.wait(async () => (await rows()).split("\n").filter((l) => l.trim() === "arrow-42").length === 1 || null, "the first echo");
  await tap('.m-keys button[aria-label="Up arrow"]');
  await s.typeTerminal("\r");
  await s.wait(async () => (await rows()).split("\n").filter((l) => l.trim() === "arrow-42").length === 2 || null, "the echo again, from ↑");
  await s.screenshot(`${shots}/terminal.png`);
  ok("Ctrl+C and ↑ from the extra-key row");

  // Esc alone, then a snippet from the terminal's menu: the shell doesn't take the snippet's first
  // bytes for the key Esc modifies (it printed "[200~echo …" before).
  await tap('.m-keys button[aria-label="Escape"]');
  await tap('.m-bar button[aria-label="More"]');
  await tapText(".m-sheet button", "Snippets");
  await tapText(".m-sheet .m-row button", "Run");
  await s.wait(async () => (await rows()).split("\n").some((l) => l.trim() === "snippet-42") || null, "the snippet's output");
  ok("Esc, then a snippet from the menu: it runs as written");


  // Back to the hosts: the session stays open, as a card and a live square.
  await tap('.m-bar button[aria-label="Hosts"]');
  await s.wait(() => s.exec(`return document.querySelector(".m-session-card") && document.querySelector(".m-avatar .live") ? true : null`), "the open session");
  await s.screenshot(`${shots}/hosts-session.png`);
  ok("the session stays open behind the host list");

  // Files: browse into .ssh and download authorized_keys.
  await tapText(".m-row", "box");
  await tapText(".m-sheet button", "Files");
  await s.wait(() => s.exec(`return document.querySelector(".m-sftp:not([hidden]) .m-file") ? true : null`), "the remote files");
  await tapText(".m-sftp:not([hidden]) .m-file", ".ssh");
  await s.wait(() => s.hasText(".m-sftp:not([hidden]) .m-file-name", "authorized_keys"), "authorized_keys");
  await tapText(".m-sftp:not([hidden]) .m-file", "authorized_keys");
  await s.waitText("1 selected", ".m-selection");
  await s.screenshot(`${shots}/sftp.png`);
  await tapText(".m-selection button", "Download");
  await s.wait(() => s.exec(`return document.querySelector(".m-transfer.done") ? true : null`), "the download", 30000);
  assert.ok(existsSync(`${downloads}/authorized_keys`), "authorized_keys is in Downloads");
  assert.ok(readFileSync(`${downloads}/authorized_keys`, "utf8").startsWith("ssh-ed25519 "));
  ok("browsed over SFTP and downloaded a file to Downloads");

  // The terminal session was recorded: disconnect it, then play it back from Session logs.
  await tap('.m-sftp:not([hidden]) .m-bar button[aria-label="Back"]');
  await tap(".m-session-card");
  await tap('.m-bar button[aria-label="More"]');
  await tapText(".m-sheet button", "Disconnect");
  await tap('.m-sftp:not([hidden]) .m-bar button[aria-label="Back"]');
  await tapText(".m-nav button", "More");
  await tapText(".m-row", "Session logs");
  await s.wait(() => s.hasText(".panel.page .lname", "box"), "the recording in Session logs");
  await tapText(".panel.page .lrow .rowact button", "Play");
  await s.wait(
    async () => (await s.exec(`const r = document.querySelector(".player-screen .xterm-rows"); return r ? r.innerText : ""`)).includes("arrow-42") || null,
    "the recording to play",
    30000,
  );
  await s.screenshot(`${shots}/session-log.png`);
  await tap('.m-bar button[aria-label="Back"]');
  await tapText(".m-nav button", "Hosts");
  ok("recorded the session into the vault and played it back");

  // Lock: the phone unlock screen, then back in.
  await tap('button[aria-label="Lock vault"]');
  await s.waitText("Unlock MorphGate", ".m-unlock");
  await s.screenshot(`${shots}/unlock.png`);
  await s.typeLabelled("Master password", PASSWORD);
  await s.click(".m-unlock-actions button[type=submit]");
  await s.wait(() => s.exec(`return document.querySelector(".m-home") ? true : null`), "the host list again", 60000);
  ok("locked and unlocked on the phone unlock screen");
} catch (e) {
  await s.screenshot(`${shots}/failed.png`).catch(() => {});
  throw e;
} finally {
  await s.close();
}
