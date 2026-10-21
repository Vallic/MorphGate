// The packaged AppImage, for real: create a vault, SSH to a local sshd, refuse a tampered update,
// install the signed one, restart, and come back as the new version with the vault intact.
//
//   node appimage.mjs <AppImage> <screenshots> <feed dir> <ssh key> <ssh port> <user> <version> <next>

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { appendFileSync, chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname } from "node:path";
import { createHash, createHmac, generateKeyPairSync } from "node:crypto";
import { fileURLToPath } from "node:url";
import { createVault, openAbout, session } from "./webdriver.mjs";

const [app, shots, feed, key, port, user, version, next] = process.argv.slice(2);

/** A new Ed25519 key as PuTTY saves it (`.ppk`, version 3, unencrypted), its public line and
 * fingerprint. */
function puttyKey(comment) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = (k, part) => Buffer.from(k.export({ format: "jwk" })[part], "base64url");
  const str = (b) => {
    const b2 = Buffer.from(b);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b2.length);
    return Buffer.concat([len, b2]);
  };
  const blob = Buffer.concat([str("ssh-ed25519"), str(raw(publicKey, "x"))]);
  const secret = str(raw(privateKey, "d"));
  const mac = createHmac("sha256", Buffer.alloc(0))
    .update(Buffer.concat([str("ssh-ed25519"), str("none"), str(comment), str(blob), str(secret)]))
    .digest("hex");
  const lines = (b) => b.toString("base64").match(/.{1,64}/g);
  const ppk = [
    "PuTTY-User-Key-File-3: ssh-ed25519",
    "Encryption: none",
    `Comment: ${comment}`,
    `Public-Lines: ${lines(blob).length}`,
    ...lines(blob),
    `Private-Lines: ${lines(secret).length}`,
    ...lines(secret),
    `Private-MAC: ${mac}`,
  ].join("\n");
  return {
    ppk: `${ppk}\n`,
    publicLine: `ssh-ed25519 ${blob.toString("base64")} ${comment}`,
    fingerprint: `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/, "")}`,
  };
}
const sha = (f) => createHash("sha256").update(readFileSync(f)).digest("hex");
const PASSWORD = "correct horse battery staple";
const ok = (...a) => console.log("  ✓", ...a);

/** Quick connect to the test sshd with the key file, chosen in the form. */
async function quickConnect(s) {
  await s.typeLabelled("Host", "127.0.0.1");
  await s.typeLabelled("Port", port);
  await s.typeLabelled("User", user);
  await s.exec(`[...document.querySelectorAll(".segmented [role=radio]")].find((b) => b.innerText === "Key").click(); return true`);
  await s.pickFile(".panel input[type=file]", basename(key), readFileSync(key, "utf8"));
  await s.exec(`document.querySelector("button[type=submit].primary").click(); return true`);
}

/** Clicks "Check now" in About and waits for that check to finish: the update shown before it
 *  may be from the check at launch, and Install takes the one the last finished check found. */
async function checkNow(s) {
  await s.exec(`const b = [...document.querySelectorAll("button")].find((b) => b.innerText.includes("Check now") && !b.disabled);
    if (!b) throw new Error("no enabled button Check now");
    window.__checked = false;
    new MutationObserver((_, o) => { if (b.innerText.includes("Check now")) { window.__checked = true; o.disconnect(); } })
      .observe(b, { subtree: true, childList: true, characterData: true });
    b.click(); return true`);
  await s.wait(() => s.exec(`return window.__checked || null`), "the update check", 60000);
}

let s = await session(app);
try {
  // A guessable master password is refused, and the form says why.
  await s.waitText("Create vault", "body", 60000);
  await s.typeLabelled("Master password", "Summer2024!");
  await s.typeLabelled("Repeat password", "Summer2024!");
  await s.waitText("Too easy to guess", ".meter", 30000);
  assert.equal(await s.exec(`return [...document.querySelectorAll("button")].find((b) => b.innerText.includes("Create vault")).disabled`), true);
  // Painted before the screenshot (WebKitGTK's can be a frame behind).
  await s.exec(`return new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`);
  assert.equal(await s.exec(`return document.querySelector("input[type=password]").value`), "Summer2024!");
  await s.screenshot(`${shots}/weak-password.png`);
  await createVault(s, PASSWORD, shots);
  ok("refused a guessable master password, saying why; created a vault with a strong one");

  // Quick connect with a key file; the new host key is trusted once.
  await quickConnect(s);
  await s.waitText("Trust and connect");
  await s.screenshot(`${shots}/hostkey-unknown.png`);
  await s.clickButton("Trust and connect");
  await s.wait(() => s.exec(`const r = document.querySelector(".xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`), "a shell prompt");
  await s.typeTerminal("echo mg-e2e-$((6*7))\r");
  await s.wait(() => s.exec(`return document.querySelector(".xterm-rows").innerText.includes("mg-e2e-42") ? true : null`), "the command's output");
  // The route bar shows the key the host is now pinned to.
  const pinned = await s.wait(
    () => s.exec(`const p = document.querySelector(".route-bar .pinned-key"); return p ? p.title : null`),
    "the pinned host key",
  );
  assert.match(pinned, /ssh-ed25519 SHA256:[A-Za-z0-9+/]{43}$/);
  await s.screenshot(`${shots}/terminal.png`);
  ok("ran a command over SSH; the route bar shows the pinned key");

  // A different key pinned for the host: the connection is refused, both keys shown.
  const knownHosts = `${process.env.XDG_DATA_HOME}/com.morphgate.desktop/known_hosts`;
  const original = readFileSync(knownHosts, "utf8");
  const OTHER = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDRbMaf7RI+oSkPOCPrFjPoMWJEIu96Drte4Q3r9OQYR";
  writeFileSync(knownHosts, original.replace(/(\S+) ssh-ed25519 \S+/, `$1 ${OTHER}`));
  await s.click("button.tab.new");
  await quickConnect(s);
  await s.waitText("Host key changed");
  const dialog = await s.exec(`return document.querySelector("dialog.hostkey.changed").innerText`);
  assert.match(dialog, /SHA256:cS8T\+87q\/3OOXl3\+m1vOyYgIbZg5M0XGFpdH\+32DQwg/, "the pinned key");
  assert.ok(dialog.includes(pinned.split(" ").at(-1)), "the presented key");
  const line = original.split("\n").findIndex((l) => l.includes(`]:${port} `)) + 1;
  assert.ok(dialog.includes(`known_hosts line ${line}`), `known_hosts line ${line}`);
  await s.screenshot(`${shots}/hostkey-changed.png`);
  await s.exec(`document.querySelector("dialog.hostkey.changed button.primary").click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector("dialog.hostkey") ? null : true`), "the dialog to close");
  await s.click(".tab.active .close");
  writeFileSync(knownHosts, original);
  ok("refused a changed host key, showing the pinned and the presented one");

  // Hosts from ~/.ssh/config: a host behind a jump host, both with a key file, beside what
  // can't be imported (a forward, a Match block).
  mkdirSync(`${process.env.HOME}/.ssh`, { recursive: true });
  copyFileSync(key, `${process.env.HOME}/.ssh/e2e_key`);
  chmodSync(`${process.env.HOME}/.ssh/e2e_key`, 0o600);
  writeFileSync(
    `${process.env.HOME}/.ssh/config`,
    `Host e2e-jump\n  HostName 127.0.0.1\n  Port ${port}\n  User ${user}\n  IdentityFile ~/.ssh/e2e_key\n\n` +
      `Host e2e-box\n  HostName localhost\n  Port ${port}\n  ProxyJump e2e-jump\n  LocalForward 8080 localhost:80\n\n` +
      `Host *\n  User ${user}\n  IdentityFile ~/.ssh/e2e_key\n  ServerAliveInterval 30\n\n` +
      `Match exec "true"\n  User nobody\n`,
  );
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await s.addFrom("Import…");
  await s.wait(() => s.exec(`return document.querySelectorAll(".import-list li").length === 2 || null`), "the two hosts in ~/.ssh/config");
  const listed = await s.exec(`return document.querySelector(".import-hosts").innerText`);
  assert.match(listed, /Match blocks are skipped/);
  assert.match(listed, /e2e-box[\s\S]*via e2e-jump/);
  assert.match(listed, /Not imported: LocalForward 8080 localhost:80/);
  assert.match(listed, /~\/\.ssh\/e2e_key[\s\S]*Copied into the vault/);
  await s.screenshot(`${shots}/import-preview.png`);
  await s.clickButton("Import 2 hosts");
  const imported = await s.wait(() => s.exec(`const p = document.querySelector(".import-result p.ok"); return p ? p.innerText : null`), "the import");
  assert.equal(imported, "Imported 2 hosts and 1 key.");
  // Read again: both are in the vault now, so nothing is ticked.
  await s.wait(() => s.exec(`return document.querySelectorAll(".import-list li .kind-badge.me").length === 2 || null`), "both in the vault");
  assert.equal(await s.exec(`return document.querySelectorAll(".import-list input:checked").length`), 0);
  await s.screenshot(`${shots}/import-done.png`);
  // e2e-box goes through e2e-jump (pinned above); its own host key, localhost's, is new.
  await s.clickButton("Close");
  await s.exec(
    `[...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === "e2e-box").querySelector(".row-main").click(); return true`,
  );
  await s.waitText("Trust and connect", "body", 60000);
  await s.clickButton("Trust and connect");
  await s.wait(() => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`), "a shell on e2e-box", 60000);
  await s.exec(
    `const t = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-helper-textarea"); t.focus();
     t.dispatchEvent(new InputEvent("input", { data: arguments[0], inputType: "insertText", bubbles: true })); return true`,
    "echo mg-import-$((6*7))\r",
  );
  await s.wait(() => s.exec(`return document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows").innerText.includes("mg-import-42") ? true : null`), "e2e-box's output");
  await s.screenshot(`${shots}/import-session.png`);
  await s.click(".tab.active .close");
  ok("imported two hosts and a key from ~/.ssh/config; connected to one through the other");

  // Hosts from other clients, at sshd's second address so they're new to the vault: a PuTTY
  // session with a new key in a .ppk file (and a Telnet one that isn't imported), a CSV file in
  // Termius' template with a group, a Royal TS document whose folder names the credentials.
  const home = process.env.HOME;
  const putty = puttyKey("e2e-putty");
  // sshd's authorized_keys is shared with the scenarios after this one (teams counts its lines):
  // the PuTTY key is in it only for this step.
  const authorized = `${dirname(key)}/home/.ssh/authorized_keys`;
  const authorizedBefore = readFileSync(authorized);
  appendFileSync(authorized, `${putty.publicLine}\n`);
  mkdirSync(`${home}/keys`, { recursive: true });
  writeFileSync(`${home}/keys/e2e-putty.ppk`, putty.ppk);
  mkdirSync(`${home}/.putty/sessions`, { recursive: true });
  writeFileSync(
    `${home}/.putty/sessions/E2E%20PuTTY`,
    `HostName=127.0.0.2\nPortNumber=${port}\nUserName=${user}\nProtocol=ssh\nPublicKeyFile=${home}/keys/e2e-putty.ppk\nPortForwardings=L8080=localhost:80\n`,
  );
  writeFileSync(`${home}/.putty/sessions/router`, "HostName=10.0.0.1\nProtocol=telnet\n");
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await s.addFrom("Import…");
  await s.clickButton("PuTTY");
  await s.wait(() => s.exec(`return document.querySelector(".import-list")?.innerText.includes("E2E PuTTY") || null`), "the PuTTY session");
  let page = await s.exec(`return document.querySelector(".import-hosts").innerText`);
  assert.match(page, /Not SSH, so not imported: router \(Telnet\)/);
  assert.match(page, /E2E PuTTY[\s\S]*key e2e-putty\.ppk/);
  assert.match(page, /Not imported: port forwards \(L8080=localhost:80\)/);
  assert.ok(page.includes(`~/keys/e2e-putty.ppk`) && page.includes(`Copied into the vault (${putty.fingerprint})`), page);
  await s.screenshot(`${shots}/import-putty.png`);
  await s.clickButton("Import 1 host");
  const fromPutty = await s.wait(() => s.exec(`const p = document.querySelector(".import-result p.ok"); return p ? p.innerText : null`), "the PuTTY import");
  assert.equal(fromPutty, "Imported 1 host and 1 key.");

  const readFile = async (radio, file) => {
    await s.clickButton(radio);
    await s.type(".import-hosts .row input:not([type=file])", file);
    await s.exec(`[...document.querySelectorAll(".import-hosts button")].find((b) => b.innerText === "Read").click(); return true`);
  };
  writeFileSync(
    `${home}/hosts.csv`,
    `Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,Password\n` +
      `E2E Lab,e2e-csv,"lab,e2e",csv.e2e.invalid,ssh,2200,ops,\n` +
      `,switch,,10.0.0.9,telnet,23,,\n`,
  );
  await readFile("CSV", "~/hosts.csv");
  await s.wait(() => s.exec(`return document.querySelector(".import-list")?.innerText.includes("e2e-csv") || null`), "the CSV host");
  page = await s.exec(`return document.querySelector(".import-hosts").innerText`);
  assert.match(page, /e2e-csv[\s\S]*group E2E Lab[\s\S]*ops@csv\.e2e\.invalid:2200[\s\S]*Tags: lab, e2e/);
  assert.match(page, /Not SSH, so not imported: switch \(telnet\)/);
  await s.clickButton("Import 1 host");
  await s.wait(() => s.exec(`return document.querySelector(".import-result p.ok")?.innerText === "Imported 1 host, 0 keys and 1 group." || null`), "the CSV import");

  writeFileSync(
    `${home}/Connections.rtsx`,
    `<?xml version="1.0" encoding="utf-8"?>\n<RTSZDocument>\n` +
      `<RoyalFolder><ID>f1</ID><Name>Connections</Name></RoyalFolder>\n` +
      `<RoyalFolder><ID>f2</ID><ParentID>f1</ParentID><Name>Servers</Name><CredentialMode>4</CredentialMode><CredentialName>e2e</CredentialName></RoyalFolder>\n` +
      `<RoyalCredential><ID>c1</ID><Name>e2e</Name><UserName>${user}</UserName><PrivateKeyPath>~/.ssh/e2e_key</PrivateKeyPath></RoyalCredential>\n` +
      `<RoyalSSHConnection><ID>s1</ID><ParentID>f2</ParentID><Name>e2e-royal</Name><URI>royal.e2e.invalid</URI><Port>${port}</Port><CredentialMode>1</CredentialMode></RoyalSSHConnection>\n` +
      `<RoyalRDSConnection><ID>r1</ID><Name>Windows</Name><URI>win.e2e.invalid</URI></RoyalRDSConnection>\n` +
      `</RTSZDocument>\n`,
  );
  await readFile("Royal TS", "~/Connections.rtsx");
  await s.wait(() => s.exec(`return document.querySelector(".import-list")?.innerText.includes("e2e-royal") || null`), "the Royal TS connection");
  page = await s.exec(`return document.querySelector(".import-hosts").innerText`);
  assert.match(page, new RegExp(`e2e-royal[\\s\\S]*key e2e_key[\\s\\S]*group Servers[\\s\\S]*${user}@royal\\.e2e\\.invalid:${port}`));
  assert.match(page, /Not SSH, so not imported: RDS \(1\)/);
  assert.match(page, /The vault has this key: the hosts use that one/);
  await s.screenshot(`${shots}/import-royal.png`);
  await s.clickButton("Import 1 host");
  await s.wait(() => s.exec(`return document.querySelector(".import-result p.ok")?.innerText === "Imported 1 host, 0 keys and 1 group." || null`), "the Royal TS import");
  await s.clickButton("Close");

  // The PuTTY session signs in with its key, now an OpenSSH key in the vault.
  await s.exec(
    `[...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === "E2E PuTTY").querySelector(".row-main").click(); return true`,
  );
  await s.waitText("Trust and connect", "body", 60000);
  await s.clickButton("Trust and connect");
  await s.wait(() => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`), "a shell on E2E PuTTY", 60000);
  await s.click(".tab.active .close");
  writeFileSync(authorized, authorizedBefore);
  ok("imported a PuTTY session (its .ppk key converted), a CSV file with a group and a Royal TS document; signed in with the PuTTY key");

  // A key with an OpenSSH certificate from the run's user CA, which sshd trusts. The key itself
  // isn't in authorized_keys: signing in proves the certificate went along (sshd logs its ID).
  const certified = `${home}/keys/certified`;
  const sshdLog = () => readFileSync(`${dirname(key)}/sshd.log`, "utf8");
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "certified", "-f", certified]);
  execFileSync("ssh-keygen", ["-q", "-s", `${dirname(key)}/user_ca`, "-I", "e2e-cert", "-n", user, "-V", "-5m:+1h", `${certified}.pub`]);
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Keys")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Keys" || null`), "the Keys page");
  await s.clickButton("New key");
  await s.exec(`[...document.querySelectorAll('.panel button[role="radio"]')].find((b) => b.innerText === "Import").click(); return true`);
  await s.typeLabelled("Label", "certified");
  await s.pickFile(".panel input[type=file]", basename(certified), readFileSync(certified, "utf8"));
  await s.clickButton("Import key");
  await s.waitText("Add certificate", ".panel", 30000);
  await s.clickButton("Add certificate");
  await s.pickFile(".key-certificate input[type=file]", `${basename(certified)}-cert.pub`, readFileSync(`${certified}-cert.pub`, "utf8"));
  await s.clickButton("Save certificate");
  const certFacts = await s.wait(() => s.exec(`const c = document.querySelector(".key-certificate"); return c && c.innerText.includes("Signs in as") ? c.innerText : null`), "the certificate's details");
  // An hour left: the warning.
  assert.match(certFacts, new RegExp(`Expires in 1 hour[\\s\\S]*Signs in as\\s+${user}[\\s\\S]*Key ID\\s+e2e-cert`));
  await s.screenshot(`${shots}/key-certificate.png`);
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await s.clickButton("New host");
  await s.waitText("New host", ".panel");
  await s.typeLabelled("Label", "cert-box");
  await s.typeLabelled("Hostname or IP", "127.0.0.2");
  await s.typeLabelled("Port", port);
  await s.typeLabelled("User", user);
  await s.exec(`[...document.querySelectorAll('.panel button[role="radio"]')].find((b) => b.innerText === "SSH key").click(); return true`);
  await s.exec(
    `const l = [...document.querySelectorAll(".panel label")].find((l) => l.querySelector("span")?.innerText === "Key" && l.querySelector("select"));
     const e = l.querySelector("select"); const o = [...e.options].find((o) => o.text.startsWith("certified"));
     Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(e, o.value);
     e.dispatchEvent(new Event("change", { bubbles: true })); return true`,
  );
  await s.clickButton("Save & connect");
  await s.wait(
    () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "a shell on cert-box",
    60000,
  );
  assert.match(sshdLog(), /Accepted publickey for .* ED25519-CERT SHA256:\S+ ID e2e-cert/);
  await s.click(".tab.active .close");
  ok("a key with a certificate from a CA the server trusts signed in (the key alone isn't authorized)");

  // A host behind e2e-jump that the jump host reaches by a command (a relay, as `nc %h %p`
  // would), with a login command that runs instead of the shell.
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await s.clickButton("New host");
  await s.waitText("New host", ".panel");
  await s.typeLabelled("Label", "cmd-box");
  await s.typeLabelled("Hostname or IP", "127.0.0.2");
  await s.typeLabelled("Port", port);
  await s.typeLabelled("User", user);
  await s.exec(`[...document.querySelectorAll('.panel button[role="radio"]')].find((b) => b.innerText === "SSH key").click(); return true`);
  await s.exec(
    `const l = [...document.querySelectorAll(".panel label")].find((l) => l.querySelector("span")?.innerText === "Key" && l.querySelector("select"));
     const e = l.querySelector("select"); const o = [...e.options].find((o) => o.text.startsWith("e2e_key"));
     Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(e, o.value);
     e.dispatchEvent(new Event("change", { bubbles: true })); return true`,
  );
  await s.exec(
    `const l = [...document.querySelectorAll(".panel label")].find((l) => l.querySelector("span")?.innerText === "Connect via");
     const e = l.querySelector("select"); const o = [...e.options].find((o) => o.text.startsWith("Jump host: e2e-jump"));
     Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(e, o.value);
     e.dispatchEvent(new Event("change", { bubbles: true })); return true`,
  );
  // A relay to %h:%p, as `nc %h %p` (the sshd runs on this machine).
  const relay = fileURLToPath(new URL("../../../crates/mg-ssh/tests/relay.py", import.meta.url));
  await s.typeLabelled("Through the jump host by a command", `exec python3 -I '${relay}' %h %p`);
  await s.typeLabelled("Login command", "echo mg-login-$((6*7)); exec bash --norc -i");
  await s.clickButton("Save & connect");
  await s.wait(
    () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && r.innerText.includes("mg-login-42") && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "the login command's output and a shell on cmd-box",
    60000,
  );
  await s.screenshot(`${shots}/login-command.png`);
  await s.click(".tab.active .close");
  ok("a host reached by a command its jump host runs, with a login command instead of the shell");

  // A host reached by a command on this computer (OpenSSH's ProxyCommand): the relay again, run
  // here. Typed in the editor, so this device runs it.
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await s.clickButton("New host");
  await s.waitText("New host", ".panel");
  await s.typeLabelled("Label", "proxy-box");
  await s.typeLabelled("Hostname or IP", "127.0.0.2");
  await s.typeLabelled("Port", port);
  await s.typeLabelled("User", user);
  await s.exec(`[...document.querySelectorAll('.panel button[role="radio"]')].find((b) => b.innerText === "SSH key").click(); return true`);
  await s.exec(
    `const l = [...document.querySelectorAll(".panel label")].find((l) => l.querySelector("span")?.innerText === "Key" && l.querySelector("select"));
     const e = l.querySelector("select"); const o = [...e.options].find((o) => o.text.startsWith("e2e_key"));
     Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(e, o.value);
     e.dispatchEvent(new Event("change", { bubbles: true })); return true`,
  );
  await s.exec(
    `const l = [...document.querySelectorAll(".panel label")].find((l) => l.querySelector("span")?.innerText === "Connect via");
     const e = l.querySelector("select"); const o = [...e.options].find((o) => o.value === "proxy");
     Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(e, o.value);
     e.dispatchEvent(new Event("change", { bubbles: true })); return true`,
  );
  await s.typeLabelled("Proxy command", `exec python3 -I '${relay}' %h %p`);
  await s.clickButton("Save & connect");
  await s.wait(
    () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "a shell on proxy-box",
    60000,
  );
  await s.click(".tab.active .close");
  ok("a host reached by a command on this computer (a proxy command typed here)");

  // A host CA (Keys → New host CA): the sshd's certificate for 127.0.0.3 is trusted without the
  // host key prompt, and the route bar says who vouched for it.
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Keys")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Keys" || null`), "the Keys page");
  await s.pageTab("Host CAs");
  await s.clickButton("New host CA");
  await s.waitText("New host CA", ".panel");
  await s.typeLabelled("Name", "e2e host CA");
  await s.typeLabelled("The CA's public key", readFileSync(`${dirname(key)}/host_ca.pub`, "utf8").trim());
  await s.typeLabelled("For hosts", "127.0.0.3");
  await s.clickButton("Save host CA");
  const saved = await s
    .wait(
      () => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Keys" ? "ok" : document.querySelector(".panel .error")?.innerText || null`),
      "back on the Keys page",
    )
    .catch(async (e) => {
      await s.screenshot(`${shots}/host-ca-not-saved.png`);
      throw e;
    });
  assert.equal(saved, "ok", `saving the host CA: ${saved}`);
  await s.wait(() => s.hasText(".panel .lname", "e2e host CA"), "the host CA listed");
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await s.clickButton("New host");
  await s.waitText("New host", ".panel");
  await s.typeLabelled("Label", "ca-box");
  await s.typeLabelled("Hostname or IP", "127.0.0.3");
  await s.typeLabelled("Port", port);
  await s.typeLabelled("User", user);
  await s.exec(`[...document.querySelectorAll('.panel button[role="radio"]')].find((b) => b.innerText === "SSH key").click(); return true`);
  await s.exec(
    `const l = [...document.querySelectorAll(".panel label")].find((l) => l.querySelector("span")?.innerText === "Key" && l.querySelector("select"));
     const e = l.querySelector("select"); const o = [...e.options].find((o) => o.text.startsWith("e2e_key"));
     Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(e, o.value);
     e.dispatchEvent(new Event("change", { bubbles: true })); return true`,
  );
  await s.clickButton("Save & connect");
  // No host key prompt: the shell comes straight up.
  await s.wait(
    () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "a shell on ca-box without the host key prompt",
    60000,
  );
  await s.waitText("certified by e2e host CA", ".route-bar", 30000);
  await s.screenshot(`${shots}/host-ca.png`);
  await s.click(".tab.active .close");
  ok("a host CA trusted 127.0.0.3's host certificate: no host key prompt, and the route bar says who vouched");

  // Renewing a certificate with a command: the certified key's, by ssh-keygen -s with the run's
  // user CA (as a CA's signing command would), under a new key ID that cert-box then sees.
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Keys")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Keys" || null`), "the Keys page");
  await s.click('button[aria-label="Open certified"]');
  await s.waitText("Renew with a command…", ".panel");
  await s.clickButton("Renew with a command…");
  await s.typeLabelled("Renew with a command", `ssh-keygen -q -s '${dirname(key)}/user_ca' -I e2e-renewed -n ${user} -V -5m:+1h %k`);
  await s.clickButton("Save renewal");
  await s.waitText("Renew now", ".key-renewal", 30000);
  await s.clickButton("Renew now");
  await s.waitText("Renewed.", ".key-renewal", 60000);
  await s.waitText("e2e-renewed", ".key-certificate", 30000);
  await s.screenshot(`${shots}/renewed.png`);
  await s.clickButton("Close");
  await s.exec(
    `[...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === "cert-box").querySelector(".row-main").click(); return true`,
  );
  await s.wait(
    () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "a shell on cert-box with the renewed certificate",
    60000,
  );
  assert.match(sshdLog(), /ID e2e-renewed/);
  await s.click(".tab.active .close");
  ok("renewed the certified key's certificate with a command (ssh-keygen -s), and cert-box took the new one");

  // Vallic Cloud, through a stand-in console: sign in (approved on the second poll); its
  // production environment (this sshd) becomes a host that signs in with the key the page sets;
  // the key goes on the account; a refresh changes nothing; no Files for its hosts (no SFTP).
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await s.addFrom("Clouds…");
  // The page shows what to add once it has listed the sources.
  await s.waitText("Connect Vallic Cloud", ".cloud-page", 30000);
  await s.clickButton("Connect Vallic Cloud");
  await s.waitText("WXYZ-1234", ".cloud-sign-in", 30000);
  await s.screenshot(`${shots}/vallic-sign-in.png`);
  await s.wait(() => s.exec(`return document.querySelector(".cloud-source")?.innerText.includes("1 host") || null`), "the Vallic Cloud source", 30000);
  page = await s.exec(`return document.querySelector(".cloud-page").innerText`);
  assert.match(page, /e2e@example\.com · 1 host/);
  assert.match(page, /1 host added/);
  assert.match(page, /No shell for you[^\n]*E2E Shop · Preview/);
  await s.choose(".cloud-source select", "e2e_key");
  // Enabled again once the key is saved.
  await s.wait(
    () => s.exec(`return [...document.querySelectorAll(".cloud-source button")].some((b) => b.innerText.includes("Add e2e_key") && !b.disabled) || null`),
    "the key saved",
  );
  await s.clickButton("Add e2e_key to your Vallic account");
  await s.waitText("e2e_key is on your Vallic account now", ".cloud-source", 30000);
  const added = await (await fetch(`${process.env.MORPHGATE_VALLIC_CONSOLE}/e2e/keys`)).json();
  assert.equal(added.keys.length, 1);
  assert.match(added.keys[0].public_key, /^ssh-ed25519 /);
  await s.clickButton("Refresh");
  await s.waitText("Nothing changed", ".cloud-source", 30000);
  await s.screenshot(`${shots}/vallic-source.png`);
  await s.clickButton("Close");
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page again");
  const vallicRow = await s.exec(
    `const row = [...document.querySelectorAll(".panel.page [role=row]")].find((r) => r.innerText.includes("E2E Shop · Production"));
     return row ? [...row.querySelectorAll("button")].map((b) => b.getAttribute("aria-label") || b.innerText).join("|") : null`,
  );
  assert.ok(vallicRow && !vallicRow.split("|").includes("Browse files (SFTP)"), `no Files for a Vallic host: ${vallicRow}`);
  // Its SSH forwards no ports: the tunnel editor doesn't offer it.
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Tunnels")).click(); return true`);
  await s.clickButton("New tunnel");
  const through = await s.wait(
    () =>
      s.exec(
        `const sel = [...document.querySelectorAll(".panel label")].find((l) => l.innerText.startsWith("Through host"))?.querySelector("select");
         return sel ? [...sel.options].map((o) => o.text).join("|") : null`,
      ),
    "the tunnel editor's hosts",
  );
  assert.ok(!through.includes("E2E Shop · Production"), `no tunnel through a Vallic host: ${through}`);
  await s.clickButton("Cancel");
  await s.exec(
    `[...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === "E2E Shop · Production").querySelector(".row-main").click(); return true`,
  );
  await s.wait(
    () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "a shell on the Vallic host",
    60000,
  );
  await s.click(".tab.active .close");
  ok("connected Vallic Cloud: its environment became a host (no Files, no tunnels), signed in with the key added to the account; a refresh changed nothing");

  // AWS through a stand-in aws CLI (clouds/aws): the source says who the CLI is signed in as;
  // its running instance (this sshd) becomes a host signing in with the key its key pair names;
  // the stopped one without an address waits.
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await s.addFrom("Clouds…");
  // The page shows what to add once it has listed the sources.
  await s.waitText("Add AWS", ".cloud-page", 30000);
  await s.clickButton("Add AWS");
  await s.waitText("is signed in as 123456789012", ".cloud-adding", 30000);
  await s.clickButton("Add and list machines");
  await s.wait(
    () => s.exec(`return [...document.querySelectorAll(".cloud-source")].find((x) => x.innerText.includes("123456789012"))?.innerText.includes("1 host added") || null`),
    "the AWS source",
    30000,
  );
  page = await s.exec(`return [...document.querySelectorAll(".cloud-source")].find((x) => x.innerText.includes("123456789012")).innerText`);
  assert.match(page, /Without a public address: e2e-stopped/);
  assert.match(page, /every region · public addresses/);
  await s.screenshot(`${shots}/aws-source.png`);
  await s.clickButton("Close");
  await s.exec(
    `[...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === "e2e-ec2").querySelector(".row-main").click(); return true`,
  );
  await s.wait(
    () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "a shell on the EC2 host",
    60000,
  );
  await s.click(".tab.active .close");
  ok("added AWS through its CLI: the running instance became a host (its key pair's key), the stopped one without an address waits");

  // The same source through Session Manager: every instance by its id, the stopped one too; the
  // connection goes through `aws ssm start-session` (the stand-in relays it to this sshd).
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await s.addFrom("Clouds…");
  await s.waitText("123456789012", ".cloud-source", 30000);
  await s.exec(
    `const card = [...document.querySelectorAll(".cloud-source")].find((x) => x.innerText.includes("123456789012"));
     [...card.querySelectorAll("button")].find((b) => b.innerText === "Settings…").click(); return true`,
  );
  await s.waitText("is signed in as 123456789012", ".cloud-settings", 30000);
  await s.exec(
    `const l = [...document.querySelectorAll(".cloud-settings label")].find((l) => l.querySelector("span")?.innerText === "Reach its machines by");
     const e = l.querySelector("select"); Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(e, "aws-ssm");
     e.dispatchEvent(new Event("change", { bubbles: true })); return true`,
  );
  await s.clickButton("Save and refresh");
  await s.wait(
    () => s.exec(`return [...document.querySelectorAll(".cloud-source")].find((x) => x.innerText.includes("123456789012"))?.innerText.match(/1 host added, 1 updated/) ? true : null`),
    "the instances through Session Manager",
    30000,
  );
  assert.match(
    await s.exec(`return [...document.querySelectorAll(".cloud-source")].find((x) => x.innerText.includes("123456789012")).innerText`),
    /through AWS Session Manager/,
  );
  await s.clickButton("Close");
  await s.exec(
    `[...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === "e2e-ec2").querySelector(".row-main").click(); return true`,
  );
  // Its host key is kept under the instance's id: new.
  await s.waitText("Trust and connect", "body", 60000);
  await s.clickButton("Trust and connect");
  await s.wait(
    () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "a shell through Session Manager",
    60000,
  );
  await s.click(".tab.active .close");
  ok("the AWS source through Session Manager: every instance by its id (the stopped one too); connected through aws ssm start-session");

  // DigitalOcean through a stand-in doctl (clouds/doctl): no regions to choose, the key picked
  // for the source; its droplet (this sshd) connects.
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await s.addFrom("Clouds…");
  await s.waitText("Add DigitalOcean", ".cloud-page", 30000);
  await s.clickButton("Add DigitalOcean");
  await s.waitText("is signed in as e2e@example.com (E2E)", ".cloud-adding", 30000);
  assert.ok(!(await s.exec(`return document.querySelector(".cloud-adding").innerText`)).includes("Regions"), "no regions to choose");
  await s.exec(
    `const l = [...document.querySelectorAll(".cloud-adding label")].find((l) => l.querySelector("span")?.innerText === "Its hosts sign in with");
     const e = l.querySelector("select"); const o = [...e.options].find((o) => o.text.startsWith("e2e_key"));
     Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(e, o.value);
     e.dispatchEvent(new Event("change", { bubbles: true })); return true`,
  );
  await s.clickButton("Add and list machines");
  const doAdded = await s.wait(
    () =>
      s.exec(
        `return [...document.querySelectorAll(".cloud-source")].find((x) => x.innerText.toLowerCase().includes("digitalocean"))?.innerText.includes("1 host added") ? "ok" : document.querySelector(".cloud-page > .error, .cloud-adding .error")?.innerText || null`,
      ),
    "the DigitalOcean source",
    30000,
  ).catch(async (e) => {
    await s.screenshot(`${shots}/digitalocean-not-added.png`);
    throw e;
  });
  assert.equal(doAdded, "ok", `adding DigitalOcean: ${doAdded}`);
  await s.clickButton("Close");
  await s.exec(
    `[...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === "e2e-droplet").querySelector(".row-main").click(); return true`,
  );
  await s.wait(
    () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "a shell on the droplet",
    60000,
  );
  await s.click(".tab.active .close");
  ok("added DigitalOcean through its CLI: its droplet became a host and connected");

  // Several hosts at once: the CSV and Royal TS ones (nothing later uses them) into one group,
  // then both deleted.
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
  await s.clickButton("Select");
  const pick = (label) =>
    s.exec(
      `const row = [...document.querySelectorAll(".panel.page [role=row].picking")].find((r) => r.querySelector(".lname")?.innerText === arguments[0]);
       if (!row) throw new Error("no row " + arguments[0]); row.click(); return true`,
      label,
    );
  await pick("e2e-csv");
  await pick("e2e-royal");
  await s.waitText("2 hosts selected", ".select-bar");
  await s.screenshot(`${shots}/hosts-selected.png`);
  await s.choose(".select-bar select", "E2E Lab");
  await s.waitText("Moved 2 hosts.", ".select-bar-wrap", 30000);
  await s.wait(
    () =>
      s.exec(`const section = [...document.querySelectorAll(".panel.page .lsection")].find((x) => x.querySelector(".lghead")?.innerText.includes("E2E Lab"));
              const names = section ? [...section.querySelectorAll(".lname")].map((x) => x.innerText) : [];
              return names.includes("e2e-csv") && names.includes("e2e-royal") || null`),
    "both hosts in E2E Lab",
  );
  await s.clickButton("Delete…");
  await s.waitText("Delete 2 hosts?", ".select-bar");
  await s.exec(`[...document.querySelectorAll(".select-bar button")].find((b) => b.innerText === "Delete").click(); return true`);
  await s.waitText("Deleted 2 hosts.", ".select-bar-wrap", 30000);
  await s.wait(
    () => s.exec(`return ![...document.querySelectorAll(".sidebar .row-title")].some((x) => ["e2e-csv", "e2e-royal"].includes(x.innerText)) || null`),
    "the two hosts gone from the sidebar",
  );
  await s.clickButton("Done");
  ok("selected two hosts: moved them into a group, then deleted both");

  // A host signing in with a key from an SSH agent (on its own socket), only that key, and the
  // agent forwarded: on the host, `ssh-add -l` lists it. The key is the certified one, which the
  // agent holds with its certificate: only the certificate signs it in.
  // In a short folder: a Unix socket's path has room for about 100 characters, which a CI runner's
  // work folder can use up.
  const sockDir = mkdtempSync("/tmp/mg-agent-");
  const sock = `${sockDir}/agent.sock`;
  const agent = spawn("ssh-agent", ["-D", "-a", sock], { stdio: "ignore" });
  try {
    await s.wait(() => existsSync(sock) || null, "the agent's socket");
    execFileSync("ssh-add", [key, certified], { env: { ...process.env, SSH_AUTH_SOCK: sock }, stdio: "ignore" });
    const fingerprint = execFileSync("ssh-keygen", ["-lf", `${certified}.pub`], { encoding: "utf8" }).split(" ")[1];
    await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith("Hosts")).click(); return true`);
    await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page");
    await s.clickButton("New host");
    await s.waitText("New host", ".panel");
    await s.typeLabelled("Label", "agent-box");
    await s.typeLabelled("Hostname or IP", "127.0.0.1");
    await s.typeLabelled("Port", port);
    await s.typeLabelled("User", user);
    await s.exec(`[...document.querySelectorAll('.panel button[role="radio"]')].find((b) => b.innerText === "SSH agent").click(); return true`);
    // The agents load after the editor opens.
    await s.wait(
      () => s.exec(`return [...document.querySelectorAll('select[aria-label="SSH agent"] option')].some((o) => o.text.includes("Other socket or pipe")) || null`),
      "the list of agents",
    );
    await s.choose('select[aria-label="SSH agent"]', "Other socket or pipe");
    await s.typeLabelled("Socket or pipe", sock);
    await s.clickButton("Look");
    await s.wait(
      () => s.exec(`return [...document.querySelectorAll('select[aria-label="Agent key"] option')].some((o) => o.value === arguments[0]) || null`, fingerprint),
      "the agent's key",
    );
    await s.exec(
      `const e = document.querySelector('select[aria-label="Agent key"]');
       Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(e, arguments[0]);
       e.dispatchEvent(new Event("change", { bubbles: true })); return true`,
      fingerprint,
    );
    await s.exec(`[...document.querySelectorAll(".panel label.check")].find((l) => l.innerText.includes("Forward the SSH agent")).querySelector("input").click(); return true`);
    await s.waitText("Only for hosts you trust", ".panel");
    await s.screenshot(`${shots}/agent-host.png`);
    await s.clickButton("Save & connect");
    await s.wait(
      () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
      "a shell on agent-box",
      60000,
    );
    await s.exec(
      `const t = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-helper-textarea"); t.focus();
       t.dispatchEvent(new InputEvent("input", { data: arguments[0], inputType: "insertText", bubbles: true })); return true`,
      "ssh-add -l; echo agent-exit=$?\r",
    );
    await s.wait(
      () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows").innerText; return r.includes(arguments[0]) && r.includes("agent-exit=0") ? true : null`, fingerprint),
      "the forwarded agent's key on the host",
    );
    await s.screenshot(`${shots}/agent-forwarded.png`);
    await s.click(".tab.active .close");
  } finally {
    agent.kill();
    rmSync(sockDir, { recursive: true, force: true });
  }
  assert.equal(sshdLog().match(/ID e2e-cert/g)?.length, 2, "the agent's certificate signed in");
  ok("signed in with one key from an SSH agent, presented with its certificate, and forwarded it: ssh-add -l on the host lists it");

  // Split panes: e2e-jump, then itself again beside it and e2e-box (through it) below; typing
  // broadcast goes to all three, and only to one once broadcasting is off.
  const paneRows = () =>
    s.exec(`return [...document.querySelectorAll(".pane.split:not([hidden])")].map((p) => p.querySelector(".xterm-rows")?.innerText ?? "")`);
  const allPrompts = (n) => async () => {
    const rows = await paneRows();
    return rows.length === n && rows.every((r) => /[$#]\s*$/m.test(r)) ? rows : null;
  };
  const typeFocused = (text) =>
    s.exec(
      `const t = document.querySelector(".pane.split.focused .xterm-helper-textarea"); t.focus();
       t.dispatchEvent(new InputEvent("input", { data: arguments[0], inputType: "insertText", bubbles: true })); return true`,
      text,
    );
  const splitMenu = async (dir, pick) => {
    await s.exec(`[...document.querySelectorAll(".route-actions button")].find((b) => b.innerText.includes("Split")).click(); return true`);
    await s.exec(`[...document.querySelectorAll(".split-menu .menu [role=radio]")].find((b) => b.innerText === arguments[0]).click(); return true`, dir);
    if (pick !== null) await s.type('.split-menu input[aria-label="Find a host"]', pick);
    await s.wait(
      () =>
        s.exec(
          `const b = [...document.querySelectorAll(".split-menu .menu .menu-item")].find((b) => b.innerText.includes(arguments[0])); if (!b) return null; b.click(); return true`,
          pick ?? "This host again",
        ),
      `"${pick ?? "this host again"}" in the split menu`,
    );
  };
  await s.exec(
    `[...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === "e2e-jump").querySelector(".row-main").click(); return true`,
  );
  await s.wait(
    () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "a shell on e2e-jump",
    60000,
  );
  await splitMenu("Side by side", null);
  await s.wait(allPrompts(2), "two panes side by side", 60000);
  await splitMenu("Below", "e2e-box");
  await s.wait(allPrompts(3), "three panes", 60000);
  const tab = await s.exec(`return document.querySelector(".tab.active").innerText`);
  assert.match(tab, /e2e-jump\s*\+2/, "one tab, with two more panes");
  await s.exec(`document.querySelector(".broadcast-toggle").click(); return true`);
  await s.waitText("Broadcasting to 3", ".route-bar");
  await typeFocused("echo bc-$((6*7))\r");
  await s.wait(async () => ((await paneRows()).every((r) => r.includes("bc-42")) ? true : null), "the broadcast in every pane");
  await s.screenshot(`${shots}/split-broadcast.png`);
  await s.exec(`document.querySelector(".broadcast-toggle").click(); return true`);
  await typeFocused("echo solo-$((5*5))\r");
  await s.wait(async () => ((await paneRows()).filter((r) => r.includes("solo-25")).length === 1 ? true : null), "the command in one pane");
  await new Promise((r) => setTimeout(r, 1000));
  assert.equal((await paneRows()).filter((r) => r.includes("solo-25")).length, 1, "only the focused pane");
  // Dragging the border between the panes side by side.
  const widthOf = () => s.exec(`return document.querySelector(".pane.split:not([hidden])").getBoundingClientRect().width`);
  const wide = await widthOf();
  await s.exec(
    `const d = document.querySelector(".pane-divider.row"); const box = document.querySelector(".content-body").getBoundingClientRect();
     const at = (f) => ({ clientX: box.left + box.width * f, clientY: box.top + 50, pointerId: 7, bubbles: true });
     d.dispatchEvent(new PointerEvent("pointerdown", at(0.5)));
     d.dispatchEvent(new PointerEvent("pointermove", at(0.3)));
     d.dispatchEvent(new PointerEvent("pointerup", at(0.3)));
     return true`,
  );
  await s.wait(async () => ((await widthOf()) < wide * 0.8 ? true : null), "the left pane narrower");
  await s.screenshot(`${shots}/split-panes.png`);
  // Closing one pane keeps the others together; closing the tab closes them all.
  await s.click(".pane.split:not([hidden]) .pane-head .close");
  await s.wait(async () => ((await paneRows()).length === 2 ? true : null), "two panes left");
  assert.match(await s.exec(`return document.querySelector(".tab.active").innerText`), /\+1/);
  await s.click(".tab.active .close");
  await s.wait(() => s.exec(`return document.querySelectorAll(".pane.split").length === 0 || null`), "the split closed");
  ok("split a tab into three panes (beside and below), broadcast typing to all, then to one; resized and closed them");

  // morphgate:// links: launching the app again with a link hands it to the one running (and
  // exits). The link fills in quick connect (a password in it is ignored), which connects only
  // when asked; a link MorphGate doesn't know says so.
  const launch = (url) =>
    new Promise((resolve) => {
      const p = spawn(app, [url], { stdio: "ignore" });
      const timer = setTimeout(() => (p.kill(), resolve("still running")), 30000);
      p.on("exit", (code) => (clearTimeout(timer), resolve(code)));
    });
  const field = (label) =>
    s.exec(`return [...document.querySelectorAll(".panel label")].find((l) => l.querySelector("span")?.innerText === arguments[0])?.querySelector("input")?.value ?? null`, label);
  assert.equal(await launch(`morphgate://connect?host=127.0.0.1&port=${port}&user=${user}&label=linked-box&password=hunter2`), 0, "the second launch exits");
  await s.waitText("Filled in from a link for linked-box", ".panel", 30000);
  assert.deepEqual([await field("Host"), await field("Port"), await field("User")], ["127.0.0.1", port, user]);
  assert.equal(await s.exec(`return [...document.querySelectorAll(".panel input[type=password]")].some((i) => i.value === "hunter2")`), false);
  await s.screenshot(`${shots}/link-connect.png`);
  // The key isn't remembered between connections (only that it was a key): pasted this time.
  await s.exec(`[...document.querySelectorAll(".segmented [role=radio]")].find((b) => b.innerText === "Paste").click(); return true`);
  await s.typeLabelled("Private key", readFileSync(key, "utf8"));
  await s.exec(`document.querySelector(".panel form button[type=submit].primary").click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".tab.active .label")?.innerText === "linked-box" || null`), "the linked-box tab");
  await s.wait(
    () => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "a shell on linked-box",
    60000,
  );
  await s.click(".tab.active .close");
  assert.equal(await launch("morphgate://format-disk"), 0);
  await s.waitText("doesn't know “format-disk” links", ".banner", 30000);
  await s.click('.banner button[aria-label="Dismiss"]');
  ok("a morphgate:// link from a second launch filled in quick connect (no password), connected on click with a pasted key; an unknown one was refused");

  // Appearance: a pasted Ghostty theme becomes this device's, and the open terminal repaints.
  const palette = Array.from({ length: 16 }, (_, i) => `palette = ${i}=#${(i * 16).toString(16).padStart(2, "0")}8040`).join("\n");
  await s.click('button[aria-label="Settings"]');
  await s.waitText("Terminal appearance", ".panel");
  // A built-in scheme first: the open terminal repaints in Bastion's pure black.
  await s.exec(
    `[...document.querySelectorAll(".scheme-card .scheme-pick")].find((b) => b.innerText.includes("Bastion")).click(); return true`,
  );
  await s.wait(
    () => s.exec(`return [...document.querySelectorAll(".scheme-card.selected .scheme-name")].some((e) => e.innerText.includes("Bastion")) || null`),
    "Bastion in use",
  );
  await s.clickButton("Import a scheme");
  await s.clickButton("Paste");
  await s.typeLabelled("Theme", `background = #123456\nforeground = #fedcba\ncursor-color = #ff00ff\n${palette}\n`);
  await s.typeLabelled("Name", "E2E Theme");
  await s.clickButton("Import and use");
  await s.wait(
    () => s.exec(`return [...document.querySelectorAll(".scheme-card.selected .scheme-name")].some((e) => e.innerText.includes("E2E Theme")) || null`),
    "the imported theme in use",
  );
  await s.screenshot(`${shots}/appearance.png`);
  await s.exec(`document.querySelector(".tabs .tab:not(.new)").click(); return true`);
  await s.wait(
    () => s.exec(`const v = document.querySelector(".terminal:not([hidden]) .xterm-scrollable-element"); return v && getComputedStyle(v).backgroundColor === "rgb(18, 52, 86)" ? true : null`),
    "the terminal in the new theme",
  );
  ok("picked a built-in scheme, imported another; the open terminal follows");

  assert.match(await openAbout(s), new RegExp(`Version ${version} · AppImage`));
  ok(`About: ${version}, AppImage`);

  // The third-party notices that come with the app: a crate's, from the generated list.
  await s.clickButton("Open-source licenses");
  await s.wait(() => s.exec(`return document.querySelector(".licenses-list li") ? true : null`), "the license list");
  await s.type('input[aria-label="Search components"]', "russh");
  await s.wait(() => s.exec(`const b = [...document.querySelectorAll(".license-row")].find((b) => b.innerText.startsWith("russh ")); return b ? (b.click(), true) : null`), "russh in the list");
  await s.waitText("Apache License", ".license-text");
  await s.screenshot(`${shots}/about-licenses.png`);
  await s.clickButton("All components");
  await s.clickButton("Back");
  await s.waitText("Check now");
  ok("About lists the open-source licenses");

  // A tampered download is refused and the AppImage stays as it was.
  const before = sha(app);
  copyFileSync(`${feed}/latest-tampered.json`, `${feed}/latest.json`);
  await checkNow(s);
  await s.waitText(`MorphGate ${next} is available`);
  await s.clickButton("Install and restart");
  assert.match(await s.wait(s.panelError, "the refusal", 120000), /signature/);
  assert.equal(sha(app), before);
  ok("refused the tampered update; AppImage untouched");

  // The update is kept: Install works again without a new check (and is refused again).
  await s.exec(`window.__errs = 0; window.__shown = !!document.querySelector(".panel .error");
    new MutationObserver(() => { const e = !!document.querySelector(".panel .error"); if (e && !window.__shown) window.__errs++; window.__shown = e; })
      .observe(document.body, { subtree: true, childList: true, characterData: true }); return true`);
  await s.clickButton("Install and restart");
  const again = await s.wait(() => s.exec(`return window.__errs > 0 ? document.querySelector(".panel .error").innerText : null`), "the second refusal", 120000);
  assert.match(again, /signature/);
  ok("retry without a new check: refused again");

  // The signed update installs, and the app restarts by itself.
  copyFileSync(`${feed}/latest-good.json`, `${feed}/latest.json`);
  await checkNow(s);
  await s.waitText(`MorphGate ${next} is available`);
  await s.screenshot(`${shots}/update-available.png`);
  await s.clickButton("Install and restart");
  // Until it is the new AppImage, whole (it changes before it's fully written).
  const expected = sha(`${feed}/${app.split("/").pop().replace(version, next)}`);
  await s.wait(() => (sha(app) === expected ? true : null), "the AppImage to be replaced", 180000);
  ok(`installed ${next} over the AppImage`);
} catch (e) {
  await s.screenshot(`${shots}/failed.png`).catch(() => {});
  throw e;
} finally {
  await s.close();
}

/** The app's processes started from this AppImage (the runtime sets APPIMAGE for them). */
function appImagePids() {
  const pids = [];
  for (const pid of readdirSync("/proc").filter((d) => /^\d+$/.test(d))) {
    try {
      const env = readFileSync(`/proc/${pid}/environ`, "utf8").split("\0");
      if (env.includes(`APPIMAGE=${app}`) && readlinkSync(`/proc/${pid}/exe`).endsWith("/morphgate")) pids.push(Number(pid));
    } catch {
      // gone, or not ours
    }
  }
  return pids;
}

// The update relaunched the app by itself. It's the one instance a launch hands over to: stop it,
// so the next session's app is the one under test.
await new Promise((r) => setTimeout(r, 3000));
for (const pid of appImagePids()) process.kill(pid, "SIGTERM");
for (let i = 0; i < 50 && appImagePids().length > 0; i++) await new Promise((r) => setTimeout(r, 200));

// Launch again: the same vault unlocks, and the app is the new version with nothing newer.
s = await session(app);
try {
  await s.waitText("Unlock MorphGate", "body", 60000);
  await s.type("input[autocomplete=current-password]", PASSWORD);
  await s.exec(`document.querySelector("form button[type=submit]").click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector("button.brand") ? true : null`), "the workspace", 60000);
  // A vault with hosts opens on them (with none, on quick connect).
  await s.wait(() => s.exec(`return document.querySelectorAll(".sidebar .row-title").length > 0 || null`), "the vault's hosts", 30000);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Hosts" || null`), "the Hosts page as home");
  assert.match(await openAbout(s), new RegExp(`Version ${next} · AppImage`));
  await checkNow(s);
  await s.waitText("up to date");
  await s.screenshot(`${shots}/updated.png`);
  ok(`unlocked the same vault in ${next}, which is up to date`);
} finally {
  await s.close();
}
