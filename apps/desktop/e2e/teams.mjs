// Two people share a vault through the app: Alice and Bob turn on sync with a local reference
// server; Alice creates an organization and a vault and invites Bob; Bob joins after comparing the
// owner's fingerprint; Alice confirms him after comparing his; both edit a host in the shared vault;
// Alice revokes Bob (the vault leaves his device) and rotates the vault key; she lets members
// create vaults and Bob makes one; her activity log shows what happened. Then Alice offboards
// Bob against a real sshd: she removes him and rotates keys, finds his published key on a shared
// host and removes it, and replaces the host's shared key without losing access.
//
//   E2E_PEOPLE="alice bob" session.sh <dir> node teams.mjs <app> <screenshots> <sync server URL> \
//     <ssh key> <ssh port> <ssh user> <the sshd's authorized_keys>

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createVault, session } from "./webdriver.mjs";

const [app, shots, server, sshKey, sshPort, sshUser, authorizedKeys, serverBin, serverDb, idp] = process.argv.slice(2);
const keyBody = (line) => line.trim().split(/\s+/)[1];
const authorized = () => readFileSync(authorizedKeys, "utf8");
const PASSWORD = "correct horse battery staple";
const ok = (...a) => console.log("  ✓", ...a);
const run = Date.now().toString(36);
const aliceEmail = `alice-${run}@example.com`;
const bobEmail = `bob-${run}@example.com`;

/** Fingerprint shown in the element matching `css` (they're labelled "Fingerprint XXXX-…"). */
const fingerprint = (s, css = ".fingerprint") =>
  s.wait(() => s.exec(`const e = document.querySelector(arguments[0]); return e ? e.getAttribute("aria-label").replace("Fingerprint ", "") : null`, css), css);

const sidebarHas = (s, title) => s.hasText(".sidebar .row-title", title);

/** Opens one of the sidebar's pages (Hosts, Keys, Snippets, Tunnels, VPNs). */
async function openPage(s, label) {
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith(arguments[0])).click(); return true`, label);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === arguments[0] || null`, label), `the ${label} page`);
}

/** Picks the option containing `text` in the select labelled `label` in the open panel. */
async function pickIn(s, label, text) {
  await s.exec(
    `[...document.querySelectorAll(".panel label")].find((l) => l.querySelector("span")?.innerText === arguments[0]).querySelector("select").setAttribute("data-e2e", "pick"); return true`,
    label,
  );
  await s.choose("select[data-e2e=pick]", text);
  await s.exec(`document.querySelector("select[data-e2e=pick]").removeAttribute("data-e2e"); return true`);
}

/** The visible terminal's text, and typing into it. */
const tabRows = (s) => s.exec(`const r = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-rows"); return r ? r.innerText : ""`);
const typeInTab = (s, text) =>
  s.exec(
    `const t = document.querySelector(".terminal:not(.xterm):not([hidden]) .xterm-helper-textarea"); t.focus();
     t.dispatchEvent(new InputEvent("input", { data: arguments[0], inputType: "insertText", bubbles: true })); return true`,
    text,
  );

/** The sync server field starts on morphgate.com; the tests use their own server. */
async function useOwnServer(s) {
  const hosted = await s.exec(
    `return document.querySelector('.sync-server button[role="radio"][aria-checked="true"]')?.innerText ?? null`,
  );
  assert.equal(hosted, "morphgate.com", "morphgate.com is the prefilled choice");
  await s.screenshot(`${shots}/sync-server-default.png`);
  await s.exec(`[...document.querySelectorAll('.sync-server button[role="radio"]')].find((b) => b.innerText === "Your own server").click(); return true`);
  await s.typeLabelled("Server address", server);
}

async function enableSync(s, email) {
  await s.click("button.sidebar-foot.sync");
  await s.waitText("Enable sync");
  await useOwnServer(s);
  await s.typeLabelled("Email", email);
  await s.typeLabelled("Master password (to confirm)", PASSWORD);
  await s.clickButton("Enable sync");
  await s.waitText("Last sync", ".panel", 60000);
}

/** Sync now, from the Sync panel (instead of waiting for the next minute). */
async function syncNow(s, ms = 20000) {
  await s.click("button.sidebar-foot.sync");
  // Disabled while a sync (say, after an edit) is already running: found and clicked in one go,
  // so a sync starting in between can't make the click miss.
  await s.wait(
    () =>
      s.exec(
        `const b = [...document.querySelectorAll(".panel button")].find((b) => b.innerText.includes("Sync now") && !b.disabled);
         if (!b) return null; b.click(); return true`,
      ),
    "Sync now",
    ms,
  );
}

/** Syncs until `check` passes: the other side may still be pushing. */
async function syncUntil(s, check, what, ms = 60000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    await syncNow(s).catch(() => {});
    try {
      return await s.wait(check, what, 4000);
    } catch {
      // not yet: sync again
    }
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function openTeams(s) {
  await s.click("button.sidebar-foot.teams");
  // Already in an organization: back to the list.
  await s.exec(
    `const b = [...document.querySelectorAll(".panel button.link")].find((b) => b.innerText.trim() === "← Teams");
     if (b) b.click(); return true`,
  );
  await s.waitText("Your fingerprint", ".panel");
}

async function openOrg(s, name) {
  await s.exec(
    `const row = [...document.querySelectorAll(".panel [role=row]")].find((r) => r.querySelector(".lname")?.innerText === arguments[0]);
     row.querySelector("button.lnamebtn").click(); return true`,
    name,
  );
  await s.waitText("Members", ".panel");
}

/** On a team's page: turns on the setting whose name has `name`, and saves. */
async function turnOn(s, name) {
  await s.pageTab("Settings");
  const find = `[...document.querySelectorAll(".setting")].find((r) => r.querySelector(".setting-name")?.innerText.includes(arguments[0]))`;
  await s.wait(() => s.exec(`return ${find} ? true : null`, name), `the setting ${name}`);
  await s.exec(`${find}.querySelector("button[role=switch]").click(); return true`, name);
  await s.clickButton("Save settings");
  await s.wait(() => s.exec(`return [...document.querySelectorAll("button")].some((b) => b.innerText.includes("Save settings")) ? null : true`), "the settings to save");
}

/** A team page's row naming `name`, as text, or null. */
const rowText = (s, name) =>
  s.exec(`const r = [...document.querySelectorAll(".panel [role=row]")].find((r) => r.querySelector(".lname")?.innerText === arguments[0]); return r ? r.innerText : null`, name);

const alice = await session(app, process.env.WD_URL_ALICE);
const bob = await session(app, process.env.WD_URL_BOB);
// Bob's second device, for device approval.
const carol = await session(app, process.env.WD_URL_CAROL);
try {
  await Promise.all([createVault(alice, PASSWORD), createVault(bob, PASSWORD)]);
  await enableSync(alice, aliceEmail);
  await enableSync(bob, bobEmail);
  ok("Alice and Bob turned on sync");

  // Alice: an organization, a vault, and an invite for Bob with write access to it.
  await openTeams(alice);
  const aliceFp = await fingerprint(alice);
  await alice.clickButton("New team");
  await alice.type('input[aria-label="Team name"]', "Acme Ops");
  await alice.clickButton("Create team");
  await alice.wait(() => alice.exec(`return document.querySelector(".panel.page h1")?.innerText === "Acme Ops" || null`), "the team's page");
  await alice.pageTab("Vaults");
  await alice.waitText("No vaults yet", ".panel");
  await alice.type('input[aria-label="New vault name"]', "Production");
  await alice.clickButton("New vault");
  await alice.wait(() => alice.hasText(".panel .lname", "Production"), "the new vault");
  await alice.clickButton("Invite people");
  await alice.type('input[aria-label="Emails to invite"]', bobEmail);
  await alice.click(".grants input[type=checkbox]");
  await alice.clickButton("Send invite");
  const token = await alice.wait(
    () => alice.exec(`const c = document.querySelector(".invite-code"); return c ? c.innerText.trim() : null`),
    "the invite code",
  );
  await alice.screenshot(`${shots}/alice-invited.png`);
  await alice.clickButton("Done");
  ok("Alice created Acme Ops / Production and invited Bob");

  // Bob: looks the invite up and joins only because the owner's fingerprint matches.
  await openTeams(bob);
  const bobFp = await fingerprint(bob);
  await bob.type('input[aria-label="Invite code"]', token);
  await bob.clickButton("Look up");
  await bob.waitText("Join only if", ".panel");
  assert.equal(await fingerprint(bob, ".notice-box .fingerprint"), aliceFp);
  await bob.click(".notice-box label.check input");
  await bob.clickButton("Join Acme Ops");
  await bob.waitText("An admin confirms you next", ".panel");
  await new Promise((r) => setTimeout(r, 1000));
  assert.equal(await bob.panelError(), null);
  await bob.screenshot(`${shots}/bob-joined.png`);
  ok("Bob saw Alice's fingerprint and joined");

  // Alice: confirms Bob only because his fingerprint matches what he reads out.
  await openTeams(alice);
  await openOrg(alice, "Acme Ops");
  await alice.waitText("To confirm", ".panel");
  await alice.screenshot(`${shots}/alice-needs-you.png`);
  await alice.clickButton("Confirm…");
  assert.equal(await fingerprint(alice, ".lexpand .fingerprint"), bobFp);
  await alice.click(".lexpand label.check input");
  await alice.clickButton(`Confirm ${bobEmail}`);
  await alice.wait(
    () => alice.exec(`return document.querySelector(".panel").innerText.includes("To confirm") ? null : true`),
    "Bob's confirmation",
  );
  ok("Alice compared Bob's fingerprint and confirmed him");

  // Alice: a host in the shared vault.
  await alice.click('button[title="New host"]');
  await alice.waitText("New host", ".panel");
  await alice.exec(
    `[...document.querySelectorAll("label")].find((l) => l.querySelector("span")?.innerText === "Vault").querySelector("select").setAttribute("data-e2e", "vault"); return true`,
  );
  await alice.choose("select[data-e2e=vault]", "Acme Ops / Production");
  await alice.typeLabelled("Label", "db1");
  await alice.typeLabelled("Hostname or IP", "db1.internal");
  await alice.typeLabelled("User", "deploy");
  await alice.click(".panel form button[type=submit]");
  await alice.wait(() => alice.hasText(".sidebar .vault-tag", "Production"), "the shared host in Alice's sidebar");
  ok("Alice saved db1 in the shared vault");

  // Bob: the vault and its host arrive; he can edit it, and Alice gets his change.
  await syncUntil(bob, () => sidebarHas(bob, "db1"), "db1 on Bob's device");
  assert.ok(await bob.hasText(".sidebar .vault-tag", "Production"));
  await bob.screenshot(`${shots}/bob-shared-host.png`);
  ok("db1 reached Bob, tagged Production");
  await bob.exec(
    `const li = [...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === "db1");
     li.querySelector("button[aria-label^=Edit]").click(); return true`,
  );
  await bob.waitText("In the shared vault", ".panel");
  await bob.typeLabelled("Label", "db1-primary");
  await bob.click(".panel form button[type=submit]");
  await bob.wait(() => sidebarHas(bob, "db1-primary"), "Bob's edit");
  await syncNow(bob);
  await syncUntil(alice, () => sidebarHas(alice, "db1-primary"), "Bob's edit on Alice's device");
  ok("Bob renamed it to db1-primary; Alice has the change");

  // Moving: a personal host and the key it uses into Production, where Bob gets them; then back
  // out, and they leave his device.
  await openPage(alice, "Keys");
  await alice.clickButton("New key");
  await alice.waitText("New SSH key", ".panel");
  await alice.typeLabelled("Label", "lab key");
  await alice.clickButton("Generate key");
  await alice.waitText("Public key", ".panel");
  await alice.click('button[title="New host"]');
  await alice.waitText("New host", ".panel");
  await alice.typeLabelled("Label", "lab1");
  await alice.typeLabelled("Hostname or IP", "lab1.internal");
  await alice.typeLabelled("User", "deploy");
  await alice.clickButton("SSH key");
  await alice.click(".panel form button[type=submit]");
  await alice.wait(() => sidebarHas(alice, "lab1"), "lab1");
  const moveTo = async (s, vault) => {
    await s.waitText("Edit host", ".panel");
    await s.clickButton("Move to…");
    await s.wait(() => s.exec(`return document.querySelector("dialog.move-dialog[open] .move-plan li") ? true : null`), "the move plan");
    const plan = await s.exec(
      `const d = document.querySelector("dialog.move-dialog"); return { to: d.querySelector("select").selectedOptions[0].text, rows: [...d.querySelectorAll(".move-plan li")].map((l) => l.innerText) }`,
    );
    assert.equal(plan.to, vault);
    await s.exec(`document.querySelector("dialog.move-dialog .actions button.primary").click(); return true`);
    await s.wait(() => s.exec(`return document.querySelector("dialog.move-dialog") ? null : true`), "the move", 30000);
    return plan.rows;
  };
  const rows = await moveTo(alice, "Acme Ops / Production");
  assert.ok(rows.some((r) => r.includes("lab key") && r.includes("Used by lab1")), `the key goes along: ${rows.join(" | ")}`);
  await alice.wait(
    () => alice.exec(`return [...document.querySelectorAll(".sidebar .list li")].some((l) => l.querySelector(".row-title")?.innerText === "lab1" && l.querySelector(".vault-tag")) || null`),
    "lab1 in Production",
  );
  await syncNow(alice);
  await syncUntil(bob, () => sidebarHas(bob, "lab1"), "lab1 on Bob's device");
  await openPage(bob, "Keys");
  assert.ok(await bob.hasText(".panel .lname", "lab key"), "the key came along");
  ok("Alice moved lab1 and the key it uses into Production; Bob has both");
  await alice.exec(`document.querySelector('.sidebar button[aria-label="Edit lab1"]').click(); return true`);
  await moveTo(alice, "Personal (only you)");
  await syncNow(alice);
  await syncUntil(bob, () => bob.exec(`return [...document.querySelectorAll(".sidebar .row-title")].some((t) => t.innerText === "lab1") ? null : true`), "lab1 to leave Bob's device");
  assert.ok(await sidebarHas(alice, "lab1"), "Alice still has it");
  ok("moved back to Alice's personal vault, it left Bob's device");

  // Bob publishes the SSH key he uses on Acme's servers; Alice's member list counts it.
  await openPage(bob, "Keys");
  await bob.clickButton("New key");
  await bob.waitText("New SSH key", ".panel");
  await bob.typeLabelled("Label", "bob laptop");
  await bob.clickButton("Generate key");
  await bob.waitText("Public key", ".panel");
  const bobKey = await bob.exec(`return document.querySelector(".panel textarea").value`);
  await openTeams(bob);
  await openOrg(bob, "Acme Ops");
  await bob.pageTab("Your SSH keys");
  await bob.wait(() => bob.exec(`return document.querySelector('select[aria-label="Key to publish"]') ? true : null`), "the publish form");
  await bob.choose('select[aria-label="Key to publish"]', "bob laptop");
  await bob.clickButton("Publish");
  await bob.wait(() => bob.exec(`return [...document.querySelectorAll("button")].some((b) => b.innerText === "Unpublish") || null`), "the published key");
  await syncNow(bob);
  for (let i = 0; ; i++) {
    await syncNow(alice).catch(() => {});
    await openTeams(alice);
    await openOrg(alice, "Acme Ops");
    try {
      await alice.wait(async () => ((await rowText(alice, bobEmail)) ?? "").includes("1 published") || null, "Bob's published key", 3000);
      break;
    } catch (e) {
      if (i >= 15) throw e;
    }
  }
  ok("Bob published his SSH key to Acme Ops; Alice sees it");

  // Alice revokes Bob: the vault leaves his device, and Alice rotates its key.
  await openTeams(alice);
  await openOrg(alice, "Acme Ops");
  await alice.pageTab("Vaults");
  await alice.clickButton("Access");
  await alice.wait(() => alice.exec(`return document.querySelector(".lexpand .access-row button.ghost-danger") ? true : null`), "the access list");
  await alice.click(".lexpand .access-row button.ghost-danger");
  await alice.waitText("Rotate the key", ".panel");
  await syncUntil(bob, () => bob.exec(`return document.querySelector(".sidebar .vault-tag") ? null : true`), "the vault to leave Bob's device");
  assert.ok(!(await sidebarHas(bob, "db1-primary")));
  ok("Alice revoked Bob; the vault left his device");

  await syncUntil(alice, () => alice.exec(`return document.querySelector("button.sidebar-foot.teams.due") ? true : null`), "the rotation reminder");
  await openTeams(alice);
  await openOrg(alice, "Acme Ops");
  await alice.screenshot(`${shots}/alice-rotation-due.png`);
  await alice.clickButton("Rotate key");
  await alice.wait(() => alice.exec(`return [...document.querySelectorAll("button")].some((b) => b.innerText.includes("Rotate")) ? null : true`), "the rotation", 30000);
  assert.equal(await alice.panelError(), null);
  await syncUntil(alice, () => alice.exec(`return document.querySelector("button.sidebar-foot.teams.due") ? null : true`), "the reminder to go");
  assert.ok(await sidebarHas(alice, "db1-primary"));
  ok("Alice rotated the key; db1-primary is still hers");

  // Policies: members may create vaults, and Bob makes one he manages.
  await openTeams(alice);
  await openOrg(alice, "Acme Ops");
  await turnOn(alice, "Members can create vaults");
  await openTeams(bob);
  await openOrg(bob, "Acme Ops");
  await bob.wait(() => bob.exec(`return document.querySelector('input[aria-label="New vault name"]') ? true : null`), "Bob's new-vault form");
  await bob.type('input[aria-label="New vault name"]', "Bob's tools");
  await bob.clickButton("New vault");
  await bob.wait(() => bob.hasText(".panel .lname", "Bob's tools"), "Bob's vault");
  assert.ok(((await rowText(bob, "Bob's tools")) ?? "").includes("Can manage"));
  ok("Alice let members create vaults; Bob made one he manages");

  // The activity log tells the story.
  await alice.pageTab("Activity");
  const log = await alice.waitText("rotated the key of Production", ".panel");
  assert.ok(log.includes(`invited ${bobEmail}`), "the invite is in the log");
  assert.ok(log.includes(`removed ${bobEmail}'s access to Production`), "the revocation is in the log");
  await alice.screenshot(`${shots}/alice-activity.png`);
  ok("Alice's activity log shows the invite, the revocation and the rotation");

  // The whole log as a file.
  await alice.clickButton("Download CSV");
  const activity = await alice.wait(
    () => alice.exec(`const p = [...document.querySelectorAll(".panel p.ok")].find((e) => e.innerText.startsWith("Saved ")); return p ? p.innerText : null`),
    "the activity download",
  );
  const activityCsv = readFileSync(activity.match(/^Saved (\S+\.csv)/)[1].replace(/^~/, join(dirname(shots), "alice", "home")), "utf8");
  assert.ok(activityCsv.startsWith("seq,at,kind,actor_id,actor_email,target_id,target_email,vault_id,detail"), activityCsv.slice(0, 120));
  assert.ok(activityCsv.includes(",vault_key_rotated,"), "the rotation is in the file");
  ok("Alice downloaded the activity log as CSV");

  // Acme Ops asks members to publish their SSH keys: Alice hasn't, so Teams reminds her.
  await turnOn(alice, "Ask members to publish their SSH keys");
  await syncUntil(
    alice,
    () => alice.exec(`const b = document.querySelector("button.sidebar-foot.teams"); return b && b.innerText.includes("publish your keys") ? true : null`),
    "the reminder",
  );
  await alice.screenshot(`${shots}/alice-keys-reminder.png`);
  await openTeams(alice);
  await openOrg(alice, "Acme Ops");
  ok("Acme Ops asks members to publish their SSH keys; Alice, who hasn't, is reminded");

  // Device approval: Alice requires it. Bob's current device stays approved; his new one
  // (Carol's app, signed in to Bob's account) waits, Alice denies it, and Bob approves it from
  // his first device.
  await turnOn(alice, "Approve new devices");

  // Bob's second device started out with a vault of its own, a host in it, and joins his account
  // from Sync ("I have an account"): the host goes into his account, and Acme Ops' vaults wait for
  // the device's approval.
  await carol.wait(() => carol.exec(`return document.querySelector(".gate-choice") ? true : null`), "the first-run screen");
  await createVault(carol, "carol's own vault password");
  await carol.click('button[title="New host"]');
  await carol.waitText("New host", ".panel");
  await carol.typeLabelled("Label", "carol-only");
  await carol.typeLabelled("Hostname or IP", "carol.internal");
  await carol.typeLabelled("User", "bob");
  await carol.click(".panel form button[type=submit]");
  await carol.wait(() => sidebarHas(carol, "carol-only"), "the host made before joining");
  await carol.click("button.sidebar-foot.sync");
  await carol.waitText("Enable sync");
  await carol.exec(`[...document.querySelectorAll(".sync-setup .segmented button")].find((b) => b.innerText === "I have an account").click(); return true`);
  await useOwnServer(carol);
  await carol.typeLabelled("Email", bobEmail);
  await carol.typeLabelled("The account's master password", PASSWORD);
  assert.match(await carol.exec(`return document.querySelector(".sync-setup .warn").innerText`), /stops working/);
  await carol.screenshot(`${shots}/carol-join.png`);
  await carol.clickButton("Sign in");
  // Said again once merged: the password chosen on this device no longer opens it.
  await carol.waitText("no longer works", ".joined", 60000);
  await carol.screenshot(`${shots}/carol-joined.png`);
  await carol.exec(`[...document.querySelectorAll(".joined button")].find((b) => b.innerText === "OK").click(); return true`);
  await carol.wait(() => carol.exec(`return document.querySelector(".joined") ? null : true`), "the notice to close");
  await syncUntil(carol, () => carol.exec(`return document.querySelector("button.sidebar-foot.approval") ? true : null`), "the wait for approval");
  assert.match(await carol.exec(`return document.querySelector("button.sidebar-foot.approval").innerText`), /waiting/i);
  await carol.screenshot(`${shots}/carol-waiting.png`);
  await syncNow(bob);
  assert.equal(await bob.exec(`return !!document.querySelector("button.sidebar-foot.approval")`), false, "Bob's first device was approved with the policy");
  await syncUntil(bob, () => sidebarHas(bob, "carol-only"), "the joining device's host on Bob's first device");
  ok("Bob's new device joined his account with a vault of its own: its host went into his account");

  await openTeams(alice);
  await openOrg(alice, "Acme Ops");
  await alice.waitText("waits for approval", ".needs");
  await alice.screenshot(`${shots}/alice-device-request.png`);
  await alice.exec(`[...document.querySelectorAll(".device-requests button")].find((b) => b.innerText === "Deny").click(); return true`);
  await alice.waitText("Denied", ".device-requests");
  await alice.clickButton("Close");
  await syncUntil(carol, () => carol.exec(`const b = document.querySelector("button.sidebar-foot.approval"); return b && /denied/i.test(b.innerText) ? true : null`), "the denial");
  await carol.screenshot(`${shots}/carol-denied.png`);

  await openTeams(bob);
  await openOrg(bob, "Acme Ops");
  await bob.pageTab("Members");
  await bob.waitText("Denied", ".device-requests");
  await bob.exec(`[...document.querySelectorAll(".device-requests button")].find((b) => b.innerText === "Approve").click(); return true`);
  await bob.wait(() => bob.exec(`return document.querySelector(".device-requests") ? null : true`), "the request to go");
  await bob.clickButton("Close");
  await syncUntil(carol, () => carol.exec(`return document.querySelector("button.sidebar-foot.approval") ? null : true`), "the approval");
  await openTeams(carol);
  await openOrg(carol, "Acme Ops");
  await carol.wait(() => carol.hasText(".panel .lname", "Bob's tools"), "Bob's vault on his new device");
  await carol.screenshot(`${shots}/carol-approved.png`);
  ok("Acme Ops required device approval: Bob's new device waited, Alice denied it, Bob approved it from his first device");

  // A real host in Bob's vault (he can read it), logging in with a shared key; Bob's own key is
  // authorized there too. Alice's app first gets Bob's vault (she owns the organization).
  for (let i = 0; ; i++) {
    await syncNow(alice).catch(() => {});
    await openTeams(alice);
    await openOrg(alice, "Acme Ops");
    await alice.pageTab("Vaults");
    if (await alice.hasText(".panel .lname", "Bob's tools")) break;
    if (i >= 15) throw new Error("Bob's vault never reached Alice");
    await new Promise((r) => setTimeout(r, 1000));
  }
  await openPage(alice, "Keys");
  await alice.clickButton("New key");
  await alice.waitText("New SSH key", ".panel");
  await alice.clickButton("Import");
  await alice.exec(
    `[...document.querySelectorAll("label")].find((l) => l.querySelector("span")?.innerText === "Vault").querySelector("select").setAttribute("data-e2e", "vault"); return true`,
  );
  await alice.choose("select[data-e2e=vault]", "Bob's tools");
  await alice.typeLabelled("Label", "deploy");
  await alice.pickFile(".panel input[type=file]", "id_ed25519", readFileSync(sshKey, "utf8"));
  await alice.clickButton("Import key");
  await alice.waitText("Public key", ".panel");
  await alice.click('button[title="New host"]');
  await alice.waitText("New host", ".panel");
  await alice.exec(
    `[...document.querySelectorAll("label")].find((l) => l.querySelector("span")?.innerText === "Vault").querySelector("select").setAttribute("data-e2e", "vault"); return true`,
  );
  await alice.choose("select[data-e2e=vault]", "Bob's tools");
  await alice.typeLabelled("Label", "box");
  await alice.typeLabelled("Hostname or IP", "127.0.0.1");
  await alice.typeLabelled("Port", sshPort);
  await alice.typeLabelled("User", sshUser);
  await alice.clickButton("SSH key");
  await alice.screenshot(`${shots}/alice-host-editor.png`);
  await alice.click(".panel form button[type=submit]");
  await alice.wait(() => sidebarHas(alice, "box"), "the host box");
  appendFileSync(authorizedKeys, `${bobKey.trim()}\n`);
  const deployKey = readFileSync(`${sshKey}.pub`, "utf8");
  ok("Alice added box (shared key \"deploy\") in Bob's vault; Bob's key is authorized on it");

  // Attachments: Alice keeps a runbook with box; Bob's second device saves it from the server.
  const runbook = "# box\nrestart: sudo systemctl restart app\n";
  await alice.exec(`document.querySelector('.sidebar button[aria-label="Edit box"]').click(); return true`);
  await alice.waitText("Attach files", ".panel");
  await alice.exec(
    `const input = document.querySelector(".attachments input[type=file]");
     const files = new DataTransfer();
     files.items.add(new File([arguments[0]], "runbook.md", { type: "text/markdown" }));
     input.files = files.files;
     input.dispatchEvent(new Event("change", { bubbles: true }));
     return true`,
    runbook,
  );
  await alice.wait(() => alice.hasText(".attachments .attachment-row strong", "runbook.md"), "the attachment");
  await alice.screenshot(`${shots}/alice-attachment.png`);
  await alice.clickButton("Cancel");
  await syncNow(alice);
  // Box may be there already; the attachment comes with a later round.
  await syncUntil(
    carol,
    async () => {
      await carol.exec(`document.querySelector('.sidebar button[aria-label="Edit box"]')?.click(); return true`);
      return (await carol.hasText(".attachments .attachment-row strong", "runbook.md")) || null;
    },
    "the runbook on Bob's second device",
  );
  await carol.exec(`[...document.querySelectorAll(".attachments button")].find((b) => b.innerText === "Save").click(); return true`);
  const savedRunbook = await carol.wait(
    () => carol.exec(`const p = document.querySelector(".attachments p.ok"); return p ? p.innerText : null`),
    "the saved runbook",
  );
  const runbookPath = savedRunbook.match(/^Saved (\S+)/)[1].replace(/^~/, join(dirname(shots), "carol", "home"));
  assert.equal(readFileSync(runbookPath, "utf8"), runbook);
  await carol.screenshot(`${shots}/carol-attachment.png`);
  await carol.clickButton("Cancel");
  ok("Alice attached a runbook to box; Bob's second device saved it from the server");

  // Offboarding: what he could open, then removal and new keys.
  await openTeams(alice);
  await openOrg(alice, "Acme Ops");
  // The member list loads after the page.
  await alice.wait(() => alice.exec(`return [...document.querySelectorAll(".panel button")].some((b) => b.innerText.includes("Remove…")) || null`), "the member list");
  await alice.clickButton("Remove…");
  await alice.waitText("1. What they can open", ".panel");
  await alice.wait(() => alice.hasText(".panel .device-list strong", "Bob's tools"), "Bob's vaults");
  await alice.clickButton(`Remove ${bobEmail} and rotate keys`);
  await alice.waitText("every vault they had has a new key", ".panel", 60000);
  ok("Alice removed Bob and rotated every vault he had");
  // Bob's devices drop Acme Ops, and say why once.
  const removedNote = await syncUntil(bob, () => bob.exec(`const b = document.querySelector(".banner"); return b && b.innerText.includes("no longer in Acme Ops") ? b.innerText : null`), "the removal note on Bob's device");
  assert.match(removedNote, /an admin removed you/);
  await bob.screenshot(`${shots}/bob-removed-note.png`);
  await bob.click('.banner button[aria-label="Dismiss"]');
  ok("Bob's device says he's no longer in Acme Ops");

  // His published key is found on box and removed; the rest of the file stays.
  await alice.clickButton("Check hosts");
  await alice.waitText("Trust and connect", "body", 30000);
  await alice.clickButton("Trust and connect");
  await alice.waitText("1 of their keys found", ".panel", 60000);
  assert.ok(authorized().includes(keyBody(bobKey)));
  await alice.clickButton("Remove from 1 host");
  await alice.waitText("1 line removed", ".panel", 60000);
  assert.ok(!authorized().includes(keyBody(bobKey)), "Bob's key is gone from authorized_keys");
  assert.ok(authorized().includes(keyBody(deployKey)), "the other keys are untouched");
  await alice.screenshot(`${shots}/alice-offboarding.png`);
  ok("Alice found Bob's key on box and removed it");

  // The shared key he could read is replaced on box, and Alice still logs in.
  await alice.clickButton("Replace key");
  await alice.waitText("replaced (SHA256:", ".panel", 60000);
  assert.ok(!authorized().includes(keyBody(deployKey)), "the old shared key is gone");
  assert.equal(authorized().trim().split("\n").length, 1);
  await alice.exec(
    `[...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === "box").querySelector(".row-main").click(); return true`,
  );
  await alice.wait(
    () => alice.exec(`const r = document.querySelector(".xterm-rows"); return r && /[$#]\\s*$/m.test(r.innerText) ? true : null`),
    "a shell on box with the new key",
    60000,
  );
  ok("Alice replaced the shared key on box and logs in with the new one");

  // The session: box's row is live in the sidebar; Files in the route bar opens SFTP on it.
  await alice.wait(
    () => alice.exec(`return document.querySelector(".sidebar .list li.selected .sq.connected") ? true : null`),
    "box's live square",
  );
  await alice.wait(() => alice.exec(`return document.querySelector(".route-bar .pinned-key") ? true : null`), "the pinned key");
  await alice.screenshot(`${shots}/alice-session.png`);
  await alice.exec(`[...document.querySelectorAll(".route-bar button")].find((b) => b.innerText.includes("Files")).click(); return true`);
  await alice.wait(
    () => alice.exec(`const p = document.querySelectorAll(".sftp:not([hidden]) .fpane")[1]; return p && p.querySelector(".frow:not(.fhead)") ? true : null`),
    "box's files",
    60000,
  );
  await alice.screenshot(`${shots}/alice-sftp.png`);
  ok("box is live in the sidebar; Files in the route bar lists it over SFTP");

  // Shared credentials and a group: box signs in as the group's "lab" identity and keeps its
  // session in tmux on the server; Reconnect picks that session back up.
  await openPage(alice, "Keys");
  await alice.pageTab("Identities");
  await alice.clickButton("New identity");
  await alice.waitText("New identity", ".panel");
  await pickIn(alice, "Vault", "Bob's tools");
  await alice.typeLabelled("Name", "lab");
  await alice.typeLabelled("User", sshUser);
  await alice.clickButton("SSH key");
  await alice.click(".panel form button[type=submit]");
  await alice.waitText("Edit identity", ".panel");
  await openPage(alice, "Keys");
  await alice.pageTab("Identities");
  await alice.wait(() => alice.hasText(".panel .lname", "lab"), "the lab identity");
  await alice.click('button[aria-label="New group"]');
  await alice.waitText("New group", ".panel");
  await pickIn(alice, "Vault", "Bob's tools");
  await alice.typeLabelled("Name", "Lab");
  await pickIn(alice, "Identity", "lab");
  await alice.exec(`[...document.querySelectorAll(".panel label.check")].find((l) => l.innerText.includes("Keep sessions")).querySelector("input").click(); return true`);
  await alice.click(".panel form button[type=submit]");
  await alice.wait(() => alice.exec(`return document.querySelector('.sidebar button[aria-label="Open group Lab"]') ? true : null`), "the Lab group");
  await alice.exec(`document.querySelector('.sidebar button[aria-label="Edit box"]').click(); return true`);
  await alice.waitText("Sign in as", ".panel");
  await pickIn(alice, "Group", "Lab");
  await pickIn(alice, "Sign in as", "From the group");
  await alice.screenshot(`${shots}/alice-host-in-group.png`);
  await alice.click(".panel form button[type=submit]");
  await alice.wait(
    () =>
      alice.exec(
        `return [...document.querySelectorAll(".host-group")].some((g) => g.querySelector(".group-name")?.innerText === "Lab" && [...g.querySelectorAll(".row-title")].some((t) => t.innerText === "box")) ? true : null`,
      ),
    "box in the Lab group",
  );
  // The group's page lists it, with the identity its hosts use.
  await alice.exec(`document.querySelector('.sidebar button[aria-label="Open group Lab"]').click(); return true`);
  await alice.wait(() => alice.exec(`return document.querySelector(".panel.page h1")?.innerText === "Lab" || null`), "the Lab group's page");
  assert.ok(await alice.hasText(".panel .page-main .lname", "box"), "box is on the Lab page");
  assert.ok(await alice.hasText(".panel .use-card .use-name", "lab"), "so is the lab identity");
  await alice.screenshot(`${shots}/alice-group-page.png`);
  await alice.exec(
    `[...document.querySelectorAll(".sidebar .host-group li")].find((l) => l.querySelector(".row-title")?.innerText === "box").querySelector(".row-main").click(); return true`,
  );
  await alice.wait(async () => /\[morphgate/.test(await tabRows(alice)) || null, "box's tmux session", 60000);
  await typeInTab(alice, "echo kept-$((40+2))\r");
  await alice.wait(async () => (await tabRows(alice)).includes("kept-42") || null, "the marker");
  await typeInTab(alice, "tmux detach-client\r");
  await alice.waitText("The session ended.", ".reconnect-bar");
  await alice.screenshot(`${shots}/alice-session-ended.png`);
  await alice.click(".reconnect-bar button");
  await alice.wait(
    async () => (await alice.exec(`return document.querySelector(".reconnect-bar") ? null : true`)) && ((await tabRows(alice)).includes("kept-42") || null),
    "the kept session, reattached",
    60000,
  );
  await alice.screenshot(`${shots}/alice-session-kept.png`);
  ok("box signs in as its group's identity, keeps its session in tmux, and Reconnect picks it back up");

  // Single sign-on: the operator puts Acme Ops behind its identity provider, required. Alice's
  // copy of its vaults stays (the server leaves them out of its list until she signs in), she's
  // asked to sign in, and they sync again once she has.
  execFileSync(serverBin, ["sso", "--db", serverDb, "--org", "Acme Ops", "--issuer", idp, "--client-id", "morphgate", "--client-secret", "s3cret", "--require"]);
  await syncUntil(alice, () => alice.exec(`return document.querySelector("button.sidebar-foot.sso") ? true : null`), "the sign-in prompt");
  assert.ok(await sidebarHas(alice, "db1-primary"), "the team's host stays on Alice's device");
  assert.equal(
    await alice.exec(`return document.querySelector("button.sidebar-foot.sync").className.includes("error")`),
    false,
    "waiting for a sign-in is no sync problem",
  );
  await alice.screenshot(`${shots}/alice-sso-prompt.png`);
  await alice.click("button.sidebar-foot.sso");
  await alice.waitText("Sign in to Acme Ops", "dialog");
  await alice.screenshot(`${shots}/alice-sso-dialog.png`);
  await alice.exec(`[...document.querySelectorAll("dialog.sso button")].find((b) => b.innerText === "Sign in").click(); return true`);
  await alice.wait(() => alice.exec(`return document.querySelector("dialog.sso") ? null : true`), "the sign-in to finish", 60000);
  await syncUntil(alice, () => alice.exec(`return document.querySelector("button.sidebar-foot.sso") ? null : true`), "the prompt to go");
  assert.ok(await sidebarHas(alice, "db1-primary"));
  ok("Acme Ops required single sign-on: its vaults stayed, and synced once Alice signed in");

  // Her data: what the server keeps about her account, as JSON in her downloads.
  await alice.click("button.sidebar-foot.sync");
  await alice.waitText("Download your data", ".panel");
  await alice.clickButton("Download your data");
  const saved = await alice.wait(
    () => alice.exec(`const p = [...document.querySelectorAll(".panel p.ok")].find((e) => e.innerText.startsWith("Saved ")); return p ? p.innerText : null`),
    "the export",
  );
  const file = saved.match(/^Saved (\S+\.json)/)[1].replace(/^~/, join(dirname(shots), "alice", "home"));
  const data = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(data.format, "morphgate-account-export/1");
  assert.equal(data.account.email, aliceEmail);
  assert.ok(data.organizations.some((o) => o.name === "Acme Ops"), "her membership");
  assert.equal(data.sso_sessions?.length, 1, "her sign-in at Acme Ops' provider");
  await alice.screenshot(`${shots}/alice-export.png`);
  ok("Alice downloaded what the server keeps about her account");

  // Her vault, readable: the team's vaults included, secrets left out.
  await alice.click('button[aria-label="Security"]');
  await alice.waitText("Export vault", ".panel");
  await alice.exec(`[...document.querySelectorAll(".export-vault label.check")].find((l) => l.innerText.includes("team vaults")).querySelector("input").click(); return true`);
  await alice.typeLabelled("Master password (to confirm)", PASSWORD);
  await alice.clickButton("Export vault");
  const exported = await alice.wait(
    () => alice.exec(`const p = document.querySelector(".export-vault p.ok"); return p ? p.innerText : null`),
    "the vault export",
    60000,
  );
  const vaultFile = JSON.parse(readFileSync(exported.match(/^Saved (\S+\.json)/)[1].replace(/^~/, join(dirname(shots), "alice", "home")), "utf8"));
  assert.equal(vaultFile.format, "morphgate-vault-export/1");
  assert.equal(vaultFile.secrets_included, false);
  const production = vaultFile.vaults.find((v) => v.name === "Production");
  assert.ok(production?.items.some((i) => i.type === "host" && i.label === "db1-primary"), "the team's host is in it");
  await alice.screenshot(`${shots}/alice-vault-export.png`);
  await alice.clickButton("Close");
  ok("Alice exported her vault, team vaults included, without secrets");

  // Both devices end with a clean sync (Bob's without the organization).
  for (const [who, s] of [["Alice", alice], ["Bob", bob]]) {
    // A background round may be running: give it time.
    await syncNow(s, 90000);
    await s.wait(
      () => s.exec(`const b = document.querySelector("button.sidebar-foot.sync"); return b && !b.className.includes("busy") ? true : null`),
      `${who}'s last sync`,
    );
    const problem = await s.exec(`return document.querySelector("button.sidebar-foot.sync").title || null`);
    assert.equal(problem, null, `${who}'s sync: ${problem}`);
  }
  ok("Alice's and Bob's syncs end clean");

  // Bob signs his second device out from his first: on its next sync it erases itself and says
  // why, and signing in again brings his vault back.
  await bob.click("button.sidebar-foot.sync");
  await bob.wait(() => bob.exec(`return [...document.querySelectorAll(".panel .device-list li")].some((l) => !l.innerText.includes("this device") && l.querySelector("button")) || null`), "Bob's second device in his list");
  await bob.exec(`[...document.querySelectorAll(".panel .device-list li")].find((l) => !l.innerText.includes("this device") && l.querySelector("button")).querySelector("button").click(); return true`);
  await bob.clickButton("Really sign out?");
  await bob.clickButton("Close");
  const notice = await syncUntil(carol, () => carol.exec(`const n = document.querySelector(".gate-notice"); return n ? n.innerText : null`), "the second device erased");
  assert.match(notice, new RegExp(`signed out of ${bobEmail.replace(/[.+]/g, "\\$&")} from another device`));
  assert.ok(await carol.exec(`return !!document.querySelector(".gate-choice")`), "back at the first screen");
  await carol.screenshot(`${shots}/carol-signed-out.png`);
  await carol.exec(`[...document.querySelectorAll(".gate-choice button")].find((b) => b.innerText === "Sign in").click(); return true`);
  await useOwnServer(carol);
  await carol.typeLabelled("Email", bobEmail);
  await carol.typeLabelled("Master password", PASSWORD);
  await carol.click(".gate-card form button[type=submit]");
  await syncUntil(carol, () => sidebarHas(carol, "carol-only"), "Bob's vault back on his second device", 90000);
  ok("Bob signed his second device out: it erased itself, said why, and got his vault back by signing in");

  // Deleting the account from the app. Alice owns Acme Ops: she's sent to Teams to hand it over
  // or delete it first (the server would refuse).
  const deleteAccount = async (s) => {
    await s.click("button.sidebar-foot.sync");
    await s.waitText("Delete account…", ".panel");
    await s.clickButton("Delete account…");
  };
  await deleteAccount(alice);
  await alice.waitText("You own Acme Ops.", ".panel .warn", 30000);
  await alice.screenshot(`${shots}/alice-delete-account-owner.png`);
  await alice.clickButton("Open Teams");
  await alice.waitText("Your fingerprint", ".panel");
  ok("Alice owns Acme Ops: Delete account sends her to Teams first");

  // Bob can: this device keeps his own hosts, with sync off; his second device stops syncing.
  await deleteAccount(bob);
  await bob.typeLabelled("Master password", PASSWORD);
  await bob.clickButton("Delete account");
  await bob.waitText("is deleted", ".panel p.ok", 60000);
  assert.ok(await bob.hasText("button.sidebar-foot.sync span", "Sync off"));
  assert.ok(await sidebarHas(bob, "carol-only"), "his own host stays");
  await bob.screenshot(`${shots}/bob-account-deleted.png`);
  // His second device hears the account was deleted (401 account_deleted): sync off, his own
  // vault kept, and it says why.
  const deletedNote = await syncUntil(carol, () => carol.exec(`const b = document.querySelector(".banner"); return b && b.innerText.includes("was deleted") ? b.innerText : null`), "the second device told");
  assert.match(deletedNote, new RegExp(`The sync account ${bobEmail.replace(/[.+]/g, "\\$&")} was deleted`));
  assert.ok(await carol.hasText("button.sidebar-foot.sync span", "Sync off"), "sync is off on the second device");
  assert.ok(await sidebarHas(carol, "carol-only"), "the second device keeps what it has");
  await carol.screenshot(`${shots}/carol-account-deleted.png`);
  ok("Bob deleted his account; his devices keep their own vault, sync off, and the other one says why");
} catch (e) {
  // What each sync was doing (a stuck request times out after 30 s and says so).
  await new Promise((r) => setTimeout(r, 45000));
  for (const [who, s] of [["alice", alice], ["bob", bob], ["carol", carol]]) {
    const state = await s
      .exec(`const b = document.querySelector("button.sidebar-foot.sync"); return b ? b.className + " | " + b.innerText + " | " + b.title : "no sync button"`)
      .catch((err) => String(err));
    console.error(`e2e: ${who}'s sync: ${state}`);
  }
  await alice.screenshot(`${shots}/failed-alice.png`).catch(() => {});
  await bob.screenshot(`${shots}/failed-bob.png`).catch(() => {});
  await carol.screenshot(`${shots}/failed-carol.png`).catch(() => {});
  throw e;
} finally {
  await alice.close();
  await bob.close();
  await carol.close();
}
