// The steps people take in the app, for scenarios run against any sync server: this
// repository's e2e, and the hosted service's (which imports this file). Each takes a WebDriver
// session from webdriver.mjs. The IDs in their comments name the journeys they take part in:
// J for joining (accounts, devices), S for signing out, T for teams, P for plans.
//
// `server` is the sync server's URL (typed as "Your own server"); `mailpit`, where that server
// mails sign-up codes (Mailpit's web address), for servers that verify addresses.

import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

export const PASSWORD = "correct horse battery staple";

export const ok = (...a) => console.log("  ✓", ...a);

/** Fingerprint shown in the element matching `css` (they're labelled "Fingerprint XXXX-…"). */
export const fingerprint = (s, css = ".fingerprint") =>
  s.wait(() => s.exec(`const e = document.querySelector(arguments[0]); return e ? e.getAttribute("aria-label").replace("Fingerprint ", "") : null`, css), css);

export const sidebarHas = (s, title) => s.hasText(".sidebar .row-title", title);

/** The newest six-digit code Mailpit has for `to`, mailed after `since` (ms). */
export async function mailedCode(mailpit, to, since, ms = 30000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const found = await (await fetch(`${mailpit}/api/v1/search?${new URLSearchParams({ query: `to:"${to}"`, limit: "5" })}`)).json();
    for (const m of found.messages ?? []) {
      if (Date.parse(m.Created) < since - 2000) continue;
      const msg = await (await fetch(`${mailpit}/api/v1/message/${m.ID}`)).json();
      const code = (msg.Text ?? "").match(/\b(\d{6})\b/);
      if (code) return code[1];
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`no code mailed to ${to}`);
}

/** In a sync form: "Your own server" with this address. */
export async function chooseServer(s, server) {
  await s.exec(`[...document.querySelectorAll('.sync-server button[role="radio"]')].find((b) => b.innerText === "Your own server").click(); return true`);
  await s.typeLabelled("Server address", server);
}

/** Sync now, from the Sync panel (instead of waiting for the next minute). */
export async function syncNow(s, ms = 20000) {
  await s.click("button.sidebar-foot.sync");
  // Disabled while a sync is already running: found and clicked in one go.
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

/** Syncs until `check` passes. */
export async function syncUntil(s, check, what, ms = 60000) {
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

/**
 * J2: a device with a vault makes a new account. Accepts the server's terms and enters the
 * mailed code where the server asks for them.
 */
export async function signUp(s, { server, email, mailpit, password = PASSWORD }) {
  await s.click("button.sidebar-foot.sync");
  await s.waitText("Enable sync");
  await chooseServer(s, server);
  await s.clickButton("Check");
  await s.wait(() => s.exec(`return document.querySelector(".sync-setup p.ok, .sync-setup p.warn, .sync-setup .error") ? true : null`), "the server check");
  await s.typeLabelled("Email", email);
  await s.typeLabelled("Master password (to confirm)", password);
  if (await s.exec(`return !!document.querySelector(".terms-check input")`)) await s.click(".terms-check input");
  const since = Date.now();
  await s.clickButton("Enable sync");
  const next = await s.wait(
    () => s.exec(`return document.querySelector(".panel dl.facts") ? "synced" : [...document.querySelectorAll(".sync-setup label span")].some((l) => l.innerText.startsWith("Code sent to")) ? "code" : null`),
    "the account, or a mailed code",
    60000,
  );
  if (next === "code") {
    assert.ok(mailpit, "the server mails a code: pass where to read it (Mailpit)");
    await s.typeLabelled("Code sent to", await mailedCode(mailpit, email, since));
    await s.clickButton("Enable sync");
  }
  await s.waitText("Last sync", ".panel", 60000);
}

/** J3: the first screen's "Sign in" (a fresh device). */
export async function signInFresh(s, { server, email, password = PASSWORD }) {
  await s.wait(() => s.exec(`return document.querySelector(".gate-choice") ? true : null`), "the first screen");
  await s.exec(`[...document.querySelectorAll(".gate-choice button")].find((b) => b.innerText === "Sign in").click(); return true`);
  await chooseServer(s, server);
  await s.typeLabelled("Email", email);
  await s.typeLabelled("Master password", password);
  await s.click(".gate-card form button[type=submit]");
  await s.wait(() => s.exec(`return document.querySelector("button.brand, .m-home") ? true : null`), "the workspace", 60000);
}

/** Teams, at the list of organizations. */
export async function openTeams(s) {
  await s.click("button.sidebar-foot.teams");
  await s.exec(
    `const b = [...document.querySelectorAll(".panel button.link")].find((b) => b.innerText.trim() === "← Teams");
     if (b) b.click(); return true`,
  );
  await s.waitText("Your fingerprint", ".panel");
}

export async function openOrg(s, name) {
  await s.exec(
    `const row = [...document.querySelectorAll(".panel [role=row]")].find((r) => r.querySelector(".lname")?.innerText === arguments[0]);
     row.querySelector("button.lnamebtn").click(); return true`,
    name,
  );
  await s.waitText("Members", ".panel");
}

/** T1 and a first vault in it. Returns the owner's fingerprint. */
export async function createTeam(s, name, vault) {
  await openTeams(s);
  const fp = await fingerprint(s);
  await s.clickButton("New team");
  await s.type('input[aria-label="Team name"]', name);
  await s.clickButton("Create team");
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === arguments[0] || null`, name), "the team's page");
  await s.pageTab("Vaults");
  await s.waitText("No vaults yet", ".panel");
  await s.clickButton("New vault");
  await s.type('input[aria-label="Vault name"]', vault);
  await s.clickButton("Create vault");
  await s.wait(() => s.hasText(".panel .lname", vault), "the new vault");
  return fp;
}

/** The newest invite link Mailpit has for `to`, mailed after `since`: its token. */
export async function mailedInvite(mailpit, to, since, ms = 30000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const found = await (await fetch(`${mailpit}/api/v1/search?${new URLSearchParams({ query: `to:"${to}"`, limit: "5" })}`)).json();
    for (const m of found.messages ?? []) {
      if (Date.parse(m.Created) < since - 2000) continue;
      const msg = await (await fetch(`${mailpit}/api/v1/message/${m.ID}`)).json();
      const link = (msg.Text ?? "").match(/\/invite\/([A-Za-z0-9_-]+)/);
      if (link) return link[1];
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`no invite mailed to ${to}`);
}

/**
 * T2 (the inviter, in the organization's page): invites `email` with write access to its vaults.
 * Returns the invite's token: shown in the app by servers that don't mail invites, read from
 * the mail (Mailpit) where the server mails it.
 */
export async function invite(s, email, { mailpit } = {}) {
  await s.clickButton("Invite people");
  await s.wait(() => s.exec(`return document.querySelector("dialog.invite-dialog[open]") ? true : null`), "the invite dialog");
  await s.type('input[aria-label="Emails to invite"]', email);
  for (const box of await s.exec(`return document.querySelectorAll(".grants input[type=checkbox]").length`).then((n) => [...Array(n).keys()])) {
    await s.exec(`document.querySelectorAll(".grants input[type=checkbox]")[arguments[0]].click(); return true`, box);
  }
  const since = Date.now();
  await s.clickButton("Send invite");
  const shown = await s.wait(
    () =>
      s.exec(
        `const c = document.querySelector(".invite-code"); return c ? { token: c.innerText.trim() } : document.querySelector("dialog.invite-dialog")?.innerText.includes("Invite emailed to") ? { mailed: true } : null`,
      ),
    "the invite code, or that it was mailed",
  );
  await s.clickButton("Done");
  if (shown.token) return shown.token;
  assert.ok(mailpit, "the server mails invites: pass where to read them (Mailpit)");
  return mailedInvite(mailpit, email, since);
}

/** T2 (the invitee): joins after checking the owner's fingerprint. Returns the member's own. */
export async function acceptInvite(s, token, ownerFp, team) {
  await openTeams(s);
  await s.type('input[aria-label="Invite code"]', token);
  await s.clickButton("Look up");
  return joinLookedUp(s, ownerFp, team);
}

/** T2 (the invitee, in Teams with the invite looked up): compares the owner's fingerprint and
 * joins. Returns the member's own. */
export async function joinLookedUp(s, ownerFp, team) {
  await s.waitText("Join only if", ".panel", 30000);
  const fp = await fingerprint(s, ".teams-foot > .stack > .fingerprint");
  assert.equal(await fingerprint(s, ".notice-box .fingerprint"), ownerFp);
  await s.click(".notice-box label.check input");
  await s.clickButton(`Join ${team}`);
  await s.waitText("An admin confirms you next", ".panel", 30000);
  return fp;
}

/**
 * J2 and T2 on a fresh install: the invite pasted on the first screen ("Joining a team?"), a new
 * account with the address it names and a suggested password, then Teams opens with the invite
 * looked up. Returns the password.
 */
export async function newAccountFromInvite(s, { invite, team, email, mailpit, shots }) {
  await s.wait(() => s.exec(`return document.querySelector(".gate-choice") ? true : null`), "the first screen");
  await s.clickButton("Joining a team? Paste your invite");
  await s.typeLabelled("Invite code or link", invite);
  await s.clickButton("Use this invite");
  await s.waitText(`to join ${team}`, ".gate-invite", 30000);
  // An invite needs an account: offered first, with the invited address.
  await s.waitText("Create your account", ".gate-card");
  await s.wait(() => s.exec(`return document.querySelector(".gate-card input[type=email]")?.value === arguments[0] || null`, email), "the invited address");
  await s.clickButton("Suggest a strong password");
  const password = await s.wait(() => s.exec(`return document.querySelector(".suggested-password .mono")?.innerText || null`), "a suggested password");
  if (shots) await s.screenshot(`${shots}/first-screen-invite.png`);
  // The server's terms, once it was asked what it needs (none on a server without them).
  await s.wait(() => s.exec(`return document.querySelector(".gate-card .terms-check") ? true : null`), "the terms", 10000).catch(() => {});
  if (await s.exec(`return !!document.querySelector(".gate-card .terms-check input")`)) await s.click(".gate-card .terms-check input");
  // The recovery key (the account is made), an error, or (`code`: the first step) the mailed code's field.
  const step = (code, what, ms) =>
    s.wait(
      () =>
        s.exec(
          `const e = document.querySelector(".gate-card p.error"); if (e) return { error: e.innerText };
          if (document.querySelector(".recovery-code")) return "done";
          return arguments[0] && [...document.querySelectorAll(".gate-card label span")].some((l) => l.innerText.startsWith("Code sent to")) ? "code" : null`,
          code,
        ),
      what,
      ms,
    );
  const since = Date.now();
  await s.click(".gate-card form button.primary");
  let next = await step(true, "a mailed code, or the account", 60000);
  if (next === "code") {
    assert.ok(mailpit, "the server mails a code: pass where to read it (Mailpit)");
    await s.typeLabelled("Code sent to", await mailedCode(mailpit, email, since));
    await s.click(".gate-card form button.primary");
    next = await step(false, "the account", 90000);
  }
  assert.equal(next, "done", JSON.stringify(next));
  await s.click(".gate-card label.check input");
  await s.exec(`[...document.querySelectorAll(".gate-card button.primary")].find((b) => !b.disabled).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector("button.brand, .m-home") ? true : null`), "the workspace", 30000);
  return password;
}

/** T2 (an owner or admin, in the organization's page): confirms `email` after checking its fingerprint. */
export async function confirmMember(s, email, memberFp) {
  await s.pageTab("Members");
  await s.waitText("To confirm", ".panel", 30000);
  await s.clickButton("Confirm…");
  assert.equal(await fingerprint(s, ".lexpand .fingerprint"), memberFp);
  await s.click(".lexpand label.check input");
  await s.clickButton(`Confirm ${email}`);
  await s.wait(() => s.exec(`return document.querySelector(".panel").innerText.includes("To confirm") ? null : true`), "the confirmation", 30000);
}

/** T6 (an owner or admin, in the organization's page): removes `email` and rotates keys. */
export async function removeMember(s, email) {
  // The "Remove…" on `email`'s row in the member list.
  await s.pageTab("Members");
  const row = `[...document.querySelectorAll(".panel [role=row]")]
    .find((r) => r.querySelector(".lname")?.innerText === arguments[0] && [...r.querySelectorAll("button")].some((b) => b.innerText.includes("Remove…")))`;
  await s.wait(() => s.exec(`return ${row} ? true : null`, email), `${email} in the member list`);
  await s.exec(`[...${row}.querySelectorAll("button")].find((b) => b.innerText.includes("Remove…")).click(); return true`, email);
  await s.waitText("1. What they can open", ".panel");
  await s.clickButton(`Remove ${email} and rotate keys`);
  await s.waitText("every vault they had has a new key", ".panel", 60000);
}

/** A new host; `vault` is the Vault select's option ("Acme / Production"), personal without it. */
export async function newHost(s, { label, hostname, user = "deploy", vault }) {
  await s.click('button[title="New host"]');
  await s.waitText("New host", ".panel");
  if (vault) {
    await s.exec(
      `[...document.querySelectorAll("label")].find((l) => l.querySelector("span")?.innerText === "Vault").querySelector("select").setAttribute("data-e2e", "vault"); return true`,
    );
    await s.choose("select[data-e2e=vault]", vault);
  }
  await s.typeLabelled("Label", label);
  await s.typeLabelled("Hostname or IP", hostname);
  await s.typeLabelled("User", user);
  await s.click(".panel form button[type=submit]");
  await s.wait(() => sidebarHas(s, label), label);
}

/** T5: moves a host (by its sidebar title) to `vault` ("Acme / Production", or "Personal"). */
export async function moveHost(s, label, vault) {
  await s.exec(
    `const li = [...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === arguments[0]);
     li.querySelector("button[aria-label^=Edit]").click(); return true`,
    label,
  );
  await s.waitText("Edit host", ".panel");
  await s.clickButton("Move to…");
  await s.wait(() => s.exec(`return document.querySelector("dialog.move-dialog[open] .move-plan li") ? true : null`), "the move plan");
  await s.exec(
    `const sel = document.querySelector("dialog.move-dialog select"); const o = [...sel.options].find((o) => o.text.includes(arguments[0]));
     sel.value = o.value; sel.dispatchEvent(new Event("change", { bubbles: true })); return true`,
    vault,
  );
  await s.wait(() => s.exec(`return document.querySelector("dialog.move-dialog .move-plan li") ? true : null`), "the move plan for it");
  await s.exec(`document.querySelector("dialog.move-dialog .actions button.primary").click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector("dialog.move-dialog") ? null : true`), "the move", 30000);
}

/** Clicks the button with `text` once it's enabled (forms enable theirs after checks: strength, fields). */
export async function clickWhenEnabled(s, text, ms = 20000) {
  await s.wait(
    () => s.exec(`const b = [...document.querySelectorAll("button")].find((b) => b.innerText.includes(arguments[0]) && !b.disabled); if (!b) return null; b.click(); return true`, text),
    `"${text}" enabled`,
    ms,
  );
}

/** The unlock screen (after a relaunch or a lock): opens the vault. */
export async function unlock(s, password = PASSWORD) {
  await s.wait(() => s.exec(`return [...document.querySelectorAll("button")].some((b) => b.innerText === "Unlock") || null`), "the unlock screen", 30000);
  await s.typeLabelled("Master password", password);
  await s.clickButton("Unlock");
  await s.wait(() => s.exec(`return document.querySelector("button.brand, .m-home") ? true : null`), "the workspace", 60000);
}

/** S2, S3: Sync → Disconnect this device; `remove`: erase it, else keep a copy here. */
export async function disconnect(s, { remove }) {
  await s.click("button.sidebar-foot.sync");
  await s.clickButton("Disconnect this device");
  // The choices wait for a round in progress (a "Sync now" just before): a slow one keeps them
  // disabled a while.
  await clickWhenEnabled(s, remove ? "Remove everything from this device" : "Keep a copy here", 60000);
  if (remove) {
    await s.wait(() => s.exec(`return document.querySelector(".gate-notice") ? true : null`), "the first screen", 30000);
  } else {
    await s.waitText("Enable sync", ".panel", 30000);
  }
}

/**
 * S1 (from another of the account's devices): Sync → Devices → Sign out the first device that
 * isn't this one. (Devices are named after the computer, so apps on one machine share a name.)
 */
export async function signOutOther(s) {
  // Opened afresh, so its device list is the server's now.
  await s.exec(`[...document.querySelectorAll(".panel button")].find((b) => b.innerText === "Close")?.click(); return true`);
  await s.click("button.sidebar-foot.sync");
  const other = `[...document.querySelectorAll(".panel .device-list li")].find((l) => !l.innerText.includes("this device") && l.querySelector("button"))`;
  await s.wait(() => s.exec(`return ${other} ? true : null`), "another device in the list");
  await s.exec(`${other}.querySelector("button").click(); return true`);
  await s.clickButton("Really sign out?");
}

/** J4: a device with its own vault joins an existing account (Sync → I have an account). */
export async function joinAccount(s, { server, email, password = PASSWORD }) {
  await s.click("button.sidebar-foot.sync");
  await s.waitText("Enable sync");
  await s.exec(`[...document.querySelectorAll(".sync-setup .segmented button")].find((b) => b.innerText === "I have an account").click(); return true`);
  await chooseServer(s, server);
  await s.typeLabelled("Email", email);
  await s.typeLabelled("The account's master password", password);
  await s.click(".sync-setup form button[type=submit]");
  await s.waitText("no longer works", ".joined", 60000);
  await s.clickButton("OK");
  await s.waitText("Last sync", ".panel", 60000);
}

/** S4: Security → change the master password (set on the sync server first, with sync on). */
export async function changePassword(s, current, next) {
  await s.click('button[aria-label="Security"]');
  await s.typeLabelled("Current master password", current);
  await s.typeLabelled("New master password", next);
  await s.typeLabelled("Repeat password", next);
  // Enabled once the strength meter has judged the new password.
  await clickWhenEnabled(s, "Change master password");
  await s.waitText("Master password changed", ".panel", 60000);
}

/** J5: Sync → Sign in again, with the account's current password. */
export async function signInAgain(s, password = PASSWORD) {
  await s.click("button.sidebar-foot.sync");
  await s.waitText("Sign in again", ".panel", 30000);
  await s.typeLabelled("Master password of the sync account", password);
  await clickWhenEnabled(s, "Sign in again");
  await s.wait(() => s.exec(`return [...document.querySelectorAll(".panel button")].some((b) => b.innerText === "Sign in again") ? null : true`), "signed in", 60000);
}

/** T8 (the owner, in the organization's page): deletes it. */
export async function deleteTeam(s, name, password = PASSWORD) {
  await s.pageTab("Settings");
  await s.clickButton("Delete team…");
  await s.typeLabelled("Your master password", password);
  await clickWhenEnabled(s, `Delete ${name}`);
  await s.waitText("Your fingerprint", ".panel", 60000);
}

/**
 * T7 (a member, in the organization's page): leaves it, from their row in the member list (its
 * confirmation reads "Really leave?"). `name` is unused, kept for callers that pass it.
 */
export async function leaveTeam(s, name) {
  // A confirmed member leaves from their row in Members; one still waiting, from the notice.
  if (await s.exec(`return !!document.querySelector(".page-tabs")`)) await s.pageTab("Members");
  await s.clickButton("Leave");
  await s.clickButton("Really leave");
  await s.waitText("Your fingerprint", ".panel", 60000);
}

/** The workspace's notice (the removal note, say), or null. */
export const banner = (s) => s.exec(`const b = document.querySelector(".banner"); return b ? b.innerText : null`);


/**
 * Closes the open panel. The Sync panel reads the device list when it opens, so a device that
 * signed in elsewhere since only shows once it's opened again.
 */
export const closePanel = (s) =>
  s.exec(`const b = [...document.querySelectorAll(".panel button")].find((b) => b.innerText === "Close"); if (b) b.click(); return true`);

/** Whether no sidebar row has this title (a host gone from the device). */
export const gone = (s, label) => s.exec(`return [...document.querySelectorAll(".sidebar .row-title")].some((t) => t.innerText === arguments[0]) ? null : true`, label);

/** The sync button's problem (its title), or null when the last sync went through. */
export const syncProblem = (s) =>
  s.exec(`const b = document.querySelector("button.sidebar-foot.sync"); return b && (b.title || b.className.includes("error")) ? b.title || "error" : null`);

/** Syncs until the sync button shows a problem; returns it. */
export async function syncUntilProblem(s, what, ms = 90000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    await syncNow(s).catch(() => {});
    await new Promise((r) => setTimeout(r, 3000));
    const p = await syncProblem(s);
    if (p) return p;
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** Syncs until the last sync went through. */
export async function syncUntilClean(s, what, ms = 90000) {
  const end = Date.now() + ms;
  let last;
  while (Date.now() < end) {
    await syncNow(s).catch(() => {});
    await new Promise((r) => setTimeout(r, 3000));
    const busy = await s.exec(`return document.querySelector("button.sidebar-foot.sync")?.className.includes("busy") ?? false`);
    last = await syncProblem(s);
    if (!busy && !last) return;
  }
  throw new Error(`timed out waiting for ${what}: ${last}`);
}

/** The first screen's notice (why the device was erased), or null. */
export const gateNotice = (s) => s.exec(`const n = document.querySelector(".gate-notice"); return n ? n.innerText : null`);

/** Whether the Sync panel asks to sign in again (a plain sign-out: the data stayed). */
export async function asksToSignInAgain(s) {
  await s.click("button.sidebar-foot.sync");
  return s.exec(`return [...document.querySelectorAll(".panel button")].some((b) => b.innerText === "Sign in again")`);
}

/** Syncs until the Sync panel asks to sign in again. */
export async function syncUntilSignedOut(s, what, ms = 90000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    await syncNow(s).catch(() => {});
    await new Promise((r) => setTimeout(r, 3000));
    if (await asksToSignInAgain(s).catch(() => false)) return;
  }
  throw new Error(`timed out waiting for ${what}`);
}

/**
 * First launch, keeping the recovery key: as webdriver.mjs's createVault, and returns the key
 * the app shows once.
 */
export async function createVaultKeepingKey(s, password = PASSWORD) {
  await s.waitText("Create vault", "body", 60000);
  await s.typeLabelled("Master password", password);
  await s.typeLabelled("Repeat password", password);
  await s.wait(
    () => s.exec(`return [...document.querySelectorAll("button")].some((b) => b.innerText.includes("Create vault") && !b.disabled) || null`),
    "the password judged strong enough",
  );
  await s.clickButton("Create vault");
  await s.waitText("I stored it somewhere safe", "body", 60000);
  const key = await s.exec(`return [...document.querySelectorAll(".recovery-code span")].map((g) => g.innerText.trim()).join("-")`);
  await s.click("label.check input");
  await s.exec(`[...document.querySelectorAll("button.primary")].find((b) => !b.disabled).click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector("button.brand, .m-home") ? true : null`), "the workspace", 30000);
  await s.wait(() => s.exec(`return document.querySelector("dialog.sync-offer[open]") ? true : null`), "the offer to turn sync on");
  await s.exec(`[...document.querySelectorAll("dialog.sync-offer button")].find((b) => b.innerText === "Not now").click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector("dialog.sync-offer") ? null : true`), "the offer to close");
  return key;
}

/** J6: on the unlock screen, the recovery key and a new master password. */
export async function recoverOnUnlock(s, key, password) {
  await s.wait(() => s.exec(`return [...document.querySelectorAll("button")].some((b) => b.innerText === "Unlock") || null`), "the unlock screen", 30000);
  await s.clickButton("Use your recovery key");
  await s.waitText("Use your recovery key", "body");
  await s.typeLabelled("Recovery key", key);
  await s.typeLabelled("Master password", password);
  await s.typeLabelled("Repeat password", password);
  await s.wait(() => s.exec(`return [...document.querySelectorAll("button")].some((b) => b.innerText === "Set new password" && !b.disabled) || null`), "the new password judged strong enough");
  await s.clickButton("Set new password");
  await s.wait(() => s.exec(`return document.querySelector("button.brand, .m-home") ? true : null`), "the workspace", 60000);
}

/** In the organization's page: the vault named `vault`, its access list open. */
async function openAccess(s, vault) {
  await s.pageTab("Vaults");
  await s.wait(() => s.hasText(".panel .lname", vault), `the vault ${vault}`);
  await s.exec(
    `const row = [...document.querySelectorAll(".panel [role=row]")].find((r) => r.querySelector(".lname")?.innerText === arguments[0]);
     [...row.querySelectorAll("button")].find((b) => b.innerText.includes("Access")).click(); return true`,
    vault,
  );
  await s.wait(() => s.exec(`return document.querySelector(".lexpand .access-row") ? true : null`), "the access list");
}

/** T4 (an owner or admin, in the organization's page): takes `email`'s access to `vault` away. */
export async function revokeAccess(s, vault, email) {
  await openAccess(s, vault);
  await s.exec(
    `const row = [...document.querySelectorAll(".lexpand .access-row")].find((r) => r.innerText.includes(arguments[0]));
     row.querySelector("button.ghost-danger").click(); return true`,
    email,
  );
  await s.waitText("Rotate the key", ".panel", 30000);
}

/** T4 (an owner or admin, in the organization's page): gives `email` access to `vault`. */
export async function grantAccess(s, vault, email) {
  await openAccess(s, vault);
  await s.choose('select[aria-label="Member to give access"]', email);
  await s.exec(`const sel = document.querySelector('select[aria-label="Member to give access"]'); [...sel.closest(".row").querySelectorAll("button")].find((b) => b.innerText === "Add").click(); return true`);
  await s.wait(() => s.exec(`return [...document.querySelectorAll(".lexpand .access-row")].some((r) => r.innerText.includes(arguments[0]) && r.querySelector("button.ghost-danger")) || null`, email), `${email}'s access`, 30000);
}

/** After a removal or revocation: the rotation Teams asks for, done (every vault due). */
export async function rotateDueKeys(s, org) {
  await openTeams(s);
  await openOrg(s, org);
  for (let i = 0; i < 10; i++) {
    const more = await s.exec(`return [...document.querySelectorAll(".panel button")].some((b) => b.innerText.includes("Rotate key") && !b.disabled)`);
    if (!more) return;
    await s.clickButton("Rotate key");
    await new Promise((r) => setTimeout(r, 2000));
    assert.equal(await s.panelError(), null);
  }
}

/** An owner or admin, on the team's page: turns on the setting whose name has `text`, and saves. */
async function turnOnPolicy(s, text) {
  await s.pageTab("Settings");
  const find = `[...document.querySelectorAll(".setting")].find((r) => r.querySelector(".setting-name")?.innerText.includes(arguments[0]))`;
  await s.wait(() => s.exec(`return ${find} ? true : null`, text), "the settings");
  await s.exec(`${find}.querySelector("button[role=switch]").click(); return true`, text);
  await s.clickButton("Save settings");
  await s.wait(() => s.exec(`return [...document.querySelectorAll("button")].some((b) => b.innerText.includes("Save settings")) ? null : true`), "the settings to save");
}

/** J7 (an owner or admin, in the organization's page): requires approval of new devices. */
export const requireDeviceApproval = (s) => turnOnPolicy(s, "Approve new devices");

/** T14 (an owner or admin, in the organization's page): requires two-step verification. */
export const requireTwoStep = (s) => turnOnPolicy(s, "Require two-step verification");

/** The sidebar's "Turn on two-step verification" (a team requires it), with its tooltip, or null. */
export const twoStepDue = (s) => s.exec(`const b = document.querySelector("button.sidebar-foot.totp"); return b ? b.title : null`);

/** The current code of an authenticator app holding `secret` (RFC 6238: SHA-1, 6 digits, 30 s). */
export function totpCode(secret, at = Date.now()) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = [...secret.replace(/[\s=]/g, "").toUpperCase()].map((c) => alphabet.indexOf(c).toString(2).padStart(5, "0")).join("");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30000)));
  const mac = createHmac("sha1", key).update(counter).digest();
  const at4 = mac[mac.length - 1] & 15;
  return String((mac.readUInt32BE(at4) & 0x7fffffff) % 1e6).padStart(6, "0");
}

/** T14: turns on two-step verification with a made-up authenticator, from the sidebar's notice
 *  when a team asks for it, else from Sync; returns its secret. */
export async function turnOnTwoStep(s, password = PASSWORD) {
  const press = (text) =>
    s.exec(`const b = [...document.querySelectorAll(".panel button")].find((b) => b.innerText === arguments[0] && !b.disabled);
      if (!b) throw new Error("no enabled button " + arguments[0]); b.click(); return true`, text);
  if (await twoStepDue(s)) await s.click("button.sidebar-foot.totp");
  else {
    await s.click("button.sidebar-foot.sync");
    await s.wait(() => s.exec(`return [...document.querySelectorAll(".panel button")].some((b) => b.innerText === "Turn on two-step verification") || null`), "the account");
    await press("Turn on two-step verification");
  }
  await s.waitText("Confirm with your master password", ".panel");
  await s.typeLabelled("Master password", password);
  await press("Continue");
  const secret = await s.wait(
    () => s.exec(`const k = [...document.querySelectorAll(".panel .hint")].find((p) => p.innerText.includes("Enter this key instead")); return k ? k.querySelector(".mono").innerText : null`),
    "the authenticator key",
    30000,
  );
  await s.typeLabelled("Authenticator code", totpCode(secret));
  await press("Turn on");
  await s.waitText("Turn off two-step verification", ".panel", 30000);
  return secret.replace(/\s/g, "");
}

/** The device-approval state on this device's sidebar ("Waiting for approval", "Denied"), or null. */
export const approvalState = (s) => s.exec(`const b = document.querySelector("button.sidebar-foot.approval"); return b ? b.innerText : null`);

/** J7 (an owner, an admin or one of the member's approved devices, in the organization's page): approves the waiting device, from Needs you. */
export async function approveDevice(s) {
  await s.waitText("waits for approval", ".needs", 60000);
  await s.exec(`[...document.querySelectorAll(".needs button")].find((b) => b.innerText === "Approve").click(); return true`);
  await s.wait(() => s.exec(`return [...document.querySelectorAll(".needs button")].some((b) => b.innerText === "Approve") ? null : true`), "the request to go", 30000);
}

/** S9: Sync → Delete account, with the master password. */
export async function deleteAccount(s, password = PASSWORD) {
  await s.click("button.sidebar-foot.sync");
  await s.waitText("Delete account…", ".panel");
  await s.clickButton("Delete account…");
  await s.typeLabelled("Master password", password);
  await s.clickButton("Delete account");
  await s.waitText("is deleted", ".panel p.ok", 60000);
}

/** Whether the organization's member list names `email`. */
export async function memberListed(s, org, email) {
  await openTeams(s);
  await openOrg(s, org);
  await s.pageTab("Members");
  await s.wait(() => s.exec(`return document.querySelector(".panel").innerText.includes("Members") || null`), "the member list");
  await new Promise((r) => setTimeout(r, 1500));
  return s.exec(`return document.querySelector(".panel").innerText.includes(arguments[0])`, email);
}
