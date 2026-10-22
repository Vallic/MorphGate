// The pages at several window widths: screenshots, and a check that nothing on them overlaps or
// runs out of its box. Sync is turned on from the offer a vault without it gets a week on; then a
// key, hosts in a group, a snippet, a tunnel and a team with a vault and an open invite fill the
// pages.
//
//   session.sh <dir> node layout.mjs <app> <screenshots> <sync server URL>

import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { createVault, reload, session } from "./webdriver.mjs";

const [app, shots, server] = process.argv.slice(2);
const PASSWORD = "correct horse battery staple";
const WIDTHS = [860, 1024, 1280, 1600];
const ok = (...a) => console.log("  ✓", ...a);
mkdirSync(shots, { recursive: true });

/** Visible leaves in `root` whose boxes overlap, and content wider than its box. */
const PROBLEMS = `
  const root = document.querySelector(arguments[0]);
  if (!root) return ["nothing matches " + arguments[0]];
  const name = (e) => (e.innerText || e.getAttribute("aria-label") || e.tagName).trim().slice(0, 40);
  const leaves = [...root.querySelectorAll("button, input, select, textarea, a, strong, small, span, label > span, h1, h2, p, dt, dd")]
    .filter((e) => e.offsetParent && e.getClientRects().length)
    .filter((e) => ![...e.children].some((c) => c.matches("button, input, select, strong, small, span, p")));
  const out = [];
  for (let i = 0; i < leaves.length; i++) {
    for (let j = i + 1; j < leaves.length; j++) {
      const a = leaves[i], b = leaves[j];
      if (a.contains(b) || b.contains(a)) continue;
      const x = a.getBoundingClientRect(), y = b.getBoundingClientRect();
      const w = Math.min(x.right, y.right) - Math.max(x.left, y.left);
      const h = Math.min(x.bottom, y.bottom) - Math.max(x.top, y.top);
      if (w > 2 && h > 2) out.push(name(a) + " ⟷ " + name(b));
    }
  }
  for (const e of root.querySelectorAll("*")) {
    if (!e.offsetParent || e.clientWidth === 0 || e.closest("svg, pre, .xterm")) continue;
    if (getComputedStyle(e).overflowX === "visible" && e.scrollWidth > e.clientWidth + 2)
      out.push("too wide: <" + e.tagName.toLowerCase() + " class=" + e.className + "> " + name(e) + " " + e.scrollWidth + " > " + e.clientWidth);
  }
  return out.slice(0, 20);`;

let problems = 0;
async function shoot(s, name, root = ".panel") {
  for (const w of WIDTHS) {
    await s.resize(w, 800);
    await new Promise((r) => setTimeout(r, 300));
    await s.screenshot(`${shots}/${name}-${w}.png`);
    const bad = await s.exec(PROBLEMS, root);
    console.log(`  ${name} @ ${w}: ${bad.length ? bad.length + " problem(s)" : "clean"}`);
    for (const b of bad) console.log("     ", b);
    problems += bad.length;
  }
  await s.resize(1280, 800);
}

/** Opens a page from the sidebar's navigation. */
async function page(s, label) {
  await s.exec(`[...document.querySelectorAll(".sidebar-nav button")].find((b) => b.innerText.startsWith(arguments[0])).click(); return true`, label);
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === arguments[0] || null`, label), `the ${label} page`);
}

const s = await session(app);
try {
  // The first screen: a new vault, a new account, or the account used on other devices.
  await s.wait(() => s.exec(`return document.querySelector(".gate-choice") ? true : null`), "the first screen");
  await s.exec(`[...document.querySelectorAll(".gate-choice button")].find((b) => b.innerText === "New account").click(); return true`);
  await s.waitText("Create your account");
  await s.clickButton("Suggest a strong password");
  await s.wait(() => s.exec(`return document.querySelector(".suggested-password") ? true : null`), "a suggested password");
  await shoot(s, "first-run-new-account", ".gate");
  await s.exec(`[...document.querySelectorAll(".gate-choice button")].find((b) => b.innerText === "Sign in").click(); return true`);
  await s.waitText("Sign in to sync");
  await shoot(s, "first-run-sign-in", ".gate");
  await s.exec(`[...document.querySelectorAll(".gate-choice button")].find((b) => b.innerText === "New vault").click(); return true`);
  await createVault(s, PASSWORD, shots);
  await reload(s, { weekLater: true });
  await s.wait(() => s.exec(`return document.querySelector("dialog.sync-offer[open]") ? true : null`), "the offer to turn sync on");
  await shoot(s, "offer", "dialog.sync-offer");
  await s.exec(`[...document.querySelectorAll('dialog.sync-offer .sync-server button[role="radio"]')].find((b) => b.innerText === "Your own server").click(); return true`);
  await s.typeLabelled("Server address", server);
  await s.typeLabelled("Email", `layout-${Date.now().toString(36)}@example.com`);
  await s.typeLabelled("Master password (to confirm)", PASSWORD);
  await s.clickButton("Enable sync");
  await s.wait(() => s.exec(`return document.querySelector("dialog.sync-offer") ? null : true`), "the offer to close", 60000);
  await s.wait(() => s.exec(`return document.querySelector("button.sidebar-foot.sync")?.innerText.includes("Sync off") ? null : true`), "sync on");
  ok("turned sync on from the offer a week after the vault was created");

  // The tab bar gives way to a page while no session is open.
  await s.click("button.sidebar-foot.sync");
  await s.waitText("Last sync", ".panel", 60000);
  assert.equal(await s.exec(`return document.querySelector(".tabbar").hidden`), true, "no tab bar over a page without sessions");
  await shoot(s, "sync");

  // A key, three hosts (two in a group), a snippet and a tunnel.
  await page(s, "Keys");
  await shoot(s, "keys-empty");
  await s.clickButton("New key");
  await s.waitText("New SSH key", ".panel");
  await s.typeLabelled("Label", "deploy laptop");
  await s.clickButton("Generate key");
  await s.waitText("Public key", ".panel");
  await s.clickButton("Close");
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Keys" || null`), "back on the Keys page");
  ok("closing the key returns to the Keys page");

  await s.click('button[aria-label="New group"]');
  await s.waitText("New group", ".panel");
  await s.typeLabelled("Name", "Production");
  await s.click(".panel form button[type=submit]");
  await s.wait(() => s.exec(`return document.querySelector('.sidebar button[aria-label="Open group Production"]') ? true : null`), "the group");
  for (const [label, host, group] of [
    ["db-primary-eu-west-1", "db-primary.eu-west-1.internal.example.com", "Production"],
    ["web-1", "10.20.0.11", "Production"],
    ["router", "192.168.1.1", null],
  ]) {
    await s.click('button[title="New host"]');
    await s.waitText("New host", ".panel");
    await s.typeLabelled("Label", label);
    await s.typeLabelled("Hostname or IP", host);
    await s.typeLabelled("User", "deploy");
    if (group) {
      await s.exec(`[...document.querySelectorAll(".panel label")].find((l) => l.querySelector("span")?.innerText === "Group").querySelector("select").setAttribute("data-e2e", "pick"); return true`);
      await s.choose("select[data-e2e=pick]", group);
    }
    await s.click(".panel form button[type=submit]");
    await s.wait(() => s.hasText(".sidebar .row-title", label), label);
  }
  await page(s, "Hosts");
  await shoot(s, "hosts");
  await s.clickButton("Select");
  await s.clickButton("Select all");
  await s.waitText("selected", ".select-bar");
  await shoot(s, "hosts-selecting");
  await s.clickButton("Done");
  await s.addFrom("Clouds…");
  await s.waitText("Connect Vallic Cloud", ".panel");
  await shoot(s, "vallic-cloud");
  await s.clickButton("Close");

  // Groups, a group's page with everything in it, and its editor full screen.
  const groupPage = async () => {
    await s.exec(`[...document.querySelectorAll(".panel button.lnamebtn")].find((b) => b.querySelector(".lname")?.innerText === "Production").click(); return true`);
    await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Production" || null`), "the Production group's page");
  };
  await page(s, "Groups");
  await shoot(s, "groups");
  await groupPage();
  await shoot(s, "group");
  await s.clickButton("Edit group");
  await s.waitText("Hosts in the group", ".panel");
  await shoot(s, "group-editor");
  await s.clickButton("Cancel");
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Production" || null`), "back on the group's page");
  ok("a group's page lists its hosts; closing its editor returns there");

  await page(s, "Snippets");
  await s.clickButton("New snippet");
  await s.typeLabelled("Name", "Tail nginx errors");
  await s.typeLabelled("Commands", "sudo tail -f /var/log/nginx/error.log");
  await s.click(".panel form button[type=submit]");
  await s.waitText("Save changes", ".panel");
  await s.clickButton("Close");
  await s.wait(() => s.hasText(".panel .lname", "Tail nginx errors"), "the snippet on its page");
  await shoot(s, "snippets");
  // A page's own page (its import) closes back to it, not home.
  await s.clickButton("Import…");
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Import snippets" || null`), "Import snippets");
  await s.click(".panel.page .page-close");
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Snippets" || null`), "back on Snippets");
  ok("closing Import snippets returns to Snippets");

  await page(s, "Tunnels");
  await s.clickButton("New tunnel");
  await s.typeLabelled("Name", "Postgres on prod");
  await s.exec(`[...document.querySelectorAll(".panel label")].find((l) => l.querySelector("span")?.innerText === "Port").querySelector("input").setAttribute("data-e2e", "port"); return true`);
  await s.type("[data-e2e=port]", "15432");
  await s.typeLabelled("Destination", "127.0.0.1");
  await s.exec(`[...document.querySelectorAll(".panel label")].filter((l) => l.querySelector("span")?.innerText === "Port")[1].querySelector("input").setAttribute("data-e2e", "port2"); return true`);
  await s.type("[data-e2e=port2]", "5432");
  await s.click(".panel form button[type=submit]");
  await s.waitText("Edit tunnel", ".panel");
  await s.clickButton("Cancel");
  await s.wait(() => s.hasText(".panel .lname", "Postgres on prod"), "the tunnel on its page");
  await shoot(s, "tunnels");

  await page(s, "VPNs");
  await shoot(s, "vpns-empty");
  // Saving a new VPN closes its editor, back to the list that now has it.
  await s.clickButton("New VPN");
  await s.exec(`[...document.querySelectorAll('.panel [role="radiogroup"] button')].find((b) => b.innerText.includes("OpenConnect")).click(); return true`);
  await s.typeLabelled("Name", "Client office");
  await s.typeLabelled("Server", "vpn.client.example");
  await s.click(".panel form button[type=submit]");
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "VPNs" || null`), "the VPNs page again");
  await s.wait(() => s.hasText(".panel .lname", "Client office"), "the VPN on its page");
  await shoot(s, "vpns");
  await page(s, "Keys");
  await shoot(s, "keys");

  // A team with a vault and an invite to a long address.
  await s.click("button.sidebar-foot.teams");
  await s.wait(() => s.exec(`return [...document.querySelectorAll(".panel button")].some((b) => b.innerText === "New team") || null`), "the teams page");
  await shoot(s, "teams-list");
  // Cancel puts the New team bar away and stays on Teams.
  await s.clickButton("New team");
  await s.wait(() => s.exec(`return document.querySelector('input[aria-label="Team name"]') ? true : null`), "the New team bar");
  await shoot(s, "teams-new");
  await s.click("form.quick-bar button.quiet");
  await s.wait(() => s.exec(`return document.querySelector('input[aria-label="Team name"]') ? null : true`), "the bar to go");
  assert.equal(await s.exec(`return document.querySelector(".panel.page h1")?.innerText`), "Teams");
  ok("New team, then Cancel, stays on Teams");
  await s.clickButton("New team");
  await s.type('input[aria-label="Team name"]', "Acme Operations International");
  await s.clickButton("Create team");
  await s.wait(() => s.exec(`return document.querySelector(".panel.page h1")?.innerText === "Acme Operations International" || null`), "the team's page");
  await s.pageTab("Vaults");
  await s.waitText("No vaults yet", ".panel");
  await s.clickButton("New vault");
  await s.type('input[aria-label="Vault name"]', "Production databases");
  await s.clickButton("Create vault");
  await s.wait(() => s.hasText(".panel .lname", "Production databases"), "the new vault");
  await shoot(s, "org-vaults");
  await s.clickButton("Invite people");
  await s.type('input[aria-label="Emails to invite"]', "someone.with.a.long.address@example.com, another.person@example.com");
  await s.click(".grants input[type=checkbox]");
  await shoot(s, "invite", "dialog.invite-dialog");
  await s.clickButton("Send 2 invites");
  await s.wait(() => s.exec(`return document.querySelector(".invite-code") ? true : null`), "the invite codes");
  await shoot(s, "invite-sent", "dialog.invite-dialog");
  await s.clickButton("Done");
  await s.pageTab("Members");
  await s.wait(() => s.hasText(".panel .lname", "someone.with.a.long.address@example.com"), "the invites in Members");
  await shoot(s, "org");
  await s.pageTab("Settings");
  await s.waitText("Require two-step verification", ".panel");
  await shoot(s, "org-settings");
  await s.pageTab("Activity");
  await s.waitText("invited someone.with.a.long.address@example.com", ".panel");
  await shoot(s, "org-activity");

  // Moving the group into the team's vault: the plan, then cancel.
  await page(s, "Groups");
  await groupPage();
  await s.clickButton("Move to…");
  await s.wait(() => s.exec(`return document.querySelector("dialog.move-dialog[open] .move-plan li") ? true : null`), "the move plan");
  await shoot(s, "move", "dialog.move-dialog");
  await s.exec(`[...document.querySelectorAll("dialog.move-dialog button")].find((b) => b.innerText === "Cancel").click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector("dialog.move-dialog") ? null : true`), "the move dialog to close");

  // With a session open the tab bar stays: a page sits under it.
  await s.exec(
    `[...document.querySelectorAll(".sidebar .list li")].find((l) => l.querySelector(".row-title")?.innerText === "router").querySelector(".row-main").click(); return true`,
  );
  // It asks for a password each time; the connect may fail, the tab stays.
  await s.wait(() => s.exec(`return document.querySelector('dialog.modal[open] input[type="password"]') ? true : null`), "the password prompt");
  await s.type('dialog.modal[open] input[type="password"]', "not-a-real-password");
  await s.exec(`document.querySelector('dialog.modal[open] button[type="submit"]').click(); return true`);
  await s.wait(() => s.exec(`return document.querySelector(".tabbar .tab:not(.new)") ? true : null`), "a session tab");
  await page(s, "Hosts");
  assert.equal(await s.exec(`return document.querySelector(".tabbar").hidden`), false, "the tab bar stays while a session is open");
  await s.clickButton("Close");
  await s.wait(() => s.exec(`return document.querySelector(".tab.active:not(.new)") ? true : null`), "back on the session");
  ok("closing a page opened from a session returns to it");
  await s.screenshot(`${shots}/session.png`);

  // Disconnecting asks what to do with what's here; removing it all goes back to the start,
  // session and all, and says the account still has it.
  await s.click("button.sidebar-foot.sync");
  await s.clickButton("Disconnect this device");
  await s.waitText("Remove everything from this device", ".panel");
  await s.screenshot(`${shots}/sync-disconnect.png`);
  await s.clickButton("Remove everything from this device");
  const notice = await s.wait(() => s.exec(`const n = document.querySelector(".gate-notice"); return n ? n.innerText : null`), "the first screen, saying why", 30000);
  assert.match(notice, /removed everything it kept on this device/);
  assert.ok(await s.exec(`return !document.querySelector(".tabbar")`), "the session is gone with the workspace");
  ok("disconnecting and removing everything goes back to the first screen");
} finally {
  await s.close();
}
console.log(problems ? `  ${problems} layout problem(s)` : "  ✓ no layout problems");
process.exit(problems ? 1 : 0);
