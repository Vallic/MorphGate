// A deb or rpm's binary (extracted, not installed): it knows how it was installed, finds the
// update, and says installing will ask for an administrator password. Installing needs root, so
// that part is left to the AppImage test.
//
//   node package.mjs <binary> <screenshots> <"Debian package" | "RPM package"> <version> <next>

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createVault, openAbout, session } from "./webdriver.mjs";

const [app, shots, kind, version, next] = process.argv.slice(2);

// The package's menu entry opens morphgate:// links (the link goes to the app as %u).
const entry = readFileSync(join(dirname(app), "../share/applications/morphgate.desktop"), "utf8");
assert.match(entry, /^Exec=morphgate %u$/m);
assert.match(entry, /^MimeType=x-scheme-handler\/morphgate$/m);
console.log(`  ✓ ${kind}: its desktop entry opens morphgate:// links`);

const s = await session(app);
try {
  await createVault(s, "correct horse battery staple");
  assert.equal(await openAbout(s), `Version ${version} · ${kind}`);
  await s.clickButton("Check now");
  const text = await s.waitText(`MorphGate ${next} is available`);
  assert.match(text, /administrator password/);
  await s.screenshot(`${shots}/about.png`);
  console.log(`  ✓ ${kind}: knows how it was installed, finds ${next}, warns about the administrator password`);
} finally {
  await s.close();
}
