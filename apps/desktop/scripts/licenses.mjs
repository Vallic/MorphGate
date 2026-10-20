// Third-party notices for About → Open-source licenses: the Rust crates the app is built from,
// the npm packages in its web bundle, its fonts and, in the Android app, the Java libraries.
// Their licenses (MIT, BSD, Apache, OFL, …) ask for their notices to come with every copy.
//
// Run by `npm run build`, so by every Tauri build, for the platform being built (Tauri's
// TAURI_ENV_TARGET_TRIPLE; this computer's without one). Writes src/generated/licenses.json,
// which isn't in the repository.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const app = join(dirname(fileURLToPath(import.meta.url)), "..");
const root = join(app, "..", "..");
const out = join(app, "src", "generated", "licenses.json");

const LICENSE_FILE = /^(licen[cs]e|copying|notice|copyright|unlicense)([-._].*)?$/i;

// The standard texts, for packages that come without theirs (their authors as the holder).
const STANDARD = {
  MIT: (holder) =>
    `MIT License\n\nCopyright (c) ${holder}\n\n` +
    readFileSync(join(root, "crates", "mg-sync", "LICENSE-MIT"), "utf8").replace(/^Copyright.*\n+/, ""),
  "Apache-2.0": () => readFileSync(join(root, "crates", "mg-sync", "LICENSE-APACHE"), "utf8"),
  "MPL-2.0": () => readFileSync(join(root, "LICENSE"), "utf8"),
  "BSD-3-Clause": (holder) => `BSD 3-Clause License

Copyright (c) ${holder}

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
   and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of
   conditions and the following disclaimer in the documentation and/or other materials provided
   with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to
   endorse or promote products derived from this software without specific prior written
   permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
`,
};

const texts = [];
const textIds = new Map();
const components = [];
const warnings = [];

function textId(text) {
  const t = text.replace(/\r\n?/g, "\n").replace(/[ \t]+$/gm, "").trim();
  if (!textIds.has(t)) {
    textIds.set(t, texts.length);
    texts.push(t);
  }
  return textIds.get(t);
}

/** The license files in a package's folder, as text ids. */
function filesIn(dir, extra = []) {
  const names = existsSync(dir) ? readdirSync(dir).filter((f) => LICENSE_FILE.test(f)) : [];
  return [...new Set([...names, ...extra])]
    .sort()
    .map((f) => join(dir, f))
    .filter((p) => existsSync(p) && statSync(p).isFile())
    .map((p) => textId(readFileSync(p, "utf8")));
}

/** The standard text of the first license in an SPDX expression that has one. */
function standard(expr, holder, what) {
  const ids = (expr ?? "").split(/\s+(?:OR|AND)\s+|\/|[()]/).map((s) => s.trim());
  const id = ids.find((i) => STANDARD[i]);
  if (id) return [textId(STANDARD[id](holder))];
  warnings.push(`${what}: no license file, and no standard text for "${expr}"`);
  return [];
}

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { cwd: root, encoding: "utf8", maxBuffer: 256 << 20, ...opts });
}

// The platform: Tauri's target, or this computer. A universal macOS build has the same crates as
// an Apple silicon one.
let target = process.env.TAURI_ENV_TARGET_TRIPLE || run("rustc", ["-vV"]).match(/^host: (.+)$/m)[1];
if (target.startsWith("universal-")) target = target.replace("universal-", "aarch64-");

// Crates: what the app links, for that platform (normal dependencies, not build or dev ones).
run("cargo", ["fetch", "--locked", "--target", target], { stdio: ["ignore", "ignore", "inherit"] });
const meta = JSON.parse(run("cargo", ["metadata", "--format-version", "1", "--locked", "--filter-platform", target]));
const pkgs = new Map(meta.packages.map((p) => [p.id, p]));
const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
const appId = meta.packages.find((p) => p.name === "morphgate-desktop").id;
const linked = new Set();
for (const todo = [appId]; todo.length; ) {
  const id = todo.pop();
  if (linked.has(id)) continue;
  linked.add(id);
  for (const d of nodes.get(id).deps) if (d.dep_kinds.some((k) => k.kind === null)) todo.push(d.pkg);
}
const crates = [...linked].map((id) => pkgs.get(id)).filter((p) => p.source); // not MorphGate's own
for (const p of crates) {
  const dir = dirname(p.manifest_path);
  let ids = filesIn(dir, p.license_file ? [p.license_file] : []);
  if (!ids.length) ids = standard(p.license, p.authors?.length ? p.authors.join(", ") : `the ${p.name} authors`, `crate ${p.name}`);
  components.push({ name: p.name, version: p.version, license: p.license ?? "", kind: "crate", url: p.repository ?? undefined, texts: ids });
}

// npm packages in the web bundle: the lock file's non-dev ones.
const lock = JSON.parse(readFileSync(join(app, "package-lock.json"), "utf8"));
for (const [path, info] of Object.entries(lock.packages)) {
  if (!path.startsWith("node_modules/") || info.dev || info.devOptional) continue;
  const dir = join(app, path);
  const pj = existsSync(join(dir, "package.json")) ? JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) : {};
  const name = pj.name ?? path.slice(path.lastIndexOf("node_modules/") + 13);
  const license = info.license ?? pj.license ?? "";
  let ids = filesIn(dir);
  if (!ids.length) ids = standard(license, typeof pj.author === "string" ? pj.author : (pj.author?.name ?? `the ${name} authors`), `npm ${name}`);
  const url = typeof pj.repository === "string" ? pj.repository : pj.repository?.url;
  components.push({ name, version: info.version ?? pj.version, license, kind: "npm", url, texts: ids });
}

// Fonts (src/assets/fonts/README.md).
const ofl = textId(readFileSync(join(app, "src", "assets", "fonts", "OFL.txt"), "utf8"));
for (const [name, url] of [
  ["Martian Mono", "https://github.com/evilmartians/mono"],
  ["Atkinson Hyperlegible Next", "https://www.brailleinstitute.org/freefont/"],
  ["Atkinson Hyperlegible Mono", "https://www.brailleinstitute.org/freefont/"],
]) {
  components.push({ name, license: "OFL-1.1", kind: "font", url, texts: [ofl] });
}

// Android: the Java libraries the app, Tauri and its plugins name in their Gradle files.
if (target.includes("android")) {
  const apache = textId(STANDARD["Apache-2.0"]());
  const gradle = [join(app, "src-tauri", "gen", "android", "app", "build.gradle.kts")];
  for (const p of crates.filter((c) => c.name === "tauri" || c.name.startsWith("tauri-plugin"))) {
    const dir = dirname(p.manifest_path);
    for (const f of ["mobile/android/build.gradle.kts", "android/build.gradle.kts"]) if (existsSync(join(dir, f))) gradle.push(join(dir, f));
  }
  const seen = new Set();
  for (const file of gradle) {
    for (const [, coord] of readFileSync(file, "utf8").matchAll(/implementation\("([^":]+:[^":]+):[^"]*"\)/g)) {
      if (seen.has(coord)) continue;
      seen.add(coord);
      const license = coord.startsWith("org.rustls:") ? "MIT OR Apache-2.0" : /^(androidx\.|com\.google\.android\.|com\.fasterxml\.jackson\.)/.test(coord) ? "Apache-2.0" : null;
      if (!license) warnings.push(`Android library ${coord}: license unknown`);
      components.push({ name: coord, license: license ?? "", kind: "android", texts: license ? [apache] : [] });
    }
  }
  components.push({ name: "The AndroidX libraries and Kotlin standard library these use", license: "Apache-2.0", kind: "android", texts: [apache] });
}

components.sort((a, b) => a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version)));
mkdirSync(dirname(out), { recursive: true });
const json = JSON.stringify({ target, components, texts });
writeFileSync(out, json);
for (const w of warnings) console.warn(`licenses: ${w}`);
const count = (k) => components.filter((c) => c.kind === k).length;
console.log(
  `licenses: ${count("crate")} crates, ${count("npm")} npm packages, ${count("font")} fonts` +
    (count("android") ? `, ${count("android")} Android libraries` : "") +
    ` for ${target}; ${texts.length} texts, ${Math.round(json.length / 1024)} KiB`,
);
