// The update feed the tests point the app at: the next version's AppImage (signed with the
// test key), a tampered copy of it, and two manifests. Then serves the directory over HTTP.
//
//   node feed.mjs <dir> <port> <next AppImage> <next version> <os-arch, e.g. linux-x86_64>

import { copyFileSync, createReadStream, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { basename, join } from "node:path";

const [dir, port, appImage, version, target] = process.argv.slice(2);
const base = `http://127.0.0.1:${port}`;
const name = basename(appImage);
copyFileSync(appImage, join(dir, name));
const signature = readFileSync(`${appImage}.sig`, "utf8");

// Same size, one byte different: the signature no longer matches.
const tampered = readFileSync(appImage);
tampered[tampered.length - 1000] ^= 0xff;
writeFileSync(join(dir, "tampered.AppImage"), tampered);

const manifest = (file) => {
  const entry = { signature, url: `${base}/${file}` };
  return {
    version,
    notes: "Test release.\n\n- Nothing new, just a higher number.",
    pub_date: new Date().toISOString(),
    platforms: {
      [target]: entry,
      [`${target}-appimage`]: entry,
      // Not served: an AppImage that picked one of these would fail to update.
      [`${target}-deb`]: { signature, url: `${base}/missing.deb` },
      [`${target}-rpm`]: { signature, url: `${base}/missing.rpm` },
    },
  };
};
writeFileSync(join(dir, "latest-good.json"), JSON.stringify(manifest(name), null, 2));
writeFileSync(join(dir, "latest-tampered.json"), JSON.stringify(manifest("tampered.AppImage"), null, 2));
copyFileSync(join(dir, "latest-good.json"), join(dir, "latest.json"));

createServer((req, res) => {
  const file = join(dir, basename(decodeURIComponent(new URL(req.url, base).pathname)));
  try {
    res.writeHead(200, { "content-length": statSync(file).size });
    createReadStream(file).pipe(res);
  } catch {
    res.writeHead(404).end();
  }
}).listen(Number(port), "127.0.0.1", () => console.log(`feed: ${base}/latest.json`));
