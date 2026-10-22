// A stand-in feed (docs/features/cloud-sources.md, "Feeds"): hosts and snippets a team publishes,
// read with a token. Its host "e2e-feed-web" is the test sshd on 127.0.0.4, with the sshd's host
// key listed (so nothing asks to trust it); "e2e-feed-wrong" is the same server listed with
// another key (refused); "broken" is skipped. POST /e2e/next changes the snippet and drops the
// wrong host, as a publisher's next version would. The token is E2E_HOST_FEED_TOKEN.
//
//   node host-feed.mjs <port> <sshd host key .pub> <ssh port> <user>

import { readFileSync } from "node:fs";
import { createServer } from "node:http";

const [port, hostKeyFile, sshPort, user] = process.argv.slice(2);
const TOKEN = process.env.E2E_HOST_FEED_TOKEN;
const hostKey = readFileSync(hostKeyFile, "utf8").trim().split(/\s+/).slice(0, 2).join(" ");
const otherKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDRbMaf7RI+oSkPOCPrFjPoMWJEIu96Drte4Q3r9OQYR";
let version = 1;

const doc = () => ({
  version: 1,
  name: "E2E operations",
  hosts: [
    { id: "web", label: "e2e-feed-web", hostname: "127.0.0.4", port: Number(sshPort), user, group: "E2E feed", tags: ["feed"], key: "e2e_key", host_keys: [hostKey] },
    ...(version === 1 ? [{ id: "wrong", label: "e2e-feed-wrong", hostname: "127.0.0.4", port: Number(sshPort), user, group: "E2E feed", key: "e2e_key", host_keys: [otherKey] }] : []),
    { id: "broken", label: "broken", hostname: "-oProxyCommand=touch /tmp/x", user },
  ],
  snippets: [{ id: "hello", name: "E2E hello", body: version === 1 ? "echo e2e-feed-one" : "echo e2e-feed-two", tags: ["feed"] }],
});

createServer((req, res) => {
  const send = (status, json) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(json));
  };
  console.log(req.method, req.url, req.headers["user-agent"]);
  if (req.method === "POST" && req.url === "/e2e/next") {
    version = 2;
    return send(200, { version });
  }
  if (req.url !== "/morphgate.json") return send(404, {});
  if (req.headers.authorization !== `Bearer ${TOKEN}`) return send(401, { message: "Unauthenticated." });
  return send(200, doc());
}).listen(Number(port), "127.0.0.1");
