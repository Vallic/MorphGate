// A stand-in for Vallic Cloud's console: the device sign-in (approved on the second poll), token
// rotation (a replayed refresh token is refused, as the real one does), and the API, with one
// project whose production environment is the test sshd, in the shape console.vallic.com answers
// with (null for what doesn't apply). GET /e2e/keys lists the keys added to the account.
//
//   node vallic-console.mjs <port> <ssh host> <ssh port> <user>

import { createServer } from "node:http";

const [port, sshHost, sshPort, user] = process.argv.slice(2);
let polls = 0;
let refresh = 0;
const access = new Set();
const keys = [];

const tokens = () => {
  refresh += 1;
  const a = `A-${refresh}`;
  access.add(a);
  return { access_token: a, refresh_token: `R-${refresh}`, token_type: "Bearer", expires_in: 900 };
};

const environments = {
  7: { id: 7, slug: "production", name: "Production", project: 1, ssh: { host: sshHost, port: Number(sshPort), user, name: null, machines: [{ name: "e2e-production-web", role: "all-in-one" }], jump_to: null, workers: [], db_cli: null, has_keys: true } },
  8: { id: 8, slug: "preview", name: "Preview", project: 1, ssh: null },
};

createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const send = (status, json) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(json));
    };
    const form = new URLSearchParams(body);
    const path = req.url.split("?")[0];
    console.log(req.method, path);
    if (path === "/oauth/device_authorization") {
      if (form.get("client_id") !== "vallic-cli") return send(400, { error: "invalid_client" });
      return send(200, { device_code: "D-1", user_code: "WXYZ-1234", verification_uri: `http://127.0.0.1:${port}/device`, expires_in: 600, interval: 1 });
    }
    if (path === "/oauth/token" && form.get("grant_type") === "urn:ietf:params:oauth:grant-type:device_code") {
      polls += 1;
      return polls < 2 ? send(400, { error: "authorization_pending" }) : send(200, tokens());
    }
    if (path === "/oauth/token" && form.get("grant_type") === "refresh_token") {
      return form.get("refresh_token") === `R-${refresh}` ? send(200, tokens()) : send(400, { error: "invalid_grant" });
    }
    if (path === "/oauth/revoke") return send(200, {});
    if (path === "/e2e/keys") return send(200, { keys });
    const bearer = (req.headers.authorization ?? "").replace(/^Bearer /, "");
    if (!access.has(bearer)) return send(401, { message: "Unauthenticated." });
    if (path === "/api/vc/v1/me" && req.method === "GET") return send(200, { user: { id: 1, name: "E2E", email: "e2e@example.com" }, team: null });
    if (path === "/api/vc/v1/projects") return send(200, { projects: [{ id: 1, label: "E2E Shop", machine_name: "e2e-shop" }] });
    if (path === "/api/vc/v1/environments") {
      return send(200, { environments: Object.values(environments).map(({ ssh, ...e }) => e) });
    }
    const env = path.match(/^\/api\/vc\/v1\/environments\/(\d+)$/);
    if (env && environments[env[1]]) return send(200, { environment: environments[env[1]] });
    if (path === "/api/vc/v1/me/ssh-keys" && req.method === "POST") {
      keys.push(JSON.parse(body));
      return send(201, { ssh_key: { id: keys.length } });
    }
    send(404, { message: "Not found." });
  });
}).listen(Number(port), "127.0.0.1", () => console.log(`vallic console on ${port}`));
