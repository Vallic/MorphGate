// A stand-in OpenID provider for the teams scenario: discovery, a key set, an authorize endpoint
// that signs in whoever the login hint names (no questions asked), and a token endpoint that
// checks PKCE and the client secret, then hands out an RS256 ID token.
//
//   node idp.mjs <port> <client id> <client secret>

import { createServer } from "node:http";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";

const [port, clientId, secret] = process.argv.slice(2);
const base = `http://127.0.0.1:${port}`;
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "e2e", alg: "RS256", use: "sig" };
const codes = new Map();
const b64 = (b) => Buffer.from(b).toString("base64url");

const json = (res, status, body) => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
};

createServer(async (req, res) => {
  const url = new URL(req.url, base);
  if (url.pathname === "/.well-known/openid-configuration") {
    return json(res, 200, {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      jwks_uri: `${base}/jwks`,
    });
  }
  if (url.pathname === "/jwks") return json(res, 200, { keys: [jwk] });
  if (url.pathname === "/authorize") {
    const q = url.searchParams;
    const code = randomUUID();
    codes.set(code, { nonce: q.get("nonce"), email: q.get("login_hint"), challenge: q.get("code_challenge"), client: q.get("client_id") });
    res.writeHead(302, { location: `${q.get("redirect_uri")}?code=${code}&state=${encodeURIComponent(q.get("state"))}` });
    return res.end();
  }
  if (url.pathname === "/token" && req.method === "POST") {
    let body = "";
    for await (const chunk of req) body += chunk;
    const f = new URLSearchParams(body);
    const grant = codes.get(f.get("code"));
    codes.delete(f.get("code"));
    const pkce = grant && b64(createHash("sha256").update(f.get("code_verifier") ?? "").digest()) === grant.challenge;
    if (!grant || !pkce || f.get("client_secret") !== secret || f.get("client_id") !== clientId) {
      return json(res, 400, { error: "invalid_grant" });
    }
    const now = Math.floor(Date.now() / 1000);
    const head = b64(JSON.stringify({ alg: "RS256", kid: "e2e", typ: "JWT" }));
    const claims = b64(
      JSON.stringify({ iss: base, sub: grant.email, aud: clientId, iat: now, exp: now + 300, nonce: grant.nonce, email: grant.email, email_verified: true }),
    );
    const sig = b64(sign("sha256", Buffer.from(`${head}.${claims}`), privateKey));
    return json(res, 200, { id_token: `${head}.${claims}.${sig}`, access_token: "e2e", token_type: "Bearer" });
  }
  res.writeHead(404);
  res.end();
}).listen(Number(port), "127.0.0.1");
