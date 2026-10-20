// Prints <count> free TCP ports on loopback, held open together so they differ: several e2e runs
// can share a machine.
//
//   node free-ports.mjs <count>

import { createServer } from "node:net";

const count = Number(process.argv[2] ?? 1);
const servers = [];
const next = () => {
  if (servers.length === count) {
    console.log(servers.map((s) => s.address().port).join(" "));
    for (const s of servers) s.close();
    return;
  }
  const s = createServer();
  servers.push(s);
  s.listen(0, "127.0.0.1", next);
};
next();
