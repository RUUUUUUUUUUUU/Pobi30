// AgentGames (zkVerify) — Steal the VFY agent endpoint.
// Plain Node.js HTTP server, no build step, no framework.
//
//   POST /agent   signed task envelopes (preflight + Steal turns)
//   GET  /health  liveness probe (unsigned)
//   GET  /        liveness probe (unsigned)
//
// The server refuses to start without AGENT_GAMES_HMAC_SECRET and
// STRATEGY_SALT — a silently unproving agent is worse than one that
// refuses to start. At startup it prints the strategy commitment (decimal
// and 0x) so you can compare it with the value registered on the dashboard.

const http = require('http');
const { loadConfig } = require('./src/config');
const { handleRequest } = require('./src/handler');
const policy = require('./src/policy');

const MAX_BODY_BYTES = 1024 * 1024; // 1 MB — envelopes are small.

async function main() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    console.error('Startup failed: ' + err.message);
    process.exit(1);
  }

  const commitment = await policy.computeCommitment(config.strategyParams, config.strategySalt);
  console.log('[startup] strategy params : ' + config.strategyParams.map(String).join(','));
  console.log('[startup] commitment (dec): ' + commitment);
  console.log('[startup] commitment (hex): ' + policy.commitmentToHex(commitment));
  console.log('[startup] register the hex value on the dashboard (My Agents -> Edit agent -> Steal the VFY) before the next round pairs.');

  const server = http.createServer((req, res) => {
    const chunks = [];
    let tooLarge = false;
    req.on('data', (chunk) => {
      if (tooLarge) return;
      chunks.push(chunk);
      if (Buffer.concat(chunks).length > MAX_BODY_BYTES) {
        tooLarge = true;
        res.writeHead(413, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'body too large' }));
        req.destroy();
      }
    });
    req.on('end', async () => {
      if (tooLarge) return;
      try {
        const rawBody = Buffer.concat(chunks);
        const out = await handleRequest(config, {
          method: req.method,
          url: req.url,
          headers: req.headers,
          rawBody,
        });
        res.writeHead(out.status, out.headers);
        res.end(out.body);
      } catch (err) {
        console.error('[server] unhandled error:', err.message);
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal error' }));
      }
    });
  });

  server.listen(config.port, () => {
    console.log(`[startup] listening on :${config.port} — POST /agent`);
  });
}

main();
