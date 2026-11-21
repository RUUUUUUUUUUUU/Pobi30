// End-to-end smoke test against the REAL server (spawns it as a child).
// Usage: npm run smoke-test
// Uses test-only secrets/params (never touches your real .env values — the
// child inherits explicit env vars, which take precedence over .env).
//
// Checks:
//   1. GET /health -> 200 {ok:true}
//   2. Signed preflight -> 200 {ok:true, protocolVersion:"v1"} + valid signature
//   3. Signed Steal turn -> 200, well-formed HOLD response WITH a real
//      policyProof; response signature valid; proof verifies locally
//      against the extracted verification key; public_signals match the
//      turn (commitment, matchId, turn, balances, action HOLD, amount 0)
//   4. Redelivery of the same turn -> byte-identical body (idempotent)
//   5. Bad / missing signature -> 401; malformed JSON (signed) -> 400
//   6. Turn whose envelope commitment does NOT match local -> 200 HOLD
//      with NO policyProof (fail-closed, scores 0 instead of -2)
// Exit code 0 = all checks pass.

const { spawn } = require('child_process');
const crypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'smoke-test-secret-do-not-use-in-production';
const SALT = '42424242424242424242';
const MATCH = 'a1b2c3d4-0000-1111-2222-333344445555';

const policy = require('../src/policy');
const prover = require('../src/prover');
const hmac = require('../src/hmac');

let failures = 0;
function check(name, ok, extra) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
  if (!ok) failures++;
}

function sign(body) {
  return crypto.createHmac('sha256', SECRET).update(Buffer.from(body)).digest('hex');
}

async function postJson(pathname, obj, { rawBody, signature } = {}) {
  const body = rawBody !== undefined ? rawBody : JSON.stringify(obj);
  const res = await fetch(BASE + pathname, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      [hmac.HEADER]: signature !== undefined ? signature : sign(body),
    },
    body,
  });
  const text = await res.text();
  return { status: res.status, text, sig: res.headers.get(hmac.HEADER) };
}

async function main() {
  const commitment = await policy.computeCommitment(
    [1n, 0n, 1000n, 0n, 0n, 0n, 0n, 0n], SALT
  );
  const commitmentHex = policy.commitmentToHex(commitment);

  const child = spawn('node', ['server.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      STRATEGY_PARAMS: '1,0,1000,0,0,0,0,0',
      STRATEGY_SALT: SALT,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let childOut = '';
  child.stdout.on('data', (d) => { childOut += d; });
  child.stderr.on('data', (d) => { childOut += d; });

  try {
    // Wait for the listening line (max 10 s).
    const started = await new Promise((resolve) => {
      const t0 = Date.now();
      const iv = setInterval(() => {
        if (childOut.includes('listening on')) { clearInterval(iv); resolve(true); }
        else if (Date.now() - t0 > 10000) { clearInterval(iv); resolve(false); }
      }, 100);
    });
    check('server starts with test env', started, started ? '' : childOut.slice(-500));

    // 1. Health.
    const health = await fetch(BASE + '/health');
    check('GET /health -> 200 {ok:true}', health.status === 200 &&
      (await health.json()).ok === true);

    // 2. Signed preflight.
    const preBody = JSON.stringify({ type: 'agent-games.preflight.v1', agent_id: 'test-agent', issued_at: new Date().toISOString(), nonce: 'smoke-1' });
    const pre = await postJson('/agent', null, { rawBody: preBody });
    let preJson = null;
    try { preJson = JSON.parse(pre.text); } catch { /* leave null */ }
    check('signed preflight -> 200 {ok:true, protocolVersion:"v1"}',
      pre.status === 200 && preJson && preJson.ok === true && preJson.protocolVersion === 'v1');
    check('preflight response signature valid',
      !!pre.sig && hmac.verify(SECRET, Buffer.from(pre.text), pre.sig));

    // 3. Signed Steal turn (default params -> HOLD, with a real proof).
    const turn = {
      protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'competition',
      matchId: MATCH, turn: 1,
      issuedAt: new Date().toISOString(),
      deadlineAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      state: { selfBalance: '100', opponentBalance: '100', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
      strategyCommitment: { hash: commitmentHex },
      resolverVersion: 'v1', nonce: 'smoke-turn-1',
    };
    const t0 = Date.now();
    const r1 = await postJson('/agent', turn);
    const proveMs = Date.now() - t0;
    let r1Json = null;
    try { r1Json = JSON.parse(r1.text); } catch { /* leave null */ }
    check('signed turn -> 200', r1.status === 200, `status=${r1.status} body=${r1.text.slice(0, 200)}`);
    check('turn echoes matchId + turn', !!r1Json && r1Json.matchId === MATCH && r1Json.turn === 1);
    check('turn action is HOLD (default params)', !!r1Json && r1Json.action && r1Json.action.type === 'HOLD' && !('amount' in r1Json.action));
    check('idempotencyKey is steal:<matchId>:<turn>',
      !!r1Json && r1Json.idempotencyKey === `steal:${MATCH}:1`);
    check('turn response signature valid',
      !!r1.sig && hmac.verify(SECRET, Buffer.from(r1.text), r1.sig));
    const pp = r1Json && r1Json.policyProof;
    check('policyProof present with proof + public_signals inside',
      !!pp && !!pp.proof && Array.isArray(pp.public_signals) && pp.public_signals.length === 9 &&
      pp.circuitVersion === '1');
    if (pp) {
      check('publicInputsHash present (0x + 64 hex)',
        typeof pp.publicInputsHash === 'string' && /^0x[0-9a-f]{64}$/.test(pp.publicInputsHash));
      const s = pp.public_signals;
      check('public_signals[1] == commitment', s[1] === commitment);
      check('public_signals[2] == matchId field', s[2] === policy.matchIdToField(MATCH));
      check('public_signals[3..5] == turn/balances', s[3] === '1' && s[4] === '100' && s[5] === '100');
      check('public_signals[6..8] == HOLD/0/"1"', s[6] === '0' && s[7] === '0' && s[8] === '1');
      const ok = await prover.verifyLocal(path.join(ROOT, 'circuits'), pp.proof, pp.public_signals);
      check('proof verifies locally (groth16.verify)', ok === true);
      console.log(`      (turn answered in ${proveMs}ms including proving)`);
    }

    // 4. Redelivery -> identical body.
    const r2 = await postJson('/agent', turn);
    check('redelivery returns byte-identical body', r2.status === 200 && r2.text === r1.text);

    // 5. Bad / missing signature, malformed JSON.
    const bad = await postJson('/agent', turn, { signature: 'deadbeef' });
    check('bad signature -> 401', bad.status === 401, `status=${bad.status}`);
    const noSigRes = await fetch(BASE + '/agent', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(turn),
    });
    check('missing signature -> 401', noSigRes.status === 401, `status=${noSigRes.status}`);
    const malformed = await postJson('/agent', null, { rawBody: '{not json' });
    check('malformed JSON (signed) -> 400', malformed.status === 400, `status=${malformed.status}`);

    // 6. Commitment mismatch -> HOLD without proof.
    const mismatch = { ...turn, turn: 2, strategyCommitment: { hash: '0x' + '11'.repeat(32) } };
    const r3 = await postJson('/agent', mismatch);
    let r3Json = null;
    try { r3Json = JSON.parse(r3.text); } catch { /* leave null */ }
    check('commitment mismatch -> 200 HOLD without policyProof',
      r3.status === 200 && r3Json && r3Json.action.type === 'HOLD' && !r3Json.policyProof);
  } finally {
    child.kill('SIGTERM');
  }

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => { console.error('FATAL', err); process.exit(1); });
