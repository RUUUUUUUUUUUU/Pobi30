// Request pipeline for POST /agent. Framework-agnostic: the server passes
// the raw body and headers; this module returns { status, body, headers }.
//
// Order of operations (fail-closed):
//   1. HMAC over the RAW body, before any parsing. Bad/missing -> 401.
//   2. JSON parse. Malformed -> 400.
//   3. Preflight -> signed { ok: true, protocolVersion: "v1" }.
//   4. Steal turn -> validate, decide per the committed strategy, prove
//      locally, return a signed response. Any proof problem degrades to a
//      clean HOLD with NO proof (scores 0) — never an invalid proof (-2)
//      and never a 500/timeout (-1).
//   5. Anything else -> 400.
// Nothing here logs secrets: no raw bodies, no HMAC secret, no salt.

const hmac = require('./hmac');
const policy = require('./policy');
const prover = require('./prover');

function signedJson(config, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  return {
    status,
    body,
    headers: {
      'content-type': 'application/json',
      [hmac.HEADER]: hmac.sign(config.hmacSecret, body),
    },
  };
}

function errorJson(config, status, message) {
  return signedJson(config, status, { error: message });
}

// Idempotency: one cached response per match+turn. The platform may retry
// after a network failure; a retry must return the identical body, not a
// second proof for the same turn.
const responseCache = new Map();
function cacheKey(matchId, turn) {
  return `steal:${matchId}:${turn}`;
}

function parseDecimal(v) {
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return String(v);
  if (typeof v === 'string' && /^[0-9]+$/.test(v.trim())) return v.trim();
  throw new Error(`not a non-negative integer: ${String(v)}`);
}

function parseStealTurn(envelope) {
  if (!envelope || typeof envelope !== 'object') return null;
  const { matchId, turn, state } = envelope;
  if (typeof matchId !== 'string' || !matchId) return null;
  if (typeof turn !== 'number' || !Number.isSafeInteger(turn) || turn < 0) return null;
  if (!state || typeof state !== 'object') return null;
  try {
    parseDecimal(state.selfBalance);
    parseDecimal(state.opponentBalance);
  } catch {
    return null;
  }
  const commitment = envelope.strategyCommitment;
  return {
    matchId,
    turn,
    selfBalance: String(state.selfBalance).trim(),
    opponentBalance: String(state.opponentBalance).trim(),
    commitmentHash:
      commitment && typeof commitment.hash === 'string' ? commitment.hash : null,
    deadlineAt: typeof envelope.deadlineAt === 'string' ? envelope.deadlineAt : null,
  };
}

function normalizeHashToBytes32(hexOrDecimal) {
  const h = String(hexOrDecimal || '').trim().toLowerCase().replace(/^0x/, '');
  if (/^[0-9a-f]{64}$/.test(h)) return Buffer.from(h, 'hex');
  if (/^[0-9a-f]+$/.test(h) && h.length < 64) {
    return Buffer.from(h.padStart(64, '0'), 'hex');
  }
  if (/^\d+$/.test(h)) {
    return Buffer.from(BigInt(h).toString(16).padStart(64, '0'), 'hex');
  }
  return null;
}

async function handleStealTurn(config, turn) {
  const key = cacheKey(turn.matchId, turn.turn);
  if (responseCache.has(key)) return responseCache.get(key);

  const localCommitment = await policy.computeCommitment(
    config.strategyParams, config.strategySalt
  );
  const decision = policy.decide(config.strategyParams, turn.selfBalance, turn.opponentBalance);
  const amount = decision.type === 'EXTRACT' ? Number(config.strategyParams[0]) : 0;

  const response = {
    matchId: turn.matchId,
    turn: turn.turn,
    action: decision.type === 'EXTRACT'
      ? { type: 'EXTRACT', amount }
      : { type: decision.type },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: key,
  };

  // The envelope carries the frozen commitment the platform registered.
  // If it does not match ours, any proof we make is doomed (the platform
  // rejects it, -2). Degrade to a clean HOLD with NO proof (scores 0)
  // and say so loudly in the log — the operator must re-register the
  // commitment on the dashboard.
  let commitmentMatches = true;
  if (turn.commitmentHash) {
    const a = normalizeHashToBytes32(turn.commitmentHash);
    const b = normalizeHashToBytes32(policy.commitmentToHex(localCommitment));
    commitmentMatches = !!a && !!b && a.equals(b);
  }
  if (!commitmentMatches) {
    console.warn(
      `[steal] commitment mismatch on ${turn.matchId} turn ${turn.turn}: ` +
      'envelope commitment != local commitment; answering HOLD without proof. ' +
      'Re-register the commitment on the dashboard.'
    );
    response.action = { type: 'HOLD' };
    const out = signedJson(config, 200, response);
    responseCache.set(key, out);
    return out;
  }

  // Prove locally. Any failure (witness assert, missing artifacts, ...)
  // degrades to HOLD without proof — never an invalid proof, never a 500.
  try {
    const input = policy.buildCircuitInput({
      commitment: localCommitment,
      matchId: turn.matchId,
      turn: turn.turn,
      selfBalance: turn.selfBalance,
      opponentBalance: turn.opponentBalance,
      action: decision.type,
      amount,
      circuitVersion: config.circuitVersion,
      salt: config.strategySalt,
      params: config.strategyParams,
    });
    const { proof, publicSignals } = await prover.prove(config.circuitsDir, input);
    const verified = await prover.verifyLocal(config.circuitsDir, proof, publicSignals);
    if (!verified) throw new Error('local proof verification failed');
    response.policyProof = {
      circuitVersion: String(config.circuitVersion),
      proof,
      public_signals: publicSignals,
      publicInputsHash: policy.computePublicInputsHash({
        commitmentHash: policy.commitmentToHex(localCommitment),
        matchId: turn.matchId,
        turn: turn.turn,
        selfBalance: turn.selfBalance,
        opponentBalance: turn.opponentBalance,
        action: decision.type,
        amount,
        circuitVersion: config.circuitVersion,
      }),
    };
  } catch (err) {
    console.warn(
      `[steal] proof failed on ${turn.matchId} turn ${turn.turn} (${err.message}); ` +
      'answering HOLD without proof.'
    );
    response.action = { type: 'HOLD' };
    delete response.policyProof;
  }

  const out = signedJson(config, 200, response);
  responseCache.set(key, out);
  return out;
}

// Main entry: { method, url, headers, rawBody } -> { status, body, headers }.
// rawBody must be the exact bytes received (Buffer), for HMAC.
async function handleRequest(config, { method, url, headers, rawBody }) {
  const path = String(url || '/').split('?')[0];

  if (method === 'GET' && (path === '/' || path === '/health')) {
    return {
      status: 200,
      body: Buffer.from(JSON.stringify({ ok: true, service: 'agentgames-hermes-steal-vfy' })),
      headers: { 'content-type': 'application/json' },
    };
  }
  // Convenience for a bare curl check (unsigned): mirrors the preflight shape.
  if (method === 'GET' && path === '/agent') {
    return {
      status: 200,
      body: Buffer.from(JSON.stringify({ ok: true, protocolVersion: 'v1' })),
      headers: { 'content-type': 'application/json' },
    };
  }
  if (method !== 'POST' || path !== '/agent') {
    return { status: 404, body: Buffer.from(JSON.stringify({ error: 'not found' })), headers: { 'content-type': 'application/json' } };
  }

  // 1. HMAC over the raw body, BEFORE parsing.
  const signature = headers[hmac.HEADER] || headers[hmac.HEADER.toLowerCase()];
  if (!hmac.verify(config.hmacSecret, rawBody, signature)) {
    return errorJson(config, 401, 'bad signature');
  }

  // 2. Parse.
  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return errorJson(config, 400, 'malformed json');
  }
  if (!envelope || typeof envelope !== 'object') {
    return errorJson(config, 400, 'malformed envelope');
  }

  // 3. Preflight: signed { ok: true, protocolVersion: "v1" }.
  if (envelope.type === 'agent-games.preflight.v1') {
    return signedJson(config, 200, { ok: true, protocolVersion: 'v1' });
  }

  // 4. Steal the VFY turn.
  if (envelope.eventId === 'steal-the-vfy') {
    const turn = parseStealTurn(envelope);
    if (!turn) return errorJson(config, 400, 'malformed turn envelope');
    if (turn.deadlineAt && Date.now() > Date.parse(turn.deadlineAt)) {
      console.warn(`[steal] turn ${turn.matchId}:${turn.turn} arrived after deadlineAt; answering anyway (fast HOLD/proof).`);
    }
    return handleStealTurn(config, turn);
  }

  return errorJson(config, 400, 'unknown envelope');
}

module.exports = { handleRequest, cacheKey };
