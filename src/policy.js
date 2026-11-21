// Steal the VFY — strategy decision function, Poseidon commitment, circuit
// inputs, and the public-inputs hash.
//
// WHAT IS VERIFIED vs WHAT IS COMMUNITY-DERIVED
// ----------------------------------------------
// The platform does NOT publish the vfy-policy circuit source or its input
// signal names. The names, order, and decision function below were
// reverse-engineered by tournament participants from the public circuit
// artifacts and confirmed against the circuit itself with snarkjs:
//   - 9 public signals, in order:
//     [output, commitment, matchId, turnNumber, selfBalance,
//      opponentBalance, action, amount, circuitVersion]
//   - commitment = Poseidon([strategyParams[0..7], salt])
//   - decision function enforced by the circuit (assert lines in
//     VfyPolicyProof_154): FORTIFY if selfBalance < params[1];
//     else HOLD if opponentBalance <= params[2] (inclusive — verified:
//     at opponent == params[2] the circuit holds, EXTRACT fails);
//     else EXTRACT params[0]. params[0] must be >= 1: the circuit
//     rejects params[0] == 0 at line 90 (verified).
//   - action enum: HOLD 0, FORTIFY 1, EXTRACT 2. circuitVersion "1".
// This repo re-verifies all of it locally (scripts/verify-fixture.js):
// the published demo fixture reproduces its published public signals
// exactly, and proofs verify against the extracted verification key.
// The publicInputsHash formula (keccak256 over ABI-packed 32-byte fields)
// follows the public reference implementation; it could NOT be checked
// against a live platform turn from here, so it is labelled accordingly
// in the README. It is an OPTIONAL audit pointer — the proof itself is
// what the platform re-verifies.

const { keccak256 } = require('js-sha3');
const { buildPoseidon } = require('circomlibjs');

const ACTION_ENUM = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

// The BN128 scalar field prime (used only to reduce a hashed fallback id).
const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

// Poseidon hash of the 8 strategy params plus the salt, as a decimal string.
// This is the commitment the dashboard stores (as 0x hex of the same value).
async function computeCommitment(params, salt) {
  const poseidon = await getPoseidon();
  const inputs = [...params.map((p) => BigInt(p)), BigInt(salt)];
  return poseidon.F.toString(poseidon(inputs));
}

function commitmentToHex(commitmentDecimal) {
  return '0x' + BigInt(commitmentDecimal).toString(16).padStart(64, '0');
}

// The circuit's matchId input is the UUID as one big integer.
// a1b2c3d4-0000-1111-2222-333344445555 -> 214933908028433900551448047275865298261
function matchIdToField(matchId) {
  const stripped = String(matchId || '').replace(/-/g, '').toLowerCase();
  if (/^[0-9a-f]{32}$/.test(stripped)) return BigInt('0x' + stripped).toString();
  // Defensive fallback for a non-UUID id: hash it into the field.
  return (BigInt('0x' + keccak256(String(matchId))) % FIELD_PRIME).toString();
}

// The decision function the circuit enforces. Returns { type, amount }.
// amount is only meaningful for EXTRACT; HOLD/FORTIFY carry NO amount
// field in the response (the schema rejects it even when 0).
//
// TODO (YOUR DECISION): the behaviour is entirely determined by
// STRATEGY_PARAMS in .env. The default (1,0,1000,0,0,0,0,0) makes this
// function return HOLD on every turn: params[1]=0 means FORTIFY never
// triggers (a balance is never < 0), params[2]=1000 means HOLD always
// triggers (a balance never exceeds 1000 in a 20-turn match starting
// at 100). params[0]=1 is the extract size, unused while HOLD triggers,
// and must be >= 1 — the circuit rejects params[0] == 0.
function decide(params, selfBalance, opponentBalance) {
  const self = BigInt(selfBalance);
  const opp = BigInt(opponentBalance);
  // NOTE the asymmetry — verified empirically against the real circuit
  // (scripts/verify-fixture.js): FORTIFY uses strict <, HOLD uses <=.
  // At self == params[1] the circuit does NOT fortify (EXTRACT proves);
  // at opponent == params[2] the circuit DOES hold (EXTRACT fails).
  if (self < params[1]) return { type: 'FORTIFY' };
  if (opp <= params[2]) return { type: 'HOLD' };
  return { type: 'EXTRACT', amount: params[0] };
}

// Circuit inputs, with the exact signal names the circuit expects.
// snarkjs fullProve rejects unknown or missing names, so a typo here is
// caught locally before anything is submitted.
function buildCircuitInput({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount, circuitVersion, salt, params }) {
  return {
    commitment: String(commitment),
    matchId: matchIdToField(matchId),
    turnNumber: String(turn),
    selfBalance: String(selfBalance),
    opponentBalance: String(opponentBalance),
    action: String(ACTION_ENUM[action]),
    amount: String(amount),
    circuitVersion: String(circuitVersion),
    salt: String(salt),
    strategyParams: params.map((p) => String(p)),
  };
}

// --- publicInputsHash -----------------------------------------------------
// keccak256(abi.encodePacked(
//   strategyCommitment.hash, matchId, turn, selfBalance, opponentBalance,
//   actionEnum, amount, circuitVersion )) — each field 32-byte big-endian.
// Field order is load-bearing. Formula follows the public reference
// implementation; it has NOT been confirmed against a live platform turn
// (the platform computes it independently). It is an optional audit
// pointer inside policyProof — the proof itself is what is re-verified.

function toBytes32(value) {
  return Buffer.from(BigInt(value).toString(16).padStart(64, '0'), 'hex');
}

function hashToBytes32(hash) {
  const h = String(hash || '').trim().toLowerCase().replace(/^0x/, '');
  if (/^[0-9a-f]{64}$/.test(h)) return Buffer.from(h, 'hex');
  if (/^[0-9a-f]+$/.test(h) && h.length < 64) {
    return Buffer.from(h.padStart(64, '0'), 'hex');
  }
  return Buffer.from(keccak256(String(hash || '')), 'hex');
}

function matchIdToBytes32(matchId) {
  const stripped = String(matchId || '').replace(/-/g, '').toLowerCase();
  if (/^[0-9a-f]{32}$/.test(stripped)) return toBytes32(BigInt('0x' + stripped));
  return Buffer.from(keccak256(String(matchId)), 'hex');
}

function computePublicInputsHash({ commitmentHash, matchId, turn, selfBalance, opponentBalance, action, amount, circuitVersion }) {
  const packed = Buffer.concat([
    hashToBytes32(commitmentHash),
    matchIdToBytes32(matchId),
    toBytes32(BigInt(turn)),
    toBytes32(BigInt(selfBalance)),
    toBytes32(BigInt(opponentBalance)),
    toBytes32(BigInt(ACTION_ENUM[action])),
    toBytes32(BigInt(amount)),
    toBytes32(BigInt(circuitVersion)),
  ]);
  return '0x' + keccak256(packed);
}

module.exports = {
  ACTION_ENUM,
  FIELD_PRIME,
  computeCommitment,
  commitmentToHex,
  matchIdToField,
  decide,
  buildCircuitInput,
  computePublicInputsHash,
};
