// Local circuit verification fixture. No network, no platform, no secrets.
// Usage: npm run verify-fixture
//
// Replays the published demo cases against the REAL vfy-policy circuit
// artifacts in ./circuits and checks:
//   1. The Poseidon commitment for the demo params+salt reproduces the
//      published value exactly.
//   2. The V1 EXTRACT proof reproduces the published public_signals
//      EXACTLY (all 9), which validates the whole input pipeline:
//      matchId UUID->integer conversion, commitment, action enum, amount,
//      turn numbers, circuitVersion, and the public-signal order.
//   3. V2 (FORTIFY) and V3 (HOLD) proofs verify against the extracted
//      verification key.
//   4. The trap cases FAIL at the circuit asserts, as published.
//   5. The repo DEFAULT params (1,0,1000,0,0,0,0,0) prove HOLD on every
//      tested state and CANNOT prove a wrong action (the always-HOLD
//      default is circuit-valid).
// Exit code 0 = all checks pass; non-zero = something is wrong with the
// circuit inputs (do not deploy until this is green).

const path = require('path');
const snarkjs = require('snarkjs');
const policy = require('../src/policy');
const prover = require('../src/prover');

const CIRCUITS_DIR = path.join(__dirname, '..', 'circuits');

const DEMO_PARAMS = [8n, 18n, 8n, 0n, 0n, 0n, 0n, 0n];
const DEMO_SALT = '12345678901234567890';
const DEMO_MATCH = 'a1b2c3d4-0000-1111-2222-333344445555';
const DEMO_COMMITMENT = '18509752657592529527109630018603854483195680471699643211660232613401632907815';
const V1_SIGNALS = [
  '6396486238659655343650970048011779167413974050820627010779539413176448134638',
  '18509752657592529527109630018603854483195680471699643211660232613401632907815',
  '214933908028433900551448047275865298261',
  '1', '100', '100', '2', '8', '1',
];

const HOLD_PARAMS = [1n, 0n, 1000n, 0n, 0n, 0n, 0n, 0n];
const HOLD_SALT = '98765432109876543210';

let failures = 0;
function check(name, ok, extra) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
  if (!ok) failures++;
}

async function proveExpect(name, input, expectSuccess) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await prover.prove(CIRCUITS_DIR, input);
    const verified = await prover.verifyLocal(CIRCUITS_DIR, proof, publicSignals);
    if (!expectSuccess) {
      check(name, false, `proved but should have failed (${Date.now() - t0}ms)`);
      return null;
    }
    check(name, verified === true, `proved+verified in ${Date.now() - t0}ms`);
    return { proof, publicSignals };
  } catch (err) {
    if (expectSuccess) {
      check(name, false, `threw: ${String(err.message).split('\n')[0]}`);
      return null;
    }
    check(name, true, `failed as expected (${Date.now() - t0}ms): ${String(err.message).split('\n')[0].slice(0, 80)}`);
    return null;
  }
}

async function main() {
  // 1. Commitment + matchId conversion.
  const commitment = await policy.computeCommitment(DEMO_PARAMS, DEMO_SALT);
  check('commitment == published demo value', commitment === DEMO_COMMITMENT);
  check('matchId UUID -> field integer',
    policy.matchIdToField(DEMO_MATCH) === '214933908028433900551448047275865298261');

  const demoBase = {
    commitment, matchId: DEMO_MATCH, salt: DEMO_SALT,
    params: DEMO_PARAMS, circuitVersion: '1',
  };
  const input = ({ turn, self, opp, action, amount }) =>
    policy.buildCircuitInput({
      ...demoBase, turn, selfBalance: String(self), opponentBalance: String(opp),
      action, amount: String(amount),
    });

  // 2. V1 EXTRACT — public signals must match the published values exactly.
  const v1 = await proveExpect('V1 EXTRACT turn1 100/100 proves+verifies',
    input({ turn: 1, self: 100, opp: 100, action: 'EXTRACT', amount: 8 }), true);
  if (v1) {
    check('V1 public_signals == published (all 9)',
      JSON.stringify(v1.publicSignals) === JSON.stringify(V1_SIGNALS));
  } else {
    check('V1 public_signals == published (all 9)', false, 'no proof produced');
  }

  // 3. V2 FORTIFY, V3 HOLD.
  await proveExpect('V2 FORTIFY turn2 10/100 proves+verifies',
    input({ turn: 2, self: 10, opp: 100, action: 'FORTIFY', amount: 0 }), true);
  await proveExpect('V3 HOLD turn3 100/5 proves+verifies',
    input({ turn: 3, self: 100, opp: 5, action: 'HOLD', amount: 0 }), true);

  // 4. Trap cases must fail.
  await proveExpect('T1 trap: EXTRACT when policy says FORTIFY fails',
    input({ turn: 2, self: 10, opp: 100, action: 'EXTRACT', amount: 8 }), false);
  await proveExpect('T3 trap: EXTRACT 5 when params[0] is 8 fails',
    input({ turn: 1, self: 100, opp: 100, action: 'EXTRACT', amount: 5 }), false);

  // 5. Repo default params: always HOLD is circuit-valid.
  // params[0] must be >= 1 (the circuit rejects 0 at line 90), so the
  // default is [1,0,1000,0,0,0,0,0]: FORTIFY never triggers, HOLD
  // triggers for opponent <= 1000, EXTRACT 1 only above that.
  const holdCommitment = await policy.computeCommitment(HOLD_PARAMS, HOLD_SALT);
  const holdBase = {
    commitment: holdCommitment, matchId: DEMO_MATCH, salt: HOLD_SALT,
    params: HOLD_PARAMS, circuitVersion: '1',
  };
  const holdInput = ({ turn, self, opp, action, amount }) =>
    policy.buildCircuitInput({
      ...holdBase, turn, selfBalance: String(self), opponentBalance: String(opp),
      action, amount: String(amount),
    });
  await proveExpect('HOLD-default turn1 100/100 proves+verifies',
    holdInput({ turn: 1, self: 100, opp: 100, action: 'HOLD', amount: 0 }), true);
  await proveExpect('HOLD-default turn5 100/250 proves+verifies',
    holdInput({ turn: 5, self: 100, opp: 250, action: 'HOLD', amount: 0 }), true);
  await proveExpect('HOLD-default turn9 40/90 proves+verifies',
    holdInput({ turn: 9, self: 40, opp: 90, action: 'HOLD', amount: 0 }), true);
  await proveExpect('HOLD-default turn2 opp=1000 boundary HOLD proves+verifies',
    holdInput({ turn: 2, self: 100, opp: 1000, action: 'HOLD', amount: 0 }), true);
  await proveExpect('HOLD-default EXTRACT 1 at synthetic opp=1500 proves+verifies',
    holdInput({ turn: 3, self: 100, opp: 1500, action: 'EXTRACT', amount: 1 }), true);
  await proveExpect('HOLD-default trap: EXTRACT 8 (amount != params[0]) fails',
    holdInput({ turn: 1, self: 100, opp: 100, action: 'EXTRACT', amount: 8 }), false);
  await proveExpect('HOLD-default trap: FORTIFY when policy says HOLD fails',
    holdInput({ turn: 1, self: 100, opp: 100, action: 'FORTIFY', amount: 0 }), false);

  // 6. The decision function agrees with the circuit on the demo cases,
  // including the exact boundaries (FORTIFY is strict <, HOLD is <=).
  const d = (self, opp) => policy.decide(DEMO_PARAMS, String(self), String(opp));
  check('decide(100,100) == EXTRACT 8', d(100, 100).type === 'EXTRACT' && d(100, 100).amount === 8n);
  check('decide(10,100) == FORTIFY', d(10, 100).type === 'FORTIFY');
  check('decide(100,5) == HOLD', d(100, 5).type === 'HOLD');
  check('decide(18,100) == EXTRACT (self == params[1], strict <)',
    d(18, 100).type === 'EXTRACT');
  check('decide(100,8) == HOLD (opp == params[2], inclusive <=)',
    d(100, 8).type === 'HOLD');
  const dh = (self, opp) => policy.decide(HOLD_PARAMS, String(self), String(opp));
  check('decide-default(100,100) == HOLD', dh(100, 100).type === 'HOLD');
  check('decide-default(100,250) == HOLD', dh(100, 250).type === 'HOLD');
  check('decide-default(100,1000) == HOLD (boundary inclusive)', dh(100, 1000).type === 'HOLD');
  check('decide-default(100,1500) == EXTRACT 1', dh(100, 1500).type === 'EXTRACT' && dh(100, 1500).amount === 1n);

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => { console.error('FATAL', err); process.exit(1); });
