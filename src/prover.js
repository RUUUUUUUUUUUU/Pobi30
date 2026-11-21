// Local Groth16 proving against the official vfy-policy circuit artifacts.
// No network, no Kurier, no wallet: the proof is generated on this machine
// with snarkjs and the platform re-verifies it against its own registered
// verification key (vkHash 0x6c56...be047).

const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

let verificationKey = null;

function paths(circuitsDir) {
  return {
    wasm: path.join(circuitsDir, 'vfy-policy.wasm'),
    zkey: path.join(circuitsDir, 'vfy-policy_final.zkey'),
    vk: path.join(circuitsDir, 'verification_key.json'),
  };
}

function assertArtifacts(circuitsDir) {
  const p = paths(circuitsDir);
  for (const [name, file] of Object.entries(p)) {
    if (!fs.existsSync(file)) {
      throw new Error(`Missing circuit artifact: ${file} (${name}). ` +
        'Download them from https://agentgames.zkverify.io/circuits/ ' +
        'or run scripts/fetch-circuits.sh.');
    }
  }
  return p;
}

async function prove(circuitsDir, circuitInput) {
  const p = assertArtifacts(circuitsDir);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, p.wasm, p.zkey);
  return { proof, publicSignals };
}

// Verify a proof locally against the extracted verification key.
// This is a SELF-CHECK only: the platform re-verifies against the key it
// registered on zkVerify mainnet. A local pass means the proof is
// well-formed for this circuit; it does not prove platform acceptance.
async function verifyLocal(circuitsDir, proof, publicSignals) {
  const p = paths(circuitsDir);
  if (!verificationKey) verificationKey = JSON.parse(fs.readFileSync(p.vk, 'utf8'));
  return snarkjs.groth16.verify(verificationKey, publicSignals, proof);
}

module.exports = { prove, verifyLocal, paths, assertArtifacts };
