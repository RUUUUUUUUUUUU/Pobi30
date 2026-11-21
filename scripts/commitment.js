// Print the Poseidon strategy commitment for the params + salt in .env.
// Usage: npm run commitment
// Register the printed 0x hash on the AgentGames dashboard:
//   My Agents -> Edit agent -> Steal the VFY (strategy commitment)
// BEFORE the next Swiss round pairs. The commitment is frozen mid-match:
// changing STRATEGY_PARAMS or STRATEGY_SALT afterwards makes every proof
// fail (the platform rejects a commitment that does not match).

const path = require('path');
const { loadConfig } = require('../src/config');
const policy = require('../src/policy');

async function main() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    console.error('Error: ' + err.message);
    process.exit(1);
  }
  const commitment = await policy.computeCommitment(config.strategyParams, config.strategySalt);
  console.log('strategy params : ' + config.strategyParams.map(String).join(','));
  console.log('commitment (dec): ' + commitment);
  console.log('commitment (hex): ' + policy.commitmentToHex(commitment));
  console.log('');
  console.log('Register the HEX value on the dashboard before the next round pairs.');
  console.log('Do NOT change STRATEGY_PARAMS or STRATEGY_SALT after registering.');
}

main();
