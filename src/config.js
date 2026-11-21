// Minimal .env parsing + config. No external dependency.
// Secrets come from the environment (or .env on the host). Nothing here
// has a default value for a secret — a missing secret is a startup error.

const fs = require('fs');
const path = require('path');

function parseDotEnvFile(file) {
  const out = {};
  if (!fs.existsSync(file)) return out;
  for (const rawLine of fs.readFileSync(file, 'utf8').split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) out[key] = value;
  }
  return out;
}

function loadEnv() {
  // .env next to the repo root (and next to server.js, same thing).
  const parsed = parseDotEnvFile(path.join(__dirname, '..', '.env'));
  for (const [k, v] of Object.entries(parsed)) process.env[k] = v;
}

function parseParams(raw) {
  const parts = String(raw).split(',').map((s) => s.trim());
  if (parts.length !== 8 || parts.some((p) => !/^-?\d+$/.test(p))) {
    throw new Error('STRATEGY_PARAMS must be exactly 8 comma-separated integers');
  }
  return parts.map((p) => BigInt(p));
}

function loadConfig() {
  loadEnv();
  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!secret) {
    throw new Error(
      'Missing AGENT_GAMES_HMAC_SECRET. Copy .env.example to .env and paste the ' +
      'one-time secret from the AgentGames dashboard (agent -> Rotate Secret).'
    );
  }
  const paramsRaw = process.env.STRATEGY_PARAMS || '1,0,1000,0,0,0,0,0';
  const params = parseParams(paramsRaw);
  const salt = process.env.STRATEGY_SALT;
  if (!salt || !/^\d+$/.test(salt.trim())) {
    throw new Error(
      'Missing STRATEGY_SALT. Run `npm run gen-salt`, put the value in .env, ' +
      'then run `npm run commitment` and register the hash on the dashboard.'
    );
  }
  return {
    hmacSecret: secret,
    strategyParams: params,
    strategySalt: salt.trim(),
    circuitVersion: process.env.CIRCUIT_VERSION || '1',
    port: Number(process.env.PORT || 8787),
    circuitsDir: process.env.CIRCUITS_DIR || path.join(__dirname, '..', 'circuits'),
  };
}

module.exports = { loadConfig, parseDotEnvFile, parseParams };
