// Generate a random strategy salt (private commitment nonce).
// Usage: npm run gen-salt
// Put the printed value in .env as STRATEGY_SALT, then run
// `npm run commitment` and register the hash on the dashboard.
// The salt is SECRET: it is part of the commitment preimage. Never commit
// it, never paste it into a chat, never share it.

const crypto = require('crypto');

const salt = BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString();
console.log('STRATEGY_SALT=' + salt);
console.log('Put the line above in .env (keep it secret), then run: npm run commitment');
