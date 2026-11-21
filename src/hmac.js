// HMAC-SHA256 signing / verification for the AgentGames protocol.
//
// The platform signs every request with the x-agent-games-signature header
// computed over the RAW request body. The signature is verified BEFORE the
// body is parsed — a forged or tampered body must never reach the handler.
// Every response is signed the same way over the RAW response body.
//
// Signature encoding: the platform's exact encoding is not published. This
// module ACCEPTS both lowercase hex and base64 on verification (timing-safe
// compare either way) and SIGNS responses as lowercase hex.

const crypto = require('crypto');

const HEADER = 'x-agent-games-signature';

function sign(secret, rawBody) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody);
  return crypto.createHmac('sha256', secret).update(body).digest('hex');
}

function decodeSignature(value) {
  const v = String(value || '').trim().replace(/^sha256=/i, '');
  if (/^[0-9a-f]{64}$/i.test(v)) return Buffer.from(v, 'hex');
  if (/^[A-Za-z0-9+/]{43}={0,2}$/.test(v)) {
    try {
      const b = Buffer.from(v, 'base64');
      if (b.length === 32) return b;
    } catch { /* fall through */ }
  }
  return null;
}

// Timing-safe verification. Returns false (never throws) on any problem.
function verify(secret, rawBody, signatureHeader) {
  if (!secret || !signatureHeader) return false;
  const expected = crypto.createHmac('sha256', secret)
    .update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody))
    .digest();
  const provided = decodeSignature(signatureHeader);
  if (!provided || provided.length !== expected.length) return false;
  return crypto.timingSafeEqual(provided, expected);
}

module.exports = { HEADER, sign, verify };
