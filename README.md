# agentgames-hermes-steal-vfy

Self-hosted HTTP agent for **AgentGames (zkVerify) Season 01 — Steal the VFY**.
It answers signed turn envelopes, decides per a strategy you commit to, and
attaches a real Groth16 policy proof (generated locally with `snarkjs`
against the official `vfy-policy` circuit) to every turn.

Target event: **Steal the VFY only**. Proof Gatekeeper is not implemented.

## How a turn works

```
POST /agent  (platform, HMAC-signed over the raw body)
  1. Verify x-agent-games-signature BEFORE parsing. Bad/missing -> 401.
  2. Preflight (type agent-games.preflight.v1)
     -> signed { ok: true, protocolVersion: "v1" }
  3. Steal turn (eventId steal-the-vfy)
     -> validate envelope, decide per the committed strategy,
        generate the Groth16 policy proof locally (~1-2 s),
        return a signed response:
        { matchId, turn, action, agentTimestamp, idempotencyKey,
          policyProof: { circuitVersion, proof, public_signals,
                         publicInputsHash } }
```

Fail-closed by design: a proof that cannot be generated, or a turn whose
envelope commitment does not match the local commitment, degrades to a
clean **HOLD with NO proof** (scores 0) — never an invalid proof (-2) and
never a 500/timeout (-1). A missing proof is treated as HOLD with no proof;
an invalid proof costs -2/turn; a timeout costs -1/turn. A clean HOLD is
the safe floor.

## The strategy (YOUR decision — read this)

The circuit enforces exactly this decision function over 8 committed
parameters:

```
if selfBalance < params[1]          -> FORTIFY
else if opponentBalance <= params[2] -> HOLD
else                                -> EXTRACT params[0]
```

- `params[0]` = extract amount (cap 10), `params[1]` = fortify threshold,
  `params[2]` = hold threshold, `params[3..7]` = unused by this policy
  (kept for commitment compatibility).
- The commitment is `Poseidon([params[0..7], salt])`. The dashboard stores
  it; every proof carries it as a public input. **Change the params or
  the salt and you must re-register the commitment BEFORE the next Swiss
  round pairs — it is frozen mid-match.**

**Default (safe): `STRATEGY_PARAMS=1,0,1000,0,0,0,0,0` — HOLD on every
turn.** `params[1]=0` means FORTIFY never triggers (a balance is never
below 0); `params[2]=1000` means HOLD always triggers (a balance never
exceeds 1000 in a 20-turn match starting at 100); `params[0]=1` is the
extract size, unused while HOLD triggers, and must be >= 1 — the circuit
rejects `params[0] == 0` (assert line 90). Verified locally against the
real circuit: HOLD proofs with these params verify, and a wrong-action
proof with these params FAILS at the circuit assert (see
`npm run verify-fixture`). Note the asymmetry, verified empirically:
FORTIFY uses strict `<`, HOLD uses inclusive `<=`.

> TODO — pick the real strategy before the next round pairs. The
> published starter example is `8,18,8,0,0,0,0,0` (EXTRACT 8, unless
> self < 18 -> FORTIFY, or opponent <= 8 -> HOLD). That is an example of
> how the params map to behaviour, not a recommendation. After changing
> `STRATEGY_PARAMS`, run `npm run commitment` and register the new hash
> on the dashboard. Do NOT change it mid-match.

## Setup

```sh
npm ci
cp .env.example .env
# 1. Paste the one-time HMAC secret from the dashboard
#    (agent -> Rotate Secret; shown exactly once):
#      AGENT_GAMES_HMAC_SECRET=...
# 2. Generate a private salt and print the commitment:
npm run gen-salt        # put the value in .env as STRATEGY_SALT
npm run commitment      # register the printed 0x hash on the dashboard
npm run verify-fixture  # circuit checks (must be all green)
npm run smoke-test      # end-to-end test against the real server
npm start               # listens on :8787 (PORT env)
```

Environment variables (see `.env.example` for the full list):

| Variable | Required | Notes |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | yes | Platform-generated; dashboard -> agent -> Rotate Secret. Never a local placeholder. |
| `STRATEGY_PARAMS` | no | Default `1,0,1000,0,0,0,0,0` (always HOLD). 8 comma-separated integers. |
| `STRATEGY_SALT` | yes | Private nonce. Generate with `npm run gen-salt`. Never commit it. |
| `PORT` | no | Default 8787. |
| `CIRCUIT_VERSION` | no | Default `"1"`. The circuit does not enforce it; the platform checks it against your registered commitment. |
| `CIRCUITS_DIR` | no | Artifact location override. |

## Deploy to a public HTTPS endpoint

The platform requires a **public HTTPS** endpoint — no localhost, no
private IP ranges, no custom ports. It POSTs to the full handler path,
e.g. `https://your-agent.example.com/agent`.

### Option A — fly.dev (fastest to a public URL)

```sh
fly launch --no-deploy          # pick a name, e.g. hermes-steal-vfy
fly secrets set AGENT_GAMES_HMAC_SECRET=<paste from dashboard>
fly secrets set STRATEGY_SALT=<your salt>
fly secrets set STRATEGY_PARAMS="1,0,1000,0,0,0,0,0"
fly deploy
curl https://hermes-steal-vfy.fly.dev/health   # {"ok":true,...}
```

Free-tier machines sleep after inactivity — the platform forfeits tasks
while the agent is asleep, so use a machine that stays awake (or a
long-lived host, option B).

### Option B — your own VPS (recommended for uptime)

On a small VM/container with Node >= 18, kept running 24/7:

```sh
git clone <your repo> && cd <repo>
npm ci
# create .env (HMAC secret, salt, params) — mode 600, never committed
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"  # salt material (see npm run gen-salt)
npm run commitment   # register the 0x hash on the dashboard first
npm start            # or run under systemd (see below)
```

Minimal systemd unit (`/etc/systemd/system/agentgames-hermes.service`):

```ini
[Unit]
Description=AgentGames Steal the VFY agent
After=network.target

[Service]
Type=simple
User=agentgames
WorkingDirectory=/opt/agentgames-hermes
EnvironmentFile=/opt/agentgames-hermes/.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then `systemctl enable --now agentgames-hermes`. Put a reverse proxy
(Caddy or nginx) with a TLS certificate in front of it — the platform
only talks HTTPS on the standard port.

## Register (after the endpoint is live)

1. **Account:** https://agentgames.zkverify.io/register — sign in with X
   or a wallet, pick a unique handle, country, short bio. GitHub and
   wallet are optional at signup but **required for prize eligibility**.
2. **Agent:** Dashboard -> Manage Agents
   (https://agentgames.zkverify.io/dashboard/agents) -> Register a new
   agent. Repository URL (required): the public GitHub URL of this repo.
   Agent Endpoint (optional at registration, required to play): your
   public HTTPS URL, full path, e.g. `https://your-agent.example.com/agent`.
3. **HMAC secret:** the dashboard shows a 32-byte secret exactly once.
   Put it in `.env` as `AGENT_GAMES_HMAC_SECRET` and restart the agent.
   (Rotate Secret invalidates the old one immediately.)
4. **Strategy commitment:** run `npm run commitment`, paste the 0x hash
   at Dashboard -> My Agents -> Edit agent -> Steal the VFY, **before
   the next Swiss round pairs**.
5. **Preflight + practice:** the platform sends a signed preflight
   (`agent-games.preflight.v1`); the agent must answer
   `{ ok: true, protocolVersion: "v1" }` signed. Then run practice tasks
   (Dashboard -> Practice, 10 dispatches per active agent per hour) and
   check the request/response log before the round pairs.
6. **Enter the event:** https://agentgames.zkverify.io/events/steal-the-vfy.
   One agent per owner in this event. A new agent joins from the next
   Swiss round (register, pass a health check, add a strategy commitment
   before that round pairs).

## Health / preflight check (from your machine)

```sh
curl https://your-agent.example.com/health
# {"ok":true,"service":"agentgames-hermes-steal-vfy"}

curl https://your-agent.example.com/agent
# {"ok":true,"protocolVersion":"v1"}
```

A real preflight is a signed POST from the platform; `npm run smoke-test`
replays one locally with a test secret and verifies the signature.

## What is verified, and what is not

**Verified locally in this repo (see Verification below):**

- Circuit artifacts are the official ones: SHA-256 matches the published
  values (`circuits/SHA256SUMS`); `vkHash`
  `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`
  from `/api/circuit-info`.
- The Poseidon commitment for the published demo fixture reproduces the
  published value exactly.
- A proof for the published V1 case reproduces the published
  `public_signals` **exactly (all 9)** and verifies against the extracted
  verification key — this validates the whole input pipeline (matchId
  conversion, commitment, action enum, amount, turn, circuitVersion,
  signal order).
- V2 (FORTIFY) and V3 (HOLD) proofs verify; the published trap cases
  (wrong action, wrong amount) fail at the circuit asserts.
- The default always-HOLD params prove HOLD and cannot prove a
  wrong-action move.
- The server: signed preflight returns the correct signed response;
  signed turns return well-formed responses with a locally verifiable
  proof; redelivery is byte-identical; bad/missing signatures are 401;
  malformed JSON is 400; commitment mismatch degrades to HOLD with no
  proof.

**NOT verified here (honest limits):**

- The turn envelope field names and the response schema are **not
  published on the official site in machine-readable form**. They come
  from participants' public reverse-engineering (notably the
  `soeltan-agent` README and the `vfyPolicy` verification write-up) and
  are consistent with the official `/build` prose — but the exact
  dashboard form fields are only visible after login, and no live
  platform turn has been received by this code yet. The first practice
  dispatch is the real test: check the dashboard's request/response log.
- `publicInputsHash` (keccak256 over ABI-packed 32-byte fields) follows
  the public reference implementation. It is an **optional** audit
  pointer inside `policyProof`; whether the platform's independently
  computed hash matches it for a live turn is untested from here.
- The HMAC header encoding the platform sends (hex vs base64) is not
  published; this server **accepts both** on verification and signs
  responses as lowercase hex.
- Kurier / on-chain submission is intentionally not implemented: the
  platform re-verifies the proof in the response against its own
  registered key. `proofReference` is therefore omitted.
- Registration closes 21 Nov 2026 22:00 UTC. Steal the VFY stays open
  through the tournament for new agents joining from the next Swiss
  round — but the scored rounds already ran 13–20 Nov, so a new agent
  joins late; check the event page for the current round status before
  spending effort on a strategy.

## Verification

Run these yourself; they must all be green before you register:

```sh
npm run verify-fixture   # circuit-level checks (V1/V2/V3 + traps + HOLD default)
npm run smoke-test       # server end-to-end (preflight, turn+proof, idempotency, 401/400)
```

## Files

| Path | Purpose |
| --- | --- |
| `server.js` | Plain Node HTTP server (`POST /agent`, `GET /health`). |
| `src/config.js` | Env loading (`.env` parsed locally, no dependency). |
| `src/hmac.js` | HMAC-SHA256 sign/verify (hex + base64 accepted). |
| `src/policy.js` | Decision function, Poseidon commitment, circuit inputs, publicInputsHash. |
| `src/prover.js` | snarkjs `groth16.fullProve` / `verify` wrapper. |
| `src/handler.js` | Request pipeline: HMAC -> preflight -> turn -> signed response. |
| `scripts/gen-salt.js` | Generate a random strategy salt. |
| `scripts/commitment.js` | Print the commitment hash to register. |
| `scripts/verify-fixture.js` | Circuit fixture checks (see above). |
| `scripts/smoke-test.js` | End-to-end test against the real server. |
| `scripts/fetch-circuits.sh` | Re-download circuit artifacts + verify SHA-256. |
| `circuits/` | `vfy-policy.wasm` (2,991,212 B), `vfy-policy_final.zkey` (810,586 B), `verification_key.json` (extracted), `SHA256SUMS`. |

## Security notes

- The HMAC secret and the strategy salt are **never logged and never
  committed** (`.env` is gitignored; `.env.example` ships blank).
- The server verifies the HMAC against the **raw body before parsing**;
  a tampered body is rejected in milliseconds and never reaches the
  handler or the prover.
- The strategy itself (params + salt) stays private; only the Poseidon
  commitment hash is public and registered on the dashboard.
- Keep the agent's host patched and the endpoint behind TLS. Rotate the
  HMAC secret from the dashboard if it is ever exposed.
