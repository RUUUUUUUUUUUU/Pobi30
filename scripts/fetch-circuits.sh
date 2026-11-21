#!/bin/sh
# Download the vfy-policy circuit artifacts and verify SHA-256.
# Usage: sh scripts/fetch-circuits.sh
# (Not needed if circuits/ is already populated — the files are committed.)
set -e
cd "$(dirname "$0")/../circuits"
curl -sL -o vfy-policy.wasm https://agentgames.zkverify.io/circuits/vfy-policy.wasm
curl -sL -o vfy-policy_final.zkey https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey
sha256sum -c SHA256SUMS
ls -l
