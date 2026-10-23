#!/usr/bin/env bash
#
# Configure (unfreeze) a deployed Privasys Identity Verifier over RA-TLS: load
# the ICAO CSCA Master List AND the wallet-provider JWKS in one /configure call.
# The app boots frozen (503 on every path but /health, /version,
# /.well-known/jwks.json and /configure) until trust anchors are loaded, and it
# refuses every wallet ID check until the wallet-provider keys are loaded (a
# Wallet Instance Attestation is required). See config/readme.md.
#
# Only the ICAO CSCA Master List (a CMS .ml) is accepted: the enclave validates
# its CMS signature and that it chains to the pinned ICAO/UN CSCA root before
# extracting the country CSCAs. There is no raw-PEM / arbitrary-anchor path.
#
set -euo pipefail

APP="container-app-identity-verifier"
ML=""
URL=""
JWKS_URL="https://privasys.id/wallet-provider/jwks"
JWKS_FILE=""
ATTEST=""
ENDPOINT=""

usage() {
  cat <<'EOF'
Load the ICAO CSCA Master List and the wallet-provider JWKS into a deployed
identity verifier (lifts the configure-then-freeze gate).

Usage:
  config/initialise.sh --ml <ICAO_ML.ml>            [--app <name-or-id>] [--endpoint <url>] [--attest] [--jwks-url <url> | --jwks <file>]
  config/initialise.sh --url <https://.../ml.ml>    [--app <name-or-id>] [--endpoint <url>] [--attest] [--jwks-url <url> | --jwks <file>]

Options:
  --ml <file>        ICAO/national CSCA Master List as a CMS .ml. The enclave
                     verifies its signature and that it chains to the pinned
                     ICAO/UN CSCA root, then extracts the CSCAs.
  --url <url>        Download the master list (.ml) from a URL instead.
  --jwks-url <url>   Where to fetch the wallet-provider JWKS (default:
                     https://privasys.id/wallet-provider/jwks; for dev use the
                     dev IdP's /wallet-provider/jwks).
  --jwks <file>      Use a JWKS file instead of fetching one.
  --app <name-or-id> App to configure (default: container-app-identity-verifier).
  --endpoint <url>   Platform API base URL the CLI targets, e.g.
                     https://api-test.developer.privasys.org for dev/test.
                     Defaults to your CLI config (often prod), so set this if the
                     verifier is deployed elsewhere.
  --attest           Also verify the enclave quote against the attestation server
                     (genuine TEE + TCB), not just RA-TLS locally.

Requires the `privasys` CLI on PATH and an authenticated session
(`privasys auth login`) as an owner of the app. The master list must be the
genuine ICAO one (or chain to the same ICAO/UN CSCA root); anything else is
rejected by the enclave. Source it deliberately (ICAO PKD), never an arbitrary
file off the internet.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --ml)       ML="${2:-}"; shift 2;;
    --url)      URL="${2:-}"; shift 2;;
    --jwks-url) JWKS_URL="${2:-}"; shift 2;;
    --jwks)     JWKS_FILE="${2:-}"; shift 2;;
    --app)      APP="${2:-}"; shift 2;;
    --endpoint) ENDPOINT="${2:-}"; shift 2;;
    --attest)   ATTEST="--attest"; shift;;
    -h|--help)  usage; exit 0;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 2;;
  esac
done

command -v privasys >/dev/null 2>&1 || { echo "error: 'privasys' CLI not found on PATH (install it and run 'privasys auth login')" >&2; exit 1; }
command -v python3  >/dev/null 2>&1 || { echo "error: python3 is required to build the request body" >&2; exit 1; }

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

if [ -n "$URL" ]; then
  echo "Downloading master list from $URL ..." >&2
  curl -fsSL "$URL" -o "$workdir/ml.ml"
  ML="$workdir/ml.ml"
fi

[ -n "$ML" ] || { echo "error: provide --ml <file> or --url <url>" >&2; usage; exit 2; }
[ -f "$ML" ] || { echo "error: master list not found: $ML" >&2; exit 1; }

# The wallet-provider JWKS: without it every wallet ID check is refused.
if [ -z "$JWKS_FILE" ]; then
  echo "Fetching wallet-provider JWKS from $JWKS_URL ..." >&2
  curl -fsSL "$JWKS_URL" -o "$workdir/jwks.json"
  JWKS_FILE="$workdir/jwks.json"
fi
[ -f "$JWKS_FILE" ] || { echo "error: JWKS not found: $JWKS_FILE" >&2; exit 1; }

# Build the /configure body:
#   {"master_list_cms": "<base64 of the .ml>", "wallet_provider_jwks": {...}}.
body="$workdir/configure.json"
python3 - "$ML" "$JWKS_FILE" "$body" <<'PY'
import json, base64, sys
src, jwks_path, dst = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src, "rb") as f:
    cms = base64.b64encode(f.read()).decode()
with open(jwks_path, encoding="utf-8") as f:
    jwks = json.load(f)
if not isinstance(jwks, dict) or not jwks.get("keys"):
    sys.exit("error: the wallet-provider JWKS has no keys")
with open(dst, "w", encoding="utf-8") as f:
    json.dump({"master_list_cms": cms, "wallet_provider_jwks": jwks}, f)
PY

echo "Configuring '$APP' over RA-TLS ..." >&2
# --no-challenge: the bundled CLI uses deterministic verify; the fresh-nonce
# challenge needs the Privasys/go RA-TLS fork. Your access token is presented to
# the app for owner auth; the control plane is never in the data path.
privasys apps call "$APP" configure ${ENDPOINT:+--endpoint "$ENDPOINT"} --data "@$body" --no-challenge $ATTEST

echo >&2
echo "Done. The response above carries trust_anchors_digest (attested at OID" >&2
echo "1.3.6.1.4.1.65230.5.4.1) and wallet_provider_jwks_digest (OID .5.4.2). Both" >&2
echo "persist on the app's sealed volume; a fresh volume needs this run again." >&2
echo "Check: privasys apps call $APP wallet-provider-jwks/status --data '{}'  (count >= 1)" >&2
