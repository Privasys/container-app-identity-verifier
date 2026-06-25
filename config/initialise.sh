#!/usr/bin/env bash
#
# Configure (unfreeze) a deployed Privasys Identity Verifier by loading its CSCA
# trust anchors over RA-TLS. The app boots frozen (503 on every path but
# /health, /version, /.well-known/jwks.json and /configure) until trust anchors
# are loaded; this script sources them, builds the request body, and POSTs it to
# /configure with the Privasys CLI. See config/readme.md for the full runbook.
#
# Steps performed:
#   1. source the CSCA anchors (a local file, or downloaded from --url)
#   2. build the /configure request body (master_list_cms or trust_anchors_pem)
#   3. call <app> /configure over RA-TLS with `privasys apps call`
#
set -euo pipefail

APP="container-app-identity-verifier"
ANCHORS=""
URL=""
ATTEST=""
ENDPOINT=""

usage() {
  cat <<'EOF'
Load CSCA trust anchors into a deployed identity verifier (lifts the
configure-then-freeze gate).

Usage:
  config/initialise.sh --anchors <ICAO_ML.ml | csca-bundle.pem> [--app <name-or-id>] [--attest]
  config/initialise.sh --url <https://.../master-list.ml>        [--app <name-or-id>] [--attest]

Options:
  --anchors <file>   ICAO/national CSCA Master List (CMS .ml) OR a PEM bundle of
                     CSCA roots. The verifier validates the CMS signature and the
                     signer chain itself before extracting the CSCAs.
  --url <url>        Download the master list (.ml) from a URL instead.
  --app <name-or-id> App to configure (default: container-app-identity-verifier).
  --endpoint <url>   Platform API base URL the CLI targets, e.g.
                     https://api-test.developer.privasys.org for the dev/test
                     environment. Defaults to your CLI config (often prod), so
                     set this if the verifier is deployed elsewhere.
  --attest           Also verify the enclave quote against the attestation server
                     (genuine TEE + TCB), not just RA-TLS locally.

Requires the `privasys` CLI on PATH and an authenticated session
(`privasys auth login`) as an owner of the app. The anchors must include the
CSCA of every issuing country you intend to verify (e.g. the German CSCA for a
German passport). This is the root of trust for Passive Authentication: source
it deliberately (ICAO PKD or a trusted national master list), never an arbitrary
file off the internet.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --anchors) ANCHORS="${2:-}"; shift 2;;
    --url)     URL="${2:-}"; shift 2;;
    --app)      APP="${2:-}"; shift 2;;
    --endpoint) ENDPOINT="${2:-}"; shift 2;;
    --attest)   ATTEST="--attest"; shift;;
    -h|--help) usage; exit 0;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 2;;
  esac
done

command -v privasys >/dev/null 2>&1 || { echo "error: 'privasys' CLI not found on PATH (install it and run 'privasys auth login')" >&2; exit 1; }
command -v python3  >/dev/null 2>&1 || { echo "error: python3 is required to build the request body" >&2; exit 1; }

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

if [ -n "$URL" ]; then
  echo "Downloading master list from $URL ..." >&2
  curl -fsSL "$URL" -o "$workdir/anchors.ml"
  ANCHORS="$workdir/anchors.ml"
fi

[ -n "$ANCHORS" ] || { echo "error: provide --anchors <file> or --url <url>" >&2; usage; exit 2; }
[ -f "$ANCHORS" ] || { echo "error: anchors file not found: $ANCHORS" >&2; exit 1; }

# Build the /configure body. Detect a PEM bundle vs a CMS master list (.ml) by
# sniffing for the PEM header; everything else is treated as binary CMS.
body="$workdir/configure.json"
if head -c 64 "$ANCHORS" 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
  echo "Anchors detected as a PEM bundle." >&2
  python3 - "$ANCHORS" "$body" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as f:
    pem = f.read()
with open(dst, "w", encoding="utf-8") as f:
    json.dump({"trust_anchors_pem": pem}, f)
PY
else
  echo "Anchors detected as a CMS master list (.ml)." >&2
  python3 - "$ANCHORS" "$body" <<'PY'
import json, base64, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src, "rb") as f:
    cms = base64.b64encode(f.read()).decode()
with open(dst, "w", encoding="utf-8") as f:
    json.dump({"master_list_cms": cms}, f)
PY
fi

echo "Configuring '$APP' over RA-TLS ..." >&2
# --no-challenge: the bundled CLI uses deterministic verify; the fresh-nonce
# challenge needs the Privasys/go RA-TLS fork. Your access token is presented to
# the app for owner auth; the control plane is never in the data path.
privasys apps call "$APP" configure ${ENDPOINT:+--endpoint "$ENDPOINT"} --data "@$body" --no-challenge $ATTEST

echo >&2
echo "Done. The response above carries trust_anchors_digest (SHA-256 of the active" >&2
echo "set, also published at attestation OID 1.3.6.1.4.1.65230.2.8). The anchors" >&2
echo "persist on the app's sealed volume, so future redeploys come back configured." >&2
