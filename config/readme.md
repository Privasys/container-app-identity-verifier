# Configuring the Identity Verifier

The verifier boots **frozen**. Until its CSCA trust anchors are loaded, every
endpoint except `/health`, `/version`, `/.well-known/jwks.json` and `/configure`
returns `503 "app is awaiting initial configuration"`. Configuration loads the
Country Signing CA (CSCA) certificates that Passive Authentication chains each
passport's Document Signer Certificate to. There is **no bypass**: this is the
root of trust for the whole verification, so it is deliberately not baked into
the image (CSCAs rotate, and the trusted set is an operational choice).

`config/initialise.sh` performs the three steps end to end: source the anchors,
build the request body, and send it to `/configure` over RA-TLS with the
Privasys CLI.

## Prerequisites

- The app is **deployed** on the Privasys platform (it has a gateway hostname).
- The **`privasys` CLI** is installed and authenticated as an **owner** of the
  app: `privasys auth login`. The verifier gates `/configure` on the caller's
  token, so a non-owner cannot configure it.
- A **CSCA master list** (see *Sourcing the anchors* below). It must include the
  CSCA of every issuing country you intend to verify (for example the German
  CSCA for a German passport), or that document's Passive Authentication fails
  with "DSC does not chain to any trusted CSCA".

## Configure it

```sh
# From a downloaded ICAO/national master list (CMS .ml):
config/initialise.sh --anchors ICAO_ML.ml

# Or download the list as part of the run:
config/initialise.sh --url https://example.org/path/to/master-list.ml

# Or a ready PEM bundle of CSCA roots:
config/initialise.sh --anchors csca-bundle.pem

# Target a specific deployment (name or id), and verify the quote too:
config/initialise.sh --anchors ICAO_ML.ml --app container-app-identity-verifier --attest
```

A successful run prints:

```json
{"status":"configured","trust_anchors_digest":"892611a7…"}
```

`trust_anchors_digest` is the SHA-256 of the active anchor set. It is also
published as attestation extension OID `1.3.6.1.4.1.65230.2.8`, so a relying
party can pin which anchors were in force from the RA-TLS certificate. The
verifier re-derives the same digest for the same set, so it is a quick check
that the right list loaded. The anchors persist on the app's per-app sealed
volume, so a later redeploy onto the same volume comes back **already
configured**; you only re-run this:

- the first time the app is provisioned, or
- after the data volume is wiped / re-created, or
- to rotate or replace the anchor set.

## Sourcing the anchors

CSCAs are not in this repo and must be sourced. In rough order of trust:

- **ICAO PKD** — the authoritative source (requires PKD access). Download the
  CSCA Master List (a CMS `SignedData` wrapping `CscaMasterListData`); the
  verifier validates the CMS signature and the ML-signer chain before extracting
  the CSCAs, so pass the raw `.ml` straight to `--anchors`.
- **National master list** — several issuers publish their CSCA Master List as a
  public CMS (for example the German BSI list). Suitable for dev/test and a
  reasonable curated production set.
- **Single-country** — the issuing country's published CSCA root, for narrow
  testing. Convert to PEM and pass it with `--anchors`.

Treat the anchor set as security-critical: choose the source deliberately and,
for production, decide who signs your "approved master list" and how often it is
refreshed.

## What the script does (and the manual equivalent)

The script base64-encodes a `.ml` into `{"master_list_cms": "<b64>"}` (or wraps
a PEM into `{"trust_anchors_pem": "<pem>"}`), then runs:

```sh
privasys apps call <app> configure --data @<body.json> --no-challenge
```

`apps call` connects to the app's enclave over RA-TLS, verifies its attestation,
and sends the request directly: the control plane is never in the data path.
`--no-challenge` is needed because the bundled CLI does deterministic verification
(the fresh-nonce challenge requires the Privasys/go RA-TLS fork). Add `--attest`
to also verify the quote (genuine TEE + TCB) against the attestation server.

The equivalent control-plane path is `POST /api/v1/apps/<app-id>/rpc/configure`
with the same body, but the direct RA-TLS call above keeps the raw anchors out
of the control plane.
