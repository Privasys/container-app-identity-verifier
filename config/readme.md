# Configuring the Identity Verifier

The verifier boots **frozen**. Until its CSCA trust anchors are loaded, every
endpoint except `/health`, `/version`, `/.well-known/jwks.json` and `/configure`
returns `503 "app is awaiting initial configuration"`. Configuration loads the
Country Signing CA (CSCA) certificates that Passive Authentication chains each
passport's Document Signer Certificate to.

Anchors are accepted **only** as the **ICAO CSCA Master List** (a CMS `.ml`, ICAO
Doc 9303 Part 12). The enclave validates the list's CMS signature and that it
chains to the **pinned ICAO/UN CSCA root** before extracting the CSCAs. There is
no raw-PEM or arbitrary-anchor path: a list that does not chain to the genuine
ICAO root is rejected. This is the root of trust for the whole verification, so
it is enforced in the enclave, not trusted from whoever supplies the file.

`config/initialise.sh` does it end to end: base64-encode the master list, send it
to `/configure` over RA-TLS with the Privasys CLI.

## Prerequisites

- The app is **deployed** on the Privasys platform (it has a gateway hostname).
- The **`privasys` CLI** is installed and authenticated as an **owner** of the
  app: `privasys auth login`.
- The **ICAO CSCA Master List** (see *Sourcing* below). It includes the CSCAs of
  the ICAO member states, so it covers any issuing country you verify.

## Configure it

```sh
config/initialise.sh --ml ICAO_ML_YYYYMMDD.ml

# Download the list as part of the run:
config/initialise.sh --url https://example.org/path/to/ICAO_ML.ml

# Target a non-default environment (the CLI default endpoint is often prod) and
# verify the quote too:
config/initialise.sh --ml ICAO_ML.ml --endpoint https://api-test.developer.privasys.org --attest
```

If your CLI is pointed at a different platform than the one the verifier runs on,
`apps call` resolves the app on the wrong environment and reports "no app named
…". Pass `--endpoint` (or set it with `privasys config set endpoint <url>`).

A successful run prints:

```json
{"status":"configured","trust_anchors_digest":"892611a7…"}
```

`trust_anchors_digest` is the SHA-256 of the active anchor set, also published as
attestation extension OID `1.3.6.1.4.1.65230.2.8`, so a relying party can pin
which anchors were in force from the RA-TLS certificate. The anchors persist on
the app's per-app sealed volume, so a later redeploy onto the same volume comes
back **already configured**. You only re-run this:

- the first time the app is provisioned, or
- after the data volume is wiped / re-created, or
- to rotate to a newer master list (the `.ml` is reissued ~quarterly). Rotation
  uses the same verified path (`POST /trust-anchors` with `master_list_cms`).

## Sourcing the master list

The master list is not in this repo and must be sourced. Use the **ICAO PKD CSCA
Master List** (the authoritative consolidated list, a CMS `SignedData` signed by
the ICAO Master List Signer, which chains to the ICAO/UN CSCA root). Hand the raw
`.ml` to `--ml`; the enclave does the rest.

A national master list works only if it chains to the same pinned ICAO/UN CSCA
root. A bare PEM bundle of CSCA roots is **not** accepted (it carries no ICAO
signature to verify). Treat the master list as security-critical and source it
deliberately.

## What the script does (and the manual equivalent)

The script base64-encodes the `.ml` into `{"master_list_cms": "<b64>"}` and runs:

```sh
privasys apps call <app> configure --data @<body.json> --no-challenge
```

`apps call` connects to the app's enclave over RA-TLS, verifies its attestation,
and sends the request directly: the control plane is never in the data path.
`--no-challenge` is needed because the bundled CLI does deterministic verification
(the fresh-nonce challenge requires the Privasys/go RA-TLS fork). Add `--attest`
to also verify the quote (genuine TEE + TCB) against the attestation server.

The equivalent control-plane path is `POST /api/v1/apps/<app-id>/rpc/configure`
with the same body, but the direct RA-TLS call above keeps the raw list out of
the control plane.
