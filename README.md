# Privasys Identity Verifier (container app)

A confidential (TDX) **enclave-os-virtual** container app that verifies a
passport/national-ID + a live biometric and issues **consented, gov-certified**
attribute disclosures — without the raw document or biometric ever leaving the
user's wallet, and without trusting the user's device.

> Full design: [`.operations/identity-platform/kyc-enclave-design.md`](https://github.com/Privasys) (Privasys ops).
> This is Phase 2 of the wallet improvement plan.

## Why this exists

On-device verifiers (e.g. the EU age-verification wallet) do passport + biometric
checks **on the phone** — which a modified/rooted device can circumvent. This app
runs the same checks **inside an attested enclave**: a relying party verifies the
enclave's RA-TLS attestation, so a tampered device cannot forge a `gov`-assurance
result. Raw data stays on the wallet; only minimal, signed claims are disclosed.

## Model: receipt-based (commit-and-prove)

1. **`verify_identity`** (heavy, once) — the wallet sends the eMRTD data groups
   (DG1/DG2/SOD) + a live biometric over RA-TLS. The enclave runs ICAO 9303
   Passive + Chip Authentication and a DG2↔live face match + liveness, then
   returns a **signed Identity Verification Receipt (IVR)**: per-field SHA-256
   **commitments** + validity + holder binding. Raw inputs are processed in
   memory and **discarded**; the wallet keeps the field values + salts and
   auto-fills its profile with the document's fields as `gov`-assurance.
2. **Derivations** (cheap, many, one consented disclosure each) —
   `prove_age_over`, `prove_age_band`, `prove_field`, `prove_document_valid`
   take the IVR + only the one value being proven, re-open its commitment, and
   return a short-lived, audience-bound, enclave-signed **disclosure token**
   (e.g. "passport-certified proof of 18+"). Each requires a holder-signed
   request (consented in the wallet).

A relying party verifies a disclosure token against the published verifier key
(`/.well-known/jwks.json`) **and** the enclave's attestation.

## API (HTTP on `:8080`; the enclave terminates RA-TLS in front)

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health`, `/version` | liveness / deployed version |
| GET | `/.well-known/jwks.json` | verifier public key (verify tokens) |
| POST | `/configure` | provision CSCA trust anchors; lift configure-then-freeze |
| POST | `/verify-identity` | → `{ivr, salts, fields}` |
| POST | `/prove/age-over` | → `{token}` (age_over_N) |
| POST | `/prove/age-band` | → `{token}` (age band) |
| POST | `/prove/field` | → `{token}` (one certified field) |
| POST | `/prove/document-valid` | → `{token}` (no attribute disclosed) |
| GET/POST | `/trust-anchors` | read / update the CSCA master list (owner-gated) |

See [`privasys.json`](privasys.json) for the tool schemas.

## Trust anchors (runtime-updatable, attested via OID)

The CSCA / ICAO master list is **not** baked into the measured image (it changes
constantly). It lives on the per-app sealed volume and is settable via
`/trust-anchors`; the active set's SHA-256 is published as the **Identity Trust
Anchors OID** (`1.3.6.1.4.1.65230.2.8`) through the manager's
attestation-extensions endpoint, so relying parties pin "which trust anchors were
in force" via the RA-TLS leaf — the direct analogue of the egress CA-root hash
(`…65230.2.1`).

## Status & open-source components

The crypto core (IVR, commitments, disclosure tokens, holder binding, the
trust-anchor OID flow, configure-then-freeze) is implemented and tested. The
heavy verifiers are **stubbed** behind `verifier/verification.py` (gated by
`IDENTITY_VERIFIER_DEV_STUB=1` for dev/test) and to be wired with permissive
open-source / no-licence-fee components:

- **eMRTD read** (wallet side): jMRTD + scuba (Android), NFCPassportReader (iOS).
- **Passive/Chip Auth**: Rust/Python CMS + x509 (refs: pymrtd, Rust `emrtd`).
- **DG2 decode**: jnbis (JPEG2000/WSQ) **+ ISO 39794-5** (new, ICAO Doc 9303 2026).
- **Face match**: AuraFace (open ArcFace, commercial-OK) / FaceNet-512 (MIT), ONNX.
- **Liveness**: Silent-Face / MiniFASNetV2 (Apache-2.0) + active challenge.

All run **in-enclave with no external calls**. iBeta liveness certification is a
later funded milestone; the model is swappable behind the same API.

## Develop & test

```sh
pip install -r requirements.txt pytest
python -m pytest -q

# run locally (dev stub accepts pre-parsed fields, no real passport):
IDENTITY_VERIFIER_DEV_STUB=1 python main.py
```

## Build & deploy

Push a `v*` tag → CI builds `ghcr.io/privasys/container-app-identity-verifier`
(linux/amd64) and deploys via the platform CLI like any container app. The
signing key must be **vault-provisioned and measurement-bound** in production
(see the design doc §4); the dev key is ephemeral.

## Licence

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
