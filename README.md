# Privasys Identity Verifier

A confidential-computing container app that verifies an ICAO 9303 electronic
travel document (passport / national ID) and a live face capture, and issues
short-lived, signed claims about the holder — **age over N, age band, or a single
certified field** — without retaining the raw document or biometric.

It is a plain Docker container (HTTP on `$PORT`, `8080` fallback) meant to run
inside a Trusted Execution Environment with RA-TLS terminated in front; it is
**not tied to a specific TEE** (it deploys on Privasys enclave-os-virtual, but the
image is TEE-agnostic). A relying party trusts a claim by verifying the app's
signature (`/.well-known/jwks.json`) together with the enclave's attestation.

Assurance target: **GPG45 / UK DVS Medium Level of Confidence (M1C)** — chip
genuineness (Passive Authentication), live-face ↔ chip-photo match, and a
document data cross-reference.

## What it does

1. **`POST /read-mrz`** *(pre-NFC, optional)* — the client photographs the data
   page and sends the image; the app OCRs the machine-readable zone **in the
   enclave** (PaddleOCR) and returns the BAC/PACE access-key fields (document
   number + birth/expiry dates), each recovered against its ICAO check digit so
   OCR-B look-alikes (`I`/`1`, `O`/`0`, …) can't yield a chip-rejecting key. The
   client uses this to unlock the chip — far more reliable than on-device OCR.

2. **`POST /verify-identity`** — given the eMRTD data groups (DG1, DG2, DG11,
   EF.SOD), the app:
   - runs **Passive Authentication** (verifies EF.SOD's CMS signature, chains the
     Document Signer Certificate to a trusted CSCA, checks that the DSC + CSCA
     were valid at the SOD signing time, and checks every data-group hash);
   - extracts the holder fields from the DG1 MRZ (+ DG11 place of birth / personal
     number), and **rejects an expired document**;
   - matches the DG2 portrait against the live capture and scores liveness;
   - cross-references the data-page image (the same enclave OCR) against the chip
     (GPG45 box 3, recorded as a fraud signal at M1C);
   - returns a signed **Identity Verification Receipt (IVR)**: per-field SHA-256
     commitments (with random salts) + the validity results + a binding to the
     holder's key. The raw inputs are processed in memory and discarded.

3. **`POST /prove/...`** — given an IVR and only the single value being proven,
   the app re-checks that value against the IVR's commitment and returns a
   short-lived, audience-bound signed token:
   - `/prove/age-over` → `age_over_N` (true/false), no birth date revealed
   - `/prove/age-band` → an age band (e.g. `18-20`)
   - `/prove/field` → one certified field (e.g. `family_name`)
   - `/prove/document-valid` → "a genuine document was verified", no attribute
   Each requires a signature from the holder key the IVR is bound to.

This split means the document is read and authenticated once; subsequent claims
are cheap, minimal, and never re-expose the whole identity.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health`, `/version` | liveness / deployed version |
| `GET` | `/.well-known/jwks.json` | signing public key (ES256) |
| `POST` | `/configure` | load CSCA trust anchors (ICAO master list or PEM); lift the startup freeze |
| `POST` | `/read-mrz` | → `{ document_number, date_of_birth, date_of_expiry }` (chip access key) |
| `POST` | `/verify-identity` | → `{ ivr, salts, fields, viz_match }` |
| `POST` | `/prove/age-over`, `/prove/age-band`, `/prove/field`, `/prove/document-valid` | → `{ token }` |
| `GET`/`POST` | `/trust-anchors` | read / replace the CSCA master list |

Tool schemas: [`privasys.json`](privasys.json). The app boots **frozen** (503 on
every path but `/health`, `/version`, `/.well-known/jwks.json`, `/configure`)
until trust anchors are loaded.

## Trust anchors

The CSCA / ICAO master list used for Passive Authentication is **not** built into
the image. Load it at runtime via `/configure` — either a raw ICAO CSCA Master
List (`{"master_list_cms": "<base64 .ml>"}`, whose CMS signature + signer chain
the app validates before extracting the CSCAs) or a ready PEM bundle
(`{"trust_anchors_pem": "<PEM>"}`). It is persisted on the per-app encrypted
volume. The SHA-256 of the active set is published as an attestation extension
(OID `1.3.6.1.4.1.65230.2.8`), so a relying party can pin which trust anchors were
in force from the RA-TLS certificate. Updating the list changes that OID; no image
rebuild.

## Libraries

| Area | Library | Licence |
| --- | --- | --- |
| HTTP server | Python standard library | PSF |
| Signing / X.509 / ECDSA | `cryptography` (pyca) | Apache-2.0 / BSD |
| ASN.1 / CMS (EF.SOD, certs) | `asn1crypto` | MIT |
| Face detect + recognise | OpenCV **YuNet** + **SFace** (bundled ONNX) | MIT / Apache-2.0 |
| Liveness (optional) | MiniFASNetV2 (Silent-Face) | Apache-2.0 |
| MRZ OCR | **PaddleOCR** (det + rec; document pre-stages off) | Apache-2.0 |
| Image decode (DG2 incl. JPEG2000) | OpenCV (`opencv-contrib-python`) | Apache-2.0 / BSD |

All processing is in-process; the app makes **no outbound network calls** with
document or biometric data. Model files (YuNet/SFace ONNX, PaddleOCR det/rec) are
checksum-pinned / baked at build time, so the runtime needs no egress.

## Keys

The ES256 signing key is **generated inside the enclave** on first start and
sealed to the Enclave Vault; the vault re-releases it only to an instance
presenting the same approved measurement, so receipts and tokens remain
verifiable across restarts and (owner-approved) upgrades. In development the key
is ephemeral.

## Run, test, build

```sh
pip install -r requirements.txt pytest
python -m pytest -q
python main.py                      # serves on $PORT (8080 fallback)
```

Push a `v*` tag → CI builds `ghcr.io/privasys/container-app-identity-verifier`
(linux/amd64) for deployment as a confidential container. The build bakes the
PaddleOCR and face models and **fails if the OCR stack can't initialise**, so a
broken reader can never ship.

## Status

- **Implemented + tested (30 tests):** the receipt/disclosure crypto (ES256,
  commitments, holder binding, all `prove_*` tokens); **Passive Authentication**
  (EF.SOD CMS + DSC→CSCA chain + per-DG hash integrity); **DG1 MRZ** + DG11 field
  extraction; **enclave MRZ OCR** (PaddleOCR) with ICAO check-digit recovery of
  OCR-B look-alikes; the runtime trust-anchor → OID flow (incl. ICAO master-list
  ingestion); configure-then-freeze; and JWKS.
- **Wired, model-provisioned:** face match (YuNet + SFace) + liveness — runs when
  the models are present, else a dev stub in CI.
- **GPG45 M1C:** box 1 (chip Passive Auth) ✓, box 2 (live face ↔ DG2) ✓, box 3
  (visual ↔ chip cross-reference, recorded as a fraud signal — not a hard fail at
  M1C) ✓.
- **TODO (hardening):** Active/Chip Authentication (anti-clone); ISO 39794-5 DG2
  decode; active-challenge liveness for an iBeta-certified PAD; binding the signing
  key to the vault in production.

## Licence

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).
