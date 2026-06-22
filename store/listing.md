# Store listing — Privasys Identity Verifier

Source of truth for the App Store listing of `container-app-identity-verifier`.
Machine-applyable values are in [`listing.json`](listing.json) (keys match the
management-service store fields). Hosted assets live in the websites repo under
`apps/fronts/privasys.org/public/store/identity-verifier/` and are served at
`https://privasys.org/store/identity-verifier/...`.

UK English. No em-dashes. Claims kept to what the app actually does today (see
the app [README](../README.md) status section); roadmap items are labelled.

## Fields

| Field | Value |
| --- | --- |
| `display_name` | Privasys Identity Verifier |
| `store_category` | Security & Privacy |
| `store_tagline` (≤120) | Passport and ID verification in a confidential enclave. Prove your age or one field, never the document. |
| `store_website_url` | https://privasys.org |
| `store_privacy_url` | https://privasys.org/legal/privacy/ |
| `store_tos_url` | https://privasys.org/legal/terms/ |
| `store_support_email` | contact@privasys.org |
| `store_icon_url` | https://privasys.org/store/identity-verifier/icon.svg |
| `store_keywords` | identity verification, KYC, passport, ID, eMRTD, NFC, age verification, age over 18, ICAO 9303, GPG45, selective disclosure, confidential computing, attestation, biometric, liveness, eIDAS |

`store_description` (≤4000) is the long copy in `listing.json`.

## Screenshots / feature panels (16:9, 1600×900)

1. `feature-1-prove.svg` — "Prove it without revealing it" (age over 18 returns
   yes/no, the date of birth stays hidden).
2. `feature-2-on-device.svg` — "Your passport never leaves your device"
   (read on device, checked in memory in the enclave, nothing retained).
3. `feature-3-attested.svg` — "Attested, auditable code" (a relying party
   verifies the signature and the enclave attestation, not an operator).

## Assets

| Asset | File | Notes |
| --- | --- | --- |
| Icon | `icon.svg` | 1024×1024, Privasys gradient (#34E89E→#00BCF2), rounded-square. Export `icon-512.png` / `icon-1024.png` if the store/wallet needs raster (RN remote SVG is awkward). |
| Feature 1–3 | `feature-*.svg` | 1600×900 panels. |

## How to apply

1. Host the assets: copy the files into the websites repo at
   `apps/fronts/privasys.org/public/store/identity-verifier/` and deploy
   privasys.org (the URLs above resolve once it is live).
2. Set the listing on the app record. Either the developer portal
   (App → Store tab) or the management-service store endpoint, e.g.

   ```sh
   # resolve the app id by name, then PATCH the store listing
   privasys apps store set container-app-identity-verifier --from store/listing.json
   ```

   (If no CLI verb exists yet, POST the `listing.json` body to the store-listing
   update handler for the app id; field names already match.)
3. The icon/screenshot URLs only need to be reachable; the store stores URLs,
   not uploaded blobs.

## Notes for the broader work (context, not part of this content task)

- The wallet currently hard-codes the verifier origin + pinned image digest in
  `auth/wallet/src/services/kyc.ts`. Once this app is in the store DB, the wallet
  should resolve `container-app-identity-verifier` by name (latest version +
  enclave details + attested image digest) from a management-service API, instead
  of the hard-coded constants.
- The verifier is a relying-party-style data request: it should reuse the wallet's
  "this app requests access to your data" consent, with the wrinkle that the NFC
  chip read only happens after consent.
