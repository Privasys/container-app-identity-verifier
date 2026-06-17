# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Privasys Identity Verifier enclave app.

A confidential-computing container app that verifies a passport/ID + biometric
and issues consented, government-certified disclosures. Runs inside a TEE
(TEE-agnostic image). See the design at
.operations/identity-platform/kyc-enclave-design.md.
"""

__version__ = "0.1.0"
