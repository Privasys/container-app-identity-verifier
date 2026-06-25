# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""CSCA Master List ingestion: the signer must chain to the *pinned* ICAO/UN
CSCA root, not merely to any self-signed certificate carried in the list."""

import hashlib

import pytest

import fixtures
from verifier import master_list


def _csca(cn="Test Country CSCA"):
    _key, cert = fixtures.self_signed_ca(cn)
    return cert


def test_pinned_root_accepted_and_cscas_extracted():
    root_key, root = fixtures.self_signed_ca("Test Root CSCA")
    root_sha = hashlib.sha256(fixtures.cert_der(root)).hexdigest()
    ml = fixtures.build_master_list(root_key, root, root.subject, [_csca(), _csca("Test Country B")])

    pem = master_list.verify_and_extract(ml, expected_root_sha256=root_sha)
    assert pem.count(b"BEGIN CERTIFICATE") == 2


def test_unpinned_root_rejected_by_default_icao_pin():
    # A self-consistent list whose root is NOT the genuine ICAO/UN CSCA must be
    # rejected under the default pin (the real ICAO root). This is the forgery
    # the pin exists to stop.
    root_key, root = fixtures.self_signed_ca("Attacker Root CSCA")
    ml = fixtures.build_master_list(root_key, root, root.subject, [_csca()])
    with pytest.raises(master_list.MasterListError):
        master_list.verify_and_extract(ml)  # default expected_root_sha256 = ICAO root


def test_wrong_pin_rejected():
    root_key, root = fixtures.self_signed_ca("Test Root CSCA")
    ml = fixtures.build_master_list(root_key, root, root.subject, [_csca()])
    with pytest.raises(master_list.MasterListError):
        master_list.verify_and_extract(ml, expected_root_sha256="00" * 32)


def test_tampered_content_rejected():
    root_key, root = fixtures.self_signed_ca("Test Root CSCA")
    root_sha = hashlib.sha256(fixtures.cert_der(root)).hexdigest()
    ml = bytearray(fixtures.build_master_list(root_key, root, root.subject, [_csca()]))
    ml[len(ml) // 2] ^= 0xFF
    with pytest.raises(master_list.MasterListError):
        master_list.verify_and_extract(bytes(ml), expected_root_sha256=root_sha)
