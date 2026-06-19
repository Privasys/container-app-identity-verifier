# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

import pytest

import fixtures
from verifier import mrz


def test_parse_dg1_td3():
    fields = mrz.parse_dg1(fixtures.build_dg1())
    assert fields == fixtures.SAMPLE_FIELDS


def test_parse_dg1_rejects_non_td3():
    bad = fixtures.build_dg1("P<GBRTOO<SHORT")
    with pytest.raises(mrz.MRZError):
        mrz.parse_dg1(bad)


def test_parse_dg1_rejects_garbage():
    with pytest.raises(mrz.MRZError):
        mrz.parse_dg1(b"\x00\x01\x02")


# ── mrz_access_fields: BAC-key extraction + OCR-B confusable correction ──────
#
# Fictional test data only (ICAO Doc 9303 SPECIMEN "Utopia"; synthetic document
# numbers). NEVER put a real document number / name / date of birth here — this
# repository is public.

_L1 = ("P<UTOSPECIMEN<<TEST" + "<" * 44)[:44]


def _make_l2(doc: str, nat: str, dob: str, sex: str, exp: str) -> str:
    """Build a valid TD3 line 2 with correct field + composite check digits."""
    cd = mrz._check_digit
    doc9 = (doc + "<<<<<<<<<")[:9]
    opt = "<" * 14
    body = doc9 + cd(doc9) + nat + dob + cd(dob) + sex + exp + cd(exp) + opt + cd(opt)
    return body + cd(body[0:10] + body[13:20] + body[21:43])


def test_access_fields_clean():
    l2 = _make_l2("L898902C3", "UTO", "740812", "F", "120415")
    assert mrz.mrz_access_fields(_L1 + l2) == {
        "document_number": "L898902C3", "date_of_birth": "740812", "date_of_expiry": "120415"}


def test_access_fields_corrects_i_misread_as_1():
    # The document number contains an 'I' the OCR renders as '1'; the ICAO check
    # digit must recover the true value (a wrong guess yields a chip-rejecting key).
    l2 = _make_l2("9IK045123", "UTO", "900101", "M", "300101")
    misread = l2.replace("9IK", "91K", 1)
    f = mrz.mrz_access_fields(_L1 + misread)
    assert f["document_number"] == "9IK045123"
    assert f["date_of_birth"] == "900101"
    assert f["date_of_expiry"] == "300101"


def test_access_fields_rejects_unrecoverable():
    with pytest.raises(mrz.MRZError):
        mrz.mrz_access_fields(_L1 + ("X" * 44))


def test_access_fields_requires_td3_length():
    with pytest.raises(mrz.MRZError):
        mrz.mrz_access_fields("P<SHORT")
