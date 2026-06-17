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
