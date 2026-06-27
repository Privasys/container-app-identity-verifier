# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

import pytest

from verifier import biometrics
from verifier.biometrics import BiometricError


def test_cosine_distance_and_match():
    a = [1.0, 0.0, 0.0]
    assert biometrics.cosine_distance(a, a) == pytest.approx(0.0)
    assert biometrics.cosine_distance([1.0, 0.0], [0.0, 1.0]) == pytest.approx(1.0)
    assert biometrics.is_match(0.1)
    assert not biometrics.is_match(0.9)


def test_cosine_distance_validates_input():
    with pytest.raises(BiometricError):
        biometrics.cosine_distance([1.0], [1.0, 2.0])
    with pytest.raises(BiometricError):
        biometrics.cosine_distance([0.0, 0.0], [1.0, 1.0])


def test_liveness_threshold():
    assert biometrics.is_live(0.95)
    assert not biometrics.is_live(0.5)


def test_match_fails_closed_without_models(monkeypatch):
    # No models + stub off (the production default) → must fail closed, never
    # silently pass. This is what stops a deployed enclave accepting any face.
    monkeypatch.setattr(biometrics, "_ALLOW_TEST_STUB", False)
    monkeypatch.setattr(biometrics, "_models_available", lambda: False)
    with pytest.raises(BiometricError):
        biometrics.match(b"dg2", b"live")


def test_match_test_stub(monkeypatch):
    # The stub is test-only (a module flag, not env/config) so CI can exercise
    # the plumbing without model artifacts.
    monkeypatch.setattr(biometrics, "_ALLOW_TEST_STUB", True)
    monkeypatch.setattr(biometrics, "_models_available", lambda: False)
    res = biometrics.match(b"dg2", b"live")
    assert res.face_match is True and res.liveness_score > 0.9
