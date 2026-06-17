# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

import pytest

from verifier import biometrics, config
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
    # No models + no dev stub → must fail closed (never silently pass).
    monkeypatch.setattr(config, "ALLOW_DEV_STUB", False)
    monkeypatch.setattr(biometrics, "_models_available", lambda: False)
    with pytest.raises(BiometricError):
        biometrics.match(b"dg2", b"live")


def test_match_dev_stub(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_DEV_STUB", True)
    monkeypatch.setattr(biometrics, "_models_available", lambda: False)
    res = biometrics.match(b"dg2", b"live")
    assert res.face_match is True and res.liveness_score > 0.9
