import numpy as np
import pytest

from shildml import artifact, features, infer


def _random_layer_spec(seed=0):
    rng = np.random.default_rng(seed)
    return [
        {"w": rng.normal(size=(64, features.N_FEATURES)).astype("float32"),
         "b": rng.normal(size=64).astype("float32"), "act": "relu"},
        {"w": rng.normal(size=(32, 64)).astype("float32"),
         "b": rng.normal(size=32).astype("float32"), "act": "relu"},
        {"w": rng.normal(size=(len(features.ACTIONS), 32)).astype("float32"),
         "b": rng.normal(size=len(features.ACTIONS)).astype("float32"), "act": None},
    ]


def test_save_load_round_trip(tmp_path):
    path = tmp_path / "model.npz"
    layer_spec = _random_layer_spec()
    artifact.save(path, layer_spec, {"trained_at": "test", "train_rows": 100,
                                      "label_distribution": {"allow": 50, "warn": 30, "ban": 20},
                                      "split_strategy": "group-by-host", "val_metrics": {}})
    loaded_spec, meta = artifact.load(path)
    assert len(loaded_spec) == 3
    assert meta["schema_hash"] == features.schema_hash()
    assert meta["actions"] == features.ACTIONS
    np.testing.assert_allclose(loaded_spec[0]["w"], layer_spec[0]["w"])


def test_schema_mismatch_rejected(tmp_path, monkeypatch):
    path = tmp_path / "model.npz"
    artifact.save(path, _random_layer_spec(), {"trained_at": "t", "train_rows": 1,
                                                "label_distribution": {}, "split_strategy": "x",
                                                "val_metrics": {}})
    # Simulate features.py having changed since training.
    monkeypatch.setattr(features, "schema_hash", lambda: "deadbeef" * 8)
    with pytest.raises(artifact.SchemaMismatch):
        artifact.load(path, strict=True)


def test_classifier_falls_back_to_unavailable_on_mismatch(tmp_path, monkeypatch):
    path = tmp_path / "model.npz"
    artifact.save(path, _random_layer_spec(), {"trained_at": "t", "train_rows": 1,
                                                "label_distribution": {}, "split_strategy": "x",
                                                "val_metrics": {}})
    monkeypatch.setattr(features, "schema_hash", lambda: "deadbeef" * 8)
    clf = infer.Classifier(path)
    assert not clf.available
    assert "schema_hash" in clf.last_error
    # Must still return a safe default, never raise.
    pred = clf.predict("nick", "~i", "1.2.3.4")
    assert pred.action == "allow"
    assert pred.confidence == 0.0


def test_classifier_missing_file_is_unavailable(tmp_path):
    clf = infer.Classifier(tmp_path / "does_not_exist.npz")
    assert not clf.available
    pred = clf.predict("nick", "~i", "1.2.3.4")
    assert pred.action == "allow"


def test_classifier_hot_reload_on_mtime_change(tmp_path):
    path = tmp_path / "model.npz"
    artifact.save(path, _random_layer_spec(seed=1), {"trained_at": "t1", "train_rows": 1,
                                                       "label_distribution": {}, "split_strategy": "x",
                                                       "val_metrics": {}})
    clf = infer.Classifier(path)
    assert clf.available
    first_pred = clf.predict("nick", "~i", "1.2.3.4")

    import time
    time.sleep(0.01)
    artifact.save(path, _random_layer_spec(seed=99), {"trained_at": "t2", "train_rows": 1,
                                                        "label_distribution": {}, "split_strategy": "x",
                                                        "val_metrics": {}})
    reloaded = clf.reload()
    assert reloaded is True
    second_pred = clf.predict("nick", "~i", "1.2.3.4")
    # Different random weights should (overwhelmingly likely) give a
    # different probability distribution.
    assert first_pred.probs != second_pred.probs
