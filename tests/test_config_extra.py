"""Additional tests for config branch coverage."""

from pathlib import Path

from shipguard.config import find_config, load_config


def test_find_config_returns_first_existing_file(tmp_path):
    cfg = tmp_path / ".shipguard.yml"
    cfg.write_text("severity_threshold: high\n")
    found = find_config(tmp_path)
    assert found == cfg


def test_load_config_reads_yaml_values(tmp_path):
    cfg = tmp_path / ".shipguard.yml"
    cfg.write_text("severity_threshold: critical\nuse_rust_secrets: true\n")
    loaded = load_config(config_path=cfg)
    assert loaded.severity_threshold == "critical"
    assert loaded.use_rust_secrets is True


def test_load_config_falls_back_to_defaults_for_missing_file(tmp_path):
    loaded = load_config(config_path=tmp_path / "missing.yml")
    assert loaded.severity_threshold == "medium"


def test_load_config_rejects_invalid_severity_threshold(tmp_path):
    """Literal type enforcement: invalid severity values fail at config load, not deep in engine."""
    cfg = tmp_path / ".shipguard.yml"
    cfg.write_text("severity_threshold: banana\n")
    import pytest
    with pytest.raises(ValueError, match="Invalid ShipGuard config"):
        load_config(config_path=cfg)


def test_load_config_raises_value_error_for_invalid_field_type(tmp_path):
    """Type errors in config produce a clear ValueError, not a cryptic Pydantic crash."""
    cfg = tmp_path / ".shipguard.yml"
    # exclude_paths expects list[str], not a plain string
    cfg.write_text("exclude_paths:\n  key: value\n")
    import pytest
    with pytest.raises(ValueError, match="Invalid ShipGuard config"):
        load_config(config_path=cfg)
