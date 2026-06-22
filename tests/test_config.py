"""Tests for configuration loading and rule filtering."""

import textwrap

from cryptoanalyzer.config import Config


def test_default_config_is_empty():
    config = Config()
    assert config.disabled_rules == []
    assert config.exclude_patterns == []


def test_load_toml_config(tmp_path):
    cfg_file = tmp_path / "cryptoanalyzer.toml"
    cfg_file.write_text(
        textwrap.dedent(
            """
            disabled_rules = ["CWE328WeakHash"]
            exclude_patterns = ["**/tests/**"]
            """
        ).strip()
    )
    config = Config.load(str(cfg_file))
    assert "CWE328WeakHash" in config.disabled_rules
    assert "**/tests/**" in config.exclude_patterns


def test_ensure_list_splits_comma_separated_string():
    # A comma-separated string should normalise into a clean list.
    assert Config._ensure_list("a, b ,c") == ["a", "b", "c"]
    assert Config._ensure_list(None) == []
