"""
Configuration loader for CryptoAnalyzer.

Loads settings (disabled_rules, exclude_patterns, etc.) from:
  - explicit path via --config, or
  - one of: .cryptoanalyzer.toml, cryptoanalyzer.toml,
            .cryptoanalyzer.yaml/yml, cryptoanalyzer.yaml/yml,
            pyproject.toml ([tool.cryptoanalyzer]),
            setup.cfg ([tool:cryptoanalyzer] or [cryptoanalyzer]).
"""

import os
import toml
import configparser
from typing import List, Dict, Any
from dataclasses import dataclass, field

# Ordered search paths
_CONFIG_FILES = [
    ".cryptoanalyzer.toml",
    "cryptoanalyzer.toml",
    ".cryptoanalyzer.yaml", ".cryptoanalyzer.yml",
    "cryptoanalyzer.yaml", "cryptoanalyzer.yml",
    "pyproject.toml",
    "setup.cfg",
]


@dataclass
class Config:
    disabled_rules: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    severity_overrides: Dict[str, str] = field(default_factory=dict)
    suppressions: Dict[str, List[int]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str = None) -> "Config":
        cfg_path = path or cls._find_config_file(os.getcwd())
        if not cfg_path:
            return cls()
        ext = os.path.splitext(cfg_path)[1].lower()
        if ext == ".toml":
            raw = toml.load(cfg_path)
            cfg = raw.get("tool", {}).get("cryptoanalyzer", raw)
        elif ext in (".yaml", ".yml"):
            import yaml  # noqa: F401
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        elif os.path.basename(cfg_path) == "setup.cfg":
            parser = configparser.ConfigParser()
            parser.read(cfg_path)
            if parser.has_section("tool:cryptoanalyzer"):
                cfg = dict(parser.items("tool:cryptoanalyzer"))
            elif parser.has_section("cryptoanalyzer"):
                cfg = dict(parser.items("cryptoanalyzer"))
            else:
                cfg = {}
        else:
            cfg = {}
        return cls._from_dict(cfg)

    @staticmethod
    def _find_config_file(start_dir: str) -> str:
        for fname in _CONFIG_FILES:
            candidate = os.path.join(start_dir, fname)
            if os.path.isfile(candidate):
                return candidate
        return ""

    @staticmethod
    def _ensure_list(val: Any) -> List[Any]:
        if val is None:
            return []
        if isinstance(val, list):
            return val
        return [v.strip() for v in str(val).split(",") if v.strip()]

    @classmethod
    def _from_dict(cls, raw: Dict[str, Any]) -> "Config":
        def get(key, default=None):
            for k in raw:
                if k.lower() == key.lower():
                    return raw[k]
            return default

        disabled = cls._ensure_list(get("disabled_rules", get("disable_rules", [])))
        exclude = cls._ensure_list(get("exclude_patterns", get("exclude", [])))
        severity = get("severity_overrides", get("severity", {})) or {}
        suppress = get("suppressions", get("suppress", {})) or {}

        if isinstance(suppress, list):
            suppress = {"global": suppress}

        return cls(
            disabled_rules=[str(r) for r in disabled],
            exclude_patterns=[str(p) for p in exclude],
            severity_overrides={str(k): str(v) for k, v in severity.items()},
            suppressions={
                str(k): [int(x) for x in v] if isinstance(v, list) else []
                for k, v in suppress.items()
            },
        )
