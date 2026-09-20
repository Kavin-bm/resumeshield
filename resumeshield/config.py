"""Configuration and policy definition for ResumeShield."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from resumeshield.models import Severity


@dataclass
class ShieldConfig:
    """Tunable thresholds, risk policies, and custom rule configurations."""

    malicious_score: int = 60
    suspicious_score: int = 15
    tiny_font_pt: float = 4.0
    min_luminance_gap: float = 0.12
    min_divergent_words: int = 8
    material_delta: int = 15
    disabled_detectors: list[str] = field(default_factory=list)
    custom_patterns: list[dict[str, Any]] = field(default_factory=list)
    enable_differential: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ShieldConfig:
        fields = {k for k in cls.__dataclass_fields__ if k != "extra"}
        init_kwargs = {}
        extra = {}

        for k, v in data.items():
            if k in fields:
                init_kwargs[k] = v
            else:
                extra[k] = v

        if extra:
            init_kwargs["extra"] = extra
        return cls(**init_kwargs)

    @classmethod
    def from_file(cls, path: str | Path) -> ShieldConfig:
        """Load configuration from a JSON or YAML file."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Config file not found: {file_path}")

        content = file_path.read_text(encoding="utf-8")
        if file_path.suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore[import-untyped]
                data = yaml.safe_load(content) or {}
            except ImportError:
                # Fallback if PyYAML is not installed: try basic JSON parsing
                try:
                    data = json.loads(content)
                except json.JSONDecodeError as err:
                    raise ImportError("PyYAML is required to parse YAML config files. Run 'uv add pyyaml'.") from err
        else:
            data = json.loads(content)

        return cls.from_dict(data)

    @classmethod
    def from_env(cls) -> ShieldConfig:
        """Load settings from environment variables."""
        cfg = cls()
        if "RESUMESHIELD_MALICIOUS_SCORE" in os.environ:
            cfg.malicious_score = int(os.environ["RESUMESHIELD_MALICIOUS_SCORE"])
        if "RESUMESHIELD_SUSPICIOUS_SCORE" in os.environ:
            cfg.suspicious_score = int(os.environ["RESUMESHIELD_SUSPICIOUS_SCORE"])
        if "RESUMESHIELD_TINY_FONT_PT" in os.environ:
            cfg.tiny_font_pt = float(os.environ["RESUMESHIELD_TINY_FONT_PT"])
        if "RESUMESHIELD_DISABLED_DETECTORS" in os.environ:
            cfg.disabled_detectors = [
                d.strip() for d in os.environ["RESUMESHIELD_DISABLED_DETECTORS"].split(",") if d.strip()
            ]
        if "RESUMESHIELD_ENABLE_DIFFERENTIAL" in os.environ:
            cfg.enable_differential = os.environ["RESUMESHIELD_ENABLE_DIFFERENTIAL"].lower() in ("true", "1", "yes")
        return cfg

    def add_custom_pattern(
        self, pattern: str, severity: Severity = Severity.HIGH, message: str = "Custom injection pattern"
    ) -> None:
        self.custom_patterns.append({
            "pattern": pattern,
            "severity": str(severity),
            "message": message,
        })

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
