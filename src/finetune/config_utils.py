from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


FINETUNE_ROOT = Path(__file__).resolve().parent
CONFIGS_ROOT = FINETUNE_ROOT / "configs"


def load_phase_config(config_name: str) -> dict[str, Any]:
    config_path = CONFIGS_ROOT / config_name
    if not config_path.exists():
        raise FileNotFoundError(f"Missing config file: {config_path}")

    with config_path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    if not isinstance(config, dict):
        raise ValueError(f"Config file must contain a mapping: {config_path}")

    config["config_path"] = str(config_path)
    return config


def resolve_path(value: str | None) -> str | None:
    if not value:
        return value

    candidate = Path(value)
    if candidate.is_absolute():
        return str(candidate)
    return str((FINETUNE_ROOT / candidate).resolve())


def resolve_paths(values: list[str]) -> list[str]:
    return [resolve_path(value) for value in values if value]