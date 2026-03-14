from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path


def get_runtime_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def get_assets_dir() -> Path:
    return get_runtime_dir() / "assets"


def get_default_input_root() -> Path:
    return Path(r"O:\qycache\download")


def get_default_output_root() -> Path:
    return get_runtime_dir() / "output"


def get_log_day_dir(now: datetime | None = None) -> Path:
    now = now or datetime.now()
    return get_runtime_dir() / "_log" / f"{now.year}-{now.month}-{now.day}"

