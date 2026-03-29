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


def get_default_cache_root() -> Path:
    return Path(r"O:\qycache\temp_cache")


def get_default_qtplog_root() -> Path:
    return Path(r"C:\Users\01080\AppData\Roaming\IQIYI Video\LStyle\qtplog\ppslog")


def get_default_localwebapp_cache_root() -> Path:
    return Path(r"C:\Users\01080\AppData\Roaming\IQIYI Video\localwebapp\cache")


def get_default_cube_log_paths() -> list[Path]:
    root = Path(r"C:\Users\01080\AppData\Roaming\IQIYI Video\LStyle")
    return [
        root / "cube.log",
        root / "cube_old.log",
    ]


def get_default_download_metadata_db_path() -> Path:
    return Path(r"C:\Users\01080\AppData\Roaming\IQIYI Video\LStyle\PPSDownLoad.db")


def get_default_qyclient_paths() -> list[Path]:
    return [
        Path(r"C:\Program Files\Common Files\IQIYI Video\LStyle\QyClient.exe"),
        Path(r"C:\Program Files\IQIYI Video\LStyle\QyClient.exe"),
    ]


def get_log_day_dir(now: datetime | None = None) -> Path:
    now = now or datetime.now()
    return get_runtime_dir() / "_log" / f"{now.year}-{now.month}-{now.day}"
