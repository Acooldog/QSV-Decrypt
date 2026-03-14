from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from .runtime_paths import get_log_day_dir


def setup_logging() -> Path:
    day_dir = get_log_day_dir()
    day_dir.mkdir(parents=True, exist_ok=True)
    log_file = day_dir / f"run_{datetime.now().strftime('%H-%M-%S')}.log"

    logger = logging.getLogger("aqy_decrypt")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return log_file
