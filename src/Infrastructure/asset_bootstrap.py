from __future__ import annotations

import shutil
from pathlib import Path

from .runtime_paths import get_assets_dir


class AssetBootstrap:
    def __init__(self) -> None:
        self.assets_dir = get_assets_dir()

    def ensure_ffmpeg_assets(self) -> None:
        self.assets_dir.mkdir(parents=True, exist_ok=True)
        ffmpeg_target = self.assets_dir / "ffmpeg.exe"
        ffprobe_target = self.assets_dir / "ffprobe.exe"
        if ffmpeg_target.exists() and ffprobe_target.exists():
            return

        candidates = [
            (
                Path(r"O:\A_python\A_QKKd\assets\ffmpeg-win-x86_64-v7.1.exe"),
                Path(r"M:\ffmpeg-6.0-full_build\ffmpeg-6.0-full_build\bin\ffprobe.exe"),
            ),
            (
                Path(r"O:\A_python\A_kudog\assets\ffmpeg-win-x86_64-v7.1.exe"),
                Path(r"M:\ffmpeg-6.0-full_build\ffmpeg-6.0-full_build\bin\ffprobe.exe"),
            ),
            (
                Path(r"M:\ffmpeg-6.0-full_build\ffmpeg-6.0-full_build\bin\ffmpeg.exe"),
                Path(r"M:\ffmpeg-6.0-full_build\ffmpeg-6.0-full_build\bin\ffprobe.exe"),
            ),
        ]
        for ffmpeg_source, ffprobe_source in candidates:
            if ffmpeg_source.exists() and ffprobe_source.exists():
                shutil.copy2(ffmpeg_source, ffmpeg_target)
                shutil.copy2(ffprobe_source, ffprobe_target)
                return
        raise FileNotFoundError("Unable to bootstrap ffmpeg assets for A_aqy")
