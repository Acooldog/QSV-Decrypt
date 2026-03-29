from __future__ import annotations

import json
import logging
import math
import shutil
import subprocess
import time
from pathlib import Path

from src.Application.models import ProbeSummary

from .runtime_paths import get_assets_dir


logger = logging.getLogger("aqy_decrypt")


class FfmpegTools:
    PROBE_TIMEOUT_SEC = 20
    SAMPLE_FRAME_TIMEOUT_SEC = 20
    DECODE_HEALTH_TIMEOUT_SEC = 30
    WINDOW_DECODE_TIMEOUT_SEC = 15
    WINDOW_DECODE_DURATION_SEC = 8.0
    REMUX_TIMEOUT_SEC = 60

    def __init__(self) -> None:
        assets_dir = get_assets_dir()
        self.ffmpeg_path = assets_dir / "ffmpeg.exe"
        self.ffprobe_path = assets_dir / "ffprobe.exe"

    @property
    def available(self) -> bool:
        return self.ffmpeg_path.exists() and self.ffprobe_path.exists()

    def ensure_available(self) -> None:
        if not self.available:
            raise FileNotFoundError(
                f"Missing ffmpeg assets: {self.ffmpeg_path} / {self.ffprobe_path}"
            )

    def probe(self, media_path: Path) -> ProbeSummary:
        self.ensure_available()
        command = [
            str(self.ffprobe_path),
            "-hide_banner",
            "-loglevel",
            "error",
            "-show_format",
            "-show_streams",
            "-of",
            "json",
            str(media_path),
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=self.PROBE_TIMEOUT_SEC,
        )
        if completed.returncode != 0:
            return ProbeSummary(ok=False, raw={"stderr": completed.stderr.strip()})

        raw = json.loads(completed.stdout)
        streams = raw.get("streams", [])
        fmt = raw.get("format", {})
        return ProbeSummary(
            ok=True,
            format_name=fmt.get("format_name", ""),
            duration_sec=float(fmt.get("duration", 0.0) or 0.0),
            stream_count=len(streams),
            video_streams=sum(1 for item in streams if item.get("codec_type") == "video"),
            audio_streams=sum(1 for item in streams if item.get("codec_type") == "audio"),
            raw=raw,
        )

    def remux_to_mp4(self, input_path: Path, output_path: Path) -> dict[str, object]:
        self.ensure_available()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        input_probe = self.probe(input_path)
        video_codec = self._first_stream_codec(input_probe.raw, "video")
        audio_codec = self._first_stream_codec(input_probe.raw, "audio")
        command = [
            str(self.ffmpeg_path),
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-fflags",
            "+genpts",
            "-i",
            str(input_path),
            "-map",
            "0:v:0",
            "-map",
            "0:a?",
            "-c",
            "copy",
            "-copyinkf",
            "-movflags",
            "+faststart",
        ]
        if audio_codec == "aac":
            command.extend(["-bsf:a", "aac_adtstoasc"])
        if video_codec == "hevc":
            command.extend(["-tag:v", "hvc1"])
        command.append(str(output_path))
        started = time.perf_counter()
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=self.REMUX_TIMEOUT_SEC,
        )
        elapsed_sec = time.perf_counter() - started
        if completed.returncode != 0:
            raise RuntimeError(
                f"ffmpeg remux failed for {input_path}: {completed.stderr.strip()}"
            )
        return {
            "mode": "stream-copy",
            "elapsed_sec": round(elapsed_sec, 6),
            "exit_code": completed.returncode,
            "input_bytes": input_path.stat().st_size if input_path.exists() else 0,
            "output_bytes": output_path.stat().st_size if output_path.exists() else 0,
            "video_codec": video_codec or "",
            "audio_codec": audio_codec or "",
            "video_tag": "hvc1" if video_codec == "hevc" else "",
            "command": command,
        }

    def sample_gray_frame_stats(self, media_path: Path, timestamps: list[float]) -> list[dict[str, float]]:
        self.ensure_available()
        stats: list[dict[str, float]] = []
        for ts in timestamps:
            command = [
                str(self.ffmpeg_path),
                "-hide_banner",
                "-loglevel",
                "error",
                "-ss",
                f"{max(0.0, float(ts)):.3f}",
                "-i",
                str(media_path),
                "-frames:v",
                "1",
                "-vf",
                "scale=160:90,format=gray",
                "-f",
                "rawvideo",
                "pipe:1",
            ]
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=self.SAMPLE_FRAME_TIMEOUT_SEC,
            )
            if completed.returncode != 0 or not completed.stdout:
                continue
            stats.append(self._gray_frame_stats(completed.stdout))
        return stats

    def decode_video_health(self, media_path: Path) -> dict[str, float]:
        self.ensure_available()
        command = [
            str(self.ffmpeg_path),
            "-hide_banner",
            "-loglevel",
            "warning",
            "-progress",
            "pipe:1",
            "-nostats",
            "-i",
            str(media_path),
            "-map",
            "0:v:0",
            "-an",
            "-f",
            "null",
            "-",
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=self.DECODE_HEALTH_TIMEOUT_SEC,
        )
        decoded_video_sec = 0.0
        for line in completed.stdout.splitlines():
            if not line.startswith("out_time_ms="):
                continue
            try:
                decoded_video_sec = max(decoded_video_sec, int(line.split("=", 1)[1]) / 1_000_000.0)
            except ValueError:
                continue
        error_lines = sum(1 for line in completed.stderr.splitlines() if line.strip())
        return {
            "decoded_video_sec": round(decoded_video_sec, 6),
            "decode_error_lines": float(error_lines),
        }

    def decode_video_window_health(
        self,
        media_path: Path,
        start_sec: float,
        duration_sec: float | None = None,
    ) -> dict[str, float]:
        self.ensure_available()
        clip_duration = float(duration_sec or self.WINDOW_DECODE_DURATION_SEC)
        command = [
            str(self.ffmpeg_path),
            "-hide_banner",
            "-loglevel",
            "warning",
            "-progress",
            "pipe:1",
            "-nostats",
            "-ss",
            f"{max(0.0, float(start_sec)):.3f}",
            "-t",
            f"{max(0.5, clip_duration):.3f}",
            "-i",
            str(media_path),
            "-map",
            "0:v:0",
            "-an",
            "-f",
            "null",
            "-",
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=self.WINDOW_DECODE_TIMEOUT_SEC,
        )
        decoded_video_sec = 0.0
        for line in completed.stdout.splitlines():
            if not line.startswith("out_time_ms="):
                continue
            try:
                decoded_video_sec = max(decoded_video_sec, int(line.split("=", 1)[1]) / 1_000_000.0)
            except ValueError:
                continue
        error_lines = sum(1 for line in completed.stderr.splitlines() if line.strip())
        return {
            "decoded_video_sec": round(decoded_video_sec, 6),
            "decode_error_lines": float(error_lines),
        }

    @staticmethod
    def _gray_frame_stats(frame_bytes: bytes) -> dict[str, float]:
        total = len(frame_bytes)
        if total == 0:
            return {
                "mean": 0.0,
                "stddev": 0.0,
                "entropy": 0.0,
                "dominant_ratio": 1.0,
                "unique_values": 0.0,
            }
        counts = [0] * 256
        acc = 0
        for value in frame_bytes:
            counts[value] += 1
            acc += value
        mean = acc / total
        variance = 0.0
        entropy = 0.0
        dominant = 0
        unique_values = 0
        for count in counts:
            if count == 0:
                continue
            unique_values += 1
            dominant = max(dominant, count)
            diff = (count / total)
            entropy -= diff * math.log2(diff)
        for value, count in enumerate(counts):
            if count:
                variance += ((value - mean) ** 2) * count
        variance /= total
        return {
            "mean": round(mean, 4),
            "stddev": round(math.sqrt(variance), 4),
            "entropy": round(entropy, 6),
            "dominant_ratio": round(dominant / total, 6),
            "unique_values": float(unique_values),
        }

    @staticmethod
    def _first_stream_codec(raw: dict[str, object], codec_type: str) -> str | None:
        streams = raw.get("streams") if isinstance(raw, dict) else None
        if not isinstance(streams, list):
            return None
        for item in streams:
            if isinstance(item, dict) and item.get("codec_type") == codec_type:
                codec_name = item.get("codec_name")
                return str(codec_name) if codec_name else None
        return None

    def copy_into_assets(self, ffmpeg_source: Path, ffprobe_source: Path) -> None:
        assets_dir = get_assets_dir()
        assets_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ffmpeg_source, self.ffmpeg_path)
        shutil.copy2(ffprobe_source, self.ffprobe_path)
