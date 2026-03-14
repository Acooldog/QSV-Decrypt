from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TimingBreakdown:
    scan_sec: float = 0.0
    analyze_sec: float = 0.0
    offline_decrypt_sec: float = 0.0
    hook_capture_sec: float = 0.0
    remux_sec: float = 0.0
    publish_sec: float = 0.0
    total_sec: float = 0.0

    def hotspot(self) -> tuple[str, float]:
        pairs = [
            ("scan_sec", self.scan_sec),
            ("analyze_sec", self.analyze_sec),
            ("offline_decrypt_sec", self.offline_decrypt_sec),
            ("hook_capture_sec", self.hook_capture_sec),
            ("remux_sec", self.remux_sec),
            ("publish_sec", self.publish_sec),
        ]
        return max(pairs, key=lambda item: item[1])


@dataclass
class ProbeSummary:
    ok: bool
    format_name: str = ""
    duration_sec: float = 0.0
    stream_count: int = 0
    video_streams: int = 0
    audio_streams: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class CacheSearchResult:
    database_headers: dict[str, str] = field(default_factory=dict)
    hits: dict[str, list[int]] = field(default_factory=dict)


@dataclass
class EmbeddedFragmentInfo:
    offset: int
    compression: str
    format_hint: str
    init_size: int = 0
    payload_size: int = 0
    note: str = ""


@dataclass
class TsRunInfo:
    offset: int
    length: int
    packet_count: int


@dataclass
class TsGapInfo:
    offset: int
    length: int
    packet_multiple: int
    packet_heads: list[str] = field(default_factory=list)


@dataclass
class QsvInspection:
    sample_path: Path
    file_size: int
    header_magic: str
    payload_offset: int | None
    payload_mode: str
    packet_sync_count: int = 0
    local_cache: CacheSearchResult = field(default_factory=CacheSearchResult)
    embedded_fragments: list[EmbeddedFragmentInfo] = field(default_factory=list)
    stable_runs: list[TsRunInfo] = field(default_factory=list)
    ts_gaps: list[TsGapInfo] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["sample_path"] = str(self.sample_path)
        return data


@dataclass
class HookCaptureResult:
    ok: bool
    reason: str
    candidate_paths: list[Path] = field(default_factory=list)
    selected_path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "candidate_paths": [str(path) for path in self.candidate_paths],
            "selected_path": str(self.selected_path) if self.selected_path else None,
        }


@dataclass
class FileDecryptResult:
    input_path: Path
    output_path: Path | None
    status: str
    reason: str
    source: str = ""
    inspection: QsvInspection | None = None
    probe_summary: ProbeSummary | None = None
    timing: TimingBreakdown = field(default_factory=TimingBreakdown)
    hook_capture: HookCaptureResult | None = None
    remux_detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_path": str(self.input_path),
            "output_path": str(self.output_path) if self.output_path else None,
            "status": self.status,
            "reason": self.reason,
            "source": self.source,
            "inspection": self.inspection.to_dict() if self.inspection else None,
            "probe_summary": asdict(self.probe_summary) if self.probe_summary else None,
            "timing": asdict(self.timing),
            "hook_capture": self.hook_capture.to_dict() if self.hook_capture else None,
            "remux_detail": dict(self.remux_detail),
        }


@dataclass
class BatchReport:
    input_root: Path
    output_root: Path
    candidate_count: int
    results: list[FileDecryptResult] = field(default_factory=list)
    wall_sec: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        success = sum(1 for item in self.results if item.status == "success")
        failed = sum(1 for item in self.results if item.status != "success")
        timing_totals = TimingBreakdown()
        for item in self.results:
            timing_totals.scan_sec += item.timing.scan_sec
            timing_totals.analyze_sec += item.timing.analyze_sec
            timing_totals.offline_decrypt_sec += item.timing.offline_decrypt_sec
            timing_totals.hook_capture_sec += item.timing.hook_capture_sec
            timing_totals.remux_sec += item.timing.remux_sec
            timing_totals.publish_sec += item.timing.publish_sec
            timing_totals.total_sec += item.timing.total_sec
        hotspot_name, hotspot_value = timing_totals.hotspot()
        return {
            "input_root": str(self.input_root),
            "output_root": str(self.output_root),
            "candidate_count": self.candidate_count,
            "success_count": success,
            "failed_count": failed,
            "results": [item.to_dict() for item in self.results],
            "wall_sec": self.wall_sec,
            "timing_total": asdict(timing_totals),
            "timing_avg": {
                key: (value / self.candidate_count if self.candidate_count else 0.0)
                for key, value in asdict(timing_totals).items()
            },
            "timing_hotspot": {
                "stage": hotspot_name,
                "total_sec": hotspot_value,
                "ratio": (hotspot_value / self.wall_sec) if self.wall_sec > 0 else 0.0,
                "wall_sec": self.wall_sec,
            },
        }
