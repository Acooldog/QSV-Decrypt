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
class SnapshotFileInfo:
    logical_name: str
    source_path: Path
    snapshot_path: Path | None
    exists: bool
    size: int = 0
    copied: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_name": self.logical_name,
            "source_path": str(self.source_path),
            "snapshot_path": str(self.snapshot_path) if self.snapshot_path else None,
            "exists": self.exists,
            "size": self.size,
            "copied": self.copied,
        }


@dataclass
class PgFileInfo:
    path: Path
    size: int
    marker_offsets: dict[str, int] = field(default_factory=dict)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "size": self.size,
            "marker_offsets": dict(self.marker_offsets),
            "note": self.note,
        }


@dataclass
class DbSnapshot:
    mode: str
    cache_root: Path
    snapshot_root: Path
    files: list[SnapshotFileInfo] = field(default_factory=list)
    pgf_inventory: list[PgFileInfo] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "cache_root": str(self.cache_root),
            "snapshot_root": str(self.snapshot_root),
            "files": [item.to_dict() for item in self.files],
            "pgf_inventory": [item.to_dict() for item in self.pgf_inventory],
            "note": self.note,
        }


@dataclass
class WalFrame:
    wal_name: str
    frame_index: int
    page_number: int
    db_size_after_commit: int
    payload_offset: int
    payload_size: int
    printable_ratio: float
    matched_needles: list[str] = field(default_factory=list)
    marker_hits: list[str] = field(default_factory=list)
    string_samples: list[str] = field(default_factory=list)


@dataclass
class WalOpaquePage:
    wal_name: str
    frame_index: int
    page_number: int
    payload_offset: int
    payload_size: int
    printable_ratio: float
    token_hits: int
    dominant_byte: int
    dominant_ratio: float
    zero_ratio: float
    head_hex: str


@dataclass
class WalInspection:
    wal_name: str
    path: Path
    ok: bool
    page_size: int = 0
    frame_count: int = 0
    page_frequencies: dict[int, int] = field(default_factory=dict)
    candidate_frames: list[WalFrame] = field(default_factory=list)
    opaque_pages: list[WalOpaquePage] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "wal_name": self.wal_name,
            "path": str(self.path),
            "ok": self.ok,
            "page_size": self.page_size,
            "frame_count": self.frame_count,
            "page_frequencies": {str(key): value for key, value in self.page_frequencies.items()},
            "candidate_frames": [asdict(item) for item in self.candidate_frames],
            "opaque_pages": [asdict(item) for item in self.opaque_pages],
            "note": self.note,
        }


@dataclass
class SnapshotWalPageDiff:
    wal_name: str
    page_number: int
    before_frame_count: int
    after_frame_count: int
    before_last_sha1: str = ""
    after_last_sha1: str = ""
    before_last_head_hex: str = ""
    after_last_head_hex: str = ""
    last_payload_diff_bytes: int = 0
    appended_only: bool = False
    last_payload_changed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SnapshotWalDiff:
    wal_name: str
    before_path: Path | None
    after_path: Path | None
    before_size: int = 0
    after_size: int = 0
    page_size: int = 0
    pages_with_count_change: list[int] = field(default_factory=list)
    pages_with_payload_change: list[int] = field(default_factory=list)
    page_diffs: list[SnapshotWalPageDiff] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "wal_name": self.wal_name,
            "before_path": str(self.before_path) if self.before_path else None,
            "after_path": str(self.after_path) if self.after_path else None,
            "before_size": self.before_size,
            "after_size": self.after_size,
            "page_size": self.page_size,
            "pages_with_count_change": list(self.pages_with_count_change),
            "pages_with_payload_change": list(self.pages_with_payload_change),
            "page_diffs": [item.to_dict() for item in self.page_diffs],
            "note": self.note,
        }


@dataclass
class DownloadMetadataEntry:
    save_dir: str
    save_file_name: str
    save_path: str
    display_name: str = ""
    album_name: str = ""
    channel_name: str = ""
    tvid: str = ""
    video_id: str = ""
    aid: str = ""
    lid: str = ""
    cf: str = ""
    ct: str = ""
    bitrate: str = ""
    duration: str = ""
    file_size: str = ""
    audio_type_name: str = ""
    pay_mark: str = ""
    album_source_type: str = ""
    cert_present: bool = False
    cert_sha1: str = ""
    raw_attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "save_dir": self.save_dir,
            "save_file_name": self.save_file_name,
            "save_path": self.save_path,
            "display_name": self.display_name,
            "album_name": self.album_name,
            "channel_name": self.channel_name,
            "tvid": self.tvid,
            "video_id": self.video_id,
            "aid": self.aid,
            "lid": self.lid,
            "cf": self.cf,
            "ct": self.ct,
            "bitrate": self.bitrate,
            "duration": self.duration,
            "file_size": self.file_size,
            "audio_type_name": self.audio_type_name,
            "pay_mark": self.pay_mark,
            "album_source_type": self.album_source_type,
            "cert_present": self.cert_present,
            "cert_sha1": self.cert_sha1,
            "raw_attrs": dict(self.raw_attrs),
        }


@dataclass
class DownloadMetadataCorrelation:
    db_path: Path
    downloaded_xml_row_size: int = 0
    matched_entries: list[DownloadMetadataEntry] = field(default_factory=list)
    total_entry_count: int = 0
    cert_entry_count: int = 0
    unique_cert_sha1s: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "db_path": str(self.db_path),
            "downloaded_xml_row_size": self.downloaded_xml_row_size,
            "matched_entries": [item.to_dict() for item in self.matched_entries],
            "total_entry_count": self.total_entry_count,
            "cert_entry_count": self.cert_entry_count,
            "unique_cert_sha1s": list(self.unique_cert_sha1s),
            "notes": list(self.notes),
        }


@dataclass
class DbCorrelation:
    sample_path: Path
    snapshot_mode: str
    wal_inspections: list[WalInspection] = field(default_factory=list)
    identifier_candidates: list[str] = field(default_factory=list)
    candidate_cache_paths: list[str] = field(default_factory=list)
    db_token_summary: dict[str, dict[str, Any]] = field(default_factory=dict)
    qtplog_segment_tasks: list[dict[str, Any]] = field(default_factory=list)
    qtplog_path_events: list[dict[str, Any]] = field(default_factory=list)
    qtplog_dispatch_events: list[dict[str, Any]] = field(default_factory=list)
    qtplog_segment_alignment: dict[str, Any] = field(default_factory=dict)
    download_metadata: DownloadMetadataCorrelation | None = None
    cube_log_summary: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_path": str(self.sample_path),
            "snapshot_mode": self.snapshot_mode,
            "wal_inspections": [item.to_dict() for item in self.wal_inspections],
            "identifier_candidates": list(self.identifier_candidates),
            "candidate_cache_paths": list(self.candidate_cache_paths),
            "db_token_summary": self.db_token_summary,
            "qtplog_segment_tasks": list(self.qtplog_segment_tasks),
            "qtplog_path_events": list(self.qtplog_path_events),
            "qtplog_dispatch_events": list(self.qtplog_dispatch_events),
            "qtplog_segment_alignment": dict(self.qtplog_segment_alignment),
            "download_metadata": self.download_metadata.to_dict() if self.download_metadata else None,
            "cube_log_summary": dict(self.cube_log_summary),
            "notes": list(self.notes),
        }
        

@dataclass
class RunProbeInfo:
    run_index: int
    offset: int
    length: int
    packet_count: int
    output_path: Path | None = None
    probe_summary: ProbeSummary | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_index": self.run_index,
            "offset": self.offset,
            "length": self.length,
            "packet_count": self.packet_count,
            "output_path": str(self.output_path) if self.output_path else None,
            "probe_summary": asdict(self.probe_summary) if self.probe_summary else None,
            "note": self.note,
        }


@dataclass
class PgfFragmentInfo:
    pgf_path: Path
    sidx_offset: int
    sidx_size: int
    moof_offset: int
    moof_size: int
    mdat_offset: int
    mdat_size: int
    total_size: int
    timescale: int
    earliest_presentation_sec: float
    duration_sec: float
    ref_count: int
    sequence_number: int = 0
    track_id: int = 0
    decode_time_sec: float = 0.0
    sample_count: int = 0
    has_saiz: bool = False
    has_saio: bool = False
    has_senc: bool = False
    reference_sizes: list[int] = field(default_factory=list)
    output_path: Path | None = None
    probe_summary: ProbeSummary | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pgf_path": str(self.pgf_path),
            "sidx_offset": self.sidx_offset,
            "sidx_size": self.sidx_size,
            "moof_offset": self.moof_offset,
            "moof_size": self.moof_size,
            "mdat_offset": self.mdat_offset,
            "mdat_size": self.mdat_size,
            "total_size": self.total_size,
            "timescale": self.timescale,
            "earliest_presentation_sec": self.earliest_presentation_sec,
            "duration_sec": self.duration_sec,
            "sequence_number": self.sequence_number,
            "track_id": self.track_id,
            "decode_time_sec": self.decode_time_sec,
            "sample_count": self.sample_count,
            "has_saiz": self.has_saiz,
            "has_saio": self.has_saio,
            "has_senc": self.has_senc,
            "ref_count": self.ref_count,
            "reference_sizes": list(self.reference_sizes),
            "output_path": str(self.output_path) if self.output_path else None,
            "probe_summary": asdict(self.probe_summary) if self.probe_summary else None,
            "note": self.note,
        }


@dataclass
class PgfSequenceInfo:
    pgf_path: Path
    fragment_count: int
    start_earliest_sec: float
    end_earliest_sec: float
    total_duration_sec: float
    avg_fragment_duration_sec: float
    first_sidx_offset: int
    last_sidx_offset: int
    pgf_paths: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pgf_path": str(self.pgf_path),
            "pgf_paths": list(self.pgf_paths),
            "fragment_count": self.fragment_count,
            "start_earliest_sec": self.start_earliest_sec,
            "end_earliest_sec": self.end_earliest_sec,
            "total_duration_sec": self.total_duration_sec,
            "avg_fragment_duration_sec": self.avg_fragment_duration_sec,
            "first_sidx_offset": self.first_sidx_offset,
            "last_sidx_offset": self.last_sidx_offset,
            "note": self.note,
        }


@dataclass
class SegmentRebuildPlan:
    sample_path: Path
    strategy: str
    status: str
    snapshot: DbSnapshot | None = None
    db_correlation: DbCorrelation | None = None
    run_probes: list[RunProbeInfo] = field(default_factory=list)
    pgf_fragments: list[PgfFragmentInfo] = field(default_factory=list)
    pgf_sequences: list[PgfSequenceInfo] = field(default_factory=list)
    artifact_paths: list[Path] = field(default_factory=list)
    output_path: Path | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_path": str(self.sample_path),
            "strategy": self.strategy,
            "status": self.status,
            "snapshot": self.snapshot.to_dict() if self.snapshot else None,
            "db_correlation": self.db_correlation.to_dict() if self.db_correlation else None,
            "run_probes": [item.to_dict() for item in self.run_probes],
            "pgf_fragments": [item.to_dict() for item in self.pgf_fragments],
            "pgf_sequences": [item.to_dict() for item in self.pgf_sequences],
            "artifact_paths": [str(path) for path in self.artifact_paths],
            "output_path": str(self.output_path) if self.output_path else None,
            "notes": list(self.notes),
        }


@dataclass
class BbtsRepairCandidateInfo:
    candidate_name: str
    key_hex: str
    operation: str
    source: str
    window_offset: int
    score: int
    video_duration_sec: float = 0.0
    audio_duration_sec: float = 0.0
    width: int = 0
    height: int = 0
    nb_frames: int = 0
    visual_score: float = 0.0
    frame_sample_count: int = 0
    frame_entropy_avg: float = 0.0
    frame_stddev_avg: float = 0.0
    dominant_ratio_max: float = 0.0
    decoded_video_sec: float = 0.0
    decode_error_lines: int = 0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BbtsRepairSegmentInfo:
    segment_index: int
    input_path: Path
    output_path: Path | None = None
    selected_candidate: BbtsRepairCandidateInfo | None = None
    candidate_count: int = 0
    top_candidates: list[BbtsRepairCandidateInfo] = field(default_factory=list)
    probe_summary: ProbeSummary | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "segment_index": self.segment_index,
            "input_path": str(self.input_path),
            "output_path": str(self.output_path) if self.output_path else None,
            "selected_candidate": self.selected_candidate.to_dict() if self.selected_candidate else None,
            "candidate_count": self.candidate_count,
            "top_candidates": [item.to_dict() for item in self.top_candidates],
            "probe_summary": asdict(self.probe_summary) if self.probe_summary else None,
            "note": self.note,
        }


@dataclass
class BbtsRepairPlan:
    sample_path: Path
    segments_dir: Path
    dispatch_json_path: Path
    status: str
    segment_results: list[BbtsRepairSegmentInfo] = field(default_factory=list)
    output_ts_path: Path | None = None
    output_mp4_path: Path | None = None
    final_probe_summary: ProbeSummary | None = None
    artifact_paths: list[Path] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_path": str(self.sample_path),
            "segments_dir": str(self.segments_dir),
            "dispatch_json_path": str(self.dispatch_json_path),
            "status": self.status,
            "segment_results": [item.to_dict() for item in self.segment_results],
            "output_ts_path": str(self.output_ts_path) if self.output_ts_path else None,
            "output_mp4_path": str(self.output_mp4_path) if self.output_mp4_path else None,
            "final_probe_summary": asdict(self.final_probe_summary) if self.final_probe_summary else None,
            "artifact_paths": [str(path) for path in self.artifact_paths],
            "notes": list(self.notes),
        }


@dataclass
class LiveHlsFrameCheck:
    timestamp_sec: float
    png_path: Path | None = None
    gray_stats: list[dict[str, float]] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp_sec": self.timestamp_sec,
            "png_path": str(self.png_path) if self.png_path else None,
            "gray_stats": [dict(item) for item in self.gray_stats],
            "note": self.note,
        }


@dataclass
class LiveHlsRebuildPlan:
    sample_path: Path
    status: str
    playlist_url: str = ""
    selected_bid: int = 0
    selected_vid: str = ""
    total_segments: int = 0
    downloaded_segments: int = 0
    target_duration_sec: float = 0.0
    downloaded_duration_sec: float = 0.0
    output_ts_path: Path | None = None
    output_mp4_path: Path | None = None
    probe_summary: ProbeSummary | None = None
    decode_health: dict[str, float] = field(default_factory=dict)
    frame_checks: list[LiveHlsFrameCheck] = field(default_factory=list)
    artifact_paths: list[Path] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_path": str(self.sample_path),
            "status": self.status,
            "playlist_url": self.playlist_url,
            "selected_bid": self.selected_bid,
            "selected_vid": self.selected_vid,
            "total_segments": self.total_segments,
            "downloaded_segments": self.downloaded_segments,
            "target_duration_sec": self.target_duration_sec,
            "downloaded_duration_sec": self.downloaded_duration_sec,
            "output_ts_path": str(self.output_ts_path) if self.output_ts_path else None,
            "output_mp4_path": str(self.output_mp4_path) if self.output_mp4_path else None,
            "probe_summary": asdict(self.probe_summary) if self.probe_summary else None,
            "decode_health": dict(self.decode_health),
            "frame_checks": [item.to_dict() for item in self.frame_checks],
            "artifact_paths": [str(path) for path in self.artifact_paths],
            "notes": list(self.notes),
        }


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
    db_correlation: DbCorrelation | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_path": str(self.sample_path),
            "file_size": self.file_size,
            "header_magic": self.header_magic,
            "payload_offset": self.payload_offset,
            "payload_mode": self.payload_mode,
            "packet_sync_count": self.packet_sync_count,
            "local_cache": asdict(self.local_cache),
            "embedded_fragments": [asdict(item) for item in self.embedded_fragments],
            "stable_runs": [asdict(item) for item in self.stable_runs],
            "ts_gaps": [asdict(item) for item in self.ts_gaps],
            "db_correlation": self.db_correlation.to_dict() if self.db_correlation else None,
            "notes": list(self.notes),
        }


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
