from __future__ import annotations

import gzip
import json
import mmap
import shutil
import subprocess
import struct
import zlib
from pathlib import Path

from src.Application.models import (
    DbCorrelation,
    DbSnapshot,
    PgfFragmentInfo,
    PgfSequenceInfo,
    ProbeSummary,
    QsvInspection,
    RunProbeInfo,
    SegmentRebuildPlan,
)

from .ffmpeg_tools import FfmpegTools
from .qsv_offline import QsvOfflineDecoder
from .runtime_paths import get_log_day_dir


class DbPrototypeRebuilder:
    MAX_PGF_FRAGMENTS_PER_FILE = 256
    MAX_EXTRACTED_PGF_ARTIFACTS = 12
    MAX_SIDX_SIZE = 4096
    MAX_MEDIA_BOX_SIZE = 64 * 1024 * 1024
    PGF_FRAGMENT_MARKERS = {
        "mfhd": b"mfhd",
        "tfhd": b"tfhd",
        "tfdt": b"tfdt",
        "trun": b"trun",
    }
    PGF_CODEC_MARKERS = {
        "hvcC": b"hvcC",
        "hev1": b"hev1",
        "hvc1": b"hvc1",
        "avcC": b"avcC",
        "avc1": b"avc1",
        "ec-3": b"ec-3",
        "ac-3": b"ac-3",
    }
    PGF_INIT_MARKERS = {
        "ftyp": b"ftyp",
        "moov": b"moov",
        "mvex": b"mvex",
        "trex": b"trex",
    }

    def __init__(
        self,
        decoder: QsvOfflineDecoder,
        ffmpeg_tools: FfmpegTools,
    ) -> None:
        self.decoder = decoder
        self.ffmpeg_tools = ffmpeg_tools

    def rebuild(
        self,
        sample_path: Path,
        snapshot: DbSnapshot,
        db_correlation: DbCorrelation,
        inspection: QsvInspection | None = None,
        output_root: Path | None = None,
    ) -> SegmentRebuildPlan:
        inspection = inspection or self.decoder.inspect(sample_path)
        work_dir = get_log_day_dir() / "db_prototype" / sample_path.stem
        work_dir.mkdir(parents=True, exist_ok=True)
        output_root = output_root or work_dir / "output"
        output_root.mkdir(parents=True, exist_ok=True)

        notes: list[str] = []
        artifact_paths: list[Path] = []
        run_probes = self._probe_stable_runs(sample_path, inspection, work_dir)
        artifact_paths.extend(path for item in run_probes if item.output_path for path in [item.output_path])

        embedded_artifacts = self._extract_embedded_fragments(sample_path, inspection, work_dir)
        artifact_paths.extend(embedded_artifacts)
        pgf_fragments, pgf_sequences, pgf_artifacts = self._scan_pgf_fragments(snapshot, work_dir)
        artifact_paths.extend(pgf_artifacts)
        pgf_marker_summary = self._scan_pgf_marker_summary(snapshot)

        strategy = "analysis-only"
        status = "analysis_only"
        output_path: Path | None = None
        embedded_audio_duration_hint: float | None = None

        if db_correlation.identifier_candidates:
            notes.append(
                f"Database/WAL candidate identifiers found: {len(db_correlation.identifier_candidates)}"
            )
        if db_correlation.download_metadata and db_correlation.download_metadata.matched_entries:
            metadata = db_correlation.download_metadata.matched_entries[0]
            notes.append(
                "Downloaded.xml maps this sample to TVID/VideoId/aid/lid/cf/ct = "
                f"{metadata.tvid}/{metadata.video_id}/{metadata.aid}/{metadata.lid}/{metadata.cf}/{metadata.ct}."
            )
            if metadata.cert_present:
                notes.append(
                    "Downloaded.xml also carries the same global DRM cert blob seen in other protected rows; the "
                    "remaining missing artifact is still the sample-specific mapping/license result, not the cert itself."
                )
        if db_correlation.qtplog_segment_tasks:
            segnums = sorted(
                {
                    int(item["segnum"])
                    for item in db_correlation.qtplog_segment_tasks
                    if isinstance(item.get("segnum"), int)
                }
            )
            notes.append(
                f"qtplog exposes {len(db_correlation.qtplog_segment_tasks)} local qsv segment task(s) for this sample"
                + (f" across segment indices {segnums[0]}..{segnums[-1]}." if segnums else ".")
            )
        if db_correlation.qtplog_path_events:
            open_fail_count = sum(
                1 for item in db_correlation.qtplog_path_events if item.get("event_type") == "open_failed_second_time"
            )
            if open_fail_count:
                notes.append(
                    f"qtplog recorded {open_fail_count} repeated local reopen failures for this sample; client-side "
                    "open/reopen instability may be part of the 4K corruption path."
                )
        if db_correlation.candidate_cache_paths:
            notes.append(
                f"Candidate cache files observed in temp_cache inventory: {len(db_correlation.candidate_cache_paths)}"
            )
        if embedded_artifacts:
            strategy = "embedded-fragment-aware-analysis"
            notes.append("Extracted embedded gzip fragment artifacts for init/tail verification.")
            for artifact_path in embedded_artifacts:
                if artifact_path.suffix.lower() != ".mp4":
                    continue
                probe = self.ffmpeg_tools.probe(artifact_path)
                if probe.ok and probe.audio_streams > 0 and probe.video_streams == 0:
                    embedded_audio_duration_hint = max(
                        embedded_audio_duration_hint or 0.0,
                        probe.duration_sec,
                    )
                    notes.append(
                        f"Embedded fragment {artifact_path.name} probes as a standalone audio-only MP4 with "
                        f"duration {probe.duration_sec:.3f}s; this explains why the current offline output keeps a "
                        "full-length audio timeline while the video timeline breaks."
                    )
        if pgf_fragments:
            strategy = "db-guided-pgf-fragment-analysis"
            notes.append(
                f"PGF scan found {len(pgf_fragments)} valid sidx+moof+mdat fragment(s) across "
                f"{len({item.pgf_path for item in pgf_fragments})} file(s)."
            )
            notes.append(
                "These cached fragments are fragmented MP4 sidecar media, not random noise; they are the strongest "
                "candidate source for the missing 4K init/index context."
            )
            earliest_fragment_sec = min(item.earliest_presentation_sec for item in pgf_fragments)
            if earliest_fragment_sec > 0.0:
                notes.append(
                    f"The earliest valid PGF media fragment starts at {earliest_fragment_sec:.3f}s, so the local PGF "
                    "warehouse is missing at least the leading init/lead-in context before that point."
                )
            encrypted_fragments = [
                item for item in pgf_fragments if item.has_senc or item.has_saiz or item.has_saio
            ]
            if encrypted_fragments:
                track_ids = sorted({item.track_id for item in encrypted_fragments if item.track_id})
                notes.append(
                    f"{len(encrypted_fragments)} PGF fragment(s) expose saiz/saio/senc sample-encryption boxes on "
                    f"track ids {track_ids or ['unknown']}. That means the warehouse holds encrypted fMP4 media, so "
                    "even a recovered init segment will still need the right decryption/mapping context."
                )
        if pgf_marker_summary["fragment_marker_paths"]:
            notes.append(
                "PGF marker scan also found low-level fragmented-MP4 boxes "
                + ", ".join(sorted(pgf_marker_summary["fragment_marker_paths"]))
                + ", which confirms that the warehouse contains real fMP4 fragments beyond the carved sidx+moof+mdat runs."
            )
        if pgf_marker_summary["codec_marker_paths"]:
            notes.append(
                "Codec markers observed in PGF warehouse: "
                + ", ".join(
                    f"{marker}@{count}"
                    for marker, count in sorted(pgf_marker_summary["codec_marker_paths"].items())
                )
                + "."
            )
        if not pgf_marker_summary["valid_init_candidates"] and pgf_marker_summary["init_marker_paths"]:
            notes.append(
                "PGF scan found isolated init-related markers "
                + ", ".join(sorted(pgf_marker_summary["init_marker_paths"]))
                + ", but no self-consistent local ftyp+moov init segment. The remaining blocker is still the missing "
                "standalone init/mapping layer, not raw media availability."
            )
        if pgf_sequences:
            longest = max(pgf_sequences, key=lambda item: item.total_duration_sec)
            notes.append(
                "Longest PGF fragment sequence spans "
                f"{longest.total_duration_sec:.3f}s across {longest.fragment_count} contiguous fragment(s)."
            )
            if len(longest.pgf_paths) > 1:
                notes.append(
                    f"That longest sequence crosses {len(longest.pgf_paths)} PGF files, which means a usable 4K "
                    "rebuild must treat the PGF store as one logical fragment warehouse rather than six unrelated files."
                )
            if embedded_audio_duration_hint:
                chain = self._find_sequence_chain(
                    pgf_sequences=pgf_sequences,
                    target_duration_sec=embedded_audio_duration_hint,
                )
                if chain is not None:
                    notes.append(
                        "PGF sequence chaining can cover "
                        f"{chain['start_sec']:.3f}s -> {chain['end_sec']:.3f}s with total media "
                        f"{chain['media_sec']:.3f}s across {chain['sequence_count']} multi-file span(s) and "
                        f"{chain['gap_sec']:.3f}s of uncovered gaps. That is close to the "
                        f"{embedded_audio_duration_hint:.3f}s embedded audio timeline and is the strongest evidence "
                        "so far that the local PGF warehouse contains the missing 4K video timeline, just not the "
                        "standalone init segment."
                    )
            if not any(item.probe_summary and item.probe_summary.ok for item in pgf_fragments if item.output_path):
                notes.append(
                    "Extracted PGF fragments are recognizable as fragmented MP4, but they do not probe cleanly by "
                    "themselves; the cache appears to be missing a standalone init segment."
                )
        else:
            notes.append(
                "No contiguous PGF fragment sequences were found; current cache snapshot may be incomplete."
            )
        if run_probes:
            if not pgf_fragments:
                strategy = "runwise-prototype-analysis"
            successful_runs = [item for item in run_probes if item.probe_summary and item.probe_summary.video_streams > 0]
            if successful_runs:
                status = "partial_restore"
            total_video = sum(
                item.probe_summary.duration_sec
                for item in run_probes
                if item.probe_summary and item.probe_summary.video_streams > 0
            )
            total_audio = sum(
                item.probe_summary.duration_sec
                for item in run_probes
                if item.probe_summary and item.probe_summary.audio_streams > 0
            )
            notes.append(
                f"Summed run durations: video={total_video:.3f}s audio={total_audio:.3f}s."
            )
            if successful_runs and len(successful_runs) == 1 and successful_runs[0].run_index == 1:
                notes.append(
                    "Only the first stable TS run remuxes into valid media; later runs appear to be missing "
                    "init/index context rather than just needing timestamp normalization."
                )
                if pgf_sequences:
                    longest = max(pgf_sequences, key=lambda item: item.total_duration_sec)
                    first_run_duration = successful_runs[0].probe_summary.duration_sec if successful_runs[0].probe_summary else 0.0
                    if first_run_duration and longest.total_duration_sec + 1.0 < first_run_duration:
                        notes.append(
                            "No single contiguous PGF fragment sequence is long enough to cover even the first valid "
                            f"run ({first_run_duration:.3f}s vs longest PGF sequence {longest.total_duration_sec:.3f}s), "
                            "which means a successful 4K rebuild will need database-guided mapping across multiple "
                            "sequences and probably multiple PGF files."
                        )
                notes.append(
                    "Bootstrapping later runs with leading TS packets from run 1 still fails to restore HEVC dimensions, "
                    "which reinforces that the missing context is external to the raw TS runs."
                )

        plan = SegmentRebuildPlan(
            sample_path=sample_path,
            strategy=strategy,
            status=status,
            snapshot=snapshot,
            db_correlation=db_correlation,
            run_probes=run_probes,
            pgf_fragments=pgf_fragments,
            pgf_sequences=pgf_sequences,
            artifact_paths=artifact_paths,
            output_path=output_path,
            notes=notes,
        )
        report_path = work_dir / f"{sample_path.stem}.prototype.json"
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(plan.to_dict(), handle, ensure_ascii=False, indent=2)
        plan.artifact_paths.append(report_path)
        return plan

    def _probe_stable_runs(
        self,
        sample_path: Path,
        inspection: QsvInspection,
        work_dir: Path,
    ) -> list[RunProbeInfo]:
        if not inspection.stable_runs:
            return []

        stride = 192 if inspection.payload_mode == "ts-192-prefix4" else 188
        emit_offset = 4 if inspection.payload_mode == "ts-192-prefix4" else 0
        run_dir = work_dir / "stable_runs"
        run_dir.mkdir(parents=True, exist_ok=True)
        results: list[RunProbeInfo] = []
        with open(sample_path, "rb") as source:
            data = mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                for index, run in enumerate(inspection.stable_runs, start=1):
                    ts_path = run_dir / f"run_{index:02d}.ts"
                    mp4_path = run_dir / f"run_{index:02d}.mp4"
                    chunk = data[run.offset : run.offset + run.length]
                    if emit_offset:
                        ts_path.write_bytes(self._strip_prefixed_packets(chunk, stride, emit_offset))
                    else:
                        ts_path.write_bytes(chunk)
                    probe = self._remux_and_probe(ts_path, mp4_path)
                    results.append(
                        RunProbeInfo(
                            run_index=index,
                            offset=run.offset,
                            length=run.length,
                            packet_count=run.packet_count,
                            output_path=mp4_path if mp4_path.exists() else ts_path,
                            probe_summary=probe,
                            note="Derived from a stable TS run; useful for run-by-run timeline checks.",
                        )
                    )
            finally:
                data.close()
        return results

    def _extract_embedded_fragments(
        self,
        sample_path: Path,
        inspection: QsvInspection,
        work_dir: Path,
    ) -> list[Path]:
        if not inspection.embedded_fragments:
            return []
        fragment_dir = work_dir / "embedded_fragments"
        fragment_dir.mkdir(parents=True, exist_ok=True)
        artifact_paths: list[Path] = []
        with open(sample_path, "rb") as source:
            data = mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                for index, fragment in enumerate(inspection.embedded_fragments, start=1):
                    gzip_path = fragment_dir / f"fragment_{index:02d}.gz"
                    gzip_blob = data[fragment.offset : min(len(data), fragment.offset + 2 * 1024 * 1024)]
                    gzip_path.write_bytes(gzip_blob)
                    artifact_paths.append(gzip_path)
                    try:
                        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        init_payload = decompressor.decompress(gzip_blob)
                        raw_payload = decompressor.unused_data
                    except zlib.error:
                        continue
                    init_path = fragment_dir / f"fragment_{index:02d}.init.bin"
                    init_path.write_bytes(init_payload)
                    artifact_paths.append(init_path)
                    if raw_payload:
                        raw_path = fragment_dir / f"fragment_{index:02d}.payload.bin"
                        raw_path.write_bytes(raw_payload)
                        artifact_paths.append(raw_path)
                    if b"mdat" in raw_payload[:64]:
                        mp4_path = fragment_dir / f"fragment_{index:02d}.mp4"
                        mp4_path.write_bytes(init_payload + raw_payload)
                        artifact_paths.append(mp4_path)
            finally:
                data.close()
        return artifact_paths

    def _remux_and_probe(self, ts_path: Path, mp4_path: Path) -> ProbeSummary | None:
        try:
            self.ffmpeg_tools.remux_to_mp4(ts_path, mp4_path)
        except RuntimeError:
            return None
        return self.ffmpeg_tools.probe(mp4_path)

    def _scan_pgf_fragments(
        self,
        snapshot: DbSnapshot,
        work_dir: Path,
    ) -> tuple[list[PgfFragmentInfo], list[PgfSequenceInfo], list[Path]]:
        fragments: list[PgfFragmentInfo] = []
        fragment_dir = work_dir / "pgf_fragments"
        fragment_dir.mkdir(parents=True, exist_ok=True)

        for pgf_info in snapshot.pgf_inventory:
            pgf_path = pgf_info.path
            if not pgf_path.exists():
                continue
            with open(pgf_path, "rb") as handle:
                mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    search_offset = 0
                    hits = 0
                    while hits < self.MAX_PGF_FRAGMENTS_PER_FILE:
                        sidx_pos = mm.find(b"sidx", search_offset)
                        if sidx_pos < 0:
                            break
                        fragment = self._try_parse_pgf_fragment(mm, pgf_path, sidx_pos)
                        search_offset = sidx_pos + 1
                        if fragment is None:
                            continue
                        fragments.append(fragment)
                        hits += 1
                finally:
                    mm.close()

        sequences = self._group_pgf_sequences(fragments)
        artifacts: list[Path] = []
        selected_keys = {
            (fragment.pgf_path, fragment.sidx_offset)
            for sequence in sequences[: self.MAX_EXTRACTED_PGF_ARTIFACTS]
            for fragment in fragments
            if fragment.pgf_path == sequence.pgf_path and fragment.sidx_offset == sequence.first_sidx_offset
        }
        if not selected_keys:
            selected_keys = {
                (fragment.pgf_path, fragment.sidx_offset)
                for fragment in fragments[: self.MAX_EXTRACTED_PGF_ARTIFACTS]
            }
        fragments_by_key = {(item.pgf_path, item.sidx_offset): item for item in fragments}
        for pgf_path, sidx_offset in selected_keys:
            fragment = fragments_by_key[(pgf_path, sidx_offset)]
            with open(pgf_path, "rb") as handle:
                mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    artifact_path = fragment_dir / f"{pgf_path.stem}_sidx_{fragment.sidx_offset:010d}.m4s"
                    artifact_path.write_bytes(mm[fragment.sidx_offset : fragment.sidx_offset + fragment.total_size])
                finally:
                    mm.close()
            fragment.output_path = artifact_path
            try:
                fragment.probe_summary = self.ffmpeg_tools.probe(artifact_path)
            except Exception:
                fragment.probe_summary = None
            artifacts.append(artifact_path)

        return fragments, sequences[:24], artifacts

    def _scan_pgf_marker_summary(self, snapshot: DbSnapshot) -> dict[str, object]:
        summary = {
            "fragment_marker_paths": set(),
            "codec_marker_paths": {},
            "init_marker_paths": set(),
            "valid_init_candidates": [],
        }
        for pgf_info in snapshot.pgf_inventory:
            pgf_path = pgf_info.path
            if not pgf_path.exists():
                continue
            with open(pgf_path, "rb") as handle:
                mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    for marker_name, marker in self.PGF_FRAGMENT_MARKERS.items():
                        if mm.find(marker) >= 0:
                            summary["fragment_marker_paths"].add(marker_name)
                    for marker_name, marker in self.PGF_CODEC_MARKERS.items():
                        if mm.find(marker) >= 0:
                            summary["codec_marker_paths"][marker_name] = (
                                summary["codec_marker_paths"].get(marker_name, 0) + 1
                            )
                    for marker_name, marker in self.PGF_INIT_MARKERS.items():
                        pos = mm.find(marker)
                        if pos >= 0:
                            summary["init_marker_paths"].add(marker_name)
                            if marker_name == "ftyp" and pos >= 4:
                                box_start = pos - 4
                                box_size = self._read_u32(mm, box_start)
                                if 16 <= box_size <= 4 * 1024 * 1024 and box_start + box_size + 8 <= len(mm):
                                    next_type = mm[box_start + box_size + 4 : box_start + box_size + 8]
                                    if next_type == b"moov":
                                        summary["valid_init_candidates"].append(
                                            {
                                                "pgf_path": str(pgf_path),
                                                "ftyp_offset": box_start,
                                                "ftyp_size": box_size,
                                            }
                                        )
                finally:
                    mm.close()
        summary["fragment_marker_paths"] = sorted(summary["fragment_marker_paths"])
        summary["init_marker_paths"] = sorted(summary["init_marker_paths"])
        return summary

    def _try_parse_pgf_fragment(
        self,
        mm: mmap.mmap,
        pgf_path: Path,
        sidx_pos: int,
    ) -> PgfFragmentInfo | None:
        if sidx_pos < 4:
            return None
        sidx_offset = sidx_pos - 4
        sidx_size = self._read_u32(mm, sidx_offset)
        if sidx_size < 44 or sidx_size > self.MAX_SIDX_SIZE:
            return None
        if sidx_offset + sidx_size > len(mm):
            return None
        if mm[sidx_offset + 4 : sidx_offset + 8] != b"sidx":
            return None

        sidx_payload = mm[sidx_offset : sidx_offset + sidx_size]
        sidx_info = self._parse_sidx_box(sidx_payload)
        if sidx_info is None:
            return None

        moof_offset = sidx_offset + sidx_size
        moof_size = self._read_u32(mm, moof_offset)
        if moof_size < 16 or moof_size > self.MAX_MEDIA_BOX_SIZE:
            return None
        if moof_offset + moof_size > len(mm):
            return None
        if mm[moof_offset + 4 : moof_offset + 8] != b"moof":
            return None

        mdat_offset = moof_offset + moof_size
        mdat_size = self._read_u32(mm, mdat_offset)
        if mdat_size < 16 or mdat_size > self.MAX_MEDIA_BOX_SIZE:
            return None
        if mdat_offset + mdat_size > len(mm):
            return None
        if mm[mdat_offset + 4 : mdat_offset + 8] != b"mdat":
            return None

        moof_info = self._parse_moof_metadata(mm[moof_offset : moof_offset + moof_size], sidx_info["timescale"])
        note = ""
        expected_payload = moof_size + mdat_size
        declared_sizes = sidx_info["reference_sizes"]
        if declared_sizes and declared_sizes[0] != expected_payload:
            note = (
                f"sidx ref size {declared_sizes[0]} differs from contiguous moof+mdat size {expected_payload}"
            )
        if moof_info["has_senc"]:
            if note:
                note += "; "
            note += "fragment carries saiz/saio/senc sample encryption boxes"

        return PgfFragmentInfo(
            pgf_path=pgf_path,
            sidx_offset=sidx_offset,
            sidx_size=sidx_size,
            moof_offset=moof_offset,
            moof_size=moof_size,
            mdat_offset=mdat_offset,
            mdat_size=mdat_size,
            total_size=sidx_size + moof_size + mdat_size,
            timescale=sidx_info["timescale"],
            earliest_presentation_sec=sidx_info["earliest_presentation_sec"],
            duration_sec=sidx_info["duration_sec"],
            ref_count=sidx_info["ref_count"],
            sequence_number=moof_info["sequence_number"],
            track_id=moof_info["track_id"],
            decode_time_sec=moof_info["decode_time_sec"],
            sample_count=moof_info["sample_count"],
            has_saiz=moof_info["has_saiz"],
            has_saio=moof_info["has_saio"],
            has_senc=moof_info["has_senc"],
            reference_sizes=declared_sizes,
            note=note,
        )

    @staticmethod
    def _read_u32(mm: mmap.mmap, offset: int) -> int:
        if offset < 0 or offset + 4 > len(mm):
            return 0
        return struct.unpack(">I", mm[offset : offset + 4])[0]

    @staticmethod
    def _parse_sidx_box(box: bytes) -> dict[str, object] | None:
        if len(box) < 32 or box[4:8] != b"sidx":
            return None
        version = box[8]
        timescale = struct.unpack(">I", box[16:20])[0]
        if timescale <= 0:
            return None
        if version == 0:
            if len(box) < 32:
                return None
            earliest = struct.unpack(">I", box[20:24])[0]
            first_offset = struct.unpack(">I", box[24:28])[0]
            count_offset = 30
            refs_offset = 32
        elif version == 1:
            if len(box) < 40:
                return None
            earliest = struct.unpack(">Q", box[20:28])[0]
            first_offset = struct.unpack(">Q", box[28:36])[0]
            count_offset = 38
            refs_offset = 40
        else:
            return None

        ref_count = struct.unpack(">H", box[count_offset : count_offset + 2])[0]
        reference_sizes: list[int] = []
        total_duration = 0.0
        pos = refs_offset
        for _ in range(ref_count):
            if pos + 12 > len(box):
                break
            ref_type_size = struct.unpack(">I", box[pos : pos + 4])[0]
            subsegment_duration = struct.unpack(">I", box[pos + 4 : pos + 8])[0]
            reference_sizes.append(ref_type_size & 0x7FFFFFFF)
            total_duration += subsegment_duration / timescale
            pos += 12

        return {
            "version": version,
            "timescale": timescale,
            "earliest_presentation_sec": earliest / timescale,
            "first_offset": first_offset,
            "ref_count": ref_count,
            "duration_sec": total_duration,
            "reference_sizes": reference_sizes,
        }

    @staticmethod
    def _parse_moof_metadata(box: bytes, timescale: int) -> dict[str, object]:
        info = {
            "sequence_number": 0,
            "track_id": 0,
            "decode_time_sec": 0.0,
            "sample_count": 0,
            "has_saiz": False,
            "has_saio": False,
            "has_senc": False,
        }
        if len(box) < 8 or box[4:8] != b"moof":
            return info
        pos = 8
        while pos + 8 <= len(box):
            size = struct.unpack(">I", box[pos : pos + 4])[0]
            if size < 8 or pos + size > len(box):
                break
            box_type = box[pos + 4 : pos + 8]
            if box_type == b"mfhd" and size >= 16:
                info["sequence_number"] = struct.unpack(">I", box[pos + 12 : pos + 16])[0]
            elif box_type == b"traf":
                traf_end = pos + size
                tpos = pos + 8
                while tpos + 8 <= traf_end:
                    tsize = struct.unpack(">I", box[tpos : tpos + 4])[0]
                    if tsize < 8 or tpos + tsize > traf_end:
                        break
                    ttype = box[tpos + 4 : tpos + 8]
                    if ttype == b"tfhd" and tsize >= 16:
                        info["track_id"] = struct.unpack(">I", box[tpos + 12 : tpos + 16])[0]
                    elif ttype == b"tfdt":
                        version = box[tpos + 8]
                        if version == 1 and tsize >= 20:
                            decode_time = struct.unpack(">Q", box[tpos + 12 : tpos + 20])[0]
                        elif tsize >= 16:
                            decode_time = struct.unpack(">I", box[tpos + 12 : tpos + 16])[0]
                        else:
                            decode_time = 0
                        if timescale > 0:
                            info["decode_time_sec"] = decode_time / timescale
                    elif ttype == b"trun" and tsize >= 16:
                        info["sample_count"] = struct.unpack(">I", box[tpos + 12 : tpos + 16])[0]
                    elif ttype == b"saiz":
                        info["has_saiz"] = True
                    elif ttype == b"saio":
                        info["has_saio"] = True
                    elif ttype == b"senc":
                        info["has_senc"] = True
                    tpos += tsize
            pos += size
        return info

    @staticmethod
    def _group_pgf_sequences(fragments: list[PgfFragmentInfo]) -> list[PgfSequenceInfo]:
        if not fragments:
            return []
        grouped: list[PgfSequenceInfo] = []
        items = sorted(
            fragments,
            key=lambda item: (
                item.earliest_presentation_sec,
                str(item.pgf_path),
                item.sidx_offset,
            ),
        )
        current: list[PgfFragmentInfo] = []
        for fragment in items:
            if not current:
                current = [fragment]
                continue
            previous = current[-1]
            previous_end = previous.earliest_presentation_sec + previous.duration_sec
            if abs(fragment.earliest_presentation_sec - previous_end) <= 0.25:
                current.append(fragment)
                continue
            grouped.append(DbPrototypeRebuilder._build_sequence(current))
            current = [fragment]
        if current:
            grouped.append(DbPrototypeRebuilder._build_sequence(current))

        grouped.sort(key=lambda item: (-item.total_duration_sec, -item.fragment_count, str(item.pgf_path)))
        return grouped

    @staticmethod
    def _build_sequence(fragments: list[PgfFragmentInfo]) -> PgfSequenceInfo:
        total_duration = sum(item.duration_sec for item in fragments)
        avg_duration = total_duration / len(fragments) if fragments else 0.0
        unique_paths = sorted({str(item.pgf_path) for item in fragments})
        return PgfSequenceInfo(
            pgf_path=fragments[0].pgf_path,
            pgf_paths=unique_paths,
            fragment_count=len(fragments),
            start_earliest_sec=fragments[0].earliest_presentation_sec,
            end_earliest_sec=fragments[-1].earliest_presentation_sec + fragments[-1].duration_sec,
            total_duration_sec=round(total_duration, 6),
            avg_fragment_duration_sec=round(avg_duration, 6),
            first_sidx_offset=fragments[0].sidx_offset,
            last_sidx_offset=fragments[-1].sidx_offset,
            note=(
                "Contiguous PGF fMP4 fragment sequence inferred from sidx earliest-time continuity"
                + (" across multiple PGF files." if len(unique_paths) > 1 else ".")
            ),
        )

    @staticmethod
    def _find_sequence_chain(
        pgf_sequences: list[PgfSequenceInfo],
        target_duration_sec: float,
    ) -> dict[str, float] | None:
        if not pgf_sequences:
            return None
        sequences = sorted(pgf_sequences, key=lambda item: (item.start_earliest_sec, item.end_earliest_sec))
        best: dict[str, float] | None = None
        best_score: tuple[float, float, float] | None = None
        for index, first in enumerate(sequences):
            if first.start_earliest_sec > 120.0:
                break
            chain = [first]
            current_end = first.end_earliest_sec
            media_total = first.total_duration_sec
            gap_total = 0.0
            for candidate in sequences[index + 1 :]:
                if candidate.start_earliest_sec <= current_end + 0.25:
                    if candidate.end_earliest_sec > current_end:
                        current_end = candidate.end_earliest_sec
                    media_total += candidate.total_duration_sec
                    chain.append(candidate)
                    continue
                gap = candidate.start_earliest_sec - current_end
                if gap > 120.0:
                    break
                gap_total += gap
                chain.append(candidate)
                current_end = candidate.end_earliest_sec
                media_total += candidate.total_duration_sec
                if current_end >= target_duration_sec - 12.0:
                    break
            score = (
                abs(current_end - target_duration_sec),
                gap_total,
                -media_total,
            )
            if best_score is None or score < best_score:
                best_score = score
                best = {
                    "start_sec": chain[0].start_earliest_sec,
                    "end_sec": current_end,
                    "media_sec": round(media_total, 6),
                    "gap_sec": round(gap_total, 6),
                    "sequence_count": float(len(chain)),
                }
        return best

    @staticmethod
    def _strip_prefixed_packets(blob: bytes, stride: int, emit_offset: int) -> bytes:
        chunks: list[bytes] = []
        for offset in range(0, len(blob) - stride + 1, stride):
            chunk = blob[offset : offset + stride]
            chunks.append(chunk[emit_offset:])
        return b"".join(chunks)
