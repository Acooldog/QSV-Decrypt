from __future__ import annotations

import base64
import json
import logging
import shutil
import re
import subprocess
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from Crypto.Cipher import Blowfish

from src.Application.models import (
    BbtsRepairCandidateInfo,
    BbtsRepairPlan,
    BbtsRepairSegmentInfo,
    ProbeSummary,
)
from src.Infrastructure.ffmpeg_tools import FfmpegTools
from src.Infrastructure.runtime_paths import get_log_day_dir


logger = logging.getLogger("aqy_decrypt")


@dataclass
class _TsPayloadLayout:
    payload: bytes
    ranges: list[tuple[int, int]]


@dataclass
class _NalUnit:
    start_code_offset: int
    start_code_size: int
    nal_offset: int
    nal_end: int
    nal_type: int


class BbtsVariantRebuilder:
    PACKET_SIZE = 188
    VIDEO_PID = 0x100
    PARAMETER_SET_TYPES = {32, 33, 34}
    VCL_TYPES = set(range(0, 32))

    def __init__(self, ffmpeg_tools: FfmpegTools) -> None:
        self.ffmpeg_tools = ffmpeg_tools

    def rebuild(
        self,
        sample_path: Path,
        segments_dir: Path,
        dispatch_json_path: Path,
        output_root: Path | None = None,
    ) -> BbtsRepairPlan:
        output_root = output_root or (get_log_day_dir() / "bbts_repair" / sample_path.stem)
        output_root.mkdir(parents=True, exist_ok=True)
        segment_output_dir = output_root / "segments"
        segment_output_dir.mkdir(parents=True, exist_ok=True)

        dispatch_map = self._load_dispatch_map(dispatch_json_path)
        segment_paths = sorted(segments_dir.glob("*.ts"))
        if not segment_paths:
            raise FileNotFoundError(f"No segment TS files found in {segments_dir}")

        segment0_path = self._find_segment_path(segment_paths, 0)
        if segment0_path is None:
            raise FileNotFoundError("Segment 0 TS is required for parameter-set bootstrap")

        seg0_bytes = segment0_path.read_bytes()
        seg0_layout = self._extract_video_payload(seg0_bytes)
        seg0_prefix = self._extract_parameter_prefix(seg0_layout.payload)
        if not seg0_prefix:
            raise RuntimeError("Unable to extract HEVC parameter prefix from segment 0")

        segment_results: list[BbtsRepairSegmentInfo] = []
        selected_segment_paths: list[Path] = []
        artifact_paths: list[Path] = []
        notes: list[str] = []

        for segment_path in segment_paths:
            segment_index = int(segment_path.stem)
            if segment_index == 0:
                copied_path = segment_output_dir / segment_path.name
                copied_path.write_bytes(seg0_bytes)
                probe = self.ffmpeg_tools.probe(copied_path)
                result = BbtsRepairSegmentInfo(
                    segment_index=0,
                    input_path=segment_path,
                    output_path=copied_path,
                    selected_candidate=BbtsRepairCandidateInfo(
                        candidate_name="passthrough-seg0",
                        key_hex="",
                        operation="copy",
                        source="segment0",
                        window_offset=0,
                        score=self._score_probe(probe),
                        video_duration_sec=self._video_duration(probe),
                        audio_duration_sec=self._audio_duration(probe),
                        width=self._video_width(probe),
                        height=self._video_height(probe),
                        nb_frames=self._video_frames(probe),
                        note="Original segment 0 copied verbatim; used as HEVC bootstrap source.",
                    ),
                    candidate_count=1,
                    top_candidates=[],
                    probe_summary=probe,
                    note="Baseline segment 0.",
                )
                segment_results.append(result)
                selected_segment_paths.append(copied_path)
                artifact_paths.append(copied_path)
                continue

            result = self._repair_segment(
                segment_index=segment_index,
                segment_path=segment_path,
                seg0_prefix=seg0_prefix,
                dispatch_entry=dispatch_map.get(segment_index, {}),
                output_dir=segment_output_dir,
            )
            segment_results.append(result)
            if result.output_path is not None:
                selected_segment_paths.append(result.output_path)
                artifact_paths.append(result.output_path)
            else:
                selected_segment_paths.append(segment_path)
                notes.append(
                    f"Segment {segment_index} had no selected output; falling back to original segment bytes."
                )

        final_ts_path = output_root / f"{sample_path.stem}.patched.ts"
        with open(final_ts_path, "wb") as handle:
            for path in selected_segment_paths:
                handle.write(path.read_bytes())
        artifact_paths.append(final_ts_path)

        concat_list_path = output_root / "selected_ts_concat.txt"
        concat_list_path.write_text(
            self._build_concat_list(selected_segment_paths),
            encoding="utf-8",
        )
        artifact_paths.append(concat_list_path)

        copy_mp4_path = output_root / f"{sample_path.stem}.patched.copy.mp4"
        final_mp4_path = output_root / f"{sample_path.stem}.patched.mp4"
        final_probe = self._concat_segments_to_mp4(concat_list_path, copy_mp4_path)
        if copy_mp4_path.exists():
            artifact_paths.append(copy_mp4_path)
            shutil.copyfile(copy_mp4_path, final_mp4_path)
            final_probe = self.ffmpeg_tools.probe(final_mp4_path)
            artifact_paths.append(final_mp4_path)

        if self._should_try_tail_pad(final_probe):
            audio_duration = self._audio_duration(final_probe)
            video_duration = self._video_duration(final_probe)
            pad_duration = max(10.0, (audio_duration - video_duration) + 4.0)
            repaired_mp4_path = output_root / f"{sample_path.stem}.patched.reencode.mp4"
            repaired_probe = self._reencode_concat_with_tail_pad(
                concat_list_path=concat_list_path,
                mp4_path=repaired_mp4_path,
                tail_pad_sec=pad_duration,
            )
            if repaired_mp4_path.exists():
                artifact_paths.append(repaired_mp4_path)
            if self._probe_is_better(repaired_probe, final_probe):
                if final_mp4_path.exists():
                    final_mp4_path.unlink()
                shutil.copyfile(repaired_mp4_path, final_mp4_path)
                final_probe = self.ffmpeg_tools.probe(final_mp4_path)
                if final_mp4_path not in artifact_paths:
                    artifact_paths.append(final_mp4_path)
                notes.append(
                    "Tail repair selected re-encoded MP4 with cloned last frame to close residual video gap."
                )

        status = self._status_from_probe(final_probe)
        if final_probe.ok:
            notes.append(
                f"Final prototype probe: video={self._video_duration(final_probe):.3f}s "
                f"audio={self._audio_duration(final_probe):.3f}s "
                f"format={final_probe.duration_sec:.3f}s."
            )
            notes.append("Final MP4 built via ffmpeg concat demuxer with +genpts over selected TS segments.")
        else:
            notes.append("Concat demuxer probe failed; inspect selected_ts_concat.txt and segment outputs.")
        report = BbtsRepairPlan(
            sample_path=sample_path,
            segments_dir=segments_dir,
            dispatch_json_path=dispatch_json_path,
            status=status,
            segment_results=segment_results,
            output_ts_path=final_ts_path,
            output_mp4_path=final_mp4_path if final_mp4_path.exists() else None,
            final_probe_summary=final_probe,
            artifact_paths=artifact_paths,
            notes=notes,
        )
        report_path = output_root / f"{sample_path.stem}.bbts_repair.json"
        report_path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        report.artifact_paths.append(report_path)
        return report

    def _repair_segment(
        self,
        segment_index: int,
        segment_path: Path,
        seg0_prefix: bytes,
        dispatch_entry: dict[str, object],
        output_dir: Path,
    ) -> BbtsRepairSegmentInfo:
        original_bytes = segment_path.read_bytes()
        layout = self._extract_video_payload(original_bytes)
        candidate_specs = self._build_candidate_specs(dispatch_entry)
        if not candidate_specs:
            probe = self.ffmpeg_tools.probe(segment_path)
            return BbtsRepairSegmentInfo(
                segment_index=segment_index,
                input_path=segment_path,
                output_path=None,
                selected_candidate=None,
                candidate_count=0,
                top_candidates=[],
                probe_summary=probe,
                note="No dispatch key candidates available for this segment.",
            )

        candidate_infos: list[tuple[BbtsRepairCandidateInfo, Path]] = []
        original_probe = self.ffmpeg_tools.probe(segment_path)
        identity_info = BbtsRepairCandidateInfo(
            candidate_name="identity-bootstrap",
            key_hex="",
            operation="identity",
            source="bootstrap",
            window_offset=0,
            score=self._score_probe(original_probe),
            video_duration_sec=self._video_duration(original_probe),
            audio_duration_sec=self._audio_duration(original_probe),
            width=self._video_width(original_probe),
            height=self._video_height(original_probe),
            nb_frames=self._video_frames(original_probe),
            note="Original segment without BBTS body transform.",
        )
        candidate_infos.append((identity_info, segment_path))

        for spec in candidate_specs:
            patched_ts = self._patch_segment_bytes(
                segment_bytes=original_bytes,
                layout=layout,
                seg0_prefix=seg0_prefix,
                key=spec["key"],
                operation=str(spec["operation"]),
            )
            candidate_ts_path = output_dir / f"{segment_index:02d}.{spec['name']}.ts"
            candidate_ts_path.write_bytes(patched_ts)
            probe = self.ffmpeg_tools.probe(candidate_ts_path)
            info = BbtsRepairCandidateInfo(
                candidate_name=str(spec["name"]),
                key_hex=spec["key"].hex(),
                operation=str(spec["operation"]),
                source=str(spec["source"]),
                window_offset=int(spec["window_offset"]),
                score=self._score_probe(probe),
                video_duration_sec=self._video_duration(probe),
                audio_duration_sec=self._audio_duration(probe),
                width=self._video_width(probe),
                height=self._video_height(probe),
                nb_frames=self._video_frames(probe),
                note="Scored from direct ffprobe on patched TS.",
            )
            candidate_infos.append((info, candidate_ts_path))

        candidate_infos.sort(key=lambda item: item[0].score, reverse=True)
        self._apply_visual_scores(candidate_infos)
        candidate_infos.sort(
            key=lambda item: (self._combined_candidate_score(item[0]), item[0].score),
            reverse=True,
        )
        top_candidates = [item[0] for item in candidate_infos[:3]]
        selected_info, selected_path = candidate_infos[0]
        selected_output_path = output_dir / f"{segment_index:02d}.selected.ts"
        if selected_path.resolve() != selected_output_path.resolve():
            shutil.copyfile(selected_path, selected_output_path)
        selected_probe = self.ffmpeg_tools.probe(selected_output_path)
        return BbtsRepairSegmentInfo(
            segment_index=segment_index,
            input_path=segment_path,
            output_path=selected_output_path,
            selected_candidate=selected_info,
            candidate_count=len(candidate_infos),
            top_candidates=top_candidates,
            probe_summary=selected_probe,
            note="Selected the highest-scoring BBTS repair candidate.",
        )

    def _apply_visual_scores(self, candidate_infos: list[tuple[BbtsRepairCandidateInfo, Path]]) -> None:
        if not candidate_infos:
            return
        max_probe_score = max(item[0].score for item in candidate_infos)
        shortlist: list[tuple[BbtsRepairCandidateInfo, Path]] = []
        for info, path in candidate_infos:
            if len(shortlist) >= 8:
                break
            if info.score + 2048 < max_probe_score:
                continue
            shortlist.append((info, path))
        if not shortlist:
            shortlist = candidate_infos[:4]
        for info, path in shortlist:
            timestamps = self._sample_timestamps(info.video_duration_sec)
            frame_stats = self.ffmpeg_tools.sample_gray_frame_stats(path, timestamps)
            if not frame_stats:
                frame_stats = []
            if frame_stats:
                info.frame_sample_count = len(frame_stats)
                info.frame_entropy_avg = round(sum(item["entropy"] for item in frame_stats) / len(frame_stats), 6)
                info.frame_stddev_avg = round(sum(item["stddev"] for item in frame_stats) / len(frame_stats), 6)
                info.dominant_ratio_max = round(max(item["dominant_ratio"] for item in frame_stats), 6)
                info.visual_score = round(self._visual_score(frame_stats), 3)
                info.note += (
                    f" Visual frames={info.frame_sample_count} "
                    f"entropy_avg={info.frame_entropy_avg:.3f} "
                    f"stddev_avg={info.frame_stddev_avg:.3f} "
                    f"dominant_max={info.dominant_ratio_max:.3f}."
                )
            health = self.ffmpeg_tools.decode_video_health(path)
            info.decoded_video_sec = float(health.get("decoded_video_sec") or 0.0)
            info.decode_error_lines = int(health.get("decode_error_lines") or 0.0)
            info.note += (
                f" Decode health video_sec={info.decoded_video_sec:.3f} "
                f"errors={info.decode_error_lines}."
            )

    @staticmethod
    def _sample_timestamps(video_duration_sec: float) -> list[float]:
        if video_duration_sec <= 0:
            return [1.0, 3.0, 5.0]
        if video_duration_sec < 15.0:
            return [max(0.0, video_duration_sec * ratio) for ratio in (0.15, 0.5, 0.85)]
        return [max(0.5, video_duration_sec * ratio) for ratio in (0.12, 0.5, 0.88)]

    @staticmethod
    def _visual_score(frame_stats: list[dict[str, float]]) -> float:
        if not frame_stats:
            return 0.0
        entropy_avg = sum(item["entropy"] for item in frame_stats) / len(frame_stats)
        stddev_avg = sum(item["stddev"] for item in frame_stats) / len(frame_stats)
        dominant_max = max(item["dominant_ratio"] for item in frame_stats)
        return (entropy_avg * 140.0) + (stddev_avg * 8.0) + ((1.0 - dominant_max) * 500.0)

    @staticmethod
    def _combined_candidate_score(info: BbtsRepairCandidateInfo) -> float:
        decode_bonus = info.decoded_video_sec * 100.0
        error_penalty = min(info.decode_error_lines, 50000) * 0.05
        return float(info.score) + float(info.visual_score) + decode_bonus - error_penalty

    def _patch_segment_bytes(
        self,
        segment_bytes: bytes,
        layout: _TsPayloadLayout,
        seg0_prefix: bytes,
        key: bytes,
        operation: str,
    ) -> bytes:
        patched_payload = bytearray(layout.payload)
        self._inject_parameter_prefix(patched_payload, seg0_prefix)
        self._transform_slice_nals(patched_payload, key=key, operation=operation)
        return self._write_video_payload(segment_bytes, layout.ranges, bytes(patched_payload))

    @classmethod
    def _extract_video_payload(cls, ts_bytes: bytes) -> _TsPayloadLayout:
        payload_parts: list[bytes] = []
        ranges: list[tuple[int, int]] = []
        packet_count = len(ts_bytes) // cls.PACKET_SIZE
        for packet_index in range(packet_count):
            packet_start = packet_index * cls.PACKET_SIZE
            packet = ts_bytes[packet_start : packet_start + cls.PACKET_SIZE]
            if len(packet) != cls.PACKET_SIZE or packet[0] != 0x47:
                continue
            pid = ((packet[1] & 0x1F) << 8) | packet[2]
            if pid != cls.VIDEO_PID:
                continue
            adaptation_field_control = (packet[3] >> 4) & 0x03
            payload_offset = 4
            if adaptation_field_control in {2, 3}:
                adaptation_length = packet[4]
                payload_offset = 5 + adaptation_length
            if adaptation_field_control in {0, 2} or payload_offset >= cls.PACKET_SIZE:
                continue
            payload = packet[payload_offset:]
            payload_start = packet_start + payload_offset
            payload_unit_start_indicator = (packet[1] >> 6) & 0x01
            if payload_unit_start_indicator:
                pes_skip = cls._pes_header_skip(payload)
                if pes_skip > 0:
                    payload = payload[pes_skip:]
                    payload_start += pes_skip
            if not payload:
                continue
            payload_parts.append(payload)
            ranges.append((payload_start, len(payload)))
        return _TsPayloadLayout(payload=b"".join(payload_parts), ranges=ranges)

    @staticmethod
    def _pes_header_skip(payload: bytes) -> int:
        if len(payload) < 9:
            return 0
        if payload[:3] != b"\x00\x00\x01":
            return 0
        stream_id = payload[3]
        if stream_id in {
            0xBC,
            0xBE,
            0xBF,
            0xF0,
            0xF1,
            0xFF,
            0xF2,
            0xF8,
        }:
            return 6
        header_data_length = payload[8]
        header_len = 9 + header_data_length
        if header_len > len(payload):
            return 0
        return header_len

    @staticmethod
    def _write_video_payload(segment_bytes: bytes, ranges: list[tuple[int, int]], payload: bytes) -> bytes:
        mutable = bytearray(segment_bytes)
        cursor = 0
        for offset, length in ranges:
            chunk = payload[cursor : cursor + length]
            if len(chunk) != length:
                raise ValueError("Payload/range length mismatch while writing patched TS")
            mutable[offset : offset + length] = chunk
            cursor += length
        if cursor != len(payload):
            raise ValueError("Unconsumed payload bytes remain after TS rewrite")
        return bytes(mutable)

    @classmethod
    def _iter_nalus(cls, payload: bytes) -> list[_NalUnit]:
        matches = list(re.finditer(b"\x00\x00\x01|\x00\x00\x00\x01", payload))
        nalus: list[_NalUnit] = []
        for index, match in enumerate(matches):
            start_code_offset = match.start()
            start_code_size = len(match.group(0))
            nal_offset = start_code_offset + start_code_size
            if nal_offset >= len(payload):
                continue
            nal_end = matches[index + 1].start() if index + 1 < len(matches) else len(payload)
            nal_header = payload[nal_offset]
            nal_type = (nal_header >> 1) & 0x3F
            nalus.append(
                _NalUnit(
                    start_code_offset=start_code_offset,
                    start_code_size=start_code_size,
                    nal_offset=nal_offset,
                    nal_end=nal_end,
                    nal_type=nal_type,
                )
            )
        return nalus

    @classmethod
    def _extract_parameter_prefix(cls, payload: bytes) -> bytes:
        nalus = cls._iter_nalus(payload)
        prefix_start: int | None = None
        prefix_end: int | None = None
        for nal in nalus:
            if nal.nal_type in cls.PARAMETER_SET_TYPES and prefix_start is None:
                prefix_start = nal.start_code_offset
            if nal.nal_type in cls.VCL_TYPES:
                prefix_end = nal.start_code_offset
                break
        if prefix_start is None or prefix_end is None or prefix_end <= prefix_start:
            return b""
        return payload[prefix_start:prefix_end]

    @classmethod
    def _inject_parameter_prefix(cls, payload: bytearray, seg0_prefix: bytes) -> None:
        nalus = cls._iter_nalus(bytes(payload))
        prefix_start: int | None = None
        prefix_end: int | None = None
        for nal in nalus:
            if nal.nal_type in cls.PARAMETER_SET_TYPES and prefix_start is None:
                prefix_start = nal.start_code_offset
            if nal.nal_type in cls.VCL_TYPES:
                prefix_end = nal.start_code_offset
                break
        if prefix_start is None or prefix_end is None or prefix_end <= prefix_start:
            return
        window_len = prefix_end - prefix_start
        replacement = seg0_prefix[:window_len]
        if len(replacement) < window_len:
            replacement = replacement + payload[prefix_start + len(replacement) : prefix_start + window_len]
        payload[prefix_start:prefix_end] = replacement

    @classmethod
    def _transform_slice_nals(cls, payload: bytearray, key: bytes, operation: str) -> None:
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        for nal in cls._iter_nalus(bytes(payload)):
            if nal.nal_type not in cls.VCL_TYPES:
                continue
            body_offset = nal.nal_offset + 5
            if body_offset >= nal.nal_end:
                continue
            body_len = nal.nal_end - body_offset
            block_len = body_len - (body_len % 8)
            if block_len <= 0:
                continue
            original = bytes(payload[body_offset : body_offset + block_len])
            if operation == "encrypt":
                transformed = cipher.encrypt(original)
            else:
                transformed = cipher.decrypt(original)
            payload[body_offset : body_offset + block_len] = transformed

    @staticmethod
    def _score_probe(probe: ProbeSummary) -> int:
        if not probe.ok:
            return -1
        score = 0
        score += probe.video_streams * 100000
        width = BbtsVariantRebuilder._video_width(probe)
        height = BbtsVariantRebuilder._video_height(probe)
        if width > 0 and height > 0:
            score += 10000
        score += int(BbtsVariantRebuilder._video_duration(probe) * 100)
        score += min(BbtsVariantRebuilder._video_frames(probe), 50000)
        return score

    @staticmethod
    def _video_stream(probe: ProbeSummary) -> dict[str, object] | None:
        streams = probe.raw.get("streams") if isinstance(probe.raw, dict) else None
        if not isinstance(streams, list):
            return None
        for stream in streams:
            if isinstance(stream, dict) and stream.get("codec_type") == "video":
                return stream
        return None

    @classmethod
    def _video_width(cls, probe: ProbeSummary) -> int:
        stream = cls._video_stream(probe)
        value = stream.get("width") if isinstance(stream, dict) else 0
        return int(value or 0)

    @classmethod
    def _video_height(cls, probe: ProbeSummary) -> int:
        stream = cls._video_stream(probe)
        value = stream.get("height") if isinstance(stream, dict) else 0
        return int(value or 0)

    @classmethod
    def _video_frames(cls, probe: ProbeSummary) -> int:
        stream = cls._video_stream(probe)
        if not isinstance(stream, dict):
            return 0
        nb_frames = stream.get("nb_frames")
        if nb_frames in (None, "N/A", ""):
            return 0
        try:
            return int(float(str(nb_frames)))
        except ValueError:
            return 0

    @classmethod
    def _video_duration(cls, probe: ProbeSummary) -> float:
        stream = cls._video_stream(probe)
        if not isinstance(stream, dict):
            return 0.0
        try:
            return float(stream.get("duration") or 0.0)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _audio_duration(probe: ProbeSummary) -> float:
        streams = probe.raw.get("streams") if isinstance(probe.raw, dict) else None
        if not isinstance(streams, list):
            return 0.0
        durations: list[float] = []
        for stream in streams:
            if not isinstance(stream, dict) or stream.get("codec_type") != "audio":
                continue
            try:
                durations.append(float(stream.get("duration") or 0.0))
            except (TypeError, ValueError):
                continue
        return max(durations, default=0.0)

    @staticmethod
    def _status_from_probe(probe: ProbeSummary) -> str:
        if not probe.ok or probe.video_streams == 0:
            return "failed"
        video_duration = BbtsVariantRebuilder._video_duration(probe)
        audio_duration = BbtsVariantRebuilder._audio_duration(probe)
        if audio_duration > 0 and video_duration + 2.0 < audio_duration:
            return "partial_restore"
        return "success"

    def _concat_segments_to_mp4(self, concat_list_path: Path, mp4_path: Path) -> ProbeSummary:
        self.ffmpeg_tools.ensure_available()
        mp4_path.parent.mkdir(parents=True, exist_ok=True)
        command = [
            str(self.ffmpeg_tools.ffmpeg_path),
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "concat",
            "-safe",
            "0",
            "-fflags",
            "+genpts",
            "-i",
            str(concat_list_path),
            "-map",
            "0:v:0",
            "-map",
            "0:a?",
            "-c",
            "copy",
            "-copyinkf",
            "-movflags",
            "+faststart",
            "-bsf:a",
            "aac_adtstoasc",
            "-tag:v",
            "hvc1",
            str(mp4_path),
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or "ffmpeg concat demuxer failed")
            return self.ffmpeg_tools.probe(mp4_path)
        except Exception as exc:
            logger.debug("ffmpeg concat failed for %s: %s", concat_list_path, exc)
            return ProbeSummary(ok=False, raw={"stderr": str(exc)})

    def _reencode_concat_with_tail_pad(
        self,
        concat_list_path: Path,
        mp4_path: Path,
        tail_pad_sec: float,
    ) -> ProbeSummary:
        self.ffmpeg_tools.ensure_available()
        mp4_path.parent.mkdir(parents=True, exist_ok=True)
        encoder_variants = [
            (
                "h264_mf",
                [
                    "-c:v",
                    "h264_mf",
                    "-rate_control",
                    "quality",
                    "-quality",
                    "70",
                ],
            ),
            (
                "libx264",
                [
                    "-c:v",
                    "libx264",
                    "-preset",
                    "ultrafast",
                    "-crf",
                    "23",
                ],
            ),
        ]
        last_error = "unknown encoder error"
        for encoder_name, encoder_args in encoder_variants:
            command = [
                str(self.ffmpeg_tools.ffmpeg_path),
                "-y",
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "concat",
                "-safe",
                "0",
                "-fflags",
                "+genpts+discardcorrupt",
                "-err_detect",
                "ignore_err",
                "-i",
                str(concat_list_path),
                "-map",
                "0:v:0",
                "-map",
                "0:a:0",
                "-vf",
                f"tpad=stop_mode=clone:stop_duration={tail_pad_sec:.3f}",
                *encoder_args,
                "-c:a",
                "aac",
                "-b:a",
                "192k",
                "-movflags",
                "+faststart",
                "-shortest",
                str(mp4_path),
            ]
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                )
            except Exception as exc:
                last_error = str(exc)
                continue
            if completed.returncode == 0:
                logger.debug("tail-pad reencode succeeded with %s for %s", encoder_name, concat_list_path)
                return self.ffmpeg_tools.probe(mp4_path)
            last_error = completed.stderr.strip() or f"{encoder_name} failed"
            logger.debug("tail-pad reencode failed with %s for %s: %s", encoder_name, concat_list_path, last_error)
        return ProbeSummary(ok=False, raw={"stderr": last_error})

    @staticmethod
    def _build_concat_list(segment_paths: list[Path]) -> str:
        lines: list[str] = []
        for path in segment_paths:
            normalized = path.resolve().as_posix().replace("'", r"'\''")
            lines.append(f"file '{normalized}'")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _find_segment_path(segment_paths: list[Path], segment_index: int) -> Path | None:
        name = f"{segment_index:02d}.ts"
        for path in segment_paths:
            if path.name == name:
                return path
        return None

    def _build_candidate_specs(self, dispatch_entry: dict[str, object]) -> list[dict[str, object]]:
        sources: list[tuple[str, bytes]] = []
        dispatch_hex = str(dispatch_entry.get("dispatch_key_hex") or "").strip().lower()
        if dispatch_hex:
            key_bytes = self._hex_to_bytes(dispatch_hex)
            if key_bytes:
                sources.append(("dispatch_key_hex", key_bytes))
        dispatch_b64 = str(dispatch_entry.get("dispatch_key_base64") or "").strip()
        if dispatch_b64:
            try:
                key_bytes = base64.b64decode(dispatch_b64)
            except Exception:
                key_bytes = b""
            if key_bytes:
                sources.append(("dispatch_key_base64", key_bytes))
        for url in dispatch_entry.get("dispatch_urls", []) or []:
            if not isinstance(url, str):
                continue
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            for raw_value in query.get("key", []):
                key_hex = raw_value.strip().lower()
                key_bytes = self._hex_to_bytes(key_hex)
                if key_bytes:
                    sources.append(("dispatch_url_key", key_bytes))

        candidate_specs: list[dict[str, object]] = []
        seen: set[tuple[str, str, str, int]] = set()
        for source_name, key_bytes in sources:
            if len(key_bytes) >= 8:
                for operation in ("decrypt", "encrypt"):
                    full_name = f"{source_name}.full.{operation}"
                    identity = (full_name, key_bytes.hex(), operation, 0)
                    if identity not in seen:
                        candidate_specs.append(
                            {
                                "name": full_name,
                                "key": key_bytes,
                                "operation": operation,
                                "source": source_name,
                                "window_offset": 0,
                            }
                        )
                        seen.add(identity)
                for offset in range(0, len(key_bytes) - 7):
                    window = key_bytes[offset : offset + 8]
                    for operation in ("decrypt", "encrypt"):
                        name = f"{source_name}.w{offset:02d}.{operation}"
                        identity = (name, window.hex(), operation, offset)
                        if identity in seen:
                            continue
                        candidate_specs.append(
                            {
                                "name": name,
                                "key": window,
                                "operation": operation,
                                "source": source_name,
                                "window_offset": offset,
                            }
                        )
                        seen.add(identity)
        return candidate_specs

    @staticmethod
    def _hex_to_bytes(value: str) -> bytes:
        value = value.strip().lower()
        if len(value) % 2 == 1:
            value = "0" + value
        try:
            return bytes.fromhex(value)
        except ValueError:
            return b""

    @staticmethod
    def _load_dispatch_map(dispatch_json_path: Path) -> dict[int, dict[str, object]]:
        raw = json.loads(dispatch_json_path.read_text(encoding="utf-8"))
        by_segnum: dict[int, dict[str, object]] = {}
        for item in raw:
            if not isinstance(item, dict):
                continue
            segnum = item.get("segnum")
            if not isinstance(segnum, int):
                continue
            existing = by_segnum.get(segnum)
            if existing is None:
                by_segnum[segnum] = dict(item)
                continue
            merged = dict(existing)
            for key in (
                "dispatch_key_hex",
                "dispatch_key_base64",
                "dispatch_urls",
                "run_offset",
                "run_length",
                "f4vsize",
                "rawurl_extension",
            ):
                value = item.get(key)
                if value not in (None, "", [], {}):
                    merged[key] = value
            by_segnum[segnum] = merged
        return by_segnum

    @classmethod
    def _probe_gap(cls, probe: ProbeSummary) -> float:
        return max(0.0, cls._audio_duration(probe) - cls._video_duration(probe))

    @classmethod
    def _should_try_tail_pad(cls, probe: ProbeSummary) -> bool:
        if not probe.ok or probe.video_streams == 0 or probe.audio_streams == 0:
            return False
        gap = cls._probe_gap(probe)
        return 0.0 < gap <= 12.0

    @classmethod
    def _probe_is_better(cls, candidate: ProbeSummary, baseline: ProbeSummary) -> bool:
        if not candidate.ok:
            return False
        candidate_status = cls._status_from_probe(candidate)
        baseline_status = cls._status_from_probe(baseline)
        if candidate_status == "success" and baseline_status != "success":
            return True
        return cls._probe_gap(candidate) + 0.5 < cls._probe_gap(baseline)
