from __future__ import annotations

import copy
import json
import logging
import shutil
import time
from pathlib import Path

from .models import BatchReport, FileDecryptResult, TimingBreakdown
from src.Infrastructure.ffmpeg_tools import FfmpegTools
from src.Infrastructure.qsv_offline import QsvOfflineDecoder
from src.Infrastructure.runtime_paths import get_log_day_dir


logger = logging.getLogger("aqy_decrypt")


class DecryptService:
    def __init__(
        self,
        decoder: QsvOfflineDecoder,
        ffmpeg_tools: FfmpegTools,
    ) -> None:
        self.decoder = decoder
        self.ffmpeg_tools = ffmpeg_tools

    def inspect(self, sample_path: Path) -> dict:
        inspection = self.decoder.inspect(sample_path)
        return inspection.to_dict()

    def decrypt_batch(
        self,
        input_root: Path,
        output_root: Path,
        recursive: bool = True,
    ) -> BatchReport:
        batch_start = time.perf_counter()
        pattern = "**/*.qsv" if recursive else "*.qsv"
        candidates = sorted(input_root.glob(pattern))
        report = BatchReport(input_root=input_root, output_root=output_root, candidate_count=len(candidates))
        logger.info("input_root: %s", input_root)
        logger.info("output_root: %s", output_root)
        logger.info("recursive: %s", recursive)
        logger.info("candidate_files: %s", len(candidates))

        for index, qsv_path in enumerate(candidates, start=1):
            logger.info("[%s/%s] decrypting: %s", index, len(candidates), qsv_path)
            result = self.decrypt_one(
                qsv_path=qsv_path,
                input_root=input_root,
                output_root=output_root,
            )
            report.results.append(result)
            hotspot_name, hotspot_total = result.timing.hotspot()
            logger.info(
                "[timing] file_done [%s/%s] %s status=%s source=%s scan=%.3fs analyze=%.3fs offline_decrypt=%.3fs hook_capture=%.3fs remux=%.3fs publish=%.3fs total=%.3fs hotspot=%s/%.3fs",
                index,
                len(candidates),
                qsv_path.name,
                result.status,
                result.source or "-",
                result.timing.scan_sec,
                result.timing.analyze_sec,
                result.timing.offline_decrypt_sec,
                result.timing.hook_capture_sec,
                result.timing.remux_sec,
                result.timing.publish_sec,
                result.timing.total_sec,
                hotspot_name,
                hotspot_total,
            )
        report.wall_sec = time.perf_counter() - batch_start
        self._write_batch_report(report)
        return report

    def decrypt_one(
        self,
        qsv_path: Path,
        input_root: Path,
        output_root: Path,
    ) -> FileDecryptResult:
        timing = TimingBreakdown()
        work_dir = get_log_day_dir() / "work" / qsv_path.stem
        failed_dir = get_log_day_dir() / "failed_raw" / qsv_path.stem
        failed_dir.mkdir(parents=True, exist_ok=True)
        start = time.perf_counter()

        inspection = None
        source = ""
        probe_summary = None
        remux_detail: dict[str, object] = {}
        final_output_path = output_root / qsv_path.relative_to(input_root)
        final_output_path = final_output_path.with_suffix(".mp4")

        try:
            scan_start = time.perf_counter()
            _ = qsv_path.stat()
            timing.scan_sec = time.perf_counter() - scan_start

            analyze_start = time.perf_counter()
            inspection = self.decoder.inspect(qsv_path)
            timing.analyze_sec = time.perf_counter() - analyze_start
            logger.info(
                "inspection: header=%s payload_offset=%s mode=%s sync_packets=%s db_hits=%s",
                inspection.header_magic,
                inspection.payload_offset,
                inspection.payload_mode,
                inspection.packet_sync_count,
                {name: len(values) for name, values in inspection.local_cache.hits.items()},
            )

            remux_input: Path | None = None
            if inspection.payload_offset is not None:
                offline_start = time.perf_counter()
                remux_input, _ = self.decoder.decode_to_ts(qsv_path, work_dir, inspection=inspection)
                timing.offline_decrypt_sec = time.perf_counter() - offline_start
                source = "offline"
                probe_summary = self.ffmpeg_tools.probe(remux_input)
                if not probe_summary.ok or (probe_summary.video_streams + probe_summary.audio_streams) == 0:
                    remux_input = None
                    source = ""

            if remux_input is None:
                self._write_failure_artifacts(qsv_path, failed_dir, inspection)
                return FileDecryptResult(
                    input_path=qsv_path,
                    output_path=None,
                    status="failed",
                    reason="offline_unresolved",
                    source=source,
                    inspection=inspection,
                    probe_summary=probe_summary,
                    timing=timing,
                    remux_detail=remux_detail,
                )

            remux_start = time.perf_counter()
            remux_target = work_dir / f"{qsv_path.stem}.mp4"
            remux_detail = self.ffmpeg_tools.remux_to_mp4(remux_input, remux_target)
            timing.remux_sec = time.perf_counter() - remux_start
            logger.info(
                "[timing] remux_detail %s mode=%s elapsed=%.3fs input_bytes=%s output_bytes=%s",
                qsv_path.name,
                remux_detail.get("mode", ""),
                float(remux_detail.get("elapsed_sec", 0.0)),
                remux_detail.get("input_bytes", 0),
                remux_detail.get("output_bytes", 0),
            )
            probe_summary = self.ffmpeg_tools.probe(remux_target)
            if not probe_summary.ok or probe_summary.video_streams == 0:
                self._write_failure_artifacts(
                    qsv_path,
                    failed_dir,
                    inspection,
                    probe_summary=probe_summary,
                    extra_paths=[remux_target],
                )
                return FileDecryptResult(
                    input_path=qsv_path,
                    output_path=None,
                    status="failed",
                    reason="remux_invalid_media",
                    source=source,
                    inspection=inspection,
                    probe_summary=probe_summary,
                    timing=timing,
                    remux_detail=remux_detail,
                )

            timeline_issue = self._validate_timeline(probe_summary)
            if timeline_issue is not None:
                inspection_for_failure = copy.deepcopy(inspection) if inspection else None
                if inspection_for_failure is not None:
                    inspection_for_failure.notes.append(timeline_issue)
                logger.warning("%s: %s", qsv_path.name, timeline_issue)
                self._write_failure_artifacts(
                    qsv_path,
                    failed_dir,
                    inspection_for_failure,
                    probe_summary=probe_summary,
                    extra_paths=[remux_input, remux_target],
                )
                return FileDecryptResult(
                    input_path=qsv_path,
                    output_path=None,
                    status="failed",
                    reason="incomplete_video_timeline",
                    source=source,
                    inspection=inspection_for_failure,
                    probe_summary=probe_summary,
                    timing=timing,
                    remux_detail=remux_detail,
                )

            publish_start = time.perf_counter()
            self._publish(remux_target, final_output_path)
            timing.publish_sec = time.perf_counter() - publish_start
            result = FileDecryptResult(
                input_path=qsv_path,
                output_path=final_output_path,
                status="success",
                reason="ok",
                source=source,
                inspection=inspection,
                probe_summary=probe_summary,
                timing=timing,
                remux_detail=remux_detail,
            )
            logger.info(
                "success: %s -> %s format=%s streams=%s source=%s",
                qsv_path.name,
                final_output_path,
                probe_summary.format_name,
                probe_summary.stream_count,
                source,
            )
            return result
        finally:
            timing.total_sec = time.perf_counter() - start

    @staticmethod
    def _publish(source_path: Path, target_path: Path) -> None:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        temp_target = target_path.with_suffix(target_path.suffix + ".tmp")
        shutil.copy2(source_path, temp_target)
        temp_target.replace(target_path)

    @staticmethod
    def _write_failure_artifacts(
        qsv_path: Path,
        failed_dir: Path,
        inspection,
        probe_summary=None,
        extra_paths: list[Path] | None = None,
    ) -> None:
        failed_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(qsv_path, failed_dir / qsv_path.name)
        if inspection:
            with open(failed_dir / f"{qsv_path.stem}.inspection.json", "w", encoding="utf-8") as handle:
                json.dump(inspection.to_dict(), handle, ensure_ascii=False, indent=2)
        if probe_summary:
            with open(failed_dir / f"{qsv_path.stem}.probe.json", "w", encoding="utf-8") as handle:
                json.dump(probe_summary.raw, handle, ensure_ascii=False, indent=2)
        for extra_path in extra_paths or []:
            if extra_path and extra_path.exists():
                shutil.copy2(extra_path, failed_dir / extra_path.name)

    @staticmethod
    def _write_batch_report(report: BatchReport) -> None:
        day_dir = get_log_day_dir()
        stamp = time.strftime("%H-%M-%S")
        report_json = day_dir / f"decrypt_batch_{stamp}.json"
        report_txt = day_dir / f"decrypt_batch_{stamp}.txt"
        payload = report.to_dict()
        with open(report_json, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        with open(report_txt, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2))
        logger.info("[timing] batch_total: %s", payload["timing_total"])
        logger.info("[timing] batch_avg: %s", payload["timing_avg"])
        logger.info(
            "[timing] batch_hotspot: stage=%s total_sec=%.3f ratio=%.2f%% wall=%.3fs",
            payload["timing_hotspot"]["stage"],
            payload["timing_hotspot"]["total_sec"],
            payload["timing_hotspot"]["ratio"] * 100.0,
            payload["timing_hotspot"]["wall_sec"],
        )
        logger.info("batch_report_json=%s", report_json)
        logger.info("batch_report_txt=%s", report_txt)

    @staticmethod
    def _validate_timeline(probe_summary) -> str | None:
        raw = probe_summary.raw if probe_summary else {}
        if not isinstance(raw, dict):
            return None
        streams = raw.get("streams")
        fmt = raw.get("format")
        if not isinstance(streams, list) or not isinstance(fmt, dict):
            return None

        format_duration = float(fmt.get("duration", 0.0) or 0.0)
        video_durations = []
        audio_durations = []
        for stream in streams:
            if not isinstance(stream, dict):
                continue
            duration = float(stream.get("duration", 0.0) or 0.0)
            if duration <= 0:
                continue
            if stream.get("codec_type") == "video":
                video_durations.append(duration)
            elif stream.get("codec_type") == "audio":
                audio_durations.append(duration)

        if not video_durations or format_duration <= 0:
            return None

        max_video = max(video_durations)
        max_audio = max(audio_durations) if audio_durations else 0.0
        reference_duration = max(format_duration, max_audio)
        gap_sec = reference_duration - max_video
        if reference_duration >= 300.0 and gap_sec >= 120.0:
            return (
                "Video timeline appears incomplete after remux: "
                f"video={max_video:.3f}s, audio={max_audio:.3f}s, format={format_duration:.3f}s."
            )
        return None
