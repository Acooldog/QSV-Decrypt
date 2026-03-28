from __future__ import annotations

import copy
import json
import logging
import shutil
import time
from dataclasses import asdict
from pathlib import Path

from .models import (
    BatchReport,
    DbCorrelation,
    DbSnapshot,
    FileDecryptResult,
    QsvInspection,
    SegmentRebuildPlan,
    TimingBreakdown,
)
from src.Infrastructure.bbts_variant_rebuilder import BbtsVariantRebuilder
from src.Infrastructure.db_cache_analysis import DbCacheAnalyzer
from src.Infrastructure.db_open_sample_prototype import DbOpenSamplePrototype
from src.Infrastructure.db_prototype_rebuilder import DbPrototypeRebuilder
from src.Infrastructure.db_snapshot import DbSnapshotService
from src.Infrastructure.ffmpeg_tools import FfmpegTools
from src.Infrastructure.qsv_offline import QsvOfflineDecoder
from src.Infrastructure.runtime_paths import get_log_day_dir


logger = logging.getLogger("aqy_decrypt")


class DecryptService:
    def __init__(
        self,
        decoder: QsvOfflineDecoder,
        ffmpeg_tools: FfmpegTools,
        db_snapshot_service: DbSnapshotService | None = None,
        db_cache_analyzer: DbCacheAnalyzer | None = None,
        db_prototype_rebuilder: DbPrototypeRebuilder | None = None,
        db_open_sample_prototype: DbOpenSamplePrototype | None = None,
        bbts_variant_rebuilder: BbtsVariantRebuilder | None = None,
    ) -> None:
        self.decoder = decoder
        self.ffmpeg_tools = ffmpeg_tools
        self.db_snapshot_service = db_snapshot_service or DbSnapshotService()
        self.db_cache_analyzer = db_cache_analyzer or DbCacheAnalyzer()
        self.db_prototype_rebuilder = db_prototype_rebuilder or DbPrototypeRebuilder(
            decoder=self.decoder,
            ffmpeg_tools=self.ffmpeg_tools,
        )
        self.db_open_sample_prototype = db_open_sample_prototype or DbOpenSamplePrototype(
            snapshot_service=self.db_snapshot_service,
            cache_analyzer=self.db_cache_analyzer,
            decoder=self.decoder,
        )
        self.bbts_variant_rebuilder = bbts_variant_rebuilder or BbtsVariantRebuilder(
            ffmpeg_tools=self.ffmpeg_tools,
        )

    def inspect(self, sample_path: Path) -> dict:
        inspection = self.decoder.inspect(sample_path)
        snapshot = self.db_snapshot_service.create_snapshot("hot")
        correlation = self.db_cache_analyzer.inspect_snapshot(
            snapshot=snapshot,
            sample_path=sample_path,
            qsv_inspection=inspection,
        )
        inspection.db_correlation = correlation
        return inspection.to_dict()

    def snapshot_db(self, mode: str) -> dict:
        snapshot = self.db_snapshot_service.create_snapshot(mode)
        return snapshot.to_dict()

    def inspect_db(self, sample_path: Path, snapshot_mode: str) -> dict:
        inspection = self.decoder.inspect(sample_path)
        snapshot = self.db_snapshot_service.create_snapshot(snapshot_mode)
        correlation = self.db_cache_analyzer.inspect_snapshot(
            snapshot=snapshot,
            sample_path=sample_path,
            qsv_inspection=inspection,
        )
        inspection.db_correlation = correlation
        return {
            "inspection": inspection.to_dict(),
            "snapshot": snapshot.to_dict(),
            "db_correlation": correlation.to_dict(),
        }

    def prototype_db_rebuild(
        self,
        sample_path: Path,
        snapshot_mode: str,
        output_root: Path | None = None,
    ) -> dict:
        inspection = self.decoder.inspect(sample_path)
        snapshot = self.db_snapshot_service.create_snapshot(snapshot_mode)
        correlation = self.db_cache_analyzer.inspect_snapshot(
            snapshot=snapshot,
            sample_path=sample_path,
            qsv_inspection=inspection,
        )
        inspection.db_correlation = correlation
        plan = self.db_prototype_rebuilder.rebuild(
            sample_path=sample_path,
            snapshot=snapshot,
            db_correlation=correlation,
            inspection=inspection,
            output_root=output_root,
        )
        return {
            "inspection": inspection.to_dict(),
            "snapshot": snapshot.to_dict(),
            "db_correlation": correlation.to_dict(),
            "prototype_plan": plan.to_dict(),
        }

    def prototype_open_diff(
        self,
        sample_path: Path,
        wait_sec: int,
        client_path: Path | None = None,
    ) -> dict:
        return self.db_open_sample_prototype.run(
            sample_path=sample_path,
            wait_sec=wait_sec,
            client_path=client_path,
        )

    def compare_db_snapshots(
        self,
        sample_path: Path,
        before_snapshot: Path,
        after_snapshot: Path,
    ) -> dict:
        return self.db_open_sample_prototype.compare_snapshots(
            sample_path=sample_path,
            before_root=before_snapshot,
            after_root=after_snapshot,
        )

    def prototype_bbts_rebuild(
        self,
        sample_path: Path,
        segments_dir: Path,
        dispatch_json_path: Path,
        output_root: Path | None = None,
    ) -> dict:
        plan = self.bbts_variant_rebuilder.rebuild(
            sample_path=sample_path,
            segments_dir=segments_dir,
            dispatch_json_path=dispatch_json_path,
            output_root=output_root,
        )
        return {
            "prototype_plan": plan.to_dict(),
        }

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
                inspection = self._ensure_db_correlation(qsv_path, inspection)
                bbts_result = self._try_bbts_repair_publish(
                    qsv_path=qsv_path,
                    inspection=inspection,
                    work_dir=work_dir,
                    final_output_path=final_output_path,
                    timing=timing,
                )
                if bbts_result is not None:
                    return bbts_result

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

    def _try_bbts_repair_publish(
        self,
        qsv_path: Path,
        inspection,
        work_dir: Path,
        final_output_path: Path,
        timing: TimingBreakdown,
    ) -> FileDecryptResult | None:
        if not inspection or not self._is_bbts_repair_candidate(inspection):
            return None

        bbts_root = get_log_day_dir() / "bbts_repair"
        existing = self._load_existing_bbts_success(qsv_path, bbts_root)
        plan = existing
        if plan is None:
            segments_dir, dispatch_json_path = self._materialize_bbts_inputs(
                qsv_path=qsv_path,
                inspection=inspection,
                work_dir=work_dir,
            )
            rebuild_start = time.perf_counter()
            plan = self.bbts_variant_rebuilder.rebuild(
                sample_path=qsv_path,
                segments_dir=segments_dir,
                dispatch_json_path=dispatch_json_path,
                output_root=bbts_root / qsv_path.stem,
            )
            timing.remux_sec += time.perf_counter() - rebuild_start

        if plan is None or plan.status != "success" or not plan.output_mp4_path or not plan.output_mp4_path.exists():
            return None
        if not self._is_confident_bbts_plan(plan):
            logger.warning("%s: bbts repair output is visually untrusted; refusing publish.", qsv_path.name)
            return None

        publish_start = time.perf_counter()
        self._publish(plan.output_mp4_path, final_output_path)
        timing.publish_sec += time.perf_counter() - publish_start
        probe_summary = plan.final_probe_summary
        return FileDecryptResult(
            input_path=qsv_path,
            output_path=final_output_path,
            status="success",
            reason="ok",
            source="offline+bbts-repair",
            inspection=inspection,
            probe_summary=probe_summary,
            timing=timing,
            remux_detail={
                "mode": "bbts-repair",
                "output_bytes": plan.output_mp4_path.stat().st_size,
                "artifact_root": str((bbts_root / qsv_path.stem)),
            },
        )

    @staticmethod
    def _is_confident_bbts_plan(plan) -> bool:
        if not plan.segment_results:
            return False
        for segment in plan.segment_results:
            if segment.segment_index == 0:
                continue
            selected = segment.selected_candidate
            if selected is None:
                return False
            top_candidates = list(segment.top_candidates or [])
            if len(top_candidates) < 2:
                continue
            first = top_candidates[0]
            second = top_candidates[1]
            if (
                first.score == second.score
                and (
                    first.operation != second.operation
                    or first.key_hex != second.key_hex
                    or first.candidate_name != second.candidate_name
                )
            ):
                return False
        return True

    @staticmethod
    def _is_bbts_repair_candidate(inspection) -> bool:
        correlation = getattr(inspection, "db_correlation", None)
        alignment = getattr(correlation, "qtplog_segment_alignment", None) if correlation else None
        if not isinstance(alignment, dict):
            return False
        if not alignment.get("run_segment_count_match"):
            return False
        bbts_segnums = alignment.get("bbts_segnums") or []
        return bool(bbts_segnums)

    def _ensure_db_correlation(self, qsv_path: Path, inspection):
        if inspection is None:
            return inspection
        if getattr(inspection, "db_correlation", None) is not None:
            return inspection
        try:
            snapshot = self.db_snapshot_service.create_snapshot("hot")
            correlation = self.db_cache_analyzer.inspect_snapshot(
                snapshot=snapshot,
                sample_path=qsv_path,
                qsv_inspection=inspection,
            )
            inspection.db_correlation = correlation
        except Exception as exc:
            logger.warning("%s: failed to enrich db_correlation for bbts repair: %s", qsv_path.name, exc)
        return inspection

    @staticmethod
    def _materialize_bbts_inputs(
        qsv_path: Path,
        inspection,
        work_dir: Path,
    ) -> tuple[Path, Path]:
        segments_dir = work_dir / "bbts_segments"
        segments_dir.mkdir(parents=True, exist_ok=True)
        qsv_bytes = qsv_path.read_bytes()
        for index, run in enumerate(inspection.stable_runs):
            start = int(run.offset)
            end = start + int(run.length)
            (segments_dir / f"{index:02d}.ts").write_bytes(qsv_bytes[start:end])

        dispatch_json_path = work_dir / "bbts_dispatch_hits.json"
        correlation = inspection.db_correlation
        tasks = list(getattr(correlation, "qtplog_segment_tasks", []) or [])
        tasks.sort(key=lambda item: (int(item.get("segnum", -1)) if isinstance(item.get("segnum"), int) else -1, str(item.get("log_path", "")), int(item.get("line_no", 0))))
        dispatch_json_path.write_text(json.dumps(tasks, ensure_ascii=False, indent=2), encoding="utf-8")
        return segments_dir, dispatch_json_path

    @staticmethod
    def _load_existing_bbts_success(qsv_path: Path, bbts_root: Path):
        report_candidates: list[Path] = []
        successful_reports: list[Path] = []
        direct_report = bbts_root / qsv_path.stem / f"{qsv_path.stem}.bbts_repair.json"
        if direct_report.exists():
            report_candidates.append(direct_report)
        if bbts_root.exists():
            expected_output_name = f"{qsv_path.stem}.patched.mp4"
            for candidate in bbts_root.rglob("*.bbts_repair.json"):
                if candidate == direct_report:
                    continue
                try:
                    payload = json.loads(candidate.read_text(encoding="utf-8-sig"))
                except Exception:
                    continue
                if payload.get("status") == "success":
                    output_mp4_path = payload.get("output_mp4_path")
                    if isinstance(output_mp4_path, str) and Path(output_mp4_path).exists():
                        successful_reports.append(candidate)
                output_mp4_path = payload.get("output_mp4_path")
                sample_path = payload.get("sample_path")
                if isinstance(output_mp4_path, str) and Path(output_mp4_path).name == expected_output_name:
                    report_candidates.append(candidate)
                    continue
                if isinstance(sample_path, str) and Path(sample_path).name == qsv_path.name:
                    report_candidates.append(candidate)

        if not report_candidates and len(successful_reports) == 1:
            report_candidates = successful_reports

        for report_path in report_candidates:
            try:
                payload = json.loads(report_path.read_text(encoding="utf-8-sig"))
            except Exception:
                continue
            if payload.get("status") != "success":
                continue
            output_mp4_path = payload.get("output_mp4_path")
            if not isinstance(output_mp4_path, str):
                continue
            output_mp4 = Path(output_mp4_path)
            if not output_mp4.exists():
                continue
            summary = payload.get("final_probe_summary") or {}
            from .models import BbtsRepairPlan, ProbeSummary
            return BbtsRepairPlan(
                sample_path=qsv_path,
                segments_dir=Path(payload.get("segments_dir") or bbts_root),
                dispatch_json_path=Path(payload.get("dispatch_json_path") or bbts_root),
                status="success",
                output_mp4_path=output_mp4,
                final_probe_summary=ProbeSummary(
                    ok=bool(summary.get("ok")),
                    format_name=str(summary.get("format_name") or ""),
                    duration_sec=float(summary.get("duration_sec") or 0.0),
                    stream_count=int(summary.get("stream_count") or 0),
                    video_streams=int(summary.get("video_streams") or 0),
                    audio_streams=int(summary.get("audio_streams") or 0),
                    raw=summary.get("raw") or {},
                ),
                notes=list(payload.get("notes") or []),
                artifact_paths=[Path(item) for item in (payload.get("artifact_paths") or []) if isinstance(item, str)],
            )
        return None

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
