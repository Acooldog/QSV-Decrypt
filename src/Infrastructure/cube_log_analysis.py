from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from src.Application.models import DownloadMetadataCorrelation

from .runtime_paths import get_default_cube_log_paths


class CubeLogAnalyzer:
    def __init__(self, log_paths: list[Path] | None = None) -> None:
        self.log_paths = log_paths or get_default_cube_log_paths()

    def inspect_sample(
        self,
        sample_path: Path,
        download_metadata: DownloadMetadataCorrelation | None = None,
    ) -> dict[str, object]:
        target_path = self._normalize_path(sample_path)
        metadata_entry = download_metadata.matched_entries[0] if download_metadata and download_metadata.matched_entries else None
        target_tvid = str(metadata_entry.tvid or "") if metadata_entry else ""
        target_vid = str(metadata_entry.video_id or "") if metadata_entry else ""
        metadata_aid = str(metadata_entry.aid or "") if metadata_entry else ""

        init_tasks: list[dict[str, object]] = []
        set_params: list[dict[str, object]] = []
        save_video_info: list[dict[str, object]] = []
        scheduler_events: list[dict[str, object]] = []
        download_events: list[dict[str, object]] = []
        interrupt_events: list[dict[str, object]] = []
        notes: list[str] = []

        for log_path in self.log_paths:
            if not log_path.exists():
                continue
            try:
                lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, start=1):
                if "CTaskParam" in line and "[task_type:1]" in line:
                    task = self._parse_init_task(log_path, lineno, line)
                    if task and self._task_matches(task, target_path, target_tvid, target_vid):
                        init_tasks.append(task)

        task_ids = {int(item["task_id"]) for item in init_tasks if isinstance(item.get("task_id"), int)}
        if not target_tvid:
            tvids = {str(item.get("tvid") or "") for item in init_tasks if item.get("tvid")}
        else:
            tvids = {target_tvid}
        if not target_vid:
            vids = {str(item.get("vid") or "") for item in init_tasks if item.get("vid")}
        else:
            vids = {target_vid}

        for log_path in self.log_paths:
            if not log_path.exists():
                continue
            try:
                lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, start=1):
                lower = line.lower()
                if "setparam" in lower:
                    event = self._parse_set_param(log_path, lineno, line)
                    if event and self._line_matches(event, task_ids, tvids, vids):
                        set_params.append(event)
                elif "savevideoinfo" in lower:
                    event = self._parse_save_video_info(log_path, lineno, line)
                    if event and self._line_matches(event, task_ids, tvids, vids):
                        save_video_info.append(event)
                elif "parseschedulerjson" in lower and "[l:" in line:
                    event = self._parse_scheduler(log_path, lineno, line)
                    if event and self._line_matches(event, task_ids, tvids, vids):
                        scheduler_events.append(event)
                elif "dealpostdownloadspeed" in lower:
                    event = self._parse_download_event(log_path, lineno, line)
                    if event and self._line_matches(event, task_ids, tvids, vids):
                        download_events.append(event)
                elif "interrupt" in lower and "[url:" in lower:
                    event = self._parse_interrupt_event(log_path, lineno, line)
                    if event and self._line_matches(event, task_ids, tvids, vids):
                        interrupt_events.append(event)

        scheduler_events.sort(key=lambda item: int(item.get("qd_index") or -1))
        unique_segnums = sorted({int(item["qd_index"]) for item in scheduler_events if isinstance(item.get("qd_index"), int)})
        qd_aids = sorted({str(item.get("qd_aid") or "") for item in scheduler_events if item.get("qd_aid")})
        param_avids = sorted(
            {
                str(item.get("param_avid") or "")
                for item in save_video_info
                if item.get("param_avid")
            }
        )
        dash_avids = sorted(
            {
                str(item.get("dash_avid") or "")
                for item in save_video_info
                if item.get("dash_avid")
            }
        )
        file_formats = sorted({str(item.get("file_format") or "") for item in download_events if item.get("file_format")})
        business_sides = sorted({str(item.get("business_side") or "") for item in download_events if item.get("business_side")})
        file_names = sorted({str(item.get("file_name") or "") for item in download_events if item.get("file_name")})
        vps_params = [item for item in set_params if item.get("event_type") == "vps_param"]
        audio_vids = sorted({str(item.get("value") or "") for item in set_params if item.get("key") == "audioVid" and item.get("value")})

        if init_tasks:
            notes.append(
                f"cube logs matched {len(init_tasks)} init task row(s) for this sample."
            )
        if unique_segnums:
            notes.append(
                "cube scheduler exposes qd_index sequence "
                + f"{unique_segnums[0]}..{unique_segnums[-1]} across {len(unique_segnums)} segment(s)."
            )
        if vps_params:
            first = vps_params[0]
            notes.append(
                "cube vps_param confirms "
                + "/".join(
                    f"{key}={first[key]}"
                    for key in ("dcdv", "ccsn", "lid", "cf", "ct")
                    if first.get(key)
                )
                + "."
            )
        if metadata_entry:
            if target_tvid and target_tvid in {str(item.get("tvid") or "") for item in scheduler_events}:
                notes.append("cube scheduler qd_tvid matches Downloaded.xml TVID.")
            if target_vid and target_vid in {str(item.get("vid") or "") for item in scheduler_events}:
                notes.append("cube scheduler vid matches Downloaded.xml VideoId.")
            if metadata_aid and metadata_aid in param_avids:
                notes.append("cube SaveVideoInfo param_avid matches Downloaded.xml aid exactly.")
            if metadata_aid and metadata_aid in dash_avids:
                notes.append("cube SaveVideoInfo dash_avid matches Downloaded.xml aid exactly.")
            if metadata_aid and qd_aids and metadata_aid not in qd_aids:
                notes.append(
                    "cube qd_aid differs from Downloaded.xml aid; treat qd_aid as the numeric download task aid, "
                    "while Downloaded.xml aid matches param_avid/dash_avid."
                )
        if file_formats:
            notes.append(
                "cube download completion reports file_format="
                + ",".join(file_formats)
                + "."
            )
        if business_sides:
            notes.append(
                "cube download completion business_side="
                + ",".join(business_sides)
                + "."
            )
        if interrupt_events:
            notes.append(f"cube interrupt logs expose {len(interrupt_events)} full DASH request url(s).")

        return {
            "init_tasks": init_tasks,
            "set_params": set_params,
            "save_video_info": save_video_info,
            "scheduler_events": scheduler_events,
            "download_events": download_events,
            "interrupt_events": interrupt_events,
            "task_ids": sorted(task_ids),
            "tvids": sorted(item for item in tvids if item),
            "vids": sorted(item for item in vids if item),
            "scheduler_segnums": unique_segnums,
            "scheduler_qd_aids": qd_aids,
            "param_avids": param_avids,
            "dash_avids": dash_avids,
            "audio_vids": audio_vids,
            "file_formats": file_formats,
            "file_names": file_names,
            "notes": notes,
        }

    def _task_matches(
        self,
        task: dict[str, object],
        target_path: str,
        target_tvid: str,
        target_vid: str,
    ) -> bool:
        if task.get("path") and self._normalize_path(str(task["path"])) == target_path:
            return True
        if target_tvid and str(task.get("tvid") or "") == target_tvid:
            return True
        if target_vid and str(task.get("vid") or "") == target_vid:
            return True
        return False

    def _line_matches(
        self,
        event: dict[str, object],
        task_ids: set[int],
        tvids: set[str],
        vids: set[str],
    ) -> bool:
        task_id = event.get("task_id")
        allow_task_id_only = bool(event.get("_allow_task_id_only"))
        if isinstance(task_id, int) and task_id in task_ids and allow_task_id_only:
            return True
        tvid = str(event.get("tvid") or "")
        if tvid and tvid in tvids:
            return True
        vid = str(event.get("vid") or "")
        if vid and vid in vids:
            return True
        return False

    def _parse_init_task(self, log_path: Path, lineno: int, line: str) -> dict[str, object] | None:
        return {
            "log_path": str(log_path),
            "line_no": lineno,
            "task_id": self._extract_int(line, "task_id"),
            "task_type": self._extract_int(line, "task_type"),
            "aid": self._extract_value(line, "aid"),
            "tvid": self._extract_value(line, "tvid"),
            "vid": self._extract_value(line, "vid"),
            "path": self._extract_value(line, "path"),
            "pay_video": self._extract_value(line, "pay_video"),
            "qypid": self._extract_value(line, "qypid"),
        }

    def _parse_set_param(self, log_path: Path, lineno: int, line: str) -> dict[str, object] | None:
        key = self._extract_value(line, "key")
        value = self._extract_value(line, "value")
        event: dict[str, object] = {
            "log_path": str(log_path),
            "line_no": lineno,
            "event_type": "set_param",
            "task_id": self._extract_int(line, "task_id"),
            "_allow_task_id_only": True,
            "key": key or "",
            "value": value or "",
            "tvid": self._extract_value(line, "tvid"),
            "vid": self._extract_value(line, "vid"),
        }
        url = self._extract_value(line, "url")
        if url and "cache.video.iqiyi.com/dash" in url:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            event.update(
                {
                    "event_type": "vps_param",
                    "url": url,
                    "tvid": (query.get("tvid") or [""])[0],
                    "vid": (query.get("vid") or [""])[0],
                    "dash_aid": (query.get("aid") or [""])[0],
                    "dcdv": (query.get("dcdv") or [""])[0],
                    "ccsn": (query.get("ccsn") or [""])[0],
                    "lid": (query.get("lid") or [""])[0],
                    "cf": (query.get("cf") or [""])[0],
                    "ct": (query.get("ct") or [""])[0],
                    "_allow_task_id_only": False,
                }
            )
        return event

    def _parse_save_video_info(self, log_path: Path, lineno: int, line: str) -> dict[str, object] | None:
        return {
            "log_path": str(log_path),
            "line_no": lineno,
            "task_id": self._extract_int(line, "task_id"),
            "tvid": self._extract_value(line, "tvid"),
            "vid": self._extract_value(line, "vid"),
            "dash_avid": self._extract_value(line, "dash_avid"),
            "param_avid": self._extract_value(line, "param_avid"),
            "qsv_ret": self._extract_value(line, "qsv_ret"),
            "vi_size": self._extract_int(line, "vi_size"),
        }

    def _parse_scheduler(self, log_path: Path, lineno: int, line: str) -> dict[str, object] | None:
        url = self._extract_value(line, "l")
        if not url:
            return None
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        return {
            "log_path": str(log_path),
            "line_no": lineno,
            "url": url,
            "resource_name": os.path.basename(parsed.path).lower(),
            "tvid": (qs.get("qd_tvid") or qs.get("tvid") or [""])[0],
            "vid": (qs.get("vid") or [""])[0],
            "cid": (qs.get("cid") or [""])[0],
            "qd_index": self._safe_int((qs.get("qd_index") or [""])[0]),
            "qd_aid": (qs.get("qd_aid") or [""])[0],
            "qd_vipres": (qs.get("qd_vipres") or [""])[0],
            "bid": (qs.get("bid") or [""])[0],
            "ext": Path(parsed.path).suffix.lower(),
        }

    def _parse_download_event(self, log_path: Path, lineno: int, line: str) -> dict[str, object] | None:
        return {
            "log_path": str(log_path),
            "line_no": lineno,
            "task_id": self._extract_int(line, "task_id"),
            "task_type": self._extract_int(line, "task_type"),
            "_allow_task_id_only": False,
            "tvid": self._extract_value(line, "tvid"),
            "vid": self._extract_value(line, "vid"),
            "business_side": self._extract_value(line, "business_side"),
            "file_format": self._extract_value(line, "file_format"),
            "file_name": self._extract_value(line, "file_name"),
            "file_size": self._extract_value(line, "file_size"),
            "speed": self._extract_value(line, "speed"),
            "limit_level": self._extract_value(line, "limit_level"),
        }

    def _parse_interrupt_event(self, log_path: Path, lineno: int, line: str) -> dict[str, object] | None:
        url = self._extract_value(line, "url")
        if not url:
            return None
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        return {
            "log_path": str(log_path),
            "line_no": lineno,
            "event_type": "interrupt",
            "url": url,
            "task_id": self._extract_int(line, "task_id"),
            "_allow_task_id_only": False,
            "tvid": (qs.get("tvid") or [""])[0],
            "vid": (qs.get("vid") or [""])[0],
            "aid": (qs.get("aid") or [""])[0],
        }

    @staticmethod
    def _extract_value(line: str, key: str) -> str | None:
        match = re.search(rf"\[{re.escape(key)}:([^\]]*)\]", line, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _extract_int(line: str, key: str) -> int | None:
        raw = CubeLogAnalyzer._extract_value(line, key)
        if raw is None or raw == "":
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    @staticmethod
    def _safe_int(value: str) -> int | None:
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def _normalize_path(path: str | Path) -> str:
        return str(path).replace("/", "\\").lower()
