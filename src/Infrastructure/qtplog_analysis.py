from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .runtime_paths import get_default_qtplog_root


class QtpLogAnalyzer:
    SEGMENT_LINE_HINTS = ("task_type=qsvd", "save_path=", "segnum=")
    DIRECT_PATH_HINTS = (
        "file open failed second time",
        "qsv_full_rename",
        "save path is =",
        "filepath=",
    )

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or get_default_qtplog_root()

    def inspect_sample(self, sample_path: Path) -> dict[str, object]:
        target = self._normalize_path(sample_path)
        segment_tasks: list[dict[str, object]] = []
        path_events: list[dict[str, object]] = []
        dispatch_events: list[dict[str, object]] = []
        notes: list[str] = []

        if not self.root.exists():
            return {
                "segment_tasks": segment_tasks,
                "path_events": path_events,
                "notes": [f"qtplog root does not exist: {self.root}"],
            }

        log_paths = sorted(self.root.rglob("*.log"))
        for log_path in log_paths:
            try:
                lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, start=1):
                if self._looks_like_segment_line(line):
                    task = self._parse_segment_line(log_path, lineno, line)
                    if task and task["decoded_save_path"] == target:
                        segment_tasks.append(task)
                dispatch = self._parse_dispatch_line(log_path, lineno, line)
                if dispatch:
                    dispatch_events.append(dispatch)
                if target in line.lower():
                    event = self._parse_path_event(log_path, lineno, line, target)
                    if event:
                        path_events.append(event)

        if segment_tasks:
            dispatch_by_name: dict[str, list[dict[str, object]]] = {}
            for dispatch in dispatch_events:
                name = str(dispatch.get("resource_name") or "").lower()
                if not name:
                    continue
                dispatch_by_name.setdefault(name, []).append(dispatch)
            deduped: dict[tuple[object, ...], dict[str, object]] = {}
            for task in segment_tasks:
                rawurl_name = ""
                if isinstance(task.get("rawurl"), str):
                    parsed = urlparse(task["rawurl"])
                    rawurl_name = os.path.basename(parsed.path).lower()
                if rawurl_name and rawurl_name in dispatch_by_name:
                    dispatches = dispatch_by_name[rawurl_name]
                    urls: list[str] = []
                    key_hex = ""
                    key_base64 = ""
                    for dispatch in dispatches:
                        for url in dispatch.get("dispatch_urls", []):
                            if isinstance(url, str) and url not in urls:
                                urls.append(url)
                        if not key_hex and dispatch.get("dispatch_key_hex"):
                            key_hex = str(dispatch["dispatch_key_hex"])
                        if not key_base64 and dispatch.get("dispatch_key_base64"):
                            key_base64 = str(dispatch["dispatch_key_base64"])
                    task["dispatch_resource_name"] = rawurl_name
                    task["dispatch_urls"] = urls
                    task["dispatch_url_count"] = len(urls)
                    task["dispatch_key_hex"] = key_hex
                    task["dispatch_key_base64"] = key_base64
                key = (
                    task.get("segnum"),
                    task.get("reason"),
                    task.get("decoded_save_path"),
                    rawurl_name,
                )
                best = deduped.get(key)
                if best is None or str(task.get("log_path", "")) < str(best.get("log_path", "")):
                    deduped[key] = task
            segment_tasks = list(deduped.values())
            segment_tasks.sort(key=lambda item: (int(item.get("segnum", -1)), str(item.get("log_path", "")), int(item.get("line_no", 0))))
            reasons = sorted({str(item.get("reason", "")) for item in segment_tasks if item.get("reason")})
            notes.append(
                f"qtplog matched {len(segment_tasks)} qsv download segment task(s) for this sample; reasons="
                + ",".join(reasons)
            )
            segnums = sorted({int(item["segnum"]) for item in segment_tasks if isinstance(item.get("segnum"), int)})
            if segnums:
                notes.append(
                    f"Observed segment indices {segnums[0]}..{segnums[-1]} across {len(segnums)} unique segment(s)."
                )
            key_segnums = [
                int(item["segnum"])
                for item in segment_tasks
                if isinstance(item.get("segnum"), int) and item.get("dispatch_key_hex")
            ]
            if key_segnums:
                notes.append(
                    "p2pfile dispatch logs expose bbts dispatch keys for segment(s) "
                    + ", ".join(str(item) for item in sorted(set(key_segnums)))
                    + "."
                )
        if path_events:
            event_types = sorted({str(item.get("event_type", "")) for item in path_events if item.get("event_type")})
            notes.append(
                f"qtplog also matched {len(path_events)} direct path event(s): " + ", ".join(event_types)
            )
        return {
            "segment_tasks": segment_tasks,
            "path_events": path_events,
            "dispatch_events": dispatch_events,
            "notes": notes,
        }

    @classmethod
    def _looks_like_segment_line(cls, line: str) -> bool:
        lower = line.lower()
        return all(token in lower for token in cls.SEGMENT_LINE_HINTS)

    @classmethod
    def _parse_segment_line(cls, log_path: Path, lineno: int, line: str) -> dict[str, object] | None:
        raw_save = cls._extract_query_value(line, "save_path")
        decoded_save = cls._decode_save_path(raw_save)
        if not decoded_save:
            return None
        task = {
            "log_path": str(log_path),
            "line_no": lineno,
            "decoded_save_path": cls._normalize_path(decoded_save),
            "raw_save_path": raw_save,
            "task_id": cls._extract_task_id(line),
            "segnum": cls._extract_int(line, "segnum"),
            "segcnt": cls._extract_int(line, "segcnt"),
            "f4vsize": cls._extract_int(line, "f4vsize"),
            "reason": cls._extract_query_value(line, "reason"),
            "tvid": cls._extract_query_value(line, "tvid"),
            "vid": cls._extract_query_value(line, "vid"),
            "cid": cls._extract_query_value(line, "cid"),
            "file_type": cls._extract_query_value(line, "file_type"),
            "task_type": cls._extract_query_value(line, "task_type"),
            "rawurl": cls._extract_query_value(line, "rawurl"),
        }
        return task

    @classmethod
    def _parse_path_event(
        cls,
        log_path: Path,
        lineno: int,
        line: str,
        target: str,
    ) -> dict[str, object] | None:
        lower = line.lower()
        event_type = "path_hit"
        if "file open failed second time" in lower:
            event_type = "open_failed_second_time"
        elif "qsv_full_rename" in lower:
            event_type = "qsv_full_rename"
        elif "save path is =" in lower:
            event_type = "save_path_open"
        elif "filepath=" in lower:
            event_type = "create_file_response"
        return {
            "log_path": str(log_path),
            "line_no": lineno,
            "event_type": event_type,
            "path": target,
            "line": line.strip(),
        }

    @classmethod
    def _parse_dispatch_line(cls, log_path: Path, lineno: int, line: str) -> dict[str, object] | None:
        if "postdispatchresult" not in line.lower() or "dispatch msg:" not in line.lower():
            return None
        start = line.find("dispatch msg:")
        if start < 0:
            return None
        payload = line[start + len("dispatch msg:") :].strip()
        brace_start = payload.find("{")
        brace_end = payload.rfind("}")
        if brace_start >= 0 and brace_end >= brace_start:
            payload = payload[brace_start : brace_end + 1]
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return None

        uri = data.get("uri")
        resource_name = ""
        if isinstance(uri, str):
            resource_name = os.path.basename(urlparse(uri).path).lower()

        dispatch_urls: list[str] = []
        dispatch_key_raw = ""
        dispatch_key_hex = ""
        dispatch_key_base64 = ""
        for item in data.get("d", []):
            if not isinstance(item, dict):
                continue
            url = item.get("URL")
            if not isinstance(url, str):
                continue
            dispatch_urls.append(url)
            parsed = urlparse(url)
            key_values = parse_qs(parsed.query).get("key") or []
            if key_values and not dispatch_key_raw:
                dispatch_key_raw = key_values[0]
                dispatch_key_hex, dispatch_key_base64 = cls._normalize_dispatch_key(dispatch_key_raw)
        if not resource_name and dispatch_urls:
            resource_name = os.path.basename(urlparse(dispatch_urls[0]).path).lower()
        if not resource_name:
            return None
        return {
            "log_path": str(log_path),
            "line_no": lineno,
            "resource_name": resource_name,
            "uri": uri,
            "dispatch_urls": dispatch_urls,
            "dispatch_key_raw": dispatch_key_raw,
            "dispatch_key_hex": dispatch_key_hex,
            "dispatch_key_base64": dispatch_key_base64,
        }

    @staticmethod
    def _extract_task_id(line: str) -> int | None:
        match = re.search(r"TaskID\((\d+)\)|task_id:(\d+)", line, re.IGNORECASE)
        if not match:
            return None
        value = match.group(1) or match.group(2)
        return int(value) if value else None

    @staticmethod
    def _extract_int(line: str, key: str) -> int | None:
        value = QtpLogAnalyzer._extract_query_value(line, key)
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def _extract_query_value(line: str, key: str) -> str | None:
        patterns = [
            rf"{re.escape(key)}=([^&\]\s]+)",
            rf"{re.escape(key)}:([^,\]\s]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return unquote(match.group(1))
        if "url=" in line or "URL:" in line or "pps_url(" in line:
            url_match = re.search(r"(pps://[^\s\]]+)", line)
            if url_match:
                parsed = urlparse(url_match.group(1))
                values = parse_qs(parsed.query).get(key)
                if values:
                    return values[0]
        return None

    @staticmethod
    def _decode_save_path(value: str | None) -> str | None:
        if not value:
            return None
        raw = value.rstrip("#")
        padded = raw + ("=" * ((4 - len(raw) % 4) % 4))
        for decoder in (base64.b64decode,):
            try:
                blob = decoder(padded)
            except Exception:
                continue
            for encoding in ("utf-8", "gb18030", "utf-16le"):
                try:
                    text = blob.decode(encoding).strip("\x00")
                except Exception:
                    continue
                if ":\\\\" in text or ":\\" in text or text.lower().startswith("o:\\"):
                    return text
        return None

    @staticmethod
    def _normalize_path(path: str | Path) -> str:
        return str(path).replace("/", "\\").lower()

    @staticmethod
    def _normalize_dispatch_key(value: str) -> tuple[str, str]:
        raw = value.strip().lower()
        if not raw:
            return ("", "")
        candidate = raw
        if len(candidate) == 33 and candidate.startswith("0"):
            candidate = candidate[1:]
        if len(candidate) % 2 != 0:
            return (candidate, "")
        try:
            key_bytes = bytes.fromhex(candidate)
        except ValueError:
            return (candidate, "")
        return (candidate, base64.b64encode(key_bytes).decode("ascii"))
