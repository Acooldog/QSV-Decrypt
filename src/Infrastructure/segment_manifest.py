from __future__ import annotations

import json
import logging
import re
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .runtime_paths import get_default_localwebapp_cache_root

logger = logging.getLogger("aqy_decrypt")


class SegmentManifestBuilder:
    def build(self, sample_path: Path, inspection, work_dir: Path) -> tuple[dict[str, Any], Path]:
        correlation = getattr(inspection, "db_correlation", None)
        if correlation is None:
            raise RuntimeError("db_correlation is required before building a segment manifest")

        download_metadata = getattr(correlation, "download_metadata", None)
        metadata_entry = download_metadata.matched_entries[0] if download_metadata and download_metadata.matched_entries else None
        qtplog_tasks = list(getattr(correlation, "qtplog_segment_tasks", []) or [])
        cube_summary = dict(getattr(correlation, "cube_log_summary", {}) or {})
        save_video_info = list(cube_summary.get("save_video_info") or [])
        scheduler_events = list(cube_summary.get("scheduler_events") or [])
        set_params = list(cube_summary.get("set_params") or [])
        interrupt_events = list(cube_summary.get("interrupt_events") or [])
        movie_payload = self._find_matching_movie_payload(metadata_entry)
        selected_movie_video = self._select_movie_video(
            movie_payload,
            preferred_video_id=str(getattr(metadata_entry, "video_id", "") or ""),
        )

        dash_url = ""
        dash_response: dict[str, Any] | None = None
        for event in set_params:
            if isinstance(event, dict) and event.get("event_type") == "vps_param" and isinstance(event.get("url"), str):
                dash_url = event["url"]
                dash_response = self._fetch_dash_response(dash_url)
                break
        if not dash_url:
            for event in interrupt_events:
                if isinstance(event, dict) and isinstance(event.get("url"), str) and "cache.video.iqiyi.com/dash" in event["url"]:
                    dash_url = event["url"]
                    dash_response = self._fetch_dash_response(dash_url)
                    break

        video_manifest = self._extract_video_manifest(dash_response)
        audio_manifest = self._extract_audio_manifest(dash_response, metadata_entry)

        merged_by_segnum: dict[int, dict[str, Any]] = {}
        for item in qtplog_tasks:
            if not isinstance(item, dict):
                continue
            segnum = item.get("segnum")
            if isinstance(segnum, int):
                merged_by_segnum[segnum] = dict(item)

        shared_segment_fields = self._build_shared_segment_fields(dash_response, selected_movie_video)

        for event in scheduler_events:
            if not isinstance(event, dict):
                continue
            qd_index = event.get("qd_index")
            if not isinstance(qd_index, int):
                continue
            segnum = qd_index - 1
            if segnum < 0:
                continue
            merged = merged_by_segnum.setdefault(segnum, {"segnum": segnum})
            cube_urls = list(merged.get("cube_dispatch_urls") or [])
            if isinstance(event.get("url"), str) and event["url"] not in cube_urls:
                cube_urls.append(event["url"])
            merged["cube_dispatch_urls"] = cube_urls
            merged["cube_qd_index"] = qd_index
            for key in ("resource_name", "tvid", "vid", "cid", "qd_aid", "bid", "qd_vipres"):
                value = event.get(key)
                if value not in (None, ""):
                    merged[f"cube_{key}"] = value

        for segnum, merged in merged_by_segnum.items():
            rawurl = str(merged.get("rawurl") or "")
            resource_name = self._resource_name(rawurl)
            if resource_name:
                merged["resource_name"] = resource_name
            video_group = video_manifest.get(resource_name)
            if video_group:
                merged["m3u8_group_urls"] = [item["url"] for item in video_group["entries"]]
                merged["m3u8_group_total_bytes"] = int(video_group["total_bytes"])
                merged["m3u8_group_entry_count"] = int(video_group["entry_count"])
                merged["m3u8_group_duration_sec"] = round(float(video_group["duration_sec"]), 6)
                merged["m3u8_group_kind"] = "video"
            cube_name_candidates = list(merged.get("cube_resource_names") or [])
            if not cube_name_candidates and isinstance(merged.get("cube_resource_name"), str):
                cube_name_candidates.append(str(merged["cube_resource_name"]))
            for cube_name in cube_name_candidates:
                audio_group = audio_manifest.get(str(cube_name).lower())
                if not audio_group:
                    continue
                merged["audio_amp4_urls"] = [item["url"] for item in audio_group["entries"]]
                merged["audio_amp4_total_bytes"] = int(audio_group["total_bytes"])
                merged["audio_amp4_entry_count"] = int(audio_group["entry_count"])
                break
            for key, value in shared_segment_fields.items():
                if key not in merged and value not in (None, "", [], {}):
                    merged[key] = value

        tasks = [merged_by_segnum[index] for index in sorted(merged_by_segnum)]
        manifest: dict[str, Any] = {
            "sample_path": str(sample_path),
            "tvid": getattr(metadata_entry, "tvid", "") if metadata_entry else "",
            "video_id": getattr(metadata_entry, "video_id", "") if metadata_entry else "",
            "aid": getattr(metadata_entry, "aid", "") if metadata_entry else "",
            "lid": getattr(metadata_entry, "lid", "") if metadata_entry else "",
            "cf": getattr(metadata_entry, "cf", "") if metadata_entry else "",
            "ct": getattr(metadata_entry, "ct", "") if metadata_entry else "",
            "dash_url": dash_url,
            "dash_video": video_manifest.get("_summary", {}),
            "dash_audio": audio_manifest.get("_summary", {}),
            "segments": tasks,
            "notes": self._build_notes(tasks, dash_response),
        }
        if dash_response is not None:
            manifest["dash_response"] = {
                "drm_type": self._nested_get(dash_response, "data", "program", "video", 0, "drmType"),
                "iv": self._nested_get(dash_response, "data", "program", "video", 0, "iv"),
                "ticket": self._nested_get(dash_response, "data", "program", "video", 0, "drm", "ticket"),
                "unencrypted_duration": self._nested_get(dash_response, "data", "program", "video", 0, "unencryptedDuration"),
                "duration": self._nested_get(dash_response, "data", "program", "video", 0, "duration"),
            }
        if selected_movie_video is not None:
            manifest["moviejson_video"] = {
                "bid": selected_movie_video.get("bid"),
                "vid": selected_movie_video.get("vid"),
                "ff": selected_movie_video.get("ff"),
                "drm_type": selected_movie_video.get("drmType"),
                "iv": selected_movie_video.get("iv"),
                "eak": selected_movie_video.get("eak"),
                "ms": selected_movie_video.get("ms"),
                "ml": selected_movie_video.get("ml"),
                "ticket": self._nested_get(selected_movie_video, "drm", "ticket"),
                "play_ts_urls": self._extract_play_ts_urls(selected_movie_video),
            }

        manifest_path = work_dir / "bbts_segment_manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        return manifest, manifest_path

    def _find_matching_movie_payload(self, metadata_entry) -> dict[str, Any] | None:
        if metadata_entry is None:
            return None
        cache_root = get_default_localwebapp_cache_root()
        if not cache_root.exists():
            return None
        tvid = str(getattr(metadata_entry, "tvid", "") or "")
        video_id = str(getattr(metadata_entry, "video_id", "") or "")
        aid = str(getattr(metadata_entry, "aid", "") or "")
        display_name = str(getattr(metadata_entry, "display_name", "") or getattr(metadata_entry, "save_file_name", "") or "")
        best_payload: dict[str, Any] | None = None
        best_score = -1
        for path in sorted(cache_root.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)[:80]:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if tvid and tvid not in text:
                continue
            try:
                payload = json.loads(text)
            except Exception:
                continue
            movie_json_text = payload.get("video_data_flow", {}).get("movieJSON") if isinstance(payload, dict) else None
            if not isinstance(movie_json_text, str):
                continue
            try:
                movie_payload = json.loads(movie_json_text)
            except Exception:
                continue
            top_tvid = str(movie_payload.get("data", {}).get("tvid") or "")
            if tvid and top_tvid and top_tvid != tvid:
                continue
            score = 0
            if video_id and video_id in text:
                score += 3
            if aid and aid in text:
                score += 2
            if display_name and display_name.split("-")[0] in text:
                score += 1
            if movie_payload.get("data", {}).get("program", {}).get("video"):
                score += 1
            if score > best_score:
                best_score = score
                best_payload = movie_payload
        return best_payload

    @staticmethod
    def _select_movie_video(movie_payload: dict[str, Any] | None, preferred_video_id: str = "") -> dict[str, Any] | None:
        if not isinstance(movie_payload, dict):
            return None
        video_list = movie_payload.get("data", {}).get("program", {}).get("video")
        if not isinstance(video_list, list):
            return None
        if preferred_video_id:
            exact = next(
                (
                    item
                    for item in video_list
                    if isinstance(item, dict) and str(item.get("vid") or "") == preferred_video_id and str(item.get("ff") or "") == "ts"
                ),
                None,
            )
            if isinstance(exact, dict):
                return exact
        selected = next(
            (
                item
                for item in video_list
                if isinstance(item, dict) and item.get("_selected") and str(item.get("ff") or "") == "ts"
            ),
            None,
        )
        if isinstance(selected, dict):
            return selected
        ts_candidates = [item for item in video_list if isinstance(item, dict) and str(item.get("ff") or "") == "ts"]
        if not ts_candidates:
            return None
        ts_candidates.sort(key=lambda item: (int(item.get("bid") or 0), int(item.get("vsize") or 0)), reverse=True)
        return ts_candidates[0]

    def _build_shared_segment_fields(
        self,
        dash_response: dict[str, Any] | None,
        selected_movie_video: dict[str, Any] | None,
    ) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if isinstance(dash_response, dict):
            fields.update(
                {
                    "dash_iv": self._nested_get(dash_response, "data", "program", "video", 0, "iv"),
                    "dash_ticket": self._nested_get(dash_response, "data", "program", "video", 0, "drm", "ticket"),
                    "dash_drm_type": self._nested_get(dash_response, "data", "program", "video", 0, "drmType"),
                }
            )
        if isinstance(selected_movie_video, dict):
            fields.update(
                {
                    "moviejson_iv": selected_movie_video.get("iv"),
                    "moviejson_eak": selected_movie_video.get("eak"),
                    "moviejson_ms": selected_movie_video.get("ms"),
                    "moviejson_ml": selected_movie_video.get("ml"),
                    "moviejson_ticket": self._nested_get(selected_movie_video, "drm", "ticket"),
                    "moviejson_play_ts_urls": self._extract_play_ts_urls(selected_movie_video),
                }
            )
        return fields

    @staticmethod
    def _extract_play_ts_urls(selected_movie_video: dict[str, Any]) -> list[str]:
        items = SegmentManifestBuilder._nested_get(selected_movie_video, "play", "ts", "d")
        if not isinstance(items, list):
            return []
        urls: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            url = item.get("URL")
            if isinstance(url, str) and url and url not in urls:
                urls.append(url)
        return urls

    def _fetch_dash_response(self, dash_url: str) -> dict[str, Any] | None:
        try:
            request = urllib.request.Request(
                dash_url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept-Encoding": "identity",
                },
            )
            with urllib.request.urlopen(request, timeout=12) as response:
                payload = response.read()
            return json.loads(payload.decode("utf-8", errors="ignore"))
        except Exception as exc:
            logger.warning("Failed to fetch dash response: %s", exc)
            return None

    def _extract_video_manifest(self, dash_response: dict[str, Any] | None) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if not isinstance(dash_response, dict):
            return result
        video_list = self._nested_get(dash_response, "data", "program", "video")
        if not isinstance(video_list, list) or not video_list:
            return result
        selected = next((item for item in video_list if isinstance(item, dict) and item.get("_selected")), video_list[0])
        if not isinstance(selected, dict):
            return result
        m3u8_text = str(selected.get("m3u8") or "")
        by_resource: dict[str, dict[str, Any]] = {}
        current_duration = 0.0
        for line in m3u8_text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("#EXTINF:"):
                try:
                    current_duration = float(line.split(":", 1)[1].split(",", 1)[0])
                except Exception:
                    current_duration = 0.0
                continue
            if not line.startswith("http"):
                continue
            resource_name = self._resource_name(line)
            if not resource_name:
                continue
            content_length = self._extract_query_int(line, "contentlength")
            entry = {
                "url": line,
                "content_length": content_length,
                "duration_sec": current_duration,
            }
            group = by_resource.setdefault(
                resource_name,
                {"entries": [], "total_bytes": 0, "entry_count": 0, "duration_sec": 0.0},
            )
            group["entries"].append(entry)
            group["entry_count"] += 1
            group["total_bytes"] += content_length
            group["duration_sec"] += current_duration
        by_resource["_summary"] = {
            "resource_count": len([key for key in by_resource if key != "_summary"]),
            "duration": selected.get("duration"),
            "unencrypted_duration": selected.get("unencryptedDuration"),
            "drm_type": selected.get("drmType"),
            "iv": selected.get("iv"),
        }
        return by_resource

    def _extract_audio_manifest(
        self,
        dash_response: dict[str, Any] | None,
        metadata_entry,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if not isinstance(dash_response, dict):
            return result
        audio_list = self._nested_get(dash_response, "data", "program", "audio")
        if not isinstance(audio_list, list) or not audio_list:
            return result
        target_aid = getattr(metadata_entry, "aid", "") if metadata_entry else ""
        selected = None
        if target_aid:
            selected = next((item for item in audio_list if isinstance(item, dict) and str(item.get("aid") or "") == target_aid), None)
        if selected is None:
            selected = next((item for item in audio_list if isinstance(item, dict) and item.get("_selected")), None)
        if not isinstance(selected, dict):
            return result
        fs_entries = selected.get("fs")
        if isinstance(fs_entries, list):
            for item in fs_entries:
                if not isinstance(item, dict):
                    continue
                url_suffix = str(item.get("l") or "")
                if not url_suffix:
                    continue
                url = url_suffix
                if url.startswith("/"):
                    url = "http://data.video.iqiyi.com" + url
                resource_name = self._resource_name(url)
                if not resource_name:
                    continue
                size = int(item.get("b") or 0)
                result[resource_name] = {
                    "entries": [{"url": url, "content_length": size}],
                    "total_bytes": size,
                    "entry_count": 1,
                }
        result["_summary"] = {
            "aid": selected.get("aid"),
            "cf": selected.get("cf"),
            "ct": selected.get("ct"),
            "ff": selected.get("ff"),
            "segment_count": len([key for key in result if key != "_summary"]),
        }
        return result

    @staticmethod
    def _resource_name(url: str) -> str:
        try:
            return Path(urlparse(url).path).name.lower()
        except Exception:
            return ""

    @staticmethod
    def _extract_query_int(url: str, key: str) -> int:
        match = re.search(rf"{re.escape(key)}=(\d+)", url)
        return int(match.group(1)) if match else 0

    @staticmethod
    def _nested_get(payload: Any, *path: Any) -> Any:
        current = payload
        for item in path:
            if isinstance(item, int):
                if not isinstance(current, list) or item >= len(current):
                    return None
                current = current[item]
                continue
            if not isinstance(current, dict):
                return None
            current = current.get(item)
        return current

    @staticmethod
    def _build_notes(tasks: list[dict[str, Any]], dash_response: dict[str, Any] | None) -> list[str]:
        notes: list[str] = []
        if tasks:
            notes.append(f"Built unified segment manifest with {len(tasks)} segment(s).")
        video_summary = SegmentManifestBuilder._nested_get(dash_response, "data", "program", "video", 0)
        if isinstance(video_summary, dict):
            notes.append(
                "DASH video metadata exposes duration="
                f"{video_summary.get('duration')} unencryptedDuration={video_summary.get('unencryptedDuration')} "
                f"drmType={video_summary.get('drmType')}."
            )
        matched = 0
        for item in tasks:
            if item.get("m3u8_group_total_bytes") and item.get("f4vsize"):
                if int(item["m3u8_group_total_bytes"]) == int(item["f4vsize"]):
                    matched += 1
        if matched:
            notes.append(
                f"DASH m3u8 byte-range grouping matches qtplog f4vsize exactly for {matched} segment(s)."
            )
        return notes
