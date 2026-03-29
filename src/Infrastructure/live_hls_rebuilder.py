from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.Application.models import DownloadMetadataEntry, LiveHlsFrameCheck, LiveHlsRebuildPlan
from src.Infrastructure.ffmpeg_tools import FfmpegTools
from src.Infrastructure.runtime_paths import get_default_localwebapp_cache_root, get_log_day_dir


logger = logging.getLogger("aqy_decrypt")


@dataclass
class _PlaylistSegment:
    index: int
    url: str
    duration_sec: float
    content_length: int


class LiveHlsRebuilder:
    def __init__(
        self,
        ffmpeg_tools: FfmpegTools,
        localwebapp_cache_root: Path | None = None,
    ) -> None:
        self.ffmpeg_tools = ffmpeg_tools
        self.localwebapp_cache_root = localwebapp_cache_root or get_default_localwebapp_cache_root()

    def rebuild(
        self,
        sample_path: Path,
        metadata_entry: DownloadMetadataEntry | None,
        output_root: Path | None = None,
        *,
        dash_url: str | None = None,
        max_duration_sec: float | None = None,
        max_segments: int | None = None,
        max_run_sec: float = 50.0,
        workers: int = 8,
        frame_check_points: list[float] | None = None,
    ) -> LiveHlsRebuildPlan:
        output_root = output_root or (get_log_day_dir() / "live_hls_rebuild" / sample_path.stem)
        output_root.mkdir(parents=True, exist_ok=True)
        segments_dir = output_root / "segments"
        segments_dir.mkdir(parents=True, exist_ok=True)

        notes: list[str] = []
        artifact_paths: list[Path] = []

        selected_bid = 0
        selected_vid = ""
        playlist_url = ""
        playlist_text = ""
        playlist_source = ""
        selected_video: dict[str, Any] | None = None

        preferred_video_id = str(getattr(metadata_entry, "video_id", "") or "")
        payload = self._find_matching_movie_payload(metadata_entry)
        if payload is not None:
            selected_video = self._select_video(payload, preferred_video_id=preferred_video_id)
            if selected_video:
                playlist_url = str(selected_video.get("ml") or "")
                selected_bid = int(selected_video.get("bid") or 0)
                selected_vid = str(selected_video.get("vid") or "")
                playlist_source = "moviejson_ml"
                if playlist_url:
                    playlist_text = self._fetch_text(playlist_url, timeout=10)

        if dash_url:
            try:
                dash_payload = self._fetch_json(dash_url, timeout=12)
            except Exception as exc:
                notes.append(f"dash_url fetch failed: {exc}")
                dash_payload = None
            if isinstance(dash_payload, dict) and not playlist_text:
                selected_video = self._select_dash_video(dash_payload, preferred_video_id=preferred_video_id)
                if selected_video:
                    selected_bid = int(selected_video.get("bid") or 0)
                    selected_vid = str(selected_video.get("vid") or "")
                    playlist_text = str(selected_video.get("m3u8") or "")
                    playlist_url = dash_url
                    playlist_source = "dash_inline_m3u8"
                    if not playlist_text:
                        playlist_url = str(selected_video.get("m3u8Url") or "")
                        if playlist_url:
                            playlist_text = self._fetch_text(playlist_url, timeout=10)
                            playlist_source = "dash_m3u8_url"

        if not playlist_text:
            if payload is None:
                return LiveHlsRebuildPlan(
                    sample_path=sample_path,
                    status="cache_payload_not_found",
                    artifact_paths=artifact_paths,
                    notes=["No matching localwebapp cache payload matched sample metadata."],
                )

            selected_video = self._select_video(payload, preferred_video_id=preferred_video_id)
            if not selected_video:
                return LiveHlsRebuildPlan(
                    sample_path=sample_path,
                    status="selected_video_not_found",
                    artifact_paths=artifact_paths,
                    notes=["movieJSON did not expose a selected ts video variant."],
                )

            playlist_url = str(selected_video.get("ml") or "")
            selected_bid = int(selected_video.get("bid") or 0)
            selected_vid = str(selected_video.get("vid") or "")
            playlist_source = "moviejson_ml"
            if not playlist_url:
                return LiveHlsRebuildPlan(
                    sample_path=sample_path,
                    status="playlist_url_missing",
                    selected_bid=selected_bid,
                    selected_vid=selected_vid,
                    artifact_paths=artifact_paths,
                    notes=["Selected video variant did not contain an ml playlist URL."],
                )
            playlist_text = self._fetch_text(playlist_url, timeout=10)

        playlist_path = output_root / "playlist.m3u8"
        playlist_path.write_text(playlist_text, encoding="utf-8")
        artifact_paths.append(playlist_path)

        all_segments = self._parse_playlist(playlist_text)
        if playlist_source == "moviejson_ml" and isinstance(selected_video, dict):
            all_segments = self._rewrite_segments_with_edge_urls(selected_video, all_segments, notes)
        target_segments = self._slice_segments(all_segments, max_duration_sec=max_duration_sec, max_segments=max_segments)
        target_duration_sec = round(sum(item.duration_sec for item in target_segments), 6)

        rewritten_playlist_path = output_root / "playlist.edge.m3u8"
        rewritten_playlist_path.write_text(
            self._render_playlist(playlist_text, all_segments),
            encoding="utf-8",
        )
        artifact_paths.append(rewritten_playlist_path)

        notes.append(
            f"Selected live HLS variant bid={selected_bid} vid={selected_vid} with {len(all_segments)} playlist segments via {playlist_source or 'unknown'}."
        )
        if max_duration_sec is not None or max_segments is not None:
            notes.append(
                f"Bounded rebuild request: selected {len(target_segments)} segment(s) covering {target_duration_sec:.3f}s."
            )

        download_manifest_path = output_root / "download_manifest.json"
        download_manifest_path.write_text(
            json.dumps(
                {
                    "playlist_url": playlist_url,
                    "selected_bid": selected_bid,
                    "selected_vid": selected_vid,
                    "segments": [
                        {
                            "index": item.index,
                            "duration_sec": item.duration_sec,
                            "content_length": item.content_length,
                            "url": item.url,
                        }
                        for item in target_segments
                    ],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        artifact_paths.append(download_manifest_path)

        downloaded_count, downloaded_duration = self._download_segments(
            target_segments,
            segments_dir,
            max_run_sec=max_run_sec,
            workers=max(1, workers),
        )

        if downloaded_count < len(target_segments):
            return LiveHlsRebuildPlan(
                sample_path=sample_path,
                status="partial_download",
                playlist_url=playlist_url,
                selected_bid=selected_bid,
                selected_vid=selected_vid,
                total_segments=len(target_segments),
                downloaded_segments=downloaded_count,
                target_duration_sec=target_duration_sec,
                downloaded_duration_sec=downloaded_duration,
                artifact_paths=artifact_paths,
                notes=notes + [
                    f"Stopped after {max_run_sec:.1f}s budget; rerun resumes from cached segments."
                ],
            )

        ts_path = output_root / f"{sample_path.stem}.live_hls.ts"
        with open(ts_path, "wb") as handle:
            for segment in target_segments:
                handle.write(self._segment_output_path(segments_dir, segment).read_bytes())
        artifact_paths.append(ts_path)

        mp4_path = output_root / f"{sample_path.stem}.live_hls.mp4"
        remux_detail_path = output_root / "remux_detail.json"
        remux_detail = self.ffmpeg_tools.remux_to_mp4(ts_path, mp4_path)
        remux_detail_path.write_text(json.dumps(remux_detail, ensure_ascii=False, indent=2), encoding="utf-8")
        artifact_paths.extend([remux_detail_path, mp4_path])

        probe = self.ffmpeg_tools.probe(mp4_path)
        decode_health = self.ffmpeg_tools.decode_video_health(mp4_path)

        frame_checks: list[LiveHlsFrameCheck] = []
        for timestamp in frame_check_points or []:
            png_path = output_root / "frames" / f"frame_{int(timestamp)}.png"
            png_path.parent.mkdir(parents=True, exist_ok=True)
            note = self._extract_frame_png(mp4_path, timestamp, png_path)
            if png_path.exists():
                artifact_paths.append(png_path)
            frame_checks.append(
                LiveHlsFrameCheck(
                    timestamp_sec=float(timestamp),
                    png_path=png_path if png_path.exists() else None,
                    gray_stats=self.ffmpeg_tools.sample_gray_frame_stats(mp4_path, [timestamp]),
                    note=note,
                )
            )

        status = "success"
        if not probe.ok or probe.video_streams == 0:
            status = "remux_invalid"

        return LiveHlsRebuildPlan(
            sample_path=sample_path,
            status=status,
            playlist_url=playlist_url,
            selected_bid=selected_bid,
            selected_vid=selected_vid,
            total_segments=len(target_segments),
            downloaded_segments=downloaded_count,
            target_duration_sec=target_duration_sec,
            downloaded_duration_sec=downloaded_duration,
            output_ts_path=ts_path,
            output_mp4_path=mp4_path if mp4_path.exists() else None,
            probe_summary=probe,
            decode_health=decode_health,
            frame_checks=frame_checks,
            artifact_paths=artifact_paths,
            notes=notes,
        )

    def _find_matching_movie_payload(self, metadata_entry: DownloadMetadataEntry | None) -> dict[str, Any] | None:
        if metadata_entry is None:
            return None
        tvid = str(metadata_entry.tvid or "")
        video_id = str(metadata_entry.video_id or "")
        aid = str(metadata_entry.aid or "")
        display_name = str(metadata_entry.display_name or metadata_entry.save_file_name or "")
        candidates = sorted(
            self.localwebapp_cache_root.glob("*.json"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        best_payload: dict[str, Any] | None = None
        best_score = -1
        for path in candidates[:80]:
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
            movie_json_text = (
                payload.get("video_data_flow", {}).get("movieJSON")
                if isinstance(payload, dict)
                else None
            )
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
    def _select_video(
        movie_payload: dict[str, Any],
        preferred_video_id: str = "",
    ) -> dict[str, Any] | None:
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

    @staticmethod
    def _fetch_json(url: str, timeout: int) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept-Encoding": "identity",
            },
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="ignore"))

    @staticmethod
    def _select_dash_video(
        dash_payload: dict[str, Any],
        preferred_video_id: str = "",
    ) -> dict[str, Any] | None:
        video_list = dash_payload.get("data", {}).get("program", {}).get("video")
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

    @staticmethod
    def _fetch_text(url: str, timeout: int) -> str:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept-Encoding": "identity",
            },
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="ignore")

    @staticmethod
    def _parse_playlist(playlist_text: str) -> list[_PlaylistSegment]:
        segments: list[_PlaylistSegment] = []
        current_duration = 0.0
        for line in playlist_text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("#EXTINF:"):
                try:
                    current_duration = float(line.split(":", 1)[1].split(",", 1)[0])
                except Exception:
                    current_duration = 0.0
                continue
            if line.startswith("#"):
                continue
            parsed = urllib.parse.urlparse(line)
            query = urllib.parse.parse_qs(parsed.query)
            try:
                content_length = int((query.get("contentlength") or ["0"])[0] or "0")
            except Exception:
                content_length = 0
            segments.append(
                _PlaylistSegment(
                    index=len(segments),
                    url=line,
                    duration_sec=current_duration,
                    content_length=content_length,
                )
            )
        return segments

    @staticmethod
    def _render_playlist(original_playlist_text: str, segments: list[_PlaylistSegment]) -> str:
        segment_iter = iter(segments)
        rendered: list[str] = []
        for line in original_playlist_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("https://"):
                try:
                    rendered.append(next(segment_iter).url)
                except StopIteration:
                    rendered.append(stripped)
            else:
                rendered.append(line)
        return "\n".join(rendered) + "\n"

    @staticmethod
    def _rewrite_segments_with_edge_urls(
        selected_video: dict[str, Any],
        segments: list[_PlaylistSegment],
        notes: list[str],
    ) -> list[_PlaylistSegment]:
        ts_info = selected_video.get("play", {}).get("ts")
        if not isinstance(ts_info, dict):
            return segments
        edge_variants = ts_info.get("d")
        if not isinstance(edge_variants, list) or not edge_variants:
            return segments
        edge_url = str(edge_variants[0].get("URL") or "")
        if not edge_url:
            return segments

        edge_parts = urllib.parse.urlsplit(edge_url)
        edge_query = urllib.parse.parse_qs(edge_parts.query)
        edge_name = Path(edge_parts.path).name.lower()
        edge_suffix = Path(edge_parts.path).suffix.lower()
        rewritten: list[_PlaylistSegment] = []
        rewritten_count = 0
        for segment in segments:
            parsed = urllib.parse.urlsplit(segment.url)
            segment_name = Path(parsed.path).name.lower()
            segment_suffix = Path(parsed.path).suffix.lower()
            # Do not coerce later protected resources (.bbts / different basename)
            # onto the early clear TS edge template. That corrupts the back half.
            if segment_name != edge_name or segment_suffix != edge_suffix:
                rewritten.append(segment)
                continue
            segment_query = urllib.parse.parse_qs(parsed.query)
            merged_query = dict(edge_query)
            for key, value in segment_query.items():
                merged_query[key] = value
            rewritten_url = urllib.parse.urlunsplit(
                (
                    edge_parts.scheme,
                    edge_parts.netloc,
                    edge_parts.path,
                    urllib.parse.urlencode({key: values[0] for key, values in merged_query.items()}),
                    "",
                )
            )
            rewritten.append(
                _PlaylistSegment(
                    index=segment.index,
                    url=rewritten_url,
                    duration_sec=segment.duration_sec,
                    content_length=segment.content_length,
                )
            )
            rewritten_count += 1
        notes.append(
            f"Rewrote {rewritten_count} playlist segment URL(s) using edge-auth template from movieJSON.play.ts.d[0].URL; preserved {len(segments) - rewritten_count} original segment URL(s) with differing resource path/suffix."
        )
        return rewritten

    @staticmethod
    def _slice_segments(
        segments: list[_PlaylistSegment],
        *,
        max_duration_sec: float | None,
        max_segments: int | None,
    ) -> list[_PlaylistSegment]:
        selected: list[_PlaylistSegment] = []
        accumulated = 0.0
        for item in segments:
            if max_segments is not None and len(selected) >= max_segments:
                break
            if max_duration_sec is not None and selected and accumulated >= max_duration_sec:
                break
            selected.append(item)
            accumulated += item.duration_sec
        return selected

    def _download_segments(
        self,
        segments: list[_PlaylistSegment],
        segments_dir: Path,
        *,
        max_run_sec: float,
        workers: int,
    ) -> tuple[int, float]:
        pending = [item for item in segments if not self._segment_complete(segments_dir, item)]
        completed = len(segments) - len(pending)
        completed_duration = sum(item.duration_sec for item in segments[:completed])
        if not pending:
            return len(segments), round(sum(item.duration_sec for item in segments), 6)

        started = time.perf_counter()
        request_timeout_sec = 3.0
        if workers <= 1:
            for segment in pending:
                if time.perf_counter() - started >= max_run_sec:
                    break
                try:
                    self._download_one(segments_dir, segment, request_timeout_sec)
                except Exception:
                    break
            downloaded = [item for item in segments if self._segment_complete(segments_dir, item)]
            downloaded_duration = round(sum(item.duration_sec for item in downloaded), 6)
            return len(downloaded), downloaded_duration
        futures: dict[Any, _PlaylistSegment] = {}
        pending_iter = iter(pending)
        executor = ThreadPoolExecutor(max_workers=workers)
        timed_out = False
        try:
            while len(futures) < workers:
                try:
                    segment = next(pending_iter)
                except StopIteration:
                    break
                futures[executor.submit(self._download_one, segments_dir, segment, request_timeout_sec)] = segment
            while futures:
                remaining = max_run_sec - (time.perf_counter() - started)
                if remaining <= 0:
                    timed_out = True
                    for future in futures:
                        future.cancel()
                    executor.shutdown(wait=False, cancel_futures=True)
                    futures.clear()
                    break
                done, _ = wait(list(futures.keys()), timeout=min(remaining, 1.0), return_when=FIRST_COMPLETED)
                if not done:
                    continue
                for future in done:
                    segment = futures.pop(future)
                    future.result()
                    if time.perf_counter() - started >= max_run_sec:
                        continue
                    try:
                        next_segment = next(pending_iter)
                    except StopIteration:
                        continue
                    futures[executor.submit(self._download_one, segments_dir, next_segment, request_timeout_sec)] = next_segment
        finally:
            if futures:
                executor.shutdown(wait=not timed_out, cancel_futures=timed_out)
        downloaded = [item for item in segments if self._segment_complete(segments_dir, item)]
        downloaded_duration = round(sum(item.duration_sec for item in downloaded), 6)
        return len(downloaded), downloaded_duration

    def _download_one(self, segments_dir: Path, segment: _PlaylistSegment, timeout_sec: float) -> None:
        output_path = self._segment_output_path(segments_dir, segment)
        if output_path.exists():
            return
        temp_path = output_path.with_suffix(output_path.suffix + ".part")
        curl_path = shutil.which("curl.exe") or shutil.which("curl")
        if curl_path:
            command = [
                curl_path,
                "--location",
                "--connect-timeout",
                "3",
                "--max-time",
                str(max(1, int(timeout_sec))),
                "--silent",
                "--show-error",
                "--output",
                str(temp_path),
                segment.url,
            ]
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=max(2.0, timeout_sec + 2.0),
            )
            if completed.returncode != 0 or not temp_path.exists():
                raise RuntimeError(completed.stderr.strip() or f"curl download failed for segment {segment.index}")
            temp_path.replace(output_path)
            return
        request = urllib.request.Request(
            segment.url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept-Encoding": "identity",
            },
        )
        with urllib.request.urlopen(request, timeout=timeout_sec) as response, open(temp_path, "wb") as handle:
            while True:
                block = response.read(512 * 1024)
                if not block:
                    break
                handle.write(block)
        temp_path.replace(output_path)

    @staticmethod
    def _segment_output_path(segments_dir: Path, segment: _PlaylistSegment) -> Path:
        suffix = Path(urllib.parse.urlparse(segment.url).path).suffix or ".bin"
        return segments_dir / f"{segment.index:05d}{suffix}"

    def _segment_complete(self, segments_dir: Path, segment: _PlaylistSegment) -> bool:
        output_path = self._segment_output_path(segments_dir, segment)
        if not output_path.exists():
            return False
        if segment.content_length > 0 and output_path.stat().st_size != segment.content_length:
            return False
        return output_path.stat().st_size > 0

    def _extract_frame_png(self, media_path: Path, timestamp: float, png_path: Path) -> str:
        self.ffmpeg_tools.ensure_available()
        command = [
            str(self.ffmpeg_tools.ffmpeg_path),
            "-hide_banner",
            "-loglevel",
            "error",
            "-ss",
            f"{max(0.0, float(timestamp)):.3f}",
            "-i",
            str(media_path),
            "-frames:v",
            "1",
            "-y",
            str(png_path),
        ]
        try:
            import subprocess

            completed = subprocess.run(command, check=False, capture_output=True, text=True, encoding="utf-8", errors="ignore")
        except Exception as exc:
            return f"frame_extract_exception: {exc}"
        if completed.returncode == 0 and png_path.exists():
            return "ok"
        return completed.stderr.strip() or "frame_extract_failed"
