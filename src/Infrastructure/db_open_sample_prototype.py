from __future__ import annotations

import hashlib
import json
import math
import struct
import subprocess
import time
from pathlib import Path

from src.Application.models import DbSnapshot, PgFileInfo, SnapshotFileInfo, SnapshotWalDiff, SnapshotWalPageDiff

from .db_cache_analysis import DbCacheAnalyzer
from .db_snapshot import DbSnapshotService
from .qsv_offline import QsvOfflineDecoder
from .runtime_paths import get_default_cache_root, get_default_qyclient_paths, get_log_day_dir


class DbOpenSamplePrototype:
    def __init__(
        self,
        snapshot_service: DbSnapshotService,
        cache_analyzer: DbCacheAnalyzer,
        decoder: QsvOfflineDecoder,
        cache_root: Path | None = None,
    ) -> None:
        self.snapshot_service = snapshot_service
        self.cache_analyzer = cache_analyzer
        self.decoder = decoder
        self.cache_root = cache_root or get_default_cache_root()

    def run(self, sample_path: Path, wait_sec: int = 25, client_path: Path | None = None) -> dict:
        client_path = client_path or self._resolve_client_path()
        work_dir = get_log_day_dir() / "prototype_open_diff" / sample_path.stem
        work_dir.mkdir(parents=True, exist_ok=True)

        before_state = self._collect_state()
        before_snapshot = self.snapshot_service.create_snapshot("hot")

        launched = subprocess.Popen([str(client_path), str(sample_path)])
        try:
            time.sleep(wait_sec)
            after_state = self._collect_state()
            after_snapshot = self.snapshot_service.create_snapshot("hot")
        finally:
            self._close_launched_client(launched)

        changed_files: dict[str, dict[str, object]] = {}
        for name in sorted(set(before_state) | set(after_state)):
            if before_state.get(name) != after_state.get(name):
                changed_files[name] = {
                    "before": before_state.get(name),
                    "after": after_state.get(name),
                }
        snapshot_file_diff = self._compare_snapshot_files(
            before_snapshot.snapshot_root,
            after_snapshot.snapshot_root,
        )
        wal_diffs = self._compare_wals(
            before_snapshot.snapshot_root,
            after_snapshot.snapshot_root,
        )

        inspection = self.decoder.inspect(sample_path)
        before_correlation = self.cache_analyzer.inspect_snapshot(
            snapshot=self._load_snapshot(before_snapshot.snapshot_root),
            sample_path=sample_path,
            qsv_inspection=inspection,
        )
        after_correlation = self.cache_analyzer.inspect_snapshot(
            snapshot=self._load_snapshot(after_snapshot.snapshot_root),
            sample_path=sample_path,
            qsv_inspection=inspection,
        )

        report = {
            "client_path": str(client_path),
            "sample_path": str(sample_path),
            "launched_pid": launched.pid,
            "wait_sec": wait_sec,
            **self._build_report_payload(
                sample_path=sample_path,
                before_root=before_snapshot.snapshot_root,
                after_root=after_snapshot.snapshot_root,
                changed_files=changed_files,
                snapshot_file_diff=snapshot_file_diff,
                wal_diffs=wal_diffs,
                before_correlation=before_correlation,
                after_correlation=after_correlation,
            ),
        }
        report["artifact_paths"] = self._write_wal_diff_artifacts(
            work_dir=work_dir,
            before_root=before_snapshot.snapshot_root,
            after_root=after_snapshot.snapshot_root,
            wal_diffs=wal_diffs,
        )
        hot_page_analysis = self._analyze_hot_payload_artifacts(
            artifact_dir=work_dir / "wal_diff_payloads",
            wal_diffs=wal_diffs,
        )
        report["hot_page_analysis"] = hot_page_analysis
        report["pgf_window_correlation"] = self._correlate_hot_pages_with_pgf_windows(
            sample_path=sample_path,
            after_correlation=after_correlation,
            hot_page_analysis=hot_page_analysis,
        )
        report["shm_diffs"] = self._compare_shms(
            before_snapshot.snapshot_root,
            after_snapshot.snapshot_root,
        )
        report_path = work_dir / f"{sample_path.stem}.open_diff.json"
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        report["report_path"] = str(report_path)
        return report

    def compare_snapshots(self, sample_path: Path, before_root: Path, after_root: Path) -> dict:
        work_dir = get_log_day_dir() / "prototype_open_diff" / sample_path.stem
        work_dir.mkdir(parents=True, exist_ok=True)
        inspection = self.decoder.inspect(sample_path)
        snapshot_file_diff = self._compare_snapshot_files(before_root, after_root)
        wal_diffs = self._compare_wals(before_root, after_root)
        before_correlation = self.cache_analyzer.inspect_snapshot(
            snapshot=self._load_snapshot(before_root),
            sample_path=sample_path,
            qsv_inspection=inspection,
        )
        after_correlation = self.cache_analyzer.inspect_snapshot(
            snapshot=self._load_snapshot(after_root),
            sample_path=sample_path,
            qsv_inspection=inspection,
        )
        report = self._build_report_payload(
            sample_path=sample_path,
            before_root=before_root,
            after_root=after_root,
            changed_files=snapshot_file_diff,
            snapshot_file_diff=snapshot_file_diff,
            wal_diffs=wal_diffs,
            before_correlation=before_correlation,
            after_correlation=after_correlation,
        )
        report["client_path"] = ""
        report["launched_pid"] = 0
        report["wait_sec"] = 0
        report["mode"] = "snapshot_compare"
        report["artifact_paths"] = self._write_wal_diff_artifacts(
            work_dir=work_dir,
            before_root=before_root,
            after_root=after_root,
            wal_diffs=wal_diffs,
        )
        hot_page_analysis = self._analyze_hot_payload_artifacts(
            artifact_dir=work_dir / "wal_diff_payloads",
            wal_diffs=wal_diffs,
        )
        report["hot_page_analysis"] = hot_page_analysis
        report["pgf_window_correlation"] = self._correlate_hot_pages_with_pgf_windows(
            sample_path=sample_path,
            after_correlation=after_correlation,
            hot_page_analysis=hot_page_analysis,
        )
        report["shm_diffs"] = self._compare_shms(before_root, after_root)
        report_path = work_dir / f"{sample_path.stem}.snapshot_compare.json"
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        report["report_path"] = str(report_path)
        return report

    @staticmethod
    def _build_report_payload(
        sample_path: Path,
        before_root: Path,
        after_root: Path,
        changed_files: dict[str, dict[str, object]],
        snapshot_file_diff: dict[str, dict[str, object]],
        wal_diffs: list[SnapshotWalDiff],
        before_correlation,
        after_correlation,
    ) -> dict[str, object]:
        after_payload_matches = DbOpenSamplePrototype._find_last_payload_matches(after_root)
        return {
            "sample_path": str(sample_path),
            "before_snapshot": str(before_root),
            "after_snapshot": str(after_root),
            "changed_files": changed_files,
            "snapshot_file_diff": snapshot_file_diff,
            "wal_diffs": [item.to_dict() for item in wal_diffs],
            "after_snapshot_last_payload_matches": after_payload_matches,
            "before_db_correlation": before_correlation.to_dict(),
            "after_db_correlation": after_correlation.to_dict(),
        }

    @staticmethod
    def _compare_snapshot_files(before_root: Path, after_root: Path) -> dict[str, dict[str, object]]:
        def scan(root: Path) -> dict[str, dict[str, object]]:
            out: dict[str, dict[str, object]] = {}
            for path in sorted(root.iterdir()):
                if not path.is_file():
                    continue
                out[path.name] = {
                    "size": path.stat().st_size,
                    "sha1_head": hashlib.sha1(path.read_bytes()[:1024 * 1024]).hexdigest()[:20],
                }
            return out

        before = scan(before_root)
        after = scan(after_root)
        diff: dict[str, dict[str, object]] = {}
        for name in sorted(set(before) | set(after)):
            if before.get(name) != after.get(name):
                diff[name] = {
                    "before": before.get(name),
                    "after": after.get(name),
                }
        return diff

    def _compare_wals(self, before_root: Path, after_root: Path) -> list[SnapshotWalDiff]:
        wal_names = sorted({path.name for path in before_root.glob("*.db-wal")} | {path.name for path in after_root.glob("*.db-wal")})
        results: list[SnapshotWalDiff] = []
        for wal_name in wal_names:
            before_path = before_root / wal_name
            after_path = after_root / wal_name
            before_exists = before_path.exists()
            after_exists = after_path.exists()
            if not before_exists and not after_exists:
                continue

            before_meta = self._parse_wal_pages(before_path) if before_exists else {"page_size": 0, "pages": {}}
            after_meta = self._parse_wal_pages(after_path) if after_exists else {"page_size": 0, "pages": {}}
            all_pages = sorted(set(before_meta["pages"]) | set(after_meta["pages"]))
            page_diffs: list[SnapshotWalPageDiff] = []
            pages_with_count_change: list[int] = []
            pages_with_payload_change: list[int] = []

            for page_number in all_pages:
                before_entries = before_meta["pages"].get(page_number, [])
                after_entries = after_meta["pages"].get(page_number, [])
                before_last = before_entries[-1] if before_entries else None
                after_last = after_entries[-1] if after_entries else None
                payload_diff_bytes = 0
                last_payload_changed = False
                if before_last and after_last:
                    payload_diff_bytes = sum(a != b for a, b in zip(before_last["payload"], after_last["payload"]))
                    last_payload_changed = before_last["sha1"] != after_last["sha1"]
                elif before_last or after_last:
                    last_payload_changed = True
                appended_only = bool(
                    before_entries
                    and after_entries
                    and len(after_entries) > len(before_entries)
                    and before_last["sha1"] == after_last["sha1"]
                )
                if len(before_entries) != len(after_entries):
                    pages_with_count_change.append(page_number)
                if last_payload_changed:
                    pages_with_payload_change.append(page_number)
                page_diffs.append(
                    SnapshotWalPageDiff(
                        wal_name=wal_name,
                        page_number=page_number,
                        before_frame_count=len(before_entries),
                        after_frame_count=len(after_entries),
                        before_last_sha1=before_last["sha1"] if before_last else "",
                        after_last_sha1=after_last["sha1"] if after_last else "",
                        before_last_head_hex=(before_last["payload"][:64].hex() if before_last else ""),
                        after_last_head_hex=(after_last["payload"][:64].hex() if after_last else ""),
                        last_payload_diff_bytes=payload_diff_bytes,
                        appended_only=appended_only,
                        last_payload_changed=last_payload_changed,
                    )
                )

            note_parts: list[str] = []
            if pages_with_count_change:
                note_parts.append(f"frame-count changed on pages {pages_with_count_change}")
            if pages_with_payload_change:
                note_parts.append(f"last payload changed on pages {pages_with_payload_change}")
            if not note_parts:
                note_parts.append("no page-level changes detected between snapshots")

            results.append(
                SnapshotWalDiff(
                    wal_name=wal_name,
                    before_path=before_path if before_exists else None,
                    after_path=after_path if after_exists else None,
                    before_size=before_path.stat().st_size if before_exists else 0,
                    after_size=after_path.stat().st_size if after_exists else 0,
                    page_size=int(after_meta["page_size"] or before_meta["page_size"] or 0),
                    pages_with_count_change=pages_with_count_change,
                    pages_with_payload_change=pages_with_payload_change,
                    page_diffs=page_diffs[:24],
                    note="; ".join(note_parts),
                )
            )
        return results

    @staticmethod
    def _parse_wal_pages(path: Path) -> dict[str, object]:
        blob = path.read_bytes()
        if len(blob) < 32 or blob[:4] != b"\x37\x7f\x06\x82":
            return {"page_size": 0, "pages": {}}
        page_size = struct.unpack(">I", blob[8:12])[0]
        if page_size <= 0:
            return {"page_size": 0, "pages": {}}
        frame_size = page_size + 24
        pages: dict[int, list[dict[str, object]]] = {}
        frame_index = 0
        offset = 32
        while offset + frame_size <= len(blob):
            header = blob[offset : offset + 24]
            page_number = struct.unpack(">I", header[:4])[0]
            if page_number == 0:
                break
            payload = blob[offset + 24 : offset + frame_size]
            pages.setdefault(page_number, []).append(
                {
                    "frame_index": frame_index,
                    "sha1": hashlib.sha1(payload).hexdigest(),
                    "payload": payload,
                }
            )
            frame_index += 1
            offset += frame_size
        return {"page_size": page_size, "pages": pages}

    @staticmethod
    def _find_last_payload_matches(snapshot_root: Path) -> list[dict[str, object]]:
        payload_map: dict[str, list[dict[str, object]]] = {}
        for wal_path in sorted(snapshot_root.glob("*.db-wal")):
            parsed = DbOpenSamplePrototype._parse_wal_pages(wal_path)
            for page_number, entries in parsed["pages"].items():
                if not entries:
                    continue
                last = entries[-1]
                payload_map.setdefault(last["sha1"], []).append(
                    {
                        "wal_name": wal_path.name,
                        "page_number": page_number,
                        "frame_count": len(entries),
                        "head_hex": last["payload"][:64].hex(),
                    }
                )

        matches: list[dict[str, object]] = []
        for sha1, refs in payload_map.items():
            if len(refs) < 2:
                continue
            matches.append(
                {
                    "sha1": sha1,
                    "refs": refs,
                }
            )
        matches.sort(key=lambda item: len(item["refs"]), reverse=True)
        return matches[:16]

    def _compare_shms(self, before_root: Path, after_root: Path) -> list[dict[str, object]]:
        shm_names = sorted({path.name for path in before_root.glob("*.db-shm")} | {path.name for path in after_root.glob("*.db-shm")})
        results: list[dict[str, object]] = []
        for shm_name in shm_names:
            before_path = before_root / shm_name
            after_path = after_root / shm_name
            before_info = self._parse_shm(before_path) if before_path.exists() else None
            after_info = self._parse_shm(after_path) if after_path.exists() else None
            if before_info is None and after_info is None:
                continue
            header_changes: dict[str, dict[str, object]] = {}
            keys = {
                "iVersion",
                "iChange",
                "isInit",
                "bigEndCksum",
                "szPage",
                "mxFrame",
                "nPage",
                "nBackfill",
                "nBackfillAttempted",
                "read_marks",
            }
            for key in keys:
                before_value = before_info.get(key) if before_info else None
                after_value = after_info.get(key) if after_info else None
                if before_value != after_value:
                    header_changes[key] = {
                        "before": before_value,
                        "after": after_value,
                    }
            results.append(
                {
                    "shm_name": shm_name,
                    "before_path": str(before_path) if before_path.exists() else None,
                    "after_path": str(after_path) if after_path.exists() else None,
                    "before_size": before_path.stat().st_size if before_path.exists() else 0,
                    "after_size": after_path.stat().st_size if after_path.exists() else 0,
                    "header_changes": header_changes,
                    "before_summary": before_info,
                    "after_summary": after_info,
                }
            )
        return results

    @staticmethod
    def _parse_shm(path: Path) -> dict[str, object] | None:
        if not path.exists():
            return None
        blob = path.read_bytes()
        if len(blob) < 136:
            return None
        def u32le(offset: int) -> int:
            return struct.unpack_from("<I", blob, offset)[0]
        def u16le(offset: int) -> int:
            return struct.unpack_from("<H", blob, offset)[0]

        mx_frame = u32le(16)
        page_count = min(mx_frame, 4062)
        a_pgno = [
            u32le(136 + i * 4)
            for i in range(page_count)
        ]
        nonzero_pgno = [value for value in a_pgno if value]
        top_pages: dict[int, int] = {}
        if nonzero_pgno:
            counts: dict[int, int] = {}
            for value in nonzero_pgno:
                counts[value] = counts.get(value, 0) + 1
            top_pages = dict(sorted(counts.items(), key=lambda item: item[1], reverse=True)[:12])
        return {
            "iVersion": u32le(0),
            "iChange": u32le(8),
            "isInit": blob[12],
            "bigEndCksum": blob[13],
            "szPage": (65536 if u16le(14) == 1 else u16le(14)),
            "mxFrame": mx_frame,
            "nPage": u32le(20),
            "nBackfill": u32le(96),
            "read_marks": [u32le(100 + i * 4) for i in range(5)],
            "nBackfillAttempted": u32le(128),
            "aPgno_nonzero_count": len(nonzero_pgno),
            "aPgno_first_entries": a_pgno[:16],
            "aPgno_top_pages": top_pages,
        }

    def _write_wal_diff_artifacts(
        self,
        work_dir: Path,
        before_root: Path,
        after_root: Path,
        wal_diffs: list[SnapshotWalDiff],
    ) -> list[str]:
        artifact_dir = work_dir / "wal_diff_payloads"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        written: list[str] = []
        for wal_diff in wal_diffs:
            pages_to_dump = set(wal_diff.pages_with_payload_change) | set(wal_diff.pages_with_count_change)
            if not pages_to_dump:
                continue
            before_meta = self._parse_wal_pages(before_root / wal_diff.wal_name) if wal_diff.before_path else {"pages": {}}
            after_meta = self._parse_wal_pages(after_root / wal_diff.wal_name) if wal_diff.after_path else {"pages": {}}
            for page_number in sorted(pages_to_dump):
                before_entries = before_meta["pages"].get(page_number, [])
                after_entries = after_meta["pages"].get(page_number, [])
                if before_entries:
                    before_last = before_entries[-1]["payload"]
                    before_path = artifact_dir / f"{wal_diff.wal_name}.page{page_number}.before.bin"
                    before_path.write_bytes(before_last)
                    written.append(str(before_path))
                if after_entries:
                    after_last = after_entries[-1]["payload"]
                    after_path = artifact_dir / f"{wal_diff.wal_name}.page{page_number}.after.bin"
                    after_path.write_bytes(after_last)
                    written.append(str(after_path))
        return written

    @staticmethod
    def _analyze_hot_payload_artifacts(artifact_dir: Path, wal_diffs: list[SnapshotWalDiff]) -> dict[str, object]:
        if not artifact_dir.exists():
            return {}

        def payload_stats(blob: bytes) -> dict[str, object]:
            if not blob:
                return {
                    "size": 0,
                    "entropy": 0.0,
                    "unique_bytes": 0,
                    "zero_ratio": 0.0,
                    "head_hex": "",
                    "tail_hex": "",
                }
            counts: dict[int, int] = {}
            for value in blob:
                counts[value] = counts.get(value, 0) + 1
            entropy = 0.0
            total = len(blob)
            for count in counts.values():
                p = count / total
                entropy -= p * math.log2(p)
            return {
                "size": len(blob),
                "entropy": round(entropy, 4),
                "unique_bytes": len(counts),
                "zero_ratio": round(counts.get(0, 0) / len(blob), 6),
                "head_hex": blob[:32].hex(),
                "tail_hex": blob[-32:].hex(),
            }

        def compare_blobs(before_blob: bytes, after_blob: bytes) -> dict[str, object]:
            prefix = 0
            while prefix < len(before_blob) and before_blob[prefix] == after_blob[prefix]:
                prefix += 1
            suffix = 0
            while suffix < len(before_blob) - prefix and before_blob[-1 - suffix] == after_blob[-1 - suffix]:
                suffix += 1

            block_matches: list[dict[str, int]] = []
            for block_size in (16, 32, 64):
                total_blocks = len(before_blob) // block_size
                same_blocks = 0
                for index in range(total_blocks):
                    start = index * block_size
                    end = start + block_size
                    if before_blob[start:end] == after_blob[start:end]:
                        same_blocks += 1
                block_matches.append(
                    {
                        "block_size": block_size,
                        "same_blocks": same_blocks,
                        "total_blocks": total_blocks,
                    }
                )
            return {
                "common_prefix": prefix,
                "common_suffix": suffix,
                "block_matches": block_matches,
            }

        page_rows: list[dict[str, object]] = []
        after_groups: dict[str, list[str]] = {}
        page_diff_map: dict[tuple[str, int], SnapshotWalPageDiff] = {}
        for wal_diff in wal_diffs:
            for page_diff in wal_diff.page_diffs:
                page_diff_map[(wal_diff.wal_name, page_diff.page_number)] = page_diff

        for before_path in sorted(artifact_dir.glob("*.before.bin")):
            base_name = before_path.name[:-11]
            after_path = artifact_dir / f"{base_name}.after.bin"
            if not after_path.exists():
                continue

            before_blob = before_path.read_bytes()
            after_blob = after_path.read_bytes()
            wal_name, _, page_part = base_name.rpartition(".page")
            try:
                page_number = int(page_part)
            except ValueError:
                continue
            after_sha1 = hashlib.sha1(after_blob).hexdigest()
            after_groups.setdefault(after_sha1, []).append(base_name)
            diff_info = page_diff_map.get((wal_name, page_number))
            page_rows.append(
                {
                    "base_name": base_name,
                    "wal_name": wal_name,
                    "page_number": page_number,
                    "before_stats": payload_stats(before_blob),
                    "after_stats": payload_stats(after_blob),
                    "diff_shape": compare_blobs(before_blob, after_blob),
                    "frame_change": (
                        [diff_info.before_frame_count, diff_info.after_frame_count]
                        if diff_info is not None
                        else []
                    ),
                    "payload_changed": bool(diff_info.last_payload_changed) if diff_info is not None else True,
                }
            )

        duplicate_after_payloads = [
            {"sha1": sha1, "pages": refs}
            for sha1, refs in after_groups.items()
            if len(refs) > 1
        ]
        duplicate_after_payloads.sort(key=lambda item: len(item["pages"]), reverse=True)

        for row in page_rows:
            row["shared_after_payload"] = any(
                row["base_name"] in group["pages"] and len(group["pages"]) > 1
                for group in duplicate_after_payloads
            )
            after_entropy = float(row["after_stats"]["entropy"])
            zero_ratio = float(row["after_stats"]["zero_ratio"])
            if after_entropy < 1.0 or zero_ratio > 0.9:
                row["classification"] = "low-entropy-state-page"
            elif row["shared_after_payload"]:
                row["classification"] = "shared-session-page"
            else:
                row["classification"] = "unique-hot-page"
            row["role_hint"] = "candidate-mapping-page"

        priority_rows = sorted(
            page_rows,
            key=lambda item: (
                0 if item["classification"] == "unique-hot-page" else 1,
                0 if item["classification"] == "shared-session-page" else 1,
                -float(item["after_stats"]["entropy"]),
                item["page_number"],
            ),
        )
        row_map = {item["base_name"]: item for item in page_rows}
        notes: list[str] = []
        duplicate_sets = [set(item["pages"]) for item in duplicate_after_payloads]
        if {"data-nor.db-wal.page1", "data-qsv.db-wal.page1"} in duplicate_sets:
            if "data-nor.db-wal.page1" in row_map:
                row_map["data-nor.db-wal.page1"]["role_hint"] = "shared-session-root-page"
            if "data-qsv.db-wal.page1" in row_map:
                row_map["data-qsv.db-wal.page1"]["role_hint"] = "shared-session-root-page"
            notes.append(
                "data-nor.db-wal.page1 and data-qsv.db-wal.page1 are byte-identical after pages, so treat them as a "
                "shared session/root page rather than a sample-specific mapping page."
            )
        db_page1 = row_map.get("data.db-wal.page1")
        nor_page1 = row_map.get("data-nor.db-wal.page1")
        if db_page1 and nor_page1 and int(db_page1["diff_shape"]["common_prefix"]) == 24:
            db_page1["role_hint"] = "db-specific-header-window"
            notes.append(
                "data.db-wal.page1 only keeps a 24-byte common prefix with the shared nor/qsv page1 header; the rest "
                "of the page diverges, so page1 likely mixes a shared root/header region with db-specific payload."
            )
        nor_page2 = row_map.get("data-nor.db-wal.page2")
        db_page2 = row_map.get("data.db-wal.page2")
        if nor_page2 and db_page2:
            nor_page2["role_hint"] = "rolling-mapping-window"
            db_page2["role_hint"] = "bootstrap-mapping-window"
            notes.append(
                "data-nor.db-wal.page2 and data.db-wal.page2 are both unique hot pages with zero common prefix/suffix, "
                "which makes them better init/mapping candidates than the mirrored page3/4 or low-entropy page8/9 set."
            )
        qsv_page2 = row_map.get("data-qsv.db-wal.page2")
        if qsv_page2 and qsv_page2["classification"] != "low-entropy-state-page":
            qsv_page2["role_hint"] = "mid-coverage-window"
        nor_page3 = row_map.get("data-nor.db-wal.page3")
        nor_page4 = row_map.get("data-nor.db-wal.page4")
        if nor_page3 and nor_page4:
            nor_page3["role_hint"] = "mirrored-tail-page"
            nor_page4["role_hint"] = "mirrored-tail-page"
        db_page3 = row_map.get("data.db-wal.page3")
        db_page4 = row_map.get("data.db-wal.page4")
        if db_page3 and db_page4:
            db_page3["role_hint"] = "mirrored-tail-page"
            db_page4["role_hint"] = "mirrored-tail-page"
        for low_entropy_name in ("data.db-wal.page8", "data.db-wal.page9"):
            low_entropy_row = row_map.get(low_entropy_name)
            if low_entropy_row:
                low_entropy_row["role_hint"] = "low-entropy-state-page"
        return {
            "page_rows": page_rows,
            "duplicate_after_payloads": duplicate_after_payloads[:16],
            "priority_pages": [
                {
                    "base_name": item["base_name"],
                    "classification": item["classification"],
                    "role_hint": item.get("role_hint", ""),
                    "after_entropy": item["after_stats"]["entropy"],
                    "frame_change": item["frame_change"],
                    "common_prefix": item["diff_shape"]["common_prefix"],
                    "common_suffix": item["diff_shape"]["common_suffix"],
                }
                for item in priority_rows[:12]
            ],
            "notes": notes,
        }

    def _correlate_hot_pages_with_pgf_windows(
        self,
        sample_path: Path,
        after_correlation,
        hot_page_analysis: dict[str, object],
    ) -> dict[str, object]:
        prototype_report = self._find_latest_prototype_report(sample_path)
        if prototype_report is None:
            return {
                "ok": False,
                "reason": "prototype_report_missing",
                "sample_path": str(sample_path),
            }

        try:
            payload = json.loads(prototype_report.read_text(encoding="utf-8"))
        except Exception as exc:
            return {
                "ok": False,
                "reason": f"prototype_report_unreadable: {exc}",
                "sample_path": str(sample_path),
                "prototype_report": str(prototype_report),
            }

        fragments = [
            item for item in payload.get("pgf_fragments", [])
            if item.get("track_id") == 1
            and item.get("earliest_presentation_sec") is not None
            and item.get("duration_sec") is not None
        ]
        if not fragments:
            return {
                "ok": False,
                "reason": "prototype_report_has_no_track1_fragments",
                "sample_path": str(sample_path),
                "prototype_report": str(prototype_report),
            }

        fragments.sort(
            key=lambda item: (
                float(item.get("earliest_presentation_sec", 0.0)),
                int(item.get("sequence_number", 0)),
            )
        )
        wal_page_counts: dict[str, int] = {}
        for inspection in after_correlation.wal_inspections:
            for page_number, frame_count in inspection.page_frequencies.items():
                wal_page_counts[f"{inspection.wal_name}.page{page_number}"] = int(frame_count)

        candidate_map: dict[str, dict[str, object]] = {
            str(item.get("base_name", "")): dict(item)
            for item in hot_page_analysis.get("priority_pages", [])
            if item.get("base_name")
        }
        default_role_hints = {
            "data.db-wal.page2": "bootstrap-window",
            "data.db-wal.page1": "early-window",
            "data-qsv.db-wal.page2": "mid-window",
            "data-nor.db-wal.page2": "rolling-window",
            "data-nor.db-wal.page1": "shared-session-root-page",
            "data-qsv.db-wal.page1": "shared-session-root-page",
        }
        for base_name in (
            "data.db-wal.page2",
            "data.db-wal.page1",
            "data-qsv.db-wal.page2",
            "data-nor.db-wal.page2",
            "data-nor.db-wal.page1",
            "data-qsv.db-wal.page1",
        ):
            if base_name not in wal_page_counts:
                continue
            row = candidate_map.setdefault(
                base_name,
                {
                    "base_name": base_name,
                    "classification": "current-hot-page",
                },
            )
            if not row.get("role_hint") and base_name in default_role_hints:
                row["role_hint"] = default_role_hints[base_name]
        candidate_pages = list(candidate_map.values())

        rows: list[dict[str, object]] = []
        for page in candidate_pages:
            base_name = str(page.get("base_name", ""))
            page_count = wal_page_counts.get(base_name)
            if not page_count:
                continue
            subset = fragments[: min(page_count, len(fragments))]
            if not subset:
                continue
            first = subset[0]
            last = subset[-1]
            covered_end_sec = float(last["earliest_presentation_sec"]) + float(last["duration_sec"])
            rows.append(
                {
                    "base_name": base_name,
                    "classification": page.get("classification"),
                    "role_hint": page.get("role_hint"),
                    "wal_frame_count": page_count,
                    "mapped_fragment_count": len(subset),
                    "first_sequence_number": int(first.get("sequence_number", 0)),
                    "last_sequence_number": int(last.get("sequence_number", 0)),
                    "window_start_sec": float(first["earliest_presentation_sec"]),
                    "last_fragment_start_sec": float(last["earliest_presentation_sec"]),
                    "covered_end_sec": covered_end_sec,
                    "avg_fragment_duration_sec": round(
                        sum(float(item["duration_sec"]) for item in subset) / len(subset),
                        6,
                    ),
                }
            )

        ladder_rows = sorted(
            [
                row for row in rows
                if row["base_name"] in {
                    "data.db-wal.page2",
                    "data.db-wal.page1",
                    "data-qsv.db-wal.page2",
                    "data-nor.db-wal.page2",
                }
            ],
            key=lambda item: (int(item["mapped_fragment_count"]), float(item["covered_end_sec"])),
        )
        inferred_roles = [
            "bootstrap-window",
            "early-window",
            "mid-window",
            "rolling-window",
        ]
        for row, role in zip(ladder_rows, inferred_roles):
            row["window_role"] = role
            if not row.get("role_hint"):
                row["role_hint"] = role

        page2_match = next((row for row in rows if row["base_name"] == "data-nor.db-wal.page2"), None)
        notes: list[str] = []
        if page2_match is not None:
            notes.append(
                "data-nor.db-wal.page2 currently spans PGF track-1 sequence "
                f"{page2_match['first_sequence_number']}..{page2_match['last_sequence_number']} "
                f"({page2_match['window_start_sec']:.3f}s -> {page2_match['covered_end_sec']:.3f}s) "
                "under a 1-frame ~= 1-fragment assumption."
            )
            if 360.0 <= float(page2_match["covered_end_sec"]) <= 420.0:
                notes.append(
                    "That window lands near the observed ~6.5 minute corruption boundary, which makes "
                    "page2 the strongest candidate for a rolling fragment-index or mapping window."
                )
        qsv_page2_match = next((row for row in rows if row["base_name"] == "data-qsv.db-wal.page2"), None)
        if qsv_page2_match is not None:
            notes.append(
                "data-qsv.db-wal.page2 currently spans PGF track-1 sequence "
                f"{qsv_page2_match['first_sequence_number']}..{qsv_page2_match['last_sequence_number']} "
                f"({qsv_page2_match['window_start_sec']:.3f}s -> {qsv_page2_match['covered_end_sec']:.3f}s)."
            )
        layered_rows = [
            row
            for row in rows
            if row["base_name"] in {
                "data.db-wal.page2",
                "data.db-wal.page1",
                "data-qsv.db-wal.page2",
                "data-nor.db-wal.page2",
            }
        ]
        if len(layered_rows) >= 3:
            layered_rows.sort(key=lambda item: int(item["wal_frame_count"]))
            notes.append(
                "Current hot pages form a nested PGF window ladder: "
                + ", ".join(
                    f"{row['base_name']}={row['wal_frame_count']}frag/{row['covered_end_sec']:.0f}s"
                    for row in layered_rows
                )
                + ". This looks more like layered fragment-index coverage than unrelated session noise."
            )
        if ladder_rows:
            notes.append(
                "Inferred ladder roles: "
                + ", ".join(
                    f"{row['base_name']}={row.get('window_role', row.get('role_hint', 'candidate'))}"
                    for row in ladder_rows
                )
                + "."
            )

        return {
            "ok": True,
            "sample_path": str(sample_path),
            "prototype_report": str(prototype_report),
            "fragment_count": len(fragments),
            "rows": rows,
            "window_ladder": ladder_rows,
            "notes": notes,
        }

    @staticmethod
    def _find_latest_prototype_report(sample_path: Path) -> Path | None:
        today_dir = get_log_day_dir() / "db_prototype" / sample_path.stem / f"{sample_path.stem}.prototype.json"
        if today_dir.exists():
            return today_dir
        log_root = get_log_day_dir().parent
        candidates = sorted(
            log_root.glob(f"*/db_prototype/{sample_path.stem}/{sample_path.stem}.prototype.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        return candidates[0] if candidates else None

    def _load_snapshot(self, root: Path) -> DbSnapshot:
        files: list[SnapshotFileInfo] = []
        for path in sorted(root.iterdir()):
            if path.name.endswith(".pgf") or not path.is_file():
                continue
            files.append(
                SnapshotFileInfo(
                    logical_name=path.name,
                    source_path=self.cache_root / path.name,
                    snapshot_path=path,
                    exists=True,
                    size=path.stat().st_size,
                    copied=True,
                )
            )
        pgf_inventory: list[PgFileInfo] = []
        for pgf_path in sorted(self.cache_root.glob("data-*.pgf")):
            pgf_inventory.append(
                PgFileInfo(
                    path=pgf_path,
                    size=pgf_path.stat().st_size,
                    marker_offsets={},
                    note="",
                )
            )
        return DbSnapshot(
            mode="hot",
            cache_root=self.cache_root,
            snapshot_root=root,
            files=files,
            pgf_inventory=pgf_inventory,
            note="open-sample prototype snapshot",
        )

    def _collect_state(self) -> dict[str, dict[str, object]]:
        items: dict[str, dict[str, object]] = {}
        for path in sorted(self.cache_root.iterdir()):
            if not path.is_file():
                continue
            stat = path.stat()
            with path.open("rb") as handle:
                head = handle.read(1024 * 1024)
            items[path.name] = {
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "sha1_head": hashlib.sha1(head).hexdigest()[:20],
            }
        return items

    @staticmethod
    def _resolve_client_path() -> Path:
        for path in get_default_qyclient_paths():
            if path.exists():
                return path
        raise FileNotFoundError("Could not find QyClient.exe in default locations.")

    @staticmethod
    def _close_launched_client(process: subprocess.Popen[bytes] | subprocess.Popen[str]) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                pass
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception:
            return
