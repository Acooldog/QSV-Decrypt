from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from src.Application.models import DbCorrelation, DbSnapshot, QsvInspection, WalFrame, WalInspection, WalOpaquePage

from .qtplog_analysis import QtpLogAnalyzer
from .runtime_paths import get_default_cache_root


class DbCacheAnalyzer:
    MARKERS = {
        "http": b"http",
        "m3u8": b".m3u8",
        "ts_ext": b".ts",
        "mp4_ext": b".mp4",
        "ftyp": b"ftyp",
        "moov": b"moov",
        "mdat": b"mdat",
        "video": b"video",
        "audio": b"audio",
        "segment": b"segment",
        "playlist": b"playlist",
        "hevc": b"hevc",
        "aac": b"aac",
        "cid": b"cid",
        "tvid": b"tvid",
        "vid": b"vid",
    }

    def __init__(self, cache_root: Path | None = None, qtplog_analyzer: QtpLogAnalyzer | None = None) -> None:
        self.cache_root = cache_root or get_default_cache_root()
        self.qtplog_analyzer = qtplog_analyzer or QtpLogAnalyzer()

    def inspect_snapshot(
        self,
        snapshot: DbSnapshot,
        sample_path: Path,
        qsv_inspection: QsvInspection | None = None,
    ) -> DbCorrelation:
        needle_specs = self._build_needles(sample_path, qsv_inspection)
        wal_inspections: list[WalInspection] = []
        identifier_candidates: list[str] = []
        candidate_cache_paths: list[str] = []
        db_token_summary: dict[str, dict[str, object]] = {}
        notes: list[str] = []

        for file_info in snapshot.files:
            if file_info.exists and file_info.snapshot_path and file_info.logical_name.endswith(".db"):
                token_summary = self._inspect_db_tokens(file_info.snapshot_path)
                if token_summary is not None:
                    db_token_summary[file_info.logical_name] = token_summary
            if not file_info.exists or not file_info.snapshot_path or not file_info.logical_name.endswith(".db-wal"):
                continue
            wal = self._inspect_wal(file_info.snapshot_path, file_info.logical_name, needle_specs)
            wal_inspections.append(wal)
            for frame in wal.candidate_frames:
                identifier_candidates.extend(self._extract_identifiers(frame.string_samples))

        for pgf in snapshot.pgf_inventory:
            strong_markers = {key for key in pgf.marker_offsets if key != "ts_sync"}
            if strong_markers:
                candidate_cache_paths.append(str(pgf.path))

        if not wal_inspections:
            notes.append("No WAL files were available in the snapshot.")
        elif not any(item.candidate_frames for item in wal_inspections):
            notes.append("WAL parsing succeeded, but no strong sample-specific correlation was found.")
        for wal in wal_inspections:
            if wal.opaque_pages:
                hot_pages = sorted({item.page_number for item in wal.opaque_pages})
                notes.append(
                    f"{wal.wal_name} also contains opaque low-entropy live pages {hot_pages}; these look like "
                    "client-encoded state/index pages rather than plain SQLite payload."
                )
        if db_token_summary:
            wal_map = {item.wal_name: item for item in wal_inspections}
            for logical_name, token_summary in db_token_summary.items():
                if token_summary["hex_token_count"]:
                    notes.append(
                        f"{logical_name} exposes {token_summary['hex_token_count']} repeated fixed-length hex token(s) "
                        f"without readable sample strings; treat it as an encoded index layer rather than plain SQLite content."
                    )
                clustered = [
                    item
                    for item in token_summary.get("top_hex_tokens", [])
                    if item.get("dominant_stride") and item.get("page_count", 0) >= 2
                ]
                if clustered:
                    strongest = clustered[0]
                    notes.append(
                        f"{logical_name} also shows fixed-record token pages: top token repeats across "
                        f"{strongest['page_count']} page(s) with dominant stride {strongest['dominant_stride']} bytes."
                    )
                page_shapes = token_summary.get("fixed_record_pages", [])
                if page_shapes:
                    stride_counts = Counter(int(item["dominant_stride"]) for item in page_shapes)
                    summary = ", ".join(f"{stride}-byte x{count}" for stride, count in sorted(stride_counts.items()))
                    notes.append(
                        f"{logical_name} contains clustered fixed-record token pages ({summary}); this looks like an "
                        "encoded index table rather than free-form cache content."
                    )
                page_families = token_summary.get("fixed_record_page_families", [])
                if page_families:
                    family_summary = ", ".join(
                        f"{item['record_size']}-byte pages={item['page_count']}"
                        for item in page_families[:4]
                    )
                    notes.append(
                        f"{logical_name} fixed-record families cluster into {family_summary}; treat these as "
                        "separate index record layouts rather than one monolithic table."
                    )
                overlaps = token_summary.get("fixed_record_family_overlaps", [])
                if overlaps:
                    strongest = overlaps[0]
                    notes.append(
                        f"{logical_name} family overlap is strongest between {strongest['left_record_size']}-byte "
                        f"and {strongest['right_record_size']}-byte pages ({strongest['shared_token_count']} shared "
                        "token(s)); this supports a dictionary-page + record-page index design."
                    )
                wal_name = f"{logical_name}-wal"
                wal_inspection = wal_map.get(wal_name)
                if wal_inspection and page_shapes:
                    fixed_pages = {int(item["page_id"]) for item in page_shapes}
                    wal_pages = {int(key) for key in wal_inspection.page_frequencies}
                    touched_pages = sorted(fixed_pages & wal_pages)
                    if touched_pages:
                        notes.append(
                            f"{wal_name} currently touches fixed-record pages {touched_pages}; the rest of the token "
                            "families look like colder base index pages."
                        )

        if qsv_inspection:
            if qsv_inspection.embedded_fragments:
                notes.append(
                    f"Inspection found {len(qsv_inspection.embedded_fragments)} embedded compressed fragment(s); "
                    "treat them as candidate init/tail media context."
                )
            if qsv_inspection.ts_gaps:
                unique_gap_lengths = sorted({gap.length for gap in qsv_inspection.ts_gaps})
                notes.append(
                    "Stable TS gaps detected at fixed lengths: "
                    + ", ".join(str(length) for length in unique_gap_lengths)
                )

        qtplog_summary = self.qtplog_analyzer.inspect_sample(sample_path)
        notes.extend(qtplog_summary["notes"])
        qtplog_alignment = self._build_qtplog_alignment(
            qtplog_summary["segment_tasks"],
            qsv_inspection,
        )
        if qtplog_alignment:
            if qtplog_alignment.get("run_segment_count_match"):
                notes.append(
                    "qtplog unique segment count matches stable TS run count exactly; treat the QSV payload as a "
                    "segment-stitching container rather than one monolithic stream."
                )
            if qtplog_alignment.get("size_delta_values"):
                notes.append(
                    "qtplog f4vsize minus stable run length stays fixed at "
                    + ", ".join(str(item) for item in qtplog_alignment["size_delta_values"])
                    + " bytes for the aligned segment(s)."
                )
            ext_summary = qtplog_alignment.get("rawurl_extension_counts", {})
            if ext_summary:
                notes.append(
                    "qtplog raw segment types: "
                    + ", ".join(f"{key} x{value}" for key, value in sorted(ext_summary.items()))
                    + "."
                )
            if qtplog_alignment.get("bbts_segnums"):
                notes.append(
                    "Later qsvd segments are .bbts, not plain .ts; this matches public reports that IQIYI only "
                    "stores the leading segment as plain TS and wraps later segments in BBTS/protected transport."
                )
            dispatch_key_segnums = qtplog_alignment.get("dispatch_key_segnums", [])
            if dispatch_key_segnums:
                notes.append(
                    "p2pfile dispatch logs expose per-segment bbts content keys for segment(s) "
                    + ", ".join(str(item) for item in dispatch_key_segnums)
                    + "; treat these as real decrypt inputs rather than generic CDN query noise."
                )
        for event in qtplog_summary["path_events"]:
            if event["event_type"] == "qsv_full_rename":
                notes.append(
                    "qtplog shows qsv_full_rename for this sample, so the local client did finish assembling the qsv "
                    "file before A_aqy later rejected it."
                )
                break
        for event in qtplog_summary["path_events"]:
            if event["event_type"] == "open_failed_second_time":
                notes.append(
                    "qtplog also shows repeated 'file open failed second time' events for this sample; the player/cache "
                    "stack itself is struggling to reopen the local qsv file."
                )
                break

        deduped_identifiers = sorted({item for item in identifier_candidates if item})
        return DbCorrelation(
            sample_path=sample_path,
            snapshot_mode=snapshot.mode,
            wal_inspections=wal_inspections,
            identifier_candidates=deduped_identifiers[:64],
            candidate_cache_paths=sorted(set(candidate_cache_paths)),
            db_token_summary=db_token_summary,
            qtplog_segment_tasks=qtplog_summary["segment_tasks"],
            qtplog_path_events=qtplog_summary["path_events"],
            qtplog_dispatch_events=qtplog_summary.get("dispatch_events", []),
            qtplog_segment_alignment=qtplog_alignment,
            notes=notes,
        )

    def inspect_live(self, sample_path: Path, qsv_inspection: QsvInspection | None = None) -> DbCorrelation:
        from .db_snapshot import DbSnapshotService

        snapshot = DbSnapshotService(self.cache_root).create_snapshot("hot")
        return self.inspect_snapshot(snapshot=snapshot, sample_path=sample_path, qsv_inspection=qsv_inspection)

    def _inspect_wal(
        self,
        wal_path: Path,
        logical_name: str,
        needle_specs: list[tuple[str, bytes]],
    ) -> WalInspection:
        blob = wal_path.read_bytes()
        if len(blob) < 32 or blob[:4] != b"\x37\x7f\x06\x82":
            return WalInspection(
                wal_name=logical_name,
                path=wal_path,
                ok=False,
                note="Not a SQLite WAL header.",
            )

        page_size = int.from_bytes(blob[8:12], "big")
        if page_size <= 0:
            return WalInspection(
                wal_name=logical_name,
                path=wal_path,
                ok=False,
                note="Invalid page size in WAL header.",
            )

        frame_offset = 32
        frame_index = 0
        page_counter: Counter[int] = Counter()
        candidates: list[WalFrame] = []
        opaque_pages: list[WalOpaquePage] = []
        while frame_offset + 24 + page_size <= len(blob):
            header = blob[frame_offset : frame_offset + 24]
            page_number = int.from_bytes(header[0:4], "big")
            db_size_after_commit = int.from_bytes(header[4:8], "big")
            if page_number == 0:
                break
            payload = blob[frame_offset + 24 : frame_offset + 24 + page_size]
            page_counter[page_number] += 1
            frame = self._analyze_frame(
                wal_name=logical_name,
                frame_index=frame_index,
                page_number=page_number,
                db_size_after_commit=db_size_after_commit,
                payload_offset=frame_offset + 24,
                payload=payload,
                needle_specs=needle_specs,
            )
            if frame is not None:
                candidates.append(frame)
            else:
                opaque_page = self._analyze_opaque_page(
                    wal_name=logical_name,
                    frame_index=frame_index,
                    page_number=page_number,
                    payload_offset=frame_offset + 24,
                    payload=payload,
                )
                if opaque_page is not None:
                    opaque_pages.append(opaque_page)
            frame_index += 1
            frame_offset += 24 + page_size

        top_pages = dict(page_counter.most_common(16))
        return WalInspection(
            wal_name=logical_name,
            path=wal_path,
            ok=True,
            page_size=page_size,
            frame_count=frame_index,
            page_frequencies=top_pages,
            candidate_frames=candidates[:24],
            opaque_pages=opaque_pages[:24],
            note="Parsed from WAL frames; main DB pages may still be encrypted or custom encoded.",
        )

    def _analyze_frame(
        self,
        wal_name: str,
        frame_index: int,
        page_number: int,
        db_size_after_commit: int,
        payload_offset: int,
        payload: bytes,
        needle_specs: list[tuple[str, bytes]],
    ) -> WalFrame | None:
        matched_needles: list[str] = []
        for label, needle in needle_specs:
            if needle and payload.find(needle) >= 0:
                matched_needles.append(label)

        marker_hits = [label for label, marker in self.MARKERS.items() if payload.find(marker) >= 0]
        printable_ratio = self._printable_ratio(payload)
        string_samples = self._extract_string_samples(payload)

        if not matched_needles and not marker_hits and printable_ratio < 0.08:
            return None
        return WalFrame(
            wal_name=wal_name,
            frame_index=frame_index,
            page_number=page_number,
            db_size_after_commit=db_size_after_commit,
            payload_offset=payload_offset,
            payload_size=len(payload),
            printable_ratio=round(printable_ratio, 5),
            matched_needles=matched_needles,
            marker_hits=marker_hits,
            string_samples=string_samples[:12],
        )

    @staticmethod
    def _build_qtplog_alignment(
        segment_tasks: list[dict[str, object]],
        qsv_inspection: QsvInspection | None,
    ) -> dict[str, object]:
        if not segment_tasks:
            return {}

        ordered_tasks = sorted(
            segment_tasks,
            key=lambda item: (
                int(item.get("segnum", -1)) if isinstance(item.get("segnum"), int) else -1,
                str(item.get("log_path", "")),
                int(item.get("line_no", 0)),
            ),
        )
        rawurl_extension_counts: Counter[str] = Counter()
        bbts_segnums: list[int] = []
        dispatch_key_segnums: list[int] = []
        aligned_segments: list[dict[str, object]] = []
        size_delta_values: set[int] = set()

        stable_runs = list(qsv_inspection.stable_runs) if qsv_inspection else []
        run_segment_count_match = len(stable_runs) == len(ordered_tasks) if stable_runs else False

        for index, task in enumerate(ordered_tasks):
            rawurl = str(task.get("rawurl") or "")
            parsed = urlparse(rawurl)
            raw_name = Path(parsed.path).name.lower()
            ext = Path(raw_name).suffix.lower() or "<none>"
            rawurl_extension_counts[ext] += 1
            if ext == ".bbts" and isinstance(task.get("segnum"), int):
                bbts_segnums.append(int(task["segnum"]))
            if task.get("dispatch_key_hex") and isinstance(task.get("segnum"), int):
                dispatch_key_segnums.append(int(task["segnum"]))

            if index < len(stable_runs):
                run = stable_runs[index]
                f4vsize = int(task["f4vsize"]) if isinstance(task.get("f4vsize"), int) else None
                size_delta = f4vsize - run.length if f4vsize is not None else None
                if size_delta is not None:
                    size_delta_values.add(size_delta)
                aligned_segments.append(
                    {
                        "segnum": task.get("segnum"),
                        "reason": task.get("reason"),
                        "rawurl_extension": ext,
                        "dispatch_key_hex": task.get("dispatch_key_hex"),
                        "dispatch_key_base64": task.get("dispatch_key_base64"),
                        "dispatch_url_count": task.get("dispatch_url_count"),
                        "f4vsize": f4vsize,
                        "run_length": run.length,
                        "size_delta": size_delta,
                        "run_offset": run.offset,
                        "packet_count": run.packet_count,
                    }
                )

        return {
            "segment_count": len(ordered_tasks),
            "stable_run_count": len(stable_runs),
            "run_segment_count_match": run_segment_count_match,
            "rawurl_extension_counts": dict(rawurl_extension_counts),
            "bbts_segnums": sorted(bbts_segnums),
            "dispatch_key_segnums": sorted(dispatch_key_segnums),
            "size_delta_values": sorted(size_delta_values),
            "aligned_segments": aligned_segments,
        }

    @staticmethod
    def _analyze_opaque_page(
        wal_name: str,
        frame_index: int,
        page_number: int,
        payload_offset: int,
        payload: bytes,
    ) -> WalOpaquePage | None:
        printable_ratio = DbCacheAnalyzer._printable_ratio(payload)
        if printable_ratio >= 0.05:
            return None
        byte_counts = Counter(payload)
        dominant_byte, dominant_count = byte_counts.most_common(1)[0]
        dominant_ratio = dominant_count / len(payload) if payload else 0.0
        zero_ratio = byte_counts.get(0, 0) / len(payload) if payload else 0.0
        token_hits = len(re.findall(rb"[a-f0-9]{40}", payload, re.IGNORECASE))
        if token_hits > 0:
            return None
        if dominant_ratio < 0.02 and zero_ratio < 0.4:
            return None
        return WalOpaquePage(
            wal_name=wal_name,
            frame_index=frame_index,
            page_number=page_number,
            payload_offset=payload_offset,
            payload_size=len(payload),
            printable_ratio=round(printable_ratio, 5),
            token_hits=token_hits,
            dominant_byte=dominant_byte,
            dominant_ratio=round(dominant_ratio, 5),
            zero_ratio=round(zero_ratio, 5),
            head_hex=payload[:64].hex(),
        )

    @staticmethod
    def _build_needles(
        sample_path: Path,
        qsv_inspection: QsvInspection | None,
    ) -> list[tuple[str, bytes]]:
        terms = {
            "sample_name": sample_path.name,
            "sample_stem": sample_path.stem,
            "sample_parent": sample_path.parent.name,
        }
        if qsv_inspection:
            terms["file_size"] = str(qsv_inspection.file_size)
            terms["payload_offset"] = str(qsv_inspection.payload_offset or 0)
        needle_specs: list[tuple[str, bytes]] = []
        for label, value in terms.items():
            if not value:
                continue
            if label not in {"sample_name", "sample_stem", "sample_parent"} and len(value) < 6:
                continue
            for encoding in ("utf-8", "utf-16le", "gb18030"):
                try:
                    needle_specs.append((f"{label}:{encoding}", value.encode(encoding)))
                except Exception:
                    continue
        return needle_specs

    @staticmethod
    def _printable_ratio(blob: bytes) -> float:
        if not blob:
            return 0.0
        printable = sum(1 for byte in blob if 32 <= byte < 127)
        return printable / len(blob)

    @staticmethod
    def _extract_string_samples(blob: bytes) -> list[str]:
        ascii_hits = [
            match.decode("ascii", errors="ignore")
            for match in re.findall(rb"[ -~]{6,}", blob)
        ]
        if ascii_hits:
            return ascii_hits[:24]
        utf16_hits = []
        for match in re.findall(rb"(?:[ -~]\x00){6,}", blob):
            try:
                utf16_hits.append(match.decode("utf-16le", errors="ignore"))
            except Exception:
                continue
        return utf16_hits[:24]

    @staticmethod
    def _extract_identifiers(strings: list[str]) -> list[str]:
        identifiers: list[str] = []
        patterns = [
            re.compile(r"https?://[^\s\"']+", re.IGNORECASE),
            re.compile(r"[A-Za-z0-9_\-]{8,}\.(?:m3u8|mp4|ts|m4s|f4v)", re.IGNORECASE),
            re.compile(r"\b(?:tvid|vid|cid|playlist|segment)[=: _-]*[A-Za-z0-9\-]{4,}\b", re.IGNORECASE),
            re.compile(r"\b\d{6,}\b"),
        ]
        for item in strings:
            for pattern in patterns:
                identifiers.extend(pattern.findall(item))
        return identifiers

    @staticmethod
    def _inspect_db_tokens(db_path: Path) -> dict[str, object] | None:
        blob = db_path.read_bytes()
        hex_tokens = [
            match.decode("ascii", errors="ignore")
            for match in re.findall(rb"\b[a-f0-9]{32,40}\b", blob, re.IGNORECASE)
        ]
        if not hex_tokens:
            return None
        counter = Counter(hex_tokens)
        top_tokens: list[dict[str, object]] = []
        for token, count in counter.most_common(12):
            offsets = DbCacheAnalyzer._find_offsets(blob, token.encode("ascii"))
            page_ids = sorted({offset // 32768 for offset in offsets})
            stride = DbCacheAnalyzer._dominant_stride(offsets)
            top_tokens.append(
                {
                    "token": token,
                    "count": count,
                    "page_ids": page_ids[:16],
                    "page_count": len(page_ids),
                    "dominant_stride": stride,
                }
            )
        fixed_record_pages = DbCacheAnalyzer._detect_fixed_record_pages(blob)
        fixed_record_page_families = DbCacheAnalyzer._summarize_fixed_record_pages(fixed_record_pages)
        fixed_record_family_overlaps = DbCacheAnalyzer._analyze_fixed_record_overlaps(fixed_record_pages)
        return {
            "hex_token_count": len(counter),
            "top_hex_tokens": top_tokens,
            "fixed_record_pages": fixed_record_pages,
            "fixed_record_page_families": fixed_record_page_families,
            "fixed_record_family_overlaps": fixed_record_family_overlaps,
        }

    @staticmethod
    def _find_offsets(blob: bytes, needle: bytes) -> list[int]:
        offsets: list[int] = []
        start = 0
        while True:
            pos = blob.find(needle, start)
            if pos < 0:
                break
            offsets.append(pos)
            start = pos + 1
        return offsets

    @staticmethod
    def _dominant_stride(offsets: list[int]) -> int | None:
        if len(offsets) < 2:
            return None
        deltas = [right - left for left, right in zip(offsets, offsets[1:])]
        counter = Counter(deltas)
        stride, count = counter.most_common(1)[0]
        if count < 4:
            return None
        return stride

    @staticmethod
    def _detect_fixed_record_pages(blob: bytes, page_size: int = 32768) -> list[dict[str, object]]:
        pages: list[dict[str, object]] = []
        pattern = re.compile(rb"[a-f0-9]{40}", re.IGNORECASE)
        allowed_strides = {40, 48, 49, 62}
        for page_id in range(len(blob) // page_size):
            page = blob[page_id * page_size : (page_id + 1) * page_size]
            hits = [match.start() for match in pattern.finditer(page)]
            if len(hits) < 16:
                continue
            stride = DbCacheAnalyzer._dominant_stride(hits)
            if stride not in allowed_strides:
                continue
            first_offset = hits[0]
            sample_token = page[first_offset : first_offset + 40].decode("ascii", errors="ignore")
            metadata_tail = b""
            if stride > 40:
                metadata_tail = page[first_offset + 40 : first_offset + stride]
            page_tokens: list[str] = []
            seen_tokens: set[str] = set()
            for offset in hits[:32]:
                token = page[offset : offset + 40].decode("ascii", errors="ignore")
                if token and token not in seen_tokens:
                    seen_tokens.add(token)
                    page_tokens.append(token)
            pages.append(
                {
                    "page_id": page_id,
                    "token_hits": len(hits),
                    "dominant_stride": stride,
                    "first_token_offset": first_offset,
                    "sample_token": sample_token,
                    "page_tokens": page_tokens,
                    "sample_tail_hex": metadata_tail.hex(),
                    "sample_tail_ascii": metadata_tail.decode("ascii", errors="ignore"),
                }
            )
        return pages[:48]

    @staticmethod
    def _summarize_fixed_record_pages(pages: list[dict[str, object]]) -> list[dict[str, object]]:
        families: dict[int, dict[str, object]] = {}
        for page in pages:
            record_size = int(page["dominant_stride"])
            family = families.setdefault(
                record_size,
                {
                    "record_size": record_size,
                    "page_ids": [],
                    "page_count": 0,
                    "token_hit_counts": [],
                    "sample_tokens": [],
                    "sample_tail_hex": [],
                },
            )
            family["page_ids"].append(int(page["page_id"]))
            family["page_count"] += 1
            family["token_hit_counts"].append(int(page["token_hits"]))
            sample_token = str(page.get("sample_token") or "")
            if sample_token and sample_token not in family["sample_tokens"] and len(family["sample_tokens"]) < 4:
                family["sample_tokens"].append(sample_token)
            for token in page.get("page_tokens", []):
                if token and token not in family["sample_tokens"] and len(family["sample_tokens"]) < 16:
                    family["sample_tokens"].append(token)
            tail_hex = str(page.get("sample_tail_hex") or "")
            if tail_hex and tail_hex not in family["sample_tail_hex"] and len(family["sample_tail_hex"]) < 4:
                family["sample_tail_hex"].append(tail_hex)

        summaries: list[dict[str, object]] = []
        for record_size, family in sorted(families.items()):
            hit_counts = family.pop("token_hit_counts")
            summaries.append(
                {
                    **family,
                    "min_token_hits": min(hit_counts) if hit_counts else 0,
                    "max_token_hits": max(hit_counts) if hit_counts else 0,
                    "avg_token_hits": round(sum(hit_counts) / len(hit_counts), 2) if hit_counts else 0.0,
                }
            )
        return summaries

    @staticmethod
    def _analyze_fixed_record_overlaps(pages: list[dict[str, object]]) -> list[dict[str, object]]:
        tokens_by_family: dict[int, set[str]] = {}
        for page in pages:
            record_size = int(page["dominant_stride"])
            tokens = tokens_by_family.setdefault(record_size, set())
            for token in page.get("page_tokens", []):
                if token:
                    tokens.add(str(token))

        overlaps: list[dict[str, object]] = []
        families = sorted(tokens_by_family)
        for index, left in enumerate(families):
            for right in families[index + 1 :]:
                shared = sorted(tokens_by_family[left] & tokens_by_family[right])
                if not shared:
                    continue
                overlaps.append(
                    {
                        "left_record_size": left,
                        "right_record_size": right,
                        "shared_token_count": len(shared),
                        "sample_shared_tokens": shared[:8],
                    }
                )
        overlaps.sort(key=lambda item: item["shared_token_count"], reverse=True)
        return overlaps
