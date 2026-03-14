from __future__ import annotations

import hashlib
import mmap
import re
import zlib
from pathlib import Path

from src.Application.models import EmbeddedFragmentInfo, QsvInspection, TsGapInfo, TsRunInfo

from .local_cache_index import LocalCacheIndex


class QsvOfflineDecoder:
    def __init__(self, cache_index: LocalCacheIndex | None = None) -> None:
        self.cache_index = cache_index or LocalCacheIndex()

    def inspect(self, sample_path: Path) -> QsvInspection:
        file_size = sample_path.stat().st_size
        with open(sample_path, "rb") as handle:
            header_magic = handle.read(10).decode("ascii", errors="replace")
            handle.seek(0)
            data = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                payload_offset, payload_mode, packet_sync_count = self._find_ts_payload_offset(data)
                embedded_fragments = self._find_embedded_fragments(data)
                stable_runs = self._collect_stable_runs(data, payload_offset, payload_mode)
                ts_gaps = self._describe_ts_gaps(data, stable_runs)
            finally:
                data.close()
        notes: list[str] = []
        if payload_offset is not None:
            notes.append(
                f"Detected MPEG-TS payload at offset {payload_offset} with {packet_sync_count} sync packets."
            )
        else:
            notes.append("Unable to detect a stable TS payload in the current sample.")
        if stable_runs:
            notes.append(
                f"Detected {len(stable_runs)} stable TS runs; first run starts at {stable_runs[0].offset}."
            )
        for gap in ts_gaps:
            notes.append(
                f"Detected TS gap at {gap.offset} with length {gap.length} bytes."
            )
        for fragment in embedded_fragments:
            notes.append(
                "Detected embedded "
                f"{fragment.format_hint} fragment at offset {fragment.offset} "
                f"(compression={fragment.compression}, init_size={fragment.init_size}, payload_size={fragment.payload_size})."
            )
        return QsvInspection(
            sample_path=sample_path,
            file_size=file_size,
            header_magic=header_magic,
            payload_offset=payload_offset,
            payload_mode=payload_mode,
            packet_sync_count=packet_sync_count,
            local_cache=self.cache_index.inspect(sample_path),
            embedded_fragments=embedded_fragments,
            stable_runs=stable_runs,
            ts_gaps=ts_gaps,
            notes=notes,
        )

    def decode_to_ts(
        self,
        sample_path: Path,
        work_dir: Path,
        inspection: QsvInspection | None = None,
    ) -> tuple[Path, QsvInspection]:
        inspection = inspection or self.inspect(sample_path)
        if inspection.payload_offset is None:
            raise RuntimeError("offline_unresolved")
        work_dir.mkdir(parents=True, exist_ok=True)
        output_path = work_dir / f"{sample_path.stem}.{self._stable_name(sample_path)}.ts"
        with open(sample_path, "rb") as source, open(output_path, "wb") as target:
            data = mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                if inspection.payload_mode == "ts-192-prefix4":
                    self._extract_stable_packets(
                        data=data,
                        target=target,
                        start=inspection.payload_offset,
                        stride=192,
                        sync_index=4,
                        emit_offset=4,
                    )
                else:
                    self._extract_stable_packets(
                        data=data,
                        target=target,
                        start=inspection.payload_offset,
                        stride=188,
                        sync_index=0,
                        emit_offset=0,
                    )
            finally:
                data.close()
        return output_path, inspection

    def _find_ts_payload_offset(self, data: mmap.mmap) -> tuple[int | None, str, int]:
        best_188 = self._find_payload_for_stride(data, stride=188, sync_index=0, mode="ts-188")
        if best_188[0] is not None:
            return best_188
        best_192 = self._find_payload_for_stride(data, stride=192, sync_index=4, mode="ts-192-prefix4")
        if best_192[0] is not None:
            return best_192
        return None, "unresolved", 0

    def _collect_stable_runs(
        self,
        data: mmap.mmap,
        payload_offset: int | None,
        payload_mode: str,
    ) -> list[TsRunInfo]:
        if payload_offset is None:
            return []
        if payload_mode == "ts-192-prefix4":
            stride = 192
            sync_index = 4
        else:
            stride = 188
            sync_index = 0

        runs: list[TsRunInfo] = []
        size = len(data)
        position = payload_offset
        while True:
            run_start = self._find_next_stable_run(
                data=data,
                start=position,
                stride=stride,
                sync_index=sync_index,
                min_run=16,
            )
            if run_start is None:
                break

            packet_start = run_start
            packet_count = 0
            while packet_start + stride <= size and data[packet_start + sync_index] == 0x47:
                packet_count += 1
                packet_start += stride

            runs.append(
                TsRunInfo(
                    offset=run_start,
                    length=packet_count * stride,
                    packet_count=packet_count,
                )
            )
            position = packet_start + 1
        return runs

    @staticmethod
    def _describe_ts_gaps(data: mmap.mmap, runs: list[TsRunInfo]) -> list[TsGapInfo]:
        gaps: list[TsGapInfo] = []
        for previous, current in zip(runs, runs[1:]):
            gap_offset = previous.offset + previous.length
            gap_length = current.offset - gap_offset
            if gap_length <= 0:
                continue
            packet_multiple = gap_length // 188 if gap_length % 188 == 0 else 0
            packet_heads: list[str] = []
            if packet_multiple:
                gap_blob = data[gap_offset:current.offset]
                for packet_index in range(min(packet_multiple, 6)):
                    start = packet_index * 188
                    packet_heads.append(gap_blob[start : start + 16].hex())
            gaps.append(
                TsGapInfo(
                    offset=gap_offset,
                    length=gap_length,
                    packet_multiple=packet_multiple,
                    packet_heads=packet_heads,
                )
            )
        return gaps

    def _extract_stable_packets(
        self,
        data: mmap.mmap,
        target,
        start: int,
        stride: int,
        sync_index: int,
        emit_offset: int,
        min_run: int = 16,
    ) -> None:
        size = len(data)
        position = start
        while True:
            run_start = self._find_next_stable_run(
                data=data,
                start=position,
                stride=stride,
                sync_index=sync_index,
                min_run=min_run,
            )
            if run_start is None:
                break

            packet_start = run_start
            while packet_start + stride <= size and data[packet_start + sync_index] == 0x47:
                chunk = data[packet_start : packet_start + stride]
                target.write(chunk[emit_offset:])
                packet_start += stride

            position = packet_start + 1

    @staticmethod
    def _find_next_stable_run(
        data: mmap.mmap,
        start: int,
        stride: int,
        sync_index: int,
        min_run: int,
    ) -> int | None:
        size = len(data)
        last_start = size - (stride * min_run) - sync_index
        if start > last_start:
            return None
        for position in range(start, last_start + 1):
            if data[position + sync_index] != 0x47:
                continue
            probe = position
            run = 0
            while run < min_run and probe + sync_index < size and data[probe + sync_index] == 0x47:
                run += 1
                probe += stride
            if run >= min_run:
                return position
        return None

    @staticmethod
    def _find_payload_for_stride(
        data: mmap.mmap,
        stride: int,
        sync_index: int,
        mode: str,
    ) -> tuple[int | None, str, int]:
        size = len(data)
        min_run = 256
        best_mod = 0
        best_count = 0
        for start_mod in range(stride):
            count = 0
            position = start_mod + sync_index
            while position < size:
                if data[position] == 0x47:
                    count += 1
                position += stride
            if count > best_count:
                best_count = count
                best_mod = start_mod

        if best_count < min_run:
            return None, mode, 0

        run = 0
        position = best_mod + sync_index
        while position < size:
            if data[position] == 0x47:
                run += 1
                if run >= min_run:
                    payload_offset = position - sync_index - (run - 1) * stride
                    return payload_offset, mode, best_count
            else:
                run = 0
            position += stride
        return None, mode, 0

    @staticmethod
    def _find_embedded_fragments(data: mmap.mmap) -> list[EmbeddedFragmentInfo]:
        size = len(data)
        tail_start = max(0, size - 32 * 1024 * 1024)
        fragments: list[EmbeddedFragmentInfo] = []
        for match in re.finditer(b"\x1f\x8b\x08", data[tail_start:]):
            offset = tail_start + match.start()
            fragment = QsvOfflineDecoder._inspect_gzip_fragment(data, offset)
            if fragment is not None:
                fragments.append(fragment)
        return fragments

    @staticmethod
    def _inspect_gzip_fragment(
        data: mmap.mmap,
        offset: int,
    ) -> EmbeddedFragmentInfo | None:
        blob = data[offset : min(len(data), offset + 2 * 1024 * 1024)]
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            init_payload = decompressor.decompress(blob)
        except zlib.error:
            return None
        if len(init_payload) < 32:
            return None
        if b"ftyp" not in init_payload[:64] or b"moov" not in init_payload[:512]:
            return None
        unused = decompressor.unused_data
        format_hint = "compressed-mp4-fragment"
        if b"mdat" in unused[:64]:
            format_hint = "compressed-mp4-init+mdat"
        return EmbeddedFragmentInfo(
            offset=offset,
            compression="gzip",
            format_hint=format_hint,
            init_size=len(init_payload),
            payload_size=len(unused),
            note="Detected by tail gzip scan.",
        )

    @staticmethod
    def _stable_name(sample_path: Path) -> str:
        return hashlib.sha1(str(sample_path).encode("utf-8")).hexdigest()[:8]
