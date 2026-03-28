from __future__ import annotations

import hashlib
import shutil
import time
from pathlib import Path

from src.Application.models import DbSnapshot, PgFileInfo, SnapshotFileInfo

from .runtime_paths import get_default_cache_root, get_log_day_dir


class DbSnapshotService:
    def __init__(self, cache_root: Path | None = None) -> None:
        self.cache_root = cache_root or get_default_cache_root()
        self.db_names = [
            "data-qsv.db",
            "data-qsv.db-wal",
            "data-qsv.db-shm",
            "data.db",
            "data.db-wal",
            "data.db-shm",
            "data-nor.db",
            "data-nor.db-wal",
            "data-nor.db-shm",
        ]

    def create_snapshot(self, mode: str) -> DbSnapshot:
        stamp = time.strftime("%H-%M-%S")
        snapshot_root = get_log_day_dir() / "db_snapshots" / f"{stamp}_{mode}"
        snapshot_root.mkdir(parents=True, exist_ok=True)
        files: list[SnapshotFileInfo] = []
        for logical_name in self.db_names:
            source_path = self.cache_root / logical_name
            if not source_path.exists():
                files.append(
                    SnapshotFileInfo(
                        logical_name=logical_name,
                        source_path=source_path,
                        snapshot_path=None,
                        exists=False,
                    )
                )
                continue
            snapshot_path = snapshot_root / logical_name
            shutil.copy2(source_path, snapshot_path)
            files.append(
                SnapshotFileInfo(
                    logical_name=logical_name,
                    source_path=source_path,
                    snapshot_path=snapshot_path,
                    exists=True,
                    size=source_path.stat().st_size,
                    copied=True,
                )
            )

        pgf_inventory: list[PgFileInfo] = []
        for pgf_path in sorted(self.cache_root.glob("data-*.pgf")):
            pgf_inventory.append(
                PgFileInfo(
                    path=pgf_path,
                    size=pgf_path.stat().st_size,
                    marker_offsets=self._inspect_pgf_markers(pgf_path),
                    note=self._hash_note(pgf_path),
                )
            )

        note = (
            "cold mode is a labeling choice only; caller is responsible for closing iQIYI "
            "before snapshot if a true cold snapshot is required."
            if mode == "cold"
            else "hot snapshot copied while client may still be running."
        )
        return DbSnapshot(
            mode=mode,
            cache_root=self.cache_root,
            snapshot_root=snapshot_root,
            files=files,
            pgf_inventory=pgf_inventory,
            note=note,
        )

    @staticmethod
    def _inspect_pgf_markers(path: Path) -> dict[str, int]:
        marker_map = {
            "ts_sync": b"\x47",
            "ftyp": b"ftyp",
            "moov": b"moov",
            "mdat": b"mdat",
            "extm3u": b"#EXTM3U",
            "m3u8": b".m3u8",
            "ts_ext": b".ts",
        }
        result: dict[str, int] = {}
        with path.open("rb") as handle:
            blob = handle.read(4 * 1024 * 1024)
        for label, marker in marker_map.items():
            offset = blob.find(marker)
            if offset >= 0:
                result[label] = offset
        return result

    @staticmethod
    def _hash_note(path: Path) -> str:
        with path.open("rb") as handle:
            chunk = handle.read(1024 * 1024)
        return hashlib.sha1(chunk).hexdigest()[:16]
