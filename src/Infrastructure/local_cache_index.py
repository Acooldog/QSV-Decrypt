from __future__ import annotations

from pathlib import Path

from src.Application.models import CacheSearchResult


class LocalCacheIndex:
    def __init__(self, cache_root: Path | None = None) -> None:
        self.cache_root = cache_root or Path(r"O:\qycache\temp_cache")
        self.database_names = [
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

    def inspect(self, qsv_path: Path) -> CacheSearchResult:
        result = CacheSearchResult()
        needles = [
            qsv_path.name.encode("utf-8", errors="ignore"),
            qsv_path.stem.encode("utf-8", errors="ignore"),
            qsv_path.parent.name.encode("utf-8", errors="ignore"),
        ]
        needles = [item for item in needles if item]
        for name in self.database_names:
            db_path = self.cache_root / name
            if not db_path.exists():
                continue
            with open(db_path, "rb", buffering=0) as handle:
                head = handle.read(32)
                handle.seek(0)
                blob = handle.read()
            result.database_headers[name] = head.hex()
            db_hits: list[int] = []
            for needle in needles:
                start = 0
                while True:
                    index = blob.find(needle, start)
                    if index < 0:
                        break
                    db_hits.append(index)
                    start = index + 1
                    if len(db_hits) >= 16:
                        break
                if len(db_hits) >= 16:
                    break
            if db_hits:
                result.hits[name] = db_hits
        return result
