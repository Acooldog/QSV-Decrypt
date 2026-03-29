from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from xml.etree import ElementTree as ET

from src.Application.models import DownloadMetadataCorrelation, DownloadMetadataEntry

from .runtime_paths import get_default_download_metadata_db_path


class DownloadMetadataAnalyzer:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or get_default_download_metadata_db_path()

    def inspect_sample(self, sample_path: Path) -> DownloadMetadataCorrelation:
        normalized_sample = self._normalize_path(sample_path)
        notes: list[str] = []
        if not self.db_path.exists():
            return DownloadMetadataCorrelation(
                db_path=self.db_path,
                notes=[f"Download metadata DB does not exist: {self.db_path}"],
            )

        try:
            row_size, xml_blob = self._load_downloaded_xml_blob()
        except Exception as exc:
            return DownloadMetadataCorrelation(
                db_path=self.db_path,
                notes=[f"Failed to read Downloaded.xml from PPSDownLoad.db: {exc}"],
            )

        try:
            xml_text = self._decode_xml(xml_blob)
            root = ET.fromstring(xml_text)
        except Exception as exc:
            return DownloadMetadataCorrelation(
                db_path=self.db_path,
                downloaded_xml_row_size=row_size,
                notes=[f"Failed to decode/parse Downloaded.xml payload: {exc}"],
            )

        entries = self._extract_entries(root)
        matched_entries = [
            item
            for item in entries
            if item.save_path == normalized_sample
            or item.save_file_name.lower() == sample_path.name.lower()
            or Path(item.save_file_name).stem.lower() == sample_path.stem.lower()
        ]

        cert_sha1s = sorted({item.cert_sha1 for item in entries if item.cert_sha1})
        cert_entry_count = sum(1 for item in entries if item.cert_present)
        if matched_entries:
            notes.append(
                f"Downloaded.xml matched {len(matched_entries)} local download row(s) for this sample."
            )
            primary = matched_entries[0]
            notes.append(
                "Download metadata exposes TVID/VideoId/aid/lid/cf/ct = "
                f"{primary.tvid}/{primary.video_id}/{primary.aid}/{primary.lid}/{primary.cf}/{primary.ct}."
            )
            if primary.cert_present:
                notes.append(
                    f"Matched row carries a DRM cert blob (sha1={primary.cert_sha1[:12]}..., length shared across "
                    "other DRM rows)."
                )
        else:
            notes.append("Downloaded.xml did not contain a row that matched this sample path/name.")

        if cert_entry_count and len(cert_sha1s) == 1:
            notes.append(
                "All cert-bearing Downloaded.xml rows currently share one identical cert blob; treat it as a global "
                "MonaLisa/device/service cert, not a sample-specific license ticket."
            )

        return DownloadMetadataCorrelation(
            db_path=self.db_path,
            downloaded_xml_row_size=row_size,
            matched_entries=matched_entries,
            total_entry_count=len(entries),
            cert_entry_count=cert_entry_count,
            unique_cert_sha1s=cert_sha1s,
            notes=notes,
        )

    def _load_downloaded_xml_blob(self) -> tuple[int, bytes]:
        connection = sqlite3.connect(self.db_path)
        try:
            cursor = connection.cursor()
            row = cursor.execute(
                "select length(Data), Data from table_file where Name='Downloaded.xml'"
            ).fetchone()
            if row is None:
                raise RuntimeError("table_file.Downloaded.xml row is missing")
            row_size = int(row[0] or 0)
            blob = row[1]
            if not isinstance(blob, (bytes, bytearray)):
                raise RuntimeError("Downloaded.xml row is not a BLOB payload")
            return row_size, bytes(blob)
        finally:
            connection.close()

    @staticmethod
    def _decode_xml(blob: bytes) -> str:
        for encoding in ("utf-8", "gb18030", "gbk"):
            try:
                return blob.decode(encoding)
            except UnicodeDecodeError:
                continue
        return blob.decode("latin-1", errors="ignore")

    @staticmethod
    def _extract_entries(root: ET.Element) -> list[DownloadMetadataEntry]:
        entries: list[DownloadMetadataEntry] = []
        for container in root.findall(".//Chs"):
            for node in container.findall("Ch"):
                attrs = dict(node.attrib)
                save_dir = attrs.get("SaveDir", "")
                save_file_name = attrs.get("SaveFileName", "")
                save_path = DownloadMetadataAnalyzer._normalize_path(Path(save_dir) / save_file_name)
                cert_blob = attrs.get("cert", "")
                cert_sha1 = hashlib.sha1(cert_blob.encode("ascii")).hexdigest() if cert_blob else ""
                entries.append(
                    DownloadMetadataEntry(
                        save_dir=save_dir,
                        save_file_name=save_file_name,
                        save_path=save_path,
                        display_name=attrs.get("DisplayName", ""),
                        album_name=attrs.get("AlbumName", ""),
                        channel_name=attrs.get("ChannelName", ""),
                        tvid=attrs.get("TVID", ""),
                        video_id=attrs.get("VideoId", ""),
                        aid=attrs.get("aid", ""),
                        lid=attrs.get("lid", ""),
                        cf=attrs.get("cf", ""),
                        ct=attrs.get("ct", ""),
                        bitrate=attrs.get("Bitrate", ""),
                        duration=attrs.get("Duration", ""),
                        file_size=attrs.get("FileSize", ""),
                        audio_type_name=attrs.get("audioTypeName", ""),
                        pay_mark=attrs.get("pay_mark", ""),
                        album_source_type=attrs.get("album_source_type", ""),
                        cert_present=bool(cert_blob),
                        cert_sha1=cert_sha1,
                        raw_attrs=attrs,
                    )
                )
        return entries

    @staticmethod
    def _normalize_path(path: Path | str) -> str:
        return str(path).replace("/", "\\").lower()
