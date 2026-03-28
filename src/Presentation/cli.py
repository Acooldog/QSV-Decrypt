from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from src.Application.decrypt_service import DecryptService
from src.Infrastructure.asset_bootstrap import AssetBootstrap
from src.Infrastructure.bbts_variant_rebuilder import BbtsVariantRebuilder
from src.Infrastructure.db_cache_analysis import DbCacheAnalyzer
from src.Infrastructure.db_open_sample_prototype import DbOpenSamplePrototype
from src.Infrastructure.db_prototype_rebuilder import DbPrototypeRebuilder
from src.Infrastructure.db_snapshot import DbSnapshotService
from src.Infrastructure.ffmpeg_tools import FfmpegTools
from src.Infrastructure.hook_capture import HookCapture
from src.Infrastructure.local_cache_index import LocalCacheIndex
from src.Infrastructure.logging_utils import setup_logging
from src.Infrastructure.qsv_offline import QsvOfflineDecoder
from src.Infrastructure.runtime_paths import (
    get_default_cache_root,
    get_default_input_root,
    get_default_output_root,
    get_runtime_dir,
)

logger = logging.getLogger("aqy_decrypt")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="iQIYI QSV offline analysis and rebuild tool")
    subparsers = parser.add_subparsers(dest="command")

    inspect = subparsers.add_parser("inspect", help="Inspect one qsv sample")
    inspect.add_argument("--sample", required=True, help="Path to the qsv sample")

    inspect_db = subparsers.add_parser("inspect-db", help="Inspect one qsv sample with DB/WAL correlation")
    inspect_db.add_argument("--sample", required=True, help="Path to the qsv sample")
    inspect_db.add_argument(
        "--snapshot-mode",
        choices=["hot", "cold"],
        default="hot",
        help="Database snapshot mode",
    )

    snapshot_db = subparsers.add_parser("snapshot-db", help="Create a temp_cache DB/WAL snapshot")
    snapshot_db.add_argument(
        "--mode",
        choices=["hot", "cold"],
        default="hot",
        help="Snapshot mode label",
    )

    prototype_rebuild = subparsers.add_parser(
        "prototype-db-rebuild",
        help="Run the DB-guided rebuild prototype for one qsv sample",
    )
    prototype_rebuild.add_argument("--sample", required=True, help="Path to the qsv sample")
    prototype_rebuild.add_argument(
        "--snapshot-mode",
        choices=["hot", "cold"],
        default="hot",
        help="Database snapshot mode",
    )
    prototype_rebuild.add_argument(
        "--output-root",
        default="",
        help="Optional prototype output directory",
    )

    prototype_open = subparsers.add_parser(
        "prototype-open-diff",
        help="Open a sample in iQIYI and diff DB/WAL snapshots before and after",
    )
    prototype_open.add_argument("--sample", required=True, help="Path to the qsv sample")
    prototype_open.add_argument("--wait-sec", type=int, default=25, help="Wait time after launching sample")
    prototype_open.add_argument("--client-path", default="", help="Optional QyClient.exe path")

    prototype_bbts = subparsers.add_parser(
        "prototype-bbts-rebuild",
        help="Run the BBTS segment repair prototype for one qsv sample",
    )
    prototype_bbts.add_argument("--sample", required=True, help="Path to the qsv sample")
    prototype_bbts.add_argument("--segments-dir", required=True, help="Directory containing split TS segments")
    prototype_bbts.add_argument("--dispatch-json", required=True, help="Dispatch hit JSON with per-segment keys")
    prototype_bbts.add_argument("--output-root", default="", help="Optional prototype output directory")

    compare_snapshots = subparsers.add_parser(
        "compare-db-snapshots",
        help="Compare two existing DB snapshot roots with page-level WAL diffs",
    )
    compare_snapshots.add_argument("--sample", required=True, help="Path to the qsv sample")
    compare_snapshots.add_argument("--before-snapshot", required=True, help="Before snapshot root")
    compare_snapshots.add_argument("--after-snapshot", required=True, help="After snapshot root")

    hook_capture = subparsers.add_parser("hook-capture", help="Attach to iQIYI and capture qsv related access")
    hook_capture.add_argument("--sample", required=True, help="Path to the qsv sample")
    hook_capture.add_argument("--timeout-sec", type=int, default=20, help="Hook duration in seconds")
    hook_capture.add_argument(
        "--launch-sample",
        action="store_true",
        help="Ask the tool to open the sample file first",
    )

    decrypt = subparsers.add_parser("decrypt", help="Batch decrypt qsv files into mp4")
    decrypt.add_argument(
        "--input-root",
        default=str(get_default_input_root()),
        help="Input directory",
    )
    decrypt.add_argument(
        "--output-root",
        default=str(get_default_output_root()),
        help="Output directory",
    )
    recursive_group = decrypt.add_mutually_exclusive_group()
    recursive_group.add_argument(
        "--recursive",
        dest="recursive",
        action="store_true",
        default=True,
        help="Scan subdirectories recursively",
    )
    recursive_group.add_argument(
        "--no-recursive",
        dest="recursive",
        action="store_false",
        help="Only scan the top-level directory",
    )
    return parser


def create_service() -> DecryptService:
    AssetBootstrap().ensure_ffmpeg_assets()
    cache_root = get_default_cache_root()
    cache_index = LocalCacheIndex(cache_root=cache_root)
    decoder = QsvOfflineDecoder(cache_index=cache_index)
    ffmpeg_tools = FfmpegTools()
    db_snapshot_service = DbSnapshotService(cache_root=cache_root)
    db_cache_analyzer = DbCacheAnalyzer(cache_root=cache_root)
    db_prototype_rebuilder = DbPrototypeRebuilder(decoder=decoder, ffmpeg_tools=ffmpeg_tools)
    db_open_sample_prototype = DbOpenSamplePrototype(
        snapshot_service=db_snapshot_service,
        cache_analyzer=db_cache_analyzer,
        decoder=decoder,
        cache_root=cache_root,
    )
    bbts_variant_rebuilder = BbtsVariantRebuilder(ffmpeg_tools=ffmpeg_tools)
    return DecryptService(
        decoder=decoder,
        ffmpeg_tools=ffmpeg_tools,
        db_snapshot_service=db_snapshot_service,
        db_cache_analyzer=db_cache_analyzer,
        db_prototype_rebuilder=db_prototype_rebuilder,
        db_open_sample_prototype=db_open_sample_prototype,
        bbts_variant_rebuilder=bbts_variant_rebuilder,
    )


def create_hook_capture() -> HookCapture:
    cache_index = LocalCacheIndex(cache_root=get_default_cache_root())
    decoder = QsvOfflineDecoder(cache_index=cache_index)
    return HookCapture(decoder=decoder)


def print_banner() -> None:
    print(
        "\n"
        "iQIYI QSV Offline Tool\n"
        f"Default input root: {get_default_input_root()}\n"
        f"Default output root: {get_default_output_root()}\n"
        f"Default cache root: {get_default_cache_root()}\n"
    )


def prompt_input(prompt: str, default: str | None = None) -> str:
    try:
        value = input(prompt).strip()
    except EOFError:
        return default or ""
    return value or (default or "")


def run_interactive(service: DecryptService) -> int:
    print_banner()
    input_root = prompt_input(
        f"Input directory [{get_default_input_root()}]: ",
        str(get_default_input_root()),
    )
    output_root = prompt_input(
        f"Output directory [{get_default_output_root()}]: ",
        str(get_default_output_root()),
    )
    recursive_raw = prompt_input("Scan subdirectories recursively? [Y/n]: ", "y").lower()
    recursive = recursive_raw not in {"n", "no"}

    input_path = Path(input_root)
    output_path = Path(output_root)

    logger.info("interactive_mode: True")
    logger.info("selected_input_root: %s", input_path)
    logger.info("selected_output_root: %s", output_path)
    logger.info("selected_recursive: %s", recursive)

    confirm = prompt_input("Start batch decrypt now? [Y/n]: ", "y").lower()
    if confirm in {"n", "no"}:
        print("Cancelled.")
        return 0

    report = service.decrypt_batch(
        input_root=input_path,
        output_root=output_path,
        recursive=recursive,
    )
    payload = report.to_dict()
    print(
        json.dumps(
            {
                "candidate_count": payload["candidate_count"],
                "success_count": payload["success_count"],
                "failed_count": payload["failed_count"],
                "timing_hotspot": payload["timing_hotspot"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if payload["failed_count"] == 0 else 2


def main(argv: list[str] | None = None) -> int:
    log_file = setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    logger.info("runtime_dir: %s", get_runtime_dir())
    logger.info("log_file: %s", log_file)
    service = create_service()

    if args.command is None:
        return run_interactive(service)

    if args.command == "inspect":
        payload = service.inspect(Path(args.sample))
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.command == "inspect-db":
        payload = service.inspect_db(
            sample_path=Path(args.sample),
            snapshot_mode=args.snapshot_mode,
        )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.command == "snapshot-db":
        payload = service.snapshot_db(mode=args.mode)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.command == "prototype-db-rebuild":
        output_root = Path(args.output_root) if args.output_root else None
        payload = service.prototype_db_rebuild(
            sample_path=Path(args.sample),
            snapshot_mode=args.snapshot_mode,
            output_root=output_root,
        )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.command == "prototype-open-diff":
        client_path = Path(args.client_path) if args.client_path else None
        payload = service.prototype_open_diff(
            sample_path=Path(args.sample),
            wait_sec=args.wait_sec,
            client_path=client_path,
        )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.command == "prototype-bbts-rebuild":
        output_root = Path(args.output_root) if args.output_root else None
        payload = service.prototype_bbts_rebuild(
            sample_path=Path(args.sample),
            segments_dir=Path(args.segments_dir),
            dispatch_json_path=Path(args.dispatch_json),
            output_root=output_root,
        )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.command == "compare-db-snapshots":
        payload = service.compare_db_snapshots(
            sample_path=Path(args.sample),
            before_snapshot=Path(args.before_snapshot),
            after_snapshot=Path(args.after_snapshot),
        )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.command == "hook-capture":
        sample = Path(args.sample)
        work_dir = get_runtime_dir() / "_log" / "hook_manual" / sample.stem
        result = create_hook_capture().capture(
            sample_path=sample,
            work_dir=work_dir,
            timeout_sec=args.timeout_sec,
            launch_sample=args.launch_sample,
        )
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        print(f"hook_artifacts: {work_dir}")
        return 0 if result.ok else 2

    if args.command == "decrypt":
        report = service.decrypt_batch(
            input_root=Path(args.input_root),
            output_root=Path(args.output_root),
            recursive=args.recursive,
        )
        payload = report.to_dict()
        print(
            json.dumps(
                {
                    "candidate_count": payload["candidate_count"],
                    "success_count": payload["success_count"],
                    "failed_count": payload["failed_count"],
                    "timing_hotspot": payload["timing_hotspot"],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if payload["failed_count"] == 0 else 2

    parser.print_help()
    return 1
