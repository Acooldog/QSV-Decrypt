from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from src.Application.decrypt_service import DecryptService
from src.Infrastructure.asset_bootstrap import AssetBootstrap
from src.Infrastructure.ffmpeg_tools import FfmpegTools
from src.Infrastructure.hook_capture import HookCapture
from src.Infrastructure.local_cache_index import LocalCacheIndex
from src.Infrastructure.logging_utils import setup_logging
from src.Infrastructure.qsv_offline import QsvOfflineDecoder
from src.Infrastructure.runtime_paths import (
    get_default_input_root,
    get_default_output_root,
    get_runtime_dir,
)


logger = logging.getLogger("aqy_decrypt")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="爱奇艺 QSV 离线解密工具")
    subparsers = parser.add_subparsers(dest="command")

    inspect = subparsers.add_parser("inspect", help="分析单个 qsv 样本")
    inspect.add_argument("--sample", required=True, help="qsv 文件路径")

    hook_capture = subparsers.add_parser("hook-capture", help="附加爱奇艺进程并抓取 qsv 相关写入")
    hook_capture.add_argument("--sample", required=True, help="qsv 文件路径")
    hook_capture.add_argument("--timeout-sec", type=int, default=20, help="hook 监控时长（秒）")
    hook_capture.add_argument(
        "--launch-sample",
        action="store_true",
        help="由工具主动打开样本文件触发爱奇艺读取",
    )

    decrypt = subparsers.add_parser("decrypt", help="批量解密 qsv 到 mp4")
    decrypt.add_argument(
        "--input-root",
        default=str(get_default_input_root()),
        help="输入目录",
    )
    decrypt.add_argument(
        "--output-root",
        default=str(get_default_output_root()),
        help="输出目录",
    )
    recursive_group = decrypt.add_mutually_exclusive_group()
    recursive_group.add_argument(
        "--recursive",
        dest="recursive",
        action="store_true",
        default=True,
        help="递归扫描子目录",
    )
    recursive_group.add_argument(
        "--no-recursive",
        dest="recursive",
        action="store_false",
        help="只扫描输入目录当前层",
    )
    return parser


def create_service() -> DecryptService:
    AssetBootstrap().ensure_ffmpeg_assets()
    cache_index = LocalCacheIndex()
    decoder = QsvOfflineDecoder(cache_index=cache_index)
    ffmpeg_tools = FfmpegTools()
    return DecryptService(decoder=decoder, ffmpeg_tools=ffmpeg_tools)


def create_hook_capture() -> HookCapture:
    cache_index = LocalCacheIndex()
    decoder = QsvOfflineDecoder(cache_index=cache_index)
    return HookCapture(decoder=decoder)


def print_banner() -> None:
    print(
        "\n"
        "爱奇艺 QSV 离线解密控制台\n"
        f"默认输入目录: {get_default_input_root()}\n"
        f"默认输出目录: {get_default_output_root()}\n"
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
        f"输入目录 [{get_default_input_root()}]: ",
        str(get_default_input_root()),
    )
    output_root = prompt_input(
        f"输出目录 [{get_default_output_root()}]: ",
        str(get_default_output_root()),
    )
    recursive_raw = prompt_input("递归扫描子目录 [Y/n]: ", "y").lower()
    recursive = recursive_raw not in {"n", "no"}

    input_path = Path(input_root)
    output_path = Path(output_root)

    logger.info("interactive_mode: True")
    logger.info("selected_input_root: %s", input_path)
    logger.info("selected_output_root: %s", output_path)
    logger.info("selected_recursive: %s", recursive)

    confirm = prompt_input("立即开始批量解密 [Y/n]: ", "y").lower()
    if confirm in {"n", "no"}:
        print("已取消。")
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
