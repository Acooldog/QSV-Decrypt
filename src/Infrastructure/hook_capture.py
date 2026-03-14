from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from src.Application.models import HookCaptureResult

from .ffmpeg_tools import FfmpegTools
from .qsv_offline import QsvOfflineDecoder
from .runtime_paths import get_runtime_dir

try:
    import frida  # type: ignore
except ImportError:  # pragma: no cover
    local_site = get_runtime_dir() / ".venv" / "Lib" / "site-packages"
    if local_site.exists():
        sys.path.append(str(local_site))
    try:
        import frida  # type: ignore
    except ImportError:
        frida = None


WRITE_CAPTURE_JS = r"""
const handleToPath = new Map();
const handleToOffset = new Map();
const mappingToPath = new Map();
function safeReadAnsi(ptr) {
  try {
    if (ptr.isNull()) return "";
    return ptr.readUtf8String();
  } catch (e) { return ""; }
}
function readWide(ptr) {
  try { return ptr.readUtf16String(); } catch (e) { return ""; }
}
function readUnicodeString(ptr) {
  try {
    if (ptr.isNull()) return "";
    const len = ptr.readU16();
    const buf = ptr.add(8).readPointer();
    if (buf.isNull() || len === 0) return "";
    return buf.readUtf16String(len / 2);
  } catch (e) {
    return "";
  }
}
function readObjectNameFromAttributes(ptr) {
  try {
    if (ptr.isNull()) return "";
    const unicodePtr = ptr.add(16).readPointer();
    return readUnicodeString(unicodePtr);
  } catch (e) {
    return "";
  }
}
function shouldTrack(path, stem) {
  if (!path) return false;
  const lower = path.toLowerCase();
  if (stem && lower.indexOf(stem.toLowerCase()) >= 0) return true;
  if (
    lower.indexOf("\\\\qycache\\\\") >= 0 ||
    lower.indexOf("\\\\iqiyi video\\\\") >= 0 ||
    lower.indexOf("\\\\qiyi\\\\") >= 0 ||
    lower.indexOf("\\\\qyclient\\\\") >= 0
  ) {
    return true;
  }
  return (
    lower.endsWith(".qsv") ||
    lower.endsWith(".ts") ||
    lower.endsWith(".mp4") ||
    lower.endsWith(".m4s") ||
    lower.endsWith(".frag") ||
    lower.endsWith(".f4v") ||
    lower.endsWith(".tmp")
  );
}
function toHex(bytes) {
  if (!bytes) return "";
  return Array.from(new Uint8Array(bytes)).map(v => v.toString(16).padStart(2, "0")).join("");
}
function safeAttach(moduleName, exportName, callbacks) {
  let address = null;
  try {
    address = Module.getGlobalExportByName(exportName);
  } catch (e) {}
  if (!address) return false;
  Interceptor.attach(address, callbacks);
  send({type: "hooked_export", module: moduleName, exportName: exportName});
  return true;
}
const createFileW = Module.getGlobalExportByName("CreateFileW");
Interceptor.attach(createFileW, {
  onEnter(args) {
    this.path = readWide(args[0]);
  },
  onLeave(retval) {
    if (shouldTrack(this.path, "%STEM%")) {
      const key = retval.toString();
      handleToPath.set(key, this.path);
      handleToOffset.set(key, 0);
      send({type: "create", path: this.path});
    }
  }
});
const ntCreateFile = Module.getGlobalExportByName("NtCreateFile");
Interceptor.attach(ntCreateFile, {
  onEnter(args) {
    this.outHandlePtr = args[0];
    this.path = readObjectNameFromAttributes(args[2]);
  },
  onLeave(retval) {
    if (!this.path || !shouldTrack(this.path, "%STEM%") || retval.toInt32() !== 0) return;
    try {
      const handleValue = this.outHandlePtr.readPointer().toString();
      handleToPath.set(handleValue, this.path);
      handleToOffset.set(handleValue, 0);
      send({type: "nt_create", path: this.path});
    } catch (e) {}
  }
});
const setFilePointerEx = Module.getGlobalExportByName("SetFilePointerEx");
Interceptor.attach(setFilePointerEx, {
  onEnter(args) {
    this.key = args[0].toString();
    this.path = handleToPath.get(this.key) || "";
    this.newPosPtr = args[2];
    this.moveMethod = args[3].toInt32();
  },
  onLeave(retval) {
    if (!this.path || retval.toInt32() === 0) return;
    let newOffset = null;
    try {
      if (!this.newPosPtr.isNull()) {
        newOffset = this.newPosPtr.readS64().toString();
      }
    } catch (e) {}
    send({type: "seek", path: this.path, moveMethod: this.moveMethod, newOffset: newOffset});
    if (newOffset !== null) {
      handleToOffset.set(this.key, parseInt(newOffset, 10));
    }
  }
});
const readFile = Module.getGlobalExportByName("ReadFile");
Interceptor.attach(readFile, {
  onEnter(args) {
    this.key = args[0].toString();
    this.path = handleToPath.get(this.key) || "";
    this.buf = args[1];
    this.requested = args[2].toInt32();
    this.bytesReadPtr = args[3];
    this.offset = handleToOffset.has(this.key) ? handleToOffset.get(this.key) : null;
  },
  onLeave(retval) {
    if (!this.path || retval.toInt32() === 0) return;
    let actual = 0;
    try {
      if (!this.bytesReadPtr.isNull()) {
        actual = this.bytesReadPtr.readU32();
      }
    } catch (e) {}
    const previewSize = Math.min(actual, 64);
    let previewHex = "";
    try {
      if (previewSize > 0) {
        previewHex = toHex(Memory.readByteArray(this.buf, previewSize));
      }
    } catch (e) {}
    send({
      type: "read",
      path: this.path,
      offset: this.offset,
      requested: this.requested,
      actual: actual,
      previewHex: previewHex
    });
    if (this.offset !== null) {
      handleToOffset.set(this.key, this.offset + actual);
    }
  }
});
const ntReadFile = Module.getGlobalExportByName("NtReadFile");
Interceptor.attach(ntReadFile, {
  onEnter(args) {
    this.key = args[0].toString();
    this.path = handleToPath.get(this.key) || "";
    this.buf = args[5];
    this.requested = args[6].toInt32();
    this.byteOffsetPtr = args[7];
    this.offset = handleToOffset.has(this.key) ? handleToOffset.get(this.key) : null;
    try {
      if (!this.byteOffsetPtr.isNull()) {
        this.offset = this.byteOffsetPtr.readS64().toNumber();
      }
    } catch (e) {}
  },
  onLeave(retval) {
    if (!this.path || retval.toInt32() !== 0) return;
    let previewHex = "";
    try {
      const previewSize = Math.min(this.requested, 64);
      if (previewSize > 0) {
        previewHex = toHex(Memory.readByteArray(this.buf, previewSize));
      }
    } catch (e) {}
    send({
      type: "nt_read",
      path: this.path,
      offset: this.offset,
      requested: this.requested,
      previewHex: previewHex
    });
    if (this.offset !== null) {
      handleToOffset.set(this.key, this.offset + this.requested);
    }
  }
});
const writeFile = Module.getGlobalExportByName("WriteFile");
Interceptor.attach(writeFile, {
  onEnter(args) {
    this.key = args[0].toString();
    this.path = handleToPath.get(this.key) || "";
    this.size = args[2].toInt32();
    if (this.path && this.size > 0 && this.size <= 2 * 1024 * 1024) {
      this.payload = Memory.readByteArray(args[1], this.size);
    }
  },
  onLeave(retval) {
    if (this.path && this.payload) {
      send({type: "write", path: this.path}, this.payload);
    }
  }
});
const ntWriteFile = Module.getGlobalExportByName("NtWriteFile");
Interceptor.attach(ntWriteFile, {
  onEnter(args) {
    this.key = args[0].toString();
    this.path = handleToPath.get(this.key) || "";
    this.buf = args[5];
    this.requested = args[6].toInt32();
  },
  onLeave(retval) {
    if (!this.path || retval.toInt32() !== 0) return;
    let previewHex = "";
    try {
      const previewSize = Math.min(this.requested, 64);
      if (previewSize > 0) {
        previewHex = toHex(Memory.readByteArray(this.buf, previewSize));
      }
    } catch (e) {}
    send({
      type: "nt_write",
      path: this.path,
      requested: this.requested,
      previewHex: previewHex
    });
  }
});
const createFileMappingW = Module.getGlobalExportByName("CreateFileMappingW");
Interceptor.attach(createFileMappingW, {
  onEnter(args) {
    this.fileKey = args[0].toString();
    this.path = handleToPath.get(this.fileKey) || "";
  },
  onLeave(retval) {
    if (!this.path) return;
    mappingToPath.set(retval.toString(), this.path);
    send({type: "create_mapping", path: this.path});
  }
});
const mapViewOfFile = Module.getGlobalExportByName("MapViewOfFile");
Interceptor.attach(mapViewOfFile, {
  onEnter(args) {
    this.mapKey = args[0].toString();
    this.path = mappingToPath.get(this.mapKey) || "";
    this.offset = (args[2].toUInt32() * 0x100000000) + args[3].toUInt32();
    this.size = args[4].toUInt32();
  },
  onLeave(retval) {
    if (!this.path || retval.isNull()) return;
    send({type: "map_view", path: this.path, offset: this.offset, size: this.size});
  }
});
const closeHandle = Module.getGlobalExportByName("CloseHandle");
Interceptor.attach(closeHandle, {
  onEnter(args) {
    const key = args[0].toString();
    if (handleToPath.has(key)) {
      send({type: "close", path: handleToPath.get(key)});
      handleToPath.delete(key);
      handleToOffset.delete(key);
    }
    if (mappingToPath.has(key)) {
      mappingToPath.delete(key);
    }
  }
});
safeAttach("kernel32.dll", "MoveFileExW", {
  onEnter(args) {
    const fromPath = readWide(args[0]);
    const toPath = readWide(args[1]);
    if (fromPath || toPath) {
      send({type: "move", from: fromPath, to: toPath});
    }
  }
});
safeAttach("avformat-61.dll", "avformat_open_input", {
  onEnter(args) {
    this.url = safeReadAnsi(args[1]);
  },
  onLeave(retval) {
    if (this.url) {
      send({type: "avformat_open_input", url: this.url, retval: retval.toInt32()});
    }
  }
});
safeAttach("avformat-61.dll", "avio_open2", {
  onEnter(args) {
    this.url = safeReadAnsi(args[1]);
  },
  onLeave(retval) {
    if (this.url) {
      send({type: "avio_open2", url: this.url, retval: retval.toInt32()});
    }
  }
});
"""


class HookCapture:
    def __init__(
        self,
        decoder: QsvOfflineDecoder | None = None,
        ffmpeg_tools: FfmpegTools | None = None,
    ) -> None:
        self.decoder = decoder or QsvOfflineDecoder()
        self.ffmpeg_tools = ffmpeg_tools or FfmpegTools()
        self.target_process_names = [
            "qyclient.exe",
            "qyplayer.exe",
            "qiyiservice.exe",
            "qyfragment.exe",
            "qykernel.exe",
        ]

    def _find_qyclient_path(self) -> Path | None:
        candidates = [
            Path(r"C:\Program Files\IQIYI Video\LStyle\14.3.0.9857\QyClient.exe"),
            Path(r"C:\Program Files\IQIYI Video\QyClient.exe"),
            Path(r"C:\Program Files (x86)\IQIYI Video\QyClient.exe"),
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        try:
            command = (
                "Get-Process QyClient -ErrorAction Stop | "
                "Select-Object -First 1 -ExpandProperty Path"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            path = result.stdout.strip()
            if path:
                candidate = Path(path)
                if candidate.exists():
                    return candidate
        except Exception:
            return None
        return None

    def capture(
        self,
        sample_path: Path,
        work_dir: Path,
        timeout_sec: int = 20,
        launch_sample: bool = False,
    ) -> HookCaptureResult:
        if frida is None:
            return HookCaptureResult(ok=False, reason="frida_not_installed")
        candidates: dict[str, Path] = {}
        work_capture = work_dir / "hook_capture"
        work_capture.mkdir(parents=True, exist_ok=True)
        js_source = WRITE_CAPTURE_JS.replace("%STEM%", sample_path.stem.replace("\\", "\\\\"))
        device = frida.get_local_device()
        known_pids: set[int] = set()
        sessions = []
        scripts = []

        def attach_matching_processes() -> None:
            for process in device.enumerate_processes():
                if process.name.lower() not in self.target_process_names:
                    continue
                if process.pid in known_pids:
                    continue
                try:
                    session = device.attach(process.pid)
                    script = session.create_script(js_source)
                    script.on("message", on_message)
                    script.load()
                except Exception:
                    continue
                known_pids.add(process.pid)
                sessions.append(session)
                scripts.append(script)

        target_processes = [
            process
            for process in device.enumerate_processes()
            if process.name.lower() in self.target_process_names
        ]
        if not target_processes and not launch_sample:
            return HookCaptureResult(ok=False, reason="offline_failed_and_hook_unavailable")

        events: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            if message.get("type") != "send":
                return
            payload = message.get("payload", {})
            payload_type = payload.get("type", "")
            if payload_type == "write":
                path = payload.get("path", "")
                if not path or not data:
                    return
                safe_name = base64.urlsafe_b64encode(path.encode("utf-8")).decode("ascii").rstrip("=")
                capture_path = work_capture / f"{safe_name}.bin"
                with open(capture_path, "ab") as handle:
                    handle.write(data)
                candidates[path] = capture_path
                events.append({"type": "write", "path": path, "size": len(data)})
                return
            events.append(dict(payload))

        attach_matching_processes()

        if launch_sample:
            launcher = self._find_qyclient_path()
            if launcher is not None:
                try:
                    subprocess.Popen([str(launcher), str(sample_path)])
                except Exception:
                    os.startfile(str(sample_path))
            else:
                os.startfile(str(sample_path))

        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            attach_matching_processes()
            time.sleep(0.5)
        for script in scripts:
            try:
                script.unload()
            except Exception:
                pass
        for session in sessions:
            try:
                session.detach()
            except Exception:
                pass

        with open(work_capture / "events.json", "w", encoding="utf-8") as handle:
            json.dump(events, handle, ensure_ascii=False, indent=2)

        candidate_paths = list(candidates.values())
        selected: Path | None = None
        for path in candidate_paths:
            try:
                probe = self.ffmpeg_tools.probe(path)
                if probe.ok and (probe.video_streams + probe.audio_streams) > 0:
                    selected = path
                    break
            except Exception:
                pass
            try:
                inspection = self.decoder.inspect(path)
                if inspection.payload_offset is not None:
                    normalized = path.with_suffix(".ts")
                    with open(path, "rb") as source, open(normalized, "wb") as target:
                        source.seek(inspection.payload_offset)
                        target.write(source.read())
                    selected = normalized
                    break
            except Exception:
                continue
        return HookCaptureResult(
            ok=selected is not None,
            reason="captured" if selected else "hook_capture_empty",
            candidate_paths=candidate_paths,
            selected_path=selected,
        )
