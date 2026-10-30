"""TShark live-capture agent — OPTIONAL, gracefully degrades if tshark is absent."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import time
from typing import Any

from .error_manager import ErrorManager
from .models import AgentStatus

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class CaptureAgent:
    """Wraps a TShark subprocess for live packet capture.

    Reads stderr asynchronously in a dedicated task to prevent pipe buffer deadlocks.
    Reports unexpected terminations and non-zero exit codes through ErrorManager.
    If TShark is absent or disabled, degrades gracefully without raising errors.
    """

    FIELDS = [
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "_ws.col.Protocol",
        "_ws.col.Info",
    ]

    def __init__(
        self,
        output_queue: asyncio.Queue[dict[str, Any]],
        error_mgr: ErrorManager | None = None,
        interface: str | None = None,
        disabled: bool = False,
    ) -> None:
        self.output_queue = output_queue
        self.error_mgr = error_mgr
        self.interface = interface
        self.disabled = disabled
        self.status = AgentStatus(name="TShark")

        self._proc: subprocess.Popen[str] | None = None
        self._task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._tshark_path: str | None = None
        self._stopping = False
        self._last_success: str = ""
        self._stderr_lines: list[str] = []



    async def start(self) -> None:
        if self.disabled:
            self.status.connected = False
            self.status.error_message = "Disabled by user (--no-tshark)"
            await self._emit_status("TShark disabled by user flag", "info")
            return

        self._stopping = False
        self._stderr_lines.clear()

        if self._tshark_path is None:
            self._tshark_path = self._find_tshark()
        if self._tshark_path is None:
            self.status.connected = False
            self.status.error_message = "TShark not found on PATH"
            await self._emit_status(
                "TShark not found — continuing without packet capture.",
                "warning",
            )
            return

        self.status.connected = True
        self._last_success = f"Found TShark at {self._tshark_path}"
        await self._emit_status(f"TShark found at {self._tshark_path}", "info")
        self._task = asyncio.create_task(self._capture_loop())

    async def stop(self) -> None:
        self._stopping = True
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass

        for t in (self._task, self._stderr_task):
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

        self._proc = None
        self.status.connected = False



    @staticmethod
    def _find_tshark() -> str | None:
        """Locate the tshark binary."""
        path = shutil.which("tshark")
        if path:
            return path
        for candidate in [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]:
            if os.path.isfile(candidate):
                return candidate
        return None

    def _build_cmd(self) -> list[str]:
        assert self._tshark_path
        cmd = [self._tshark_path, "-l", "-T", "fields"]
        for f in self.FIELDS:
            cmd += ["-e", f]
        cmd += ["-E", "separator=|", "-E", "quote=n"]
        if self.interface:
            cmd += ["-i", self.interface]
        return cmd

    async def _read_stderr_loop(self) -> None:
        """Drains stderr to avoid pipe buffer deadlocks and captures error messages."""
        loop = asyncio.get_running_loop()
        try:
            while self._proc and self._proc.stderr:
                line = await loop.run_in_executor(None, self._proc.stderr.readline)
                if not line:
                    break
                s = line.strip()
                if s:
                    self._stderr_lines.append(s)
                    if len(self._stderr_lines) > 30:
                        self._stderr_lines.pop(0)
        except asyncio.CancelledError:
            pass

    async def _capture_loop(self) -> None:
        loop = asyncio.get_running_loop()
        cmd = self._build_cmd()

        try:
            self._proc = await loop.run_in_executor(
                None,
                lambda: subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    creationflags=_CREATE_NO_WINDOW,
                ),
            )
        except Exception as exc:
            self.status.connected = False
            self.status.error_message = str(exc)
            if self.error_mgr:
                await self.error_mgr.record(
                    agent="TShark",
                    step="spawn_process",
                    exc=exc,
                    message=f"Failed to start TShark subprocess: {exc}",
                    last_success=self._last_success,
                )
            return

        proc = self._proc
        if proc is None:
            return

        self._stderr_task = asyncio.create_task(self._read_stderr_loop())
        self._last_success = f"Capture process started (PID {proc.pid})"
        await self._emit_status("TShark capture started", "info")

        try:
            while not self._stopping:
                assert self._proc and self._proc.stdout
                line = await loop.run_in_executor(None, self._proc.stdout.readline)
                if not line:

                    break

                line_str = line.strip()
                if not line_str:
                    continue

                raw = self._parse_line(line_str)
                if raw:
                    self.status.events_count += 1
                    self.status.last_event_time = time.time()
                    self._last_success = f"Packet parsed at {time.strftime('%H:%M:%S')}"
                    await self.output_queue.put(raw)

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            if not self._stopping:
                self.status.connected = False
                self.status.error_message = str(exc)
                if self.error_mgr:
                    await self.error_mgr.record(
                        agent="TShark",
                        step="stdout_read",
                        exc=exc,
                        message=f"Error reading TShark stdout: {exc}",
                        last_success=self._last_success,
                    )
        finally:

            proc_exit = self._proc
            if not self._stopping and proc_exit is not None:
                self.status.connected = False

                try:
                    await loop.run_in_executor(None, lambda: proc_exit.wait(timeout=2))
                except Exception:
                    pass

                code = proc_exit.poll()

                await asyncio.sleep(0.1)
                stderr_diag = "\n".join(self._stderr_lines[-5:]) if self._stderr_lines else "No stderr details"

                if code is not None and code != 0:
                    msg = f"TShark terminated with error exit code {code}.\nDiagnostics: {stderr_diag}"
                    self.status.error_message = msg
                    if self.error_mgr:
                        await self.error_mgr.record(
                            agent="TShark",
                            step="packet_capture",
                            message=msg,
                            last_success=self._last_success or "Capture process started",
                            error_type="TSharkExitError",
                        )
                else:
                    msg = f"TShark capture ended unexpectedly (exit code {code}).\nDiagnostics: {stderr_diag}"
                    self.status.error_message = msg
                    if self.error_mgr:
                        await self.error_mgr.record(
                            agent="TShark",
                            step="packet_capture",
                            message=msg,
                            last_success=self._last_success or "Capture process started",
                            error_type="TSharkTerminated",
                        )

            self.status.connected = False

    def _parse_line(self, line: str) -> dict[str, Any] | None:
        """Parse a TShark fields-mode output line."""
        parts = line.split("|")
        if len(parts) < 5:
            return None

        time_rel = parts[0] if len(parts) > 0 else ""
        ip_src = parts[1] if len(parts) > 1 else ""
        ip_dst = parts[2] if len(parts) > 2 else ""
        tcp_sport = parts[3] if len(parts) > 3 else ""
        tcp_dport = parts[4] if len(parts) > 4 else ""
        udp_sport = parts[5] if len(parts) > 5 else ""
        udp_dport = parts[6] if len(parts) > 6 else ""
        protocol = parts[7] if len(parts) > 7 else ""
        info = parts[8] if len(parts) > 8 else ""

        src_port = tcp_sport or udp_sport or "0"
        dst_port = tcp_dport or udp_dport or "0"

        return {
            "_source": "tshark",
            "time_rel": time_rel,
            "src": ip_src or "?",
            "dst": ip_dst or "?",
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol or "?",
            "info": info,
        }

    async def _emit_status(self, message: str, level: str = "info") -> None:
        await self.output_queue.put({
            "_source": "status",
            "agent": "TShark",
            "message": message,
            "level": level,
        })
