"""System agent — monitors Windows network connections, DNS cache, process info."""

from __future__ import annotations

import asyncio
import re
import subprocess
import time
from typing import Any

from .error_manager import ErrorManager
from .models import AgentStatus

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class SystemAgent:
    """Periodically polls ``netstat`` and DNS cache on Windows.

    Emits raw dicts with ``_source='system_conn'`` or ``_source='system_dns'``
    into *output_queue*.
    """

    _FAILURE_THRESHOLD = 3

    def __init__(
        self,
        output_queue: asyncio.Queue[dict[str, Any]],
        poll_interval: float = 5.0,
        error_mgr: ErrorManager | None = None,
    ) -> None:
        self.output_queue = output_queue
        self.poll_interval = poll_interval
        self.error_mgr = error_mgr
        self.status = AgentStatus(name="System")
        self._task: asyncio.Task | None = None
        self._dns_task: asyncio.Task | None = None
        self._known_connections: set[str] = set()
        self._known_dns: set[str] = set()
        self._netstat_failures: int = 0
        self._netstat_error_reported: bool = False
        self._dns_failures: int = 0
        self._dns_error_reported: bool = False
        self._last_netstat_success: str = ""
        self._last_dns_success: str = ""
        self.paused: bool = False
        self.discarded_count: int = 0



    async def start(self) -> None:
        self.status.connected = True
        await self._emit_status("System network monitor started", "info")
        self._task = asyncio.create_task(self._netstat_loop())
        self._dns_task = asyncio.create_task(self._dns_loop())

    async def stop(self) -> None:
        for t in (self._task, self._dns_task):
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
        self.status.connected = False

    def pause(self) -> None:
        self.paused = True

    def resume(self) -> None:
        self.paused = False
        self.discarded_count = 0



    async def _netstat_loop(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            while True:
                if self.paused:
                    await asyncio.sleep(self.poll_interval)
                    continue
                try:
                    output = await loop.run_in_executor(None, self._run_netstat)
                    new_conns = self._parse_netstat(output)
                    if self.paused:
                        self.discarded_count += sum(
                            1
                            for conn in new_conns
                            if f"{conn.get('proto')}|{conn.get('local')}|{conn.get('remote')}|{conn.get('pid')}"
                            not in self._known_connections
                        )
                        continue
                    for conn in new_conns:
                        key = f"{conn.get('proto')}|{conn.get('local')}|{conn.get('remote')}|{conn.get('pid')}"
                        if key not in self._known_connections:
                            self._known_connections.add(key)
                            self.status.events_count += 1
                            self.status.last_event_time = time.time()
                            await self.output_queue.put(conn)
                    self._netstat_failures = 0
                    self._netstat_error_reported = False
                    self._last_netstat_success = f"netstat poll at {time.strftime('%H:%M:%S')}"
                except Exception as exc:
                    if self.paused:
                        continue
                    self._netstat_failures += 1
                    await self._emit_status(f"netstat error: {exc}", "warning")
                    if (
                        self.error_mgr
                        and self._netstat_failures >= self._FAILURE_THRESHOLD
                        and not self._netstat_error_reported
                    ):
                        self._netstat_error_reported = True
                        await self.error_mgr.record(
                            agent="System",
                            step="netstat_poll",
                            exc=exc,
                            message=f"netstat failed {self._netstat_failures} times consecutively: {exc}",
                            last_success=self._last_netstat_success or "None confirmed",
                        )
                await asyncio.sleep(self.poll_interval)
        except asyncio.CancelledError:
            pass

    @staticmethod
    def _run_netstat() -> str:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=_CREATE_NO_WINDOW,
        )
        if result.returncode != 0:
            err = result.stderr.strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"netstat failed: {err}")
        return result.stdout

    def _parse_netstat(self, output: str) -> list[dict[str, Any]]:
        """Parse netstat -ano output into connection dicts."""
        results: list[dict[str, Any]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            m = re.match(
                r"(TCP|UDP)\s+"
                r"(\S+)\s+"
                r"(\S+)\s+"
                r"(\S+)?\s*"
                r"(\d+)$",
                line,
            )
            if not m:
                continue
            proto, local, remote, state, pid = m.groups()
            state = state or ""


            if remote in ("0.0.0.0:0", "*:*", "[::]:0"):
                continue
            if "127.0.0.1" in (remote.split(":")[0] if ":" in remote else remote):
                continue

            process_name = self._get_process_name(int(pid))

            results.append({
                "_source": "system_conn",
                "proto": proto,
                "local": local,
                "remote": remote,
                "state": state,
                "pid": pid,
                "process": process_name,
            })
        return results

    @staticmethod
    def _get_process_name(pid: int) -> str:
        """Resolve PID to a process name via tasklist."""
        if pid == 0:
            return "System Idle"
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=5,
                    creationflags=_CREATE_NO_WINDOW,
            )
            for line in result.stdout.strip().splitlines():
                parts = line.strip('"').split('","')
                if parts:
                    return parts[0]
        except Exception:
            pass
        return f"pid-{pid}"



    async def _dns_loop(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            while True:
                if self.paused:
                    await asyncio.sleep(0.1)
                    continue
                try:
                    initial = await loop.run_in_executor(None, self._run_dns_cache)
                    for entry in self._parse_dns_cache(initial):
                        key = f"{entry.get('domain')}|{entry.get('ip')}"
                        self._known_dns.add(key)
                    self._dns_failures = 0
                    self._dns_error_reported = False
                    self._last_dns_success = f"DNS baseline at {time.strftime('%H:%M:%S')} ({len(self._known_dns)} entries)"
                    await self._emit_status(
                        f"DNS cache baseline: {len(self._known_dns)} entries", "info"
                    )
                    break
                except Exception as exc:
                    if self.paused:
                        continue
                    self._dns_failures += 1
                    await self._emit_status(f"DNS cache baseline error: {exc}", "warning")
                    if (
                        self.error_mgr
                        and self._dns_failures >= self._FAILURE_THRESHOLD
                        and not self._dns_error_reported
                    ):
                        self._dns_error_reported = True
                        await self.error_mgr.record(
                            agent="System",
                            step="dns_cache_baseline",
                            exc=exc,
                            message=f"DNS cache baseline failed: {exc}",
                            last_success=self._last_dns_success or "None confirmed",
                        )
                    break

            while True:
                await asyncio.sleep(self.poll_interval * 2)
                if self.paused:
                    continue
                try:
                    output = await loop.run_in_executor(None, self._run_dns_cache)
                    entries = self._parse_dns_cache(output)
                    if self.paused:
                        self.discarded_count += sum(
                            1
                            for entry in entries
                            if f"{entry.get('domain')}|{entry.get('ip')}" not in self._known_dns
                        )
                        continue
                    for entry in entries:
                        key = f"{entry.get('domain')}|{entry.get('ip')}"
                        if key not in self._known_dns:
                            self._known_dns.add(key)
                            self.status.events_count += 1
                            self.status.last_event_time = time.time()
                            await self.output_queue.put(entry)
                    self._dns_failures = 0
                    self._dns_error_reported = False
                    self._last_dns_success = f"DNS cache poll at {time.strftime('%H:%M:%S')}"
                except Exception as exc:
                    if self.paused:
                        continue
                    self._dns_failures += 1
                    await self._emit_status(f"DNS cache error: {exc}", "warning")
                    if (
                        self.error_mgr
                        and self._dns_failures >= self._FAILURE_THRESHOLD
                        and not self._dns_error_reported
                    ):
                        self._dns_error_reported = True
                        await self.error_mgr.record(
                            agent="System",
                            step="dns_cache_poll",
                            exc=exc,
                            message=f"DNS cache poll failed {self._dns_failures} times consecutively: {exc}",
                            last_success=self._last_dns_success or "None confirmed",
                        )
        except asyncio.CancelledError:
            pass

    @staticmethod
    def _run_dns_cache() -> str:
        result = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=_CREATE_NO_WINDOW,
        )
        if result.returncode != 0:
            err = result.stderr.strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"ipconfig /displaydns failed: {err}")
        return result.stdout

    @staticmethod
    def _parse_dns_cache(output: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        current_domain: str | None = None
        for line in output.splitlines():
            line = line.strip()

            m = re.match(r"Record Name\s*[.:]+\s*(.+)", line)
            if m:
                current_domain = m.group(1).strip()
                continue

            m = re.match(r"(?:A \(Host\) Record|Data)\s*[.:]+\s*(.+)", line)
            if m and current_domain:
                ip = m.group(1).strip()
                results.append({
                    "_source": "system_dns",
                    "domain": current_domain,
                    "ip": ip,
                    "type": "A",
                })
                current_domain = None
        return results

    async def _emit_status(self, message: str, level: str = "info") -> None:
        if self.paused:
            return
        await self.output_queue.put({
            "_source": "status",
            "agent": "System",
            "message": message,
            "level": level,
        })
