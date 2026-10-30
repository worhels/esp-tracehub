"""System agent — monitors Windows network connections, DNS cache, process info."""

from __future__ import annotations

import asyncio
import re
import subprocess
import time
from typing import Any

from .models import AgentStatus

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class SystemAgent:
    """Periodically polls ``netstat`` and DNS cache on Windows.

    Emits raw dicts with ``_source='system_conn'`` or ``_source='system_dns'``
    into *output_queue*.
    """

    def __init__(
        self,
        output_queue: asyncio.Queue[dict[str, Any]],
        poll_interval: float = 5.0,
    ) -> None:
        self.output_queue = output_queue
        self.poll_interval = poll_interval
        self.status = AgentStatus(name="System")
        self._task: asyncio.Task | None = None
        self._dns_task: asyncio.Task | None = None
        self._known_connections: set[str] = set()
        self._known_dns: set[str] = set()



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



    async def _netstat_loop(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            while True:
                try:
                    output = await loop.run_in_executor(None, self._run_netstat)
                    new_conns = self._parse_netstat(output)
                    for conn in new_conns:
                        key = f"{conn.get('proto')}|{conn.get('local')}|{conn.get('remote')}|{conn.get('pid')}"
                        if key not in self._known_connections:
                            self._known_connections.add(key)
                            self.status.events_count += 1
                            self.status.last_event_time = time.time()
                            await self.output_queue.put(conn)
                except Exception as exc:
                    await self._emit_status(f"netstat error: {exc}", "warning")
                await asyncio.sleep(self.poll_interval)
        except asyncio.CancelledError:
            pass

    @staticmethod
    def _run_netstat() -> str:
        try:
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            )
            return result.stdout
        except FileNotFoundError:
            return ""
        except subprocess.TimeoutExpired:
            return ""

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

            try:
                initial = await loop.run_in_executor(None, self._run_dns_cache)
                for entry in self._parse_dns_cache(initial):
                    key = f"{entry.get('domain')}|{entry.get('ip')}"
                    self._known_dns.add(key)
            except Exception:
                pass
            await self._emit_status(
                f"DNS cache baseline: {len(self._known_dns)} entries", "info"
            )

            while True:
                await asyncio.sleep(self.poll_interval * 2)
                try:
                    output = await loop.run_in_executor(None, self._run_dns_cache)
                    entries = self._parse_dns_cache(output)
                    for entry in entries:
                        key = f"{entry.get('domain')}|{entry.get('ip')}"
                        if key not in self._known_dns:
                            self._known_dns.add(key)
                            self.status.events_count += 1
                            self.status.last_event_time = time.time()
                            await self.output_queue.put(entry)
                except Exception as exc:
                    await self._emit_status(f"DNS cache error: {exc}", "warning")
        except asyncio.CancelledError:
            pass

    @staticmethod
    def _run_dns_cache() -> str:
        try:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            )
            return result.stdout
        except Exception:
            return ""

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
        await self.output_queue.put({
            "_source": "status",
            "agent": "System",
            "message": message,
            "level": level,
        })
