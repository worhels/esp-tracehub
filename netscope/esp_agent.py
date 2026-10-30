"""ESP32 UART agent that reads structured events from the Wi-Fi sniffer."""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from .error_manager import ErrorManager
from .models import AgentStatus


class ESPAgent:
    """Connects to an ESP32 over UART and parses sniffer event lines.

    Maintains heartbeat monitoring and surfaces runtime board errors (ERROR=, FALSE)
    directly through ErrorManager to the UI.
    """

    def __init__(
        self,
        output_queue: asyncio.Queue[dict[str, Any]],
        error_mgr: ErrorManager | None = None,
        port: str = "COM3",
        baudrate: int = 115200,
        disabled: bool = False,
    ) -> None:
        self.output_queue = output_queue
        self.error_mgr = error_mgr
        self.port = port
        self.baudrate = baudrate
        self.disabled = disabled
        self.status = AgentStatus(name="ESP32")

        self._task: asyncio.Task[None] | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._serial: Any = None
        self._stopping = False
        self._last_success: str = ""
        self._last_heartbeat_time: float = 0.0



    async def start(self) -> None:
        if self.disabled:
            self.status.connected = False
            self.status.error_message = "Disabled by user (--no-esp)"
            await self._emit_status("ESP32 disabled by user flag", "info")
            return

        self._stopping = False

        try:
            import serial as _serial
        except ImportError as exc:
            self.status.connected = False
            self.status.error_message = "pyserial not installed"
            if self.error_mgr:
                await self.error_mgr.record(
                    agent="ESP32",
                    step="import_pyserial",
                    exc=exc,
                    message="pyserial not installed. Run: pip install pyserial",
                    last_success="None",
                )
            return

        loop = asyncio.get_running_loop()
        try:
            self._serial = await loop.run_in_executor(
                None,
                lambda: _serial.Serial(self.port, self.baudrate, timeout=1),
            )
        except Exception as exc:
            self.status.connected = False
            self.status.error_message = f"Cannot open {self.port}: {exc}"
            if self.error_mgr:
                await self.error_mgr.record(
                    agent="ESP32",
                    step="open_serial_port",
                    exc=exc,
                    message=f"Cannot open serial port {self.port}: {exc}",
                    last_success="None",
                )
            return

        self.status.connected = True
        self._last_success = f"Connected on {self.port} @ {self.baudrate}"
        self._last_heartbeat_time = time.time()
        await self._emit_status(f"ESP32 connected on {self.port} @ {self.baudrate}", "info")


        ser = self._serial
        try:
            await loop.run_in_executor(None, lambda: ser.write(b"wifi-scan\r\n"))
            self._last_success = f"Sent 'wifi-scan' to {self.port}"
            await self._emit_status("Sent 'wifi-scan' command to ESP32", "info")
        except Exception as exc:
            self.status.connected = False
            self.status.error_message = f"Failed to send wifi-scan: {exc}"
            if self.error_mgr:
                await self.error_mgr.record(
                    agent="ESP32",
                    step="send_wifi_scan",
                    exc=exc,
                    message=f"Failed to send wifi-scan command to {self.port}: {exc}",
                    last_success=self._last_success,
                )
            return

        self._task = asyncio.create_task(self._read_loop())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_watchdog())

    async def stop(self) -> None:
        self._stopping = True
        ser = self._serial

        if ser is not None and getattr(ser, "is_open", False):
            try:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, lambda: ser.write(b"wifi-stop\r\n"))
            except Exception:
                pass

        for t in (self._task, self._heartbeat_task):
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

        if ser is not None and getattr(ser, "is_open", False):
            try:
                ser.close()
            except Exception:
                pass

        self._serial = None
        self.status.connected = False



    async def _heartbeat_watchdog(self) -> None:
        """Monitors heartbeat from ESP32. If silent for >6s, triggers runtime error."""
        try:
            while not self._stopping and self.status.connected:
                await asyncio.sleep(1.0)
                if not self.status.connected or self._stopping:
                    break

                elapsed = time.time() - self._last_heartbeat_time
                if elapsed > 6.0:
                    self.status.connected = False
                    msg = (
                        f"ESP32 communication lost on {self.port}: "
                        f"no data or heartbeat received for {int(elapsed)}s"
                    )
                    self.status.error_message = msg
                    if self.error_mgr:
                        await self.error_mgr.record(
                            agent="ESP32",
                            step="heartbeat_watchdog",
                            message=msg,
                            last_success=self._last_success or f"Connected on {self.port}",
                            error_type="HeartbeatTimeout",
                        )
                    break
        except asyncio.CancelledError:
            pass

    async def _read_loop(self) -> None:
        ser = self._serial
        if ser is None:
            return
        loop = asyncio.get_running_loop()

        try:
            while not self._stopping:
                try:
                    raw_line: bytes = await loop.run_in_executor(None, ser.readline)
                except Exception as exc:
                    if self._stopping:
                        break
                    self.status.connected = False
                    self.status.error_message = str(exc)
                    if self.error_mgr:
                        await self.error_mgr.record(
                            agent="ESP32",
                            step="serial_read",
                            exc=exc,
                            message=f"Serial communication error on {self.port}: {exc}",
                            last_success=self._last_success or f"Connected on {self.port}",
                        )
                    break

                if not raw_line:
                    continue

                self._last_heartbeat_time = time.time()

                try:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                except Exception:
                    continue

                if not line:
                    continue

                if line.startswith("EVT:"):
                    event = self._parse_evt(line)
                    if event:
                        self.status.events_count += 1
                        self.status.last_event_time = time.time()
                        evt_type = event.get("type", "event")
                        self._last_success = f"Received {evt_type} at {time.strftime('%H:%M:%S')}"
                        await self.output_queue.put(event)

                elif line.startswith("STATUS:"):
                    msg = line[7:].strip()
                    self._last_success = f"ESP32 status: {msg}"
                    await self._emit_status(f"ESP32: {msg}", "info")

                elif line.startswith("FALSE") or line.startswith("ERROR=") or "ERROR=" in line or "STATE=HALTED" in line:
                    await self._handle_board_error(line)

        except asyncio.CancelledError:
            pass
        finally:
            self.status.connected = False

    async def _handle_board_error(self, line: str) -> None:
        """Parses board error lines (FALSE ..., ERROR=...) and surfaces them via ErrorManager."""
        step = "board_operation"
        m_step = re.search(r"STEP=([a-zA-Z0-9_\-]+)", line)
        if m_step:
            step = m_step.group(1)

        m_err = re.search(r"ERROR=([a-zA-Z0-9_\-]+)", line)
        err_code = m_err.group(1) if m_err else line

        self.status.connected = False
        self.status.error_message = f"ESP error: {err_code}"

        if self.error_mgr and not self._stopping:
            await self.error_mgr.record(
                agent="ESP32",
                step=f"board_{step}",
                message=f"ESP32 reported failure: {line}",
                last_success=self._last_success or f"Connected on {self.port}",
                error_type="BoardError",
            )

    @staticmethod
    def _parse_evt(line: str) -> dict[str, Any] | None:
        """Parse an EVT: line into a raw dict."""
        body = line[4:].strip()
        if not body:
            return None

        if "|" in body:
            parts = body.split("|")
            evt_type = parts[0].strip().lower()
            tokens = parts[1:]
        else:
            tokens_raw = body.split()
            if not tokens_raw:
                return None
            evt_type = tokens_raw[0].strip().lower()
            tokens = tokens_raw[1:]

        data: dict[str, Any] = {
            "_source": "esp32",
            "type": evt_type,
        }

        key_map = {
            "mac": "mac",
            "rssi": "rssi",
            "ch": "channel",
            "chan": "channel",
            "channel": "channel",
            "ssid": "ssid",
            "bssid": "bssid",
            "src": "src",
            "dst": "dst",
            "reason": "reason",
            "first_seen": "first_seen",
            "total_frames": "total_frames",
            "unique_macs": "unique_macs",
            "uptime": "uptime",
            "frames": "frames",
            "macs": "macs",
            "dropped": "dropped",
            "scanning": "scanning",
        }

        for token in tokens:
            delimiter = "=" if "=" in token else (":" if ":" in token else None)
            if not delimiter:
                continue
            key, _, value = token.partition(delimiter)
            if key.upper() == "MAC" and delimiter == ":":
                mac_val = token[len("MAC:"):]
                data["mac"] = mac_val.strip()
                continue
            key = key.strip().lower()
            value = value.strip()
            mapped = key_map.get(key, key)
            data[mapped] = value

        return data

    async def _emit_status(self, message: str, level: str = "info") -> None:
        await self.output_queue.put({
            "_source": "status",
            "agent": "ESP32",
            "message": message,
            "level": level,
        })
