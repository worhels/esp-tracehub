"""ESP32 UART agent that reads structured events from the Wi-Fi sniffer."""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Any

from .error_manager import ErrorManager
from .models import AgentStatus
from .pcap_writer import PcapWriter


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
        self._board_ready = asyncio.Event()
        self._serial: Any = None
        self._stopping = False
        self._last_success: str = ""
        self._last_heartbeat_time: float = 0.0
        self._last_step_context: str = ""
        self.paused: bool = False
        self.discarded_count: int = 0
        self._raw_capture_writer: PcapWriter | None = None
        self._raw_capture_stopped = asyncio.Event()



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
                lambda: _serial.Serial(self.port, self.baudrate, timeout=1, write_timeout=2),
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

        self._board_ready.clear()
        self._task = asyncio.create_task(self._read_loop())
        try:
            await asyncio.wait_for(self._board_ready.wait(), timeout=4.0)
        except TimeoutError:
            await self._emit_status("ESP32 ready banner not received; sending scan command anyway", "warning")

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
            if self._task:
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            if ser is not None and getattr(ser, "is_open", False):
                ser.close()
            self._serial = None
            return

        self._heartbeat_task = asyncio.create_task(self._heartbeat_watchdog())

    async def stop(self) -> None:
        if self._raw_capture_writer is not None:
            try:
                await self.stop_raw_capture()
            except Exception:
                self._close_raw_capture()
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
        self._close_raw_capture()

    async def start_raw_capture(self, channel: int, bssid: str, path: Path) -> None:
        if self._serial is None or not getattr(self._serial, "is_open", False):
            raise RuntimeError("ESP32 serial connection is not open")
        if not 1 <= channel <= 13:
            raise ValueError("ESP32 raw capture supports channels 1 through 13")
        normalized_bssid = bssid.upper()
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", normalized_bssid):
            raise ValueError("Invalid BSSID")
        if self._raw_capture_writer is not None:
            raise RuntimeError("ESP32 raw capture is already active")

        writer = PcapWriter(path)
        self._raw_capture_writer = writer
        try:
            loop = asyncio.get_running_loop()
            command = f"wifi-raw-start {channel} {normalized_bssid}\r\n".encode("ascii")
            await loop.run_in_executor(None, lambda: self._serial.write(command))
        except Exception:
            self._close_raw_capture()
            raise
        await self._emit_status(
            f"Raw 802.11 capture started for {normalized_bssid} on channel {channel}; PCAP: {path}",
            "info",
        )

    async def stop_raw_capture(self) -> Path | None:
        writer = self._raw_capture_writer
        if writer is None:
            return None
        ser = self._serial
        if ser is not None and getattr(ser, "is_open", False):
            loop = asyncio.get_running_loop()
            self._raw_capture_stopped.clear()
            await loop.run_in_executor(None, lambda: ser.write(b"wifi-raw-stop\r\n"))
            try:
                await asyncio.wait_for(self._raw_capture_stopped.wait(), timeout=5.0)
            except TimeoutError:
                pass
        path = writer.path
        count = writer.frames_written
        self._close_raw_capture()
        await self._emit_status(f"Raw capture saved: {path} ({count} frames)", "info")
        return path

    def _close_raw_capture(self) -> None:
        if self._raw_capture_writer is not None:
            self._raw_capture_writer.close()
            self._raw_capture_writer = None

    def pause(self) -> None:
        self.paused = True

    def resume(self) -> None:
        self.paused = False
        self._last_heartbeat_time = time.time()
        self.discarded_count = 0



    async def _heartbeat_watchdog(self) -> None:
        """Monitors heartbeat from ESP32. If silent for >6s, triggers runtime error."""
        try:
            while not self._stopping and self.status.connected:
                await asyncio.sleep(1.0)
                if not self.status.connected or self._stopping:
                    break

                if self.paused:
                    continue

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

                try:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                except Exception:
                    continue

                if not line:
                    continue

                if line.startswith("ESP-LAB ") and " READY" in line:
                    self._board_ready.set()
                    self._last_success = "Received ESP32 firmware ready banner"
                    await self._emit_status("ESP32 firmware ready", "info")
                    continue

                m_step_ctx = re.search(r"STEP=([a-zA-Z0-9_\-]+)", line)
                if m_step_ctx and m_step_ctx.group(1).lower() != "none":
                    self._last_step_context = m_step_ctx.group(1)

                if line.startswith("TRUE") or line.startswith("CANCELLED"):
                    self._last_step_context = ""

                if line.startswith("EVT:"):
                    if line.startswith("EVT:RAW "):
                        self._handle_raw_frame(line)
                        continue
                    event = self._parse_evt(line)
                    if event:
                        self.status.events_count += 1
                        self.status.last_event_time = time.time()
                        evt_type = event.get("type", "event")
                        if evt_type == "heartbeat":
                            self._last_heartbeat_time = time.time()
                        if self.paused:
                            self.discarded_count += 1
                            continue
                        self._last_success = f"Received {evt_type} at {time.strftime('%H:%M:%S')}"
                        await self.output_queue.put(event)

                elif line.startswith("STATUS:"):
                    msg = line[7:].strip()
                    if msg.lower() == "raw capture stopped":
                        self._raw_capture_stopped.set()
                    self._last_success = f"ESP32 status: {msg}"
                    await self._emit_status(f"ESP32: {msg}", "info")

                elif line.startswith("FALSE") or line.startswith("ERROR=") or "ERROR=" in line or "STATE=HALTED" in line:
                    await self._handle_board_error(line)

        except asyncio.CancelledError:
            pass
        finally:
            self.status.connected = False

    def _handle_raw_frame(self, line: str) -> None:
        writer = self._raw_capture_writer
        if writer is None:
            return
        if self.paused:
            self.discarded_count += 1
            return
        match = re.fullmatch(r"EVT:RAW CHAN=(\d+) RSSI=(-?\d+) LEN=(\d+) HEX=([0-9A-Fa-f]+)", line)
        if match is None:
            return
        try:
            channel = int(match.group(1))
            rssi = int(match.group(2))
            length = int(match.group(3))
            frame = bytes.fromhex(match.group(4))
            if not 1 <= channel <= 13 or length != len(frame) or length < 24:
                return
            writer.write_frame(frame, channel, rssi)
        except (ValueError, OSError):
            return

    async def _handle_board_error(self, line: str) -> None:
        """Parses board error lines (FALSE ..., ERROR=...) and surfaces them via ErrorManager."""
        step = "board_operation"
        m_step = re.search(r"STEP=([a-zA-Z0-9_\-]+)", line)
        if m_step:
            step = m_step.group(1)
        elif self._last_step_context:
            step = self._last_step_context

        self._last_step_context = ""

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
            "status": "status",
            "len": "length",
            "length": "length",
            "dir": "direction",
            "protected": "protected",
            "retry": "retry",
            "seq": "sequence",
            "subtype": "subtype",
            "tid": "qos_tid",
            "pm": "power_save",
            "first_seen": "first_seen",
            "total_frames": "total_frames",
            "unique_macs": "unique_macs",
            "uptime": "uptime",
            "frames": "frames",
            "macs": "macs",
            "dropped": "dropped",
            "scanning": "scanning",
        }

        for index, token in enumerate(tokens):
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
            if mapped == "ssid" and index + 1 < len(tokens):
                value = " ".join([value, *tokens[index + 1:]])
                value = value.strip('"')
            data[mapped] = value

        return data

    async def _emit_status(self, message: str, level: str = "info") -> None:
        if self.paused:
            return
        await self.output_queue.put({
            "_source": "status",
            "agent": "ESP32",
            "message": message,
            "level": level,
        })
