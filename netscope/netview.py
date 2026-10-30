"""NETSCOPE TUI — main Textual application.

Displays a live event stream with coloured source labels, status indicators,
an error overlay with interactive recovery, and a stats sidebar.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Footer,
    Header,
    RichLog,
    Static,
)

from . import __version__
from .capture_agent import CaptureAgent
from .error_manager import ErrorManager, ErrorRecord
from .esp_agent import ESPAgent
from .event_engine import EventEngine
from .export import export_json, export_txt
from .models import AgentStatus, NetEvent
from .system_agent import SystemAgent



NETSCOPE_CSS = """
Screen {
    layout: horizontal;
}

#main-panel {
    width: 1fr;
    height: 100%;
}

#sidebar {
    width: 38;
    height: 100%;
    border-left: thick $accent;
    padding: 1;
    overflow-y: auto;
}

#router-groups { height: 3; }
#router-list { height: 1fr; border: round $primary; padding: 0 1; }
.router-button { width: 100%; height: auto; min-height: 3; margin-bottom: 1; content-align: left middle; }
#router-hint { height: auto; color: $text-muted; margin-bottom: 1; }
RouterDetails { align: center middle; }
#router-details { width: 72; height: auto; max-height: 85%; border: thick $accent; background: $surface; padding: 1 2; }
#router-detail-body { height: auto; max-height: 1fr; margin: 1 0; }
#router-detail-events { height: 12; border: round $primary; }
#router-detail-actions { height: 3; }

#status-bar {
    dock: bottom;
    height: 3;
    padding: 0 1;
    background: $surface;
    border-top: solid $accent;
}

#event-log {
    height: 1fr;
    border: solid $primary;
    padding: 0 1;
}

#title-bar {
    dock: top;
    height: 3;
    padding: 0 1;
    background: $primary;
    color: $text;
    text-align: center;
}

.stat-label {
    margin-bottom: 1;
}

.stat-value {
    color: $accent;
    text-style: bold;
}

.section-title {
    text-style: bold underline;
    margin-bottom: 1;
    color: $secondary;
}

#source-indicators {
    height: 3;
    padding: 0 1;
    background: $surface;
    border-bottom: solid $accent;
}



ErrorOverlay {
    align: center middle;
}

#error-container {
    width: 70;
    height: auto;
    max-height: 80%;
    border: thick $error;
    background: $surface;
    padding: 1 2;
}

#error-title {
    text-style: bold;
    color: $error;
    text-align: center;
    margin-bottom: 1;
}

#error-body {
    height: auto;
    max-height: 50%;
    margin-bottom: 1;
}

#error-actions {
    text-align: center;
    color: $warning;
    text-style: bold;
}
"""


@dataclass
class AccessPoint:
    bssid: str
    ssid: str
    channel: str
    rssi: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    observations: int = 0
    data_frames: int = 0
    clients: set[str] = field(default_factory=set)
    recent_events: deque[str] = field(default_factory=lambda: deque(maxlen=20))


def _safe_text(value: object, limit: int = 48) -> str:
    text = str(value)
    text = "".join(char if char.isprintable() else "�" for char in text)
    return text[:limit] or "(hidden SSID)"


class RouterDetails(ModalScreen[str]):
    BINDINGS = [Binding("escape", "close", "Close", show=True)]

    def __init__(self, ap: AccessPoint, is_home: bool, capture_active: bool = False) -> None:
        super().__init__()
        self.ap = ap
        self.is_home = is_home
        self.capture_active = capture_active

    def compose(self) -> ComposeResult:
        with Vertical(id="router-details"):
            yield Static("Wi-Fi access point", classes="section-title")
            yield Static(self._description(), id="router-detail-body", markup=False)
            yield RichLog(id="router-detail-events", markup=False, wrap=True, max_lines=20)
            if self.is_home and self.capture_active:
                yield Button("Stop raw PCAP capture", id="router-capture-stop", variant="error")
            elif self.is_home:
                yield Button("Start raw PCAP capture", id="router-capture-start", variant="success")
            else:
                yield Static("Raw capture is limited to the AP marked as My router.")
            yield Button("Remove from My router" if self.is_home else "Set as My router", id="router-home-toggle", variant="primary")
            yield Button("Close", id="router-close")

    def _description(self) -> str:
        return (
            f"SSID: {_safe_text(self.ap.ssid)}\nBSSID: {self.ap.bssid}\n"
            f"Channel: {self.ap.channel}   Latest RSSI: {self.ap.rssi} dBm\n"
            f"AP advertisements: {self.ap.observations}   Sampled data frames: {self.ap.data_frames}\n"
            f"Heard client addresses: {len(self.ap.clients)}\n"
            f"First seen: {time.strftime('%H:%M:%S', time.localtime(self.ap.first_seen))}\n\n"
            "ESP32 sees this access point over the air. This does not prove a device is connected to your router."
        )

    def on_mount(self) -> None:
        log = self.query_one("#router-detail-events", RichLog)
        if self.ap.recent_events:
            for line in self.ap.recent_events:
                log.write(line)
        else:
            log.write("Waiting for ESP32 observations…")

    def add_event(self, event: NetEvent) -> None:
        raw = event.raw_data
        mac = str(raw.get("mac", "")).upper()
        bssid = str(raw.get("bssid", "")).upper()
        if mac != self.ap.bssid and bssid != self.ap.bssid:
            return
        if event.source.value != "ESP32":
            return
        try:
            self.query_one("#router-detail-events", RichLog).write(event.export_line())
            self.query_one("#router-detail-body", Static).update(self._description())
        except NoMatches:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "router-capture-start":
            self.dismiss("start-capture")
        elif event.button.id == "router-capture-stop":
            self.dismiss("stop-capture")
        elif event.button.id == "router-home-toggle":
            self.dismiss("unset-home" if self.is_home else "set-home")
        elif event.button.id == "router-close":
            self.dismiss("close")

    def action_close(self) -> None:
        self.dismiss("close")





class ErrorOverlay(ModalScreen[str]):
    """Modal screen that shows an error and offers R/D/Q actions."""

    BINDINGS = [
        Binding("r", "retry", "Retry", show=True),
        Binding("d", "diagnostics", "Diagnostics", show=True),
        Binding("q", "quit_app", "Quit", show=True),
        Binding("escape", "dismiss_error", "Dismiss", show=True),
    ]

    def __init__(self, error: ErrorRecord, error_mgr: ErrorManager) -> None:
        super().__init__()
        self.error = error
        self.error_mgr = error_mgr

    def compose(self) -> ComposeResult:
        with Vertical(id="error-container"):
            yield Static("⛔  NETSCOPE HALTED — RUNTIME ERROR  ⛔", id="error-title")
            yield Static(self._format_error(), id="error-body")
            yield Static(
                "[R] Retry step   [D] Diagnostics   [Esc] Dismiss   [Q] Quit",
                id="error-actions",
            )

    def _format_error(self) -> str:
        e = self.error
        lines = [
            f"Source:   [{e.agent}]",
            f"Stage:    {e.step}",
            f"Type:     {e.error_type}",
            f"Details:  {e.message}",
            f"Last OK:  {e.last_success or 'None confirmed'}",
        ]
        if e.traceback_str:
            lines.append("")
            lines.append("Traceback (last 4 lines):")
            for tb in e.traceback_str.splitlines()[-4:]:
                lines.append(f"  {tb}")
        return "\n".join(lines)

    def action_retry(self) -> None:
        self.error.resolved = True
        self.dismiss("retry")

    def action_diagnostics(self) -> None:

        try:
            body = self.query_one("#error-body", Static)
            body.update(self.error_mgr.diagnostics())
        except NoMatches:
            pass

    def action_quit_app(self) -> None:
        self.error.resolved = True
        self.dismiss("quit")

    def action_dismiss_error(self) -> None:
        self.error.resolved = True
        self.dismiss("dismiss")





class NetScopeApp(App):
    """The NETSCOPE real-time network monitoring TUI."""

    TITLE = "NETSCOPE"
    SUB_TITLE = f"v{__version__} — Real-time Network Monitor"
    CSS = NETSCOPE_CSS

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("e", "export_txt", "Export TXT", show=True),
        Binding("j", "export_json", "Export JSON", show=True),
        Binding("c", "clear_log", "Clear Log", show=True),
        Binding("p", "pause_resume", "Pause/Resume", show=True),
    ]


    total_events: reactive[int] = reactive(0)
    unique_ips: reactive[int] = reactive(0)
    unique_macs: reactive[int] = reactive(0)
    paused: reactive[bool] = reactive(False)

    def __init__(
        self,
        esp_port: str = "COM3",
        no_tshark: bool = False,
        no_esp: bool = False,
        export_dir: str = ".",
        tshark_interface: str | None = None,
    ) -> None:
        super().__init__()
        self.esp_port = esp_port
        self.no_tshark = no_tshark
        self.no_esp = no_esp
        self.export_dir = Path(export_dir)
        self.tshark_interface = tshark_interface


        self._events: list[NetEvent] = []
        self._ip_set: set[str] = set()
        self._mac_set: set[str] = set()
        self._start_time = time.time()


        self.error_mgr = ErrorManager()
        self.event_engine = EventEngine()
        self.capture_agent: CaptureAgent | None = None
        self.system_agent: SystemAgent | None = None
        self.esp_agent: ESPAgent | None = None
        self._session_paused: bool = False
        self._pause_start_time: float | None = None
        self._paused_discarded_count: int = 0
        self._access_points: dict[str, AccessPoint] = {}
        self._router_group = "others"
        self._home_bssid = self._load_home_bssid()
        self._raw_capture_bssid: str | None = None
        self._router_list_dirty = False



    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="main-panel"):
                yield Static(self._build_indicators(), id="source-indicators")
                yield RichLog(
                    id="event-log",
                    highlight=True,
                    markup=True,
                    max_lines=2000,
                    wrap=True,
                )
                yield Static(self._build_status_bar(), id="status-bar")
            with Vertical(id="sidebar"):
                yield Static("[b u]📡 Wi-Fi access points[/b u]", classes="section-title")
                with Horizontal(id="router-groups"):
                    yield Button("My router", id="router-group-home", compact=True)
                    yield Button("Others", id="router-group-others", compact=True, variant="primary")
                yield Static("Click a point to open its live event feed.", id="router-hint")
                with VerticalScroll(id="router-list"):
                    yield Static("Waiting for ESP32 access-point frames…", id="router-empty")
                yield Static("[b u]📊 Statistics[/b u]", classes="section-title")
                yield Static("Events: 0", id="stat-events", classes="stat-label")
                yield Static("IPs: 0", id="stat-ips", classes="stat-label")
                yield Static("MACs: 0", id="stat-macs", classes="stat-label")
                yield Static("Uptime: 0s", id="stat-uptime", classes="stat-label")
                yield Static("", id="stat-spacer")
                yield Static("[b u]🔌 Sources[/b u]", classes="section-title")
                yield Static("● PC: starting…", id="src-pc", classes="stat-label")
                yield Static("● ESP32: --", id="src-esp", classes="stat-label")
                yield Static("● TShark: --", id="src-tshark", classes="stat-label")
        yield Footer()



    async def on_mount(self) -> None:
        self._log_write(f"[bold cyan]NETSCOPE[/bold cyan] v{__version__} started")
        self._log_write("Press [bold]Q[/bold]=Quit  [bold]E[/bold]=Export TXT  [bold]J[/bold]=Export JSON  [bold]C[/bold]=Clear  [bold]P[/bold]=Pause")
        self._log_write("─" * 60)


        await self._start_agents()


        self._event_consumer_task = asyncio.create_task(self._consume_events())
        self._error_watcher_task = asyncio.create_task(self._watch_errors())
        self._stats_updater = self.set_interval(1.0, self._update_stats)
        self._router_updater = self.set_interval(1.0, self._refresh_router_list)

    async def on_unmount(self) -> None:
        await self._stop_agents()
        for t in (self._event_consumer_task, self._error_watcher_task):
            if t and not t.done():
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass



    async def _start_agents(self) -> None:
        raw_q = self.event_engine.input_queue


        await self.event_engine.start()


        self.system_agent = SystemAgent(raw_q, error_mgr=self.error_mgr)
        try:
            await self.system_agent.start()
        except Exception as exc:
            await self.error_mgr.record("System", "start", exc)


        self.capture_agent = CaptureAgent(
            raw_q,
            error_mgr=self.error_mgr,
            interface=self.tshark_interface,
            disabled=self.no_tshark,
        )
        try:
            await self.capture_agent.start()
        except Exception as exc:
            await self.error_mgr.record("TShark", "start", exc)


        self.esp_agent = ESPAgent(
            raw_q,
            error_mgr=self.error_mgr,
            port=self.esp_port,
            disabled=self.no_esp,
        )
        try:
            await self.esp_agent.start()
        except Exception as exc:
            await self.error_mgr.record("ESP32", "start", exc)

    async def _retry_esp(self) -> bool:
        """Retry only the ESP32 connection and sniffer."""
        if self.esp_agent:
            await self.esp_agent.stop()
        self.esp_agent = ESPAgent(
            self.event_engine.input_queue,
            error_mgr=self.error_mgr,
            port=self.esp_port,
            disabled=self.no_esp,
        )
        self.esp_agent.paused = self._session_paused
        try:
            await self.esp_agent.start()
            if not self.esp_agent.status.connected:
                return False
            self._log_write(f"[green]✓ ESP32 retry started on {self.esp_port}[/green]")
            return True
        except Exception as exc:
            await self.error_mgr.record("ESP32", "retry_start", exc)
            return False

    async def _retry_tshark(self) -> bool:
        """Retry only the TShark capture agent."""
        if self.capture_agent:
            await self.capture_agent.stop()
        self.capture_agent = CaptureAgent(
            self.event_engine.input_queue,
            error_mgr=self.error_mgr,
            interface=self.tshark_interface,
            disabled=self.no_tshark,
        )
        self.capture_agent.paused = self._session_paused
        try:
            await self.capture_agent.start()
            if not self.capture_agent.status.connected:
                return False
            self._log_write("[green]✓ TShark capture retry started[/green]")
            return True
        except Exception as exc:
            await self.error_mgr.record("TShark", "retry_start", exc)
            return False

    async def _retry_system(self) -> bool:
        """Retry only the local system agent."""
        if self.system_agent:
            await self.system_agent.stop()
        self.system_agent = SystemAgent(self.event_engine.input_queue, error_mgr=self.error_mgr)
        self.system_agent.paused = self._session_paused
        try:
            await self.system_agent.start()
            if not self.system_agent.status.connected:
                return False
            self._log_write("[green]✓ System agent retry started[/green]")
            return True
        except Exception as exc:
            await self.error_mgr.record("System", "retry_start", exc)
            return False

    def _pause_session(self) -> None:
        if self._session_paused:
            return
        self._session_paused = True
        self._pause_start_time = time.time()
        self.paused = True
        self._paused_discarded_count = 0
        for agent in (self.esp_agent, self.capture_agent, self.system_agent):
            if agent:
                agent.pause()
        if self.event_engine:
            self.event_engine.pause()

    def _resume_session(self) -> None:
        if not self._session_paused:
            return
        self._session_paused = False
        pause_start = self._pause_start_time or time.time()
        pause_duration = max(0, int(time.time() - pause_start))
        total_discarded = self._paused_discarded_count
        for agent in (self.esp_agent, self.capture_agent, self.system_agent):
            if agent:
                total_discarded += getattr(agent, "discarded_count", 0)
                agent.resume()
        if self.event_engine:
            total_discarded += self.event_engine.discarded_count
            self.event_engine.resume()
        self.paused = False
        start_str = time.strftime("%H:%M:%S", time.localtime(pause_start))
        now_str = time.strftime("%H:%M:%S")
        self._log_write(
            f"[yellow]▶ Resumed session (paused {start_str} -> {now_str}, "
            f"duration {pause_duration}s, {total_discarded} events discarded)[/yellow]"
        )

    async def _stop_agents(self) -> None:
        for agent in (self.capture_agent, self.system_agent, self.esp_agent):
            if agent:
                try:
                    await agent.stop()
                except Exception:
                    pass
        await self.event_engine.stop()



    async def _consume_events(self) -> None:
        """Read NetEvents from the engine's output queue and display them."""
        try:
            while True:
                if self._session_paused:
                    await asyncio.sleep(0.1)
                    continue
                try:
                    event = await asyncio.wait_for(
                        self.event_engine.output_queue.get(), timeout=0.3
                    )
                except TimeoutError:
                    continue

                if self._session_paused:
                    self._paused_discarded_count += 1
                    continue

                self._events.append(event)
                self.total_events = len(self._events)
                self._record_access_point(event)
                if isinstance(self.screen, RouterDetails):
                    self.screen.add_event(event)


                for addr in (event.who, event.where):
                    if self._looks_like_ip(addr):
                        self._ip_set.add(addr)
                    if self._looks_like_mac(addr):
                        self._mac_set.add(addr)
                self.unique_ips = len(self._ip_set)
                self.unique_macs = len(self._mac_set)

                if not self.paused:
                    self._log_write(event.one_line())
        except asyncio.CancelledError:
            pass



    async def _watch_errors(self) -> None:
        """Watch for errors and show modal overlay."""
        try:
            while True:
                try:
                    error = await asyncio.wait_for(
                        self.error_mgr.error_queue.get(), timeout=0.5
                    )
                except TimeoutError:
                    continue


                self._pause_session()
                self._log_write(f"[bold red]⛔ HALTED: Error in [{error.agent}] at step '{error.step}'[/bold red]")

                result = await self.push_screen_wait(
                    ErrorOverlay(error, self.error_mgr)
                )

                if result == "quit":
                    await self._stop_agents()
                    self.exit()
                elif result == "retry":
                    self.error_mgr.drain_agent_errors(error.agent)
                    self._log_write(f"[yellow]⟳ Retrying [{error.agent}] (step: {error.step})…[/yellow]")
                    success = False
                    if error.agent == "ESP32":
                        success = await self._retry_esp()
                    elif error.agent == "TShark":
                        success = await self._retry_tshark()
                    elif error.agent == "System":
                        success = await self._retry_system()
                    else:
                        self._log_write(f"[yellow]No isolated retry procedure for '{error.agent}'.[/yellow]")

                    if success:
                        self._resume_session()
                    else:
                        self._log_write(f"[bold red]✖ Retry failed for [{error.agent}]. Session remains HALTED.[/bold red]")
                elif result == "dismiss":
                    self.error_mgr.drain_agent_errors(error.agent)
                    self._log_write(f"[dim]Error in [{error.agent}] dismissed by user. Continuing…[/dim]")
                    self._resume_session()
                else:
                    self._resume_session()
        except asyncio.CancelledError:
            pass



    def _update_stats(self) -> None:
        uptime = int(time.time() - self._start_time)
        m, s = divmod(uptime, 60)
        h, m = divmod(m, 60)
        uptime_str = f"{h}h {m:02d}m {s:02d}s" if h else f"{m}m {s:02d}s"

        try:
            self.query_one("#stat-events", Static).update(
                f"[b]Events:[/b] [bright_cyan]{self.total_events}[/bright_cyan]"
            )
            self.query_one("#stat-ips", Static).update(
                f"[b]IPs:[/b] [bright_green]{self.unique_ips}[/bright_green]"
            )
            self.query_one("#stat-macs", Static).update(
                f"[b]MACs:[/b] [bright_magenta]{self.unique_macs}[/bright_magenta]"
            )
            self.query_one("#stat-uptime", Static).update(
                f"[b]Uptime:[/b] {uptime_str}"
            )


            pc_status = self._agent_indicator(self.system_agent)
            esp_status = self._agent_indicator(self.esp_agent)
            tshark_status = self._agent_indicator(self.capture_agent)
            self.query_one("#src-pc", Static).update(f"● PC: {pc_status}")
            self.query_one("#src-esp", Static).update(f"● ESP32: {esp_status}")
            self.query_one("#src-tshark", Static).update(f"● TShark: {tshark_status}")


            self.query_one("#source-indicators", Static).update(
                self._build_indicators()
            )


            self.query_one("#status-bar", Static).update(self._build_status_bar())
        except NoMatches:
            pass

    @staticmethod
    def _home_file() -> Path:
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "ESP TraceHub" / "home_access_point.json"

    @classmethod
    def _load_home_bssid(cls) -> str | None:
        try:
            value = json.loads(cls._home_file().read_text(encoding="utf-8"))
            bssid = value.get("bssid") if isinstance(value, dict) else None
            if isinstance(bssid, str) and re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", bssid.upper()):
                return bssid.upper()
        except (OSError, ValueError, TypeError):
            pass
        return None

    def _save_home_bssid(self) -> None:
        path = self._home_file()
        try:
            if self._home_bssid:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({"bssid": self._home_bssid}), encoding="utf-8")
            else:
                path.unlink(missing_ok=True)
        except OSError as exc:
            self._log_write(f"[yellow]Could not save My router selection: {exc}[/yellow]")

    def _record_access_point(self, event: NetEvent) -> None:
        raw = event.raw_data
        if event.source.value != "ESP32":
            return
        event_type = str(raw.get("type", "")).lower()
        bssid = str(raw.get("mac", "")).upper()
        if event_type == "data":
            bssid = str(raw.get("bssid", "")).upper()
        if event_type not in {"beacon", "probe_resp", "data"}:
            return
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", bssid):
            return
        ap = self._access_points.get(bssid)
        if event_type == "data":
            if ap is None:
                return
            ap.data_frames += 1
            for address in (str(raw.get("src", "")).upper(), str(raw.get("dst", "")).upper()):
                if address and address != bssid and re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", address):
                    ap.clients.add(address)
            ap.recent_events.append(event.export_line())
            self._router_list_dirty = True
            return
        if ap is None:
            ap = AccessPoint(
                bssid=bssid,
                ssid=_safe_text(raw.get("ssid", "")),
                channel=_safe_text(raw.get("channel", "?"), 8),
                rssi=_safe_text(raw.get("rssi", "?"), 8),
                first_seen=event.timestamp,
            )
            self._access_points[bssid] = ap
        ap.ssid = _safe_text(raw.get("ssid", ap.ssid))
        ap.channel = _safe_text(raw.get("channel", ap.channel), 8)
        ap.rssi = _safe_text(raw.get("rssi", ap.rssi), 8)
        ap.last_seen = event.timestamp
        ap.observations += 1
        ap.recent_events.append(event.export_line())
        self._router_list_dirty = True

    def _refresh_router_list(self) -> None:
        if not self._router_list_dirty:
            return
        try:
            container = self.query_one("#router-list", VerticalScroll)
        except NoMatches:
            return
        self._router_list_dirty = False
        aps = sorted(self._access_points.values(), key=lambda ap: ap.last_seen, reverse=True)
        visible = [ap for ap in aps if (ap.bssid == self._home_bssid) == (self._router_group == "home")]
        widgets: list[Button | Static] = []
        if not visible:
            message = "No router marked yet. Open an access point under Others and set it as My router." if self._router_group == "home" else "No access points observed yet. Check that ESP32 is scanning 2.4 GHz Wi-Fi."
            widgets.append(Static(message, id="router-empty"))
        else:
            for ap in visible:
                label = f"{'★ ' if ap.bssid == self._home_bssid else ''}{ap.ssid}\n{ap.bssid} · ch{ap.channel} · {ap.rssi} dBm · {ap.data_frames} data samples"
                widgets.append(Button(label, id=f"ap-{ap.bssid.replace(':', '')}", classes="router-button", variant="primary" if ap.bssid == self._home_bssid else "default"))

        async def replace_children() -> None:
            await container.remove_children()
            await container.mount(*widgets)

        self.call_later(replace_children)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "router-group-home":
            self._router_group = "home"
        elif button_id == "router-group-others":
            self._router_group = "others"
        elif button_id.startswith("ap-"):
            compact_bssid = button_id[3:]
            bssid = ":".join(compact_bssid[index:index + 2] for index in range(0, 12, 2))
            ap = self._access_points.get(bssid)
            if ap:
                self.push_screen(
                    RouterDetails(ap, bssid == self._home_bssid, bssid == self._raw_capture_bssid),
                    callback=lambda result: self._handle_router_detail_result(bssid, result),
                )
            return
        else:
            return
        self.query_one("#router-group-home", Button).variant = "primary" if self._router_group == "home" else "default"
        self.query_one("#router-group-others", Button).variant = "primary" if self._router_group == "others" else "default"
        self._router_list_dirty = True
        self._refresh_router_list()

    def _handle_router_detail_result(self, bssid: str, result: str | None) -> None:
        if result == "start-capture":
            asyncio.create_task(self._start_raw_capture(bssid))
            return
        if result == "stop-capture":
            asyncio.create_task(self._stop_raw_capture())
            return
        if result == "set-home":
            self._home_bssid = bssid
            self._save_home_bssid()
        elif result == "unset-home":
            self._home_bssid = None
            self._save_home_bssid()
        else:
            return
        self._router_list_dirty = True
        self._refresh_router_list()

    async def _start_raw_capture(self, bssid: str) -> None:
        ap = self._access_points.get(bssid)
        agent = self.esp_agent
        if ap is None or agent is None or not agent.status.connected:
            self._log_write("[bold red]Raw capture failed: ESP32 is not connected or the AP is unavailable.[/bold red]")
            return
        try:
            channel = int(ap.channel)
        except ValueError:
            self._log_write("[bold red]Raw capture failed: the AP channel is unknown.[/bold red]")
            return
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        capture_dir = base / "ESP TraceHub" / "captures"
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        path = capture_dir / f"wifi-{timestamp}-{bssid.replace(':', '')}.pcap"
        try:
            await agent.start_raw_capture(channel, bssid, path)
        except Exception as exc:
            self._log_write(f"[bold red]Raw capture failed: {exc}[/bold red]")
            return
        self._raw_capture_bssid = bssid
        self._log_write(
            f"[bold green]Raw Wi-Fi capture started for {ap.ssid} ({bssid}) on channel {channel}. "
            f"File: {path}[/bold green]"
        )

    async def _stop_raw_capture(self) -> None:
        agent = self.esp_agent
        if agent is None:
            return
        try:
            path = await agent.stop_raw_capture()
        except Exception as exc:
            self._log_write(f"[bold red]Could not stop raw capture: {exc}[/bold red]")
            return
        self._raw_capture_bssid = None
        if path is not None:
            self._log_write(f"[bold green]Raw capture saved to {path}. Open it in Wireshark.[/bold green]")

    def _agent_indicator(self, agent: Any) -> str:
        if agent is None:
            return "[dim]not loaded[/dim]"
        st: AgentStatus = agent.status
        if st.connected:
            return f"[green]active[/green] ({st.events_count})"
        elif st.error_message:
            msg = st.error_message[:30]
            return f"[red]{msg}[/red]"
        else:
            return "[yellow]offline[/yellow]"

    def _build_indicators(self) -> str:
        def dot(agent: Any, label: str) -> str:
            if agent is None:
                return f"[dim]⊘ {label}[/dim]"
            if agent.status.connected:
                return f"[green]● {label}[/green]"
            if agent.status.error_message:
                return f"[red]✖ {label}[/red]"
            return f"[yellow]○ {label}[/yellow]"

        pc = dot(self.system_agent, "PC")
        esp = dot(self.esp_agent, "ESP32")
        ts = dot(self.capture_agent, "TSHARK")
        if self._session_paused:
            pause_str = "  [bold red]⛔ HALTED (events discarded)[/bold red]"
        elif self.paused:
            pause_str = "  [bold red]⏸ PAUSED[/bold red]"
        else:
            pause_str = ""
        return f"  {pc}   {esp}   {ts}{pause_str}"

    def _build_status_bar(self) -> str:
        errors = len(self.error_mgr.unresolved)
        err_str = f"  [red]Errors: {errors}[/red]" if errors else ""
        return (
            f"[dim]Events: {self.total_events} │ "
            f"IPs: {self.unique_ips} │ "
            f"MACs: {self.unique_macs}{err_str}[/dim]"
        )



    def _log_write(self, text: str) -> None:
        try:
            log = self.query_one("#event-log", RichLog)
            log.write(text)
        except Exception:
            pass

    @staticmethod
    def _looks_like_ip(s: str) -> bool:

        parts = s.split(":")
        addr = parts[0] if parts else s
        octets = addr.split(".")
        if len(octets) == 4:
            return all(o.isdigit() for o in octets)
        return False

    @staticmethod
    def _looks_like_mac(s: str) -> bool:
        return s.count(":") == 5 and len(s) == 17



    def action_export_txt(self) -> None:
        if not self._events:
            self._log_write("[yellow]No events to export.[/yellow]")
            return
        try:
            path = export_txt(self._events, self.export_dir)
            self._log_write(f"[green]✔ Exported {len(self._events)} events to {path}[/green]")
        except Exception as exc:
            self._log_write(f"[red]Export failed: {exc}[/red]")

    def action_export_json(self) -> None:
        if not self._events:
            self._log_write("[yellow]No events to export.[/yellow]")
            return
        try:
            path = export_json(self._events, self.export_dir)
            self._log_write(f"[green]✔ Exported {len(self._events)} events to {path}[/green]")
        except Exception as exc:
            self._log_write(f"[red]Export failed: {exc}[/red]")

    def action_clear_log(self) -> None:
        try:
            log = self.query_one("#event-log", RichLog)
            log.clear()
        except NoMatches:
            pass
        self._log_write("[dim]Log cleared[/dim]")

    def action_pause_resume(self) -> None:
        if self._session_paused:
            self._resume_session()
        else:
            self._pause_session()
            self._log_write("[yellow]⏸ PAUSED[/yellow]")
