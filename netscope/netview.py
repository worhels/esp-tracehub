"""NETSCOPE TUI — main Textual application.

Displays a live event stream with coloured source labels, status indicators,
an error overlay with interactive recovery, and a stats sidebar.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
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
    width: 32;
    height: 100%;
    border-left: thick $accent;
    padding: 1;
}

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

    async def _retry_esp(self) -> None:
        """Retry only the ESP32 connection and sniffer."""
        if self.esp_agent:
            await self.esp_agent.stop()
        self.esp_agent = ESPAgent(
            self.event_engine.input_queue,
            error_mgr=self.error_mgr,
            port=self.esp_port,
            disabled=self.no_esp,
        )
        try:
            await self.esp_agent.start()
            self._log_write(f"[green]✓ ESP32 retry started on {self.esp_port}[/green]")
        except Exception as exc:
            await self.error_mgr.record("ESP32", "retry_start", exc)

    async def _retry_tshark(self) -> None:
        """Retry only the TShark capture agent."""
        if self.capture_agent:
            await self.capture_agent.stop()
        self.capture_agent = CaptureAgent(
            self.event_engine.input_queue,
            error_mgr=self.error_mgr,
            interface=self.tshark_interface,
            disabled=self.no_tshark,
        )
        try:
            await self.capture_agent.start()
            self._log_write("[green]✓ TShark capture retry started[/green]")
        except Exception as exc:
            await self.error_mgr.record("TShark", "retry_start", exc)

    async def _retry_system(self) -> None:
        """Retry only the local system agent."""
        if self.system_agent:
            await self.system_agent.stop()
        self.system_agent = SystemAgent(self.event_engine.input_queue, error_mgr=self.error_mgr)
        try:
            await self.system_agent.start()
            self._log_write("[green]✓ System agent retry started[/green]")
        except Exception as exc:
            await self.error_mgr.record("System", "retry_start", exc)

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
                try:
                    event = await asyncio.wait_for(
                        self.event_engine.output_queue.get(), timeout=0.3
                    )
                except TimeoutError:
                    continue

                self._events.append(event)
                self.total_events = len(self._events)


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


                prev_paused = self.paused
                self.paused = True
                self._log_write(f"[bold red]⛔ HALTED: Error in [{error.agent}] at step '{error.step}'[/bold red]")

                result = await self.push_screen_wait(
                    ErrorOverlay(error, self.error_mgr)
                )

                if result == "quit":
                    self.exit()
                elif result == "retry":
                    self._log_write(f"[yellow]⟳ Retrying [{error.agent}] (step: {error.step})…[/yellow]")
                    if error.agent == "ESP32":
                        await self._retry_esp()
                    elif error.agent == "TShark":
                        await self._retry_tshark()
                    elif error.agent == "System":
                        await self._retry_system()
                    else:
                        self._log_write(f"[yellow]No isolated retry procedure for '{error.agent}'.[/yellow]")
                    self.paused = prev_paused
                elif result == "dismiss":
                    self.paused = prev_paused
                    self._log_write(f"[dim]Error in [{error.agent}] dismissed by user. Continuing…[/dim]")
                else:
                    self.paused = prev_paused
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
        pause_str = "  [bold red]⏸ PAUSED[/bold red]" if self.paused else ""
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
        except NoMatches:
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
        self.paused = not self.paused
        state = "PAUSED" if self.paused else "RESUMED"
        self._log_write(f"[yellow]⏸ {state}[/yellow]")
