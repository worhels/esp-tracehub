import asyncio
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netscope.error_manager import ErrorManager
from netscope.esp_agent import ESPAgent
from netscope.capture_agent import CaptureAgent
from netscope.models import Source, NetEvent, AlertLevel
from netscope.netview import NetScopeApp
from netscope.system_agent import SystemAgent


class TestTargeted(unittest.IsolatedAsyncioTestCase):
    async def test_watchdog_real_loop(self):
        error_mgr = ErrorManager()
        queue: asyncio.Queue = asyncio.Queue()
        agent = ESPAgent(output_queue=queue, error_mgr=error_mgr, port="COM3")
        agent.status.connected = True
        agent._last_heartbeat_time = time.time() - 6.5

        mock_serial = MagicMock()
        mock_serial.is_open = True
        agent._serial = mock_serial

        watchdog_task = asyncio.create_task(agent._heartbeat_watchdog())
        for _ in range(25):
            if not agent.status.connected and len(error_mgr.errors) > 0:
                break
            await asyncio.sleep(0.1)

        self.assertFalse(agent.status.connected)
        self.assertEqual(len(error_mgr.errors), 1)
        self.assertEqual(error_mgr.errors[0].step, "heartbeat_watchdog")
        self.assertEqual(error_mgr.errors[0].error_type, "HeartbeatTimeout")

        await agent.stop()
        try:
            await watchdog_task
        except asyncio.CancelledError:
            pass

    async def test_read_loop_heartbeat_vs_beacon(self):
        error_mgr = ErrorManager()
        queue: asyncio.Queue = asyncio.Queue()
        agent = ESPAgent(output_queue=queue, error_mgr=error_mgr, port="COM3")
        agent.status.connected = True
        initial_time = 1000.0
        agent._last_heartbeat_time = initial_time

        beacon_lines = [
            b"EVT:BEACON MAC:AA:BB:CC:DD:EE:FF RSSI:-60 CHAN:1 SSID:TestNet\r\n",
            b"EVT:BEACON MAC:11:22:33:44:55:66 RSSI:-70 CHAN:6 SSID:Other\r\n",
        ]
        b_idx = 0

        def mock_readline_beacon():
            nonlocal b_idx
            if b_idx < len(beacon_lines):
                line = beacon_lines[b_idx]
                b_idx += 1
                return line
            agent._stopping = True
            return b""

        mock_ser = MagicMock()
        mock_ser.readline = mock_readline_beacon
        agent._serial = mock_ser

        await agent._read_loop()
        self.assertEqual(agent._last_heartbeat_time, initial_time)

        agent._stopping = False
        hb_lines = [
            b"EVT:HEARTBEAT SCANNING=1 UPTIME=10 FRAMES=100 MACS=10 DROPPED=0\r\n",
        ]
        h_idx = 0

        def mock_readline_hb():
            nonlocal h_idx
            if h_idx < len(hb_lines):
                line = hb_lines[h_idx]
                h_idx += 1
                return line
            agent._stopping = True
            return b""

        mock_ser.readline = mock_readline_hb
        await agent._read_loop()
        self.assertGreater(agent._last_heartbeat_time, initial_time)

    async def test_read_loop_step_context_correlation(self):
        error_mgr = ErrorManager()
        queue: asyncio.Queue = asyncio.Queue()
        agent = ESPAgent(output_queue=queue, error_mgr=error_mgr, port="COM3")
        agent.status.connected = True

        lines = [
            b"STEP=flash-size REQUIRED_MIB=16\r\n",
            b"FALSE ERROR=flash_smaller_than_required STATE=HALTED; waiting for retry or cancel\r\n",
            b"FALSE ERROR=unspecified STATE=HALTED\r\n",
            b"STEP=usb-host INTERFACE=native-usb-serial-jtag\r\n",
            b"TRUE STATE=PASSED USB_HOST_ACTIVITY=observed\r\n",
            b"FALSE ERROR=after_true STATE=HALTED\r\n",
            b"STEP=flash-size REQUIRED_MIB=16\r\n",
            b"CANCELLED STATE=IDLE\r\n",
            b"FALSE ERROR=after_cancelled STATE=HALTED\r\n",
            b"STATE=IDLE STEP=none REQUIRED_MIB=16\r\n",
            b"FALSE ERROR=after_none STATE=HALTED\r\n",
        ]
        idx = 0

        def mock_readline():
            nonlocal idx
            if idx < len(lines):
                line = lines[idx]
                idx += 1
                return line
            agent._stopping = True
            return b""

        mock_ser = MagicMock()
        mock_ser.readline = mock_readline
        agent._serial = mock_ser

        await agent._read_loop()

        self.assertEqual(len(error_mgr.errors), 5)
        self.assertEqual(error_mgr.errors[0].step, "board_flash-size")
        self.assertEqual(error_mgr.errors[1].step, "board_board_operation")
        self.assertEqual(error_mgr.errors[2].step, "board_board_operation")
        self.assertEqual(error_mgr.errors[3].step, "board_board_operation")
        self.assertEqual(error_mgr.errors[4].step, "board_board_operation")
        self.assertEqual(agent._last_step_context, "")

    async def test_netstat_real_loop(self):
        error_mgr = ErrorManager()
        queue: asyncio.Queue = asyncio.Queue()
        agent = SystemAgent(output_queue=queue, poll_interval=0.01, error_mgr=error_mgr)

        with patch.object(SystemAgent, "_run_netstat", side_effect=RuntimeError("netstat failed: exit code 1")) as mock_ns:
            task = asyncio.create_task(agent._netstat_loop())
            for _ in range(50):
                if agent._netstat_failures >= 3 and agent._netstat_error_reported:
                    break
                await asyncio.sleep(0.01)

            self.assertGreaterEqual(agent._netstat_failures, 3)
            self.assertTrue(agent._netstat_error_reported)
            self.assertEqual(len(error_mgr.errors), 1)
            self.assertEqual(error_mgr.errors[0].step, "netstat_poll")
            self.assertEqual(error_mgr.errors[0].last_success, "None confirmed")

            await asyncio.sleep(0.05)
            self.assertEqual(len(error_mgr.errors), 1)

            mock_ns.side_effect = None
            mock_ns.return_value = "TCP 192.168.1.50:5000 1.2.3.4:443 ESTABLISHED 100\n"
            for _ in range(50):
                if agent._netstat_failures == 0 and not agent._netstat_error_reported:
                    break
                await asyncio.sleep(0.01)

            self.assertEqual(agent._netstat_failures, 0)
            self.assertFalse(agent._netstat_error_reported)
            self.assertIn("netstat poll at", agent._last_netstat_success)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def test_dns_real_loop(self):
        error_mgr = ErrorManager()
        queue: asyncio.Queue = asyncio.Queue()
        agent = SystemAgent(output_queue=queue, poll_interval=0.01, error_mgr=error_mgr)

        with patch.object(SystemAgent, "_run_dns_cache", side_effect=RuntimeError("ipconfig failed: exit code 2")) as mock_dns:
            task = asyncio.create_task(agent._dns_loop())
            for _ in range(50):
                if agent._dns_failures >= 1:
                    break
                await asyncio.sleep(0.01)

            self.assertGreaterEqual(agent._dns_failures, 1)
            status_evts = []
            while not queue.empty():
                status_evts.append(await queue.get())
            self.assertTrue(any("DNS cache baseline error" in e.get("message", "") for e in status_evts))

            for _ in range(50):
                if agent._dns_failures >= 3 and agent._dns_error_reported:
                    break
                await asyncio.sleep(0.01)

            self.assertGreaterEqual(agent._dns_failures, 3)
            self.assertTrue(agent._dns_error_reported)
            dns_errors = [e for e in error_mgr.errors if e.step in ("dns_cache_baseline", "dns_cache_poll")]
            self.assertEqual(len(dns_errors), 1)
            self.assertEqual(dns_errors[0].last_success, "None confirmed")

            await asyncio.sleep(0.05)
            self.assertEqual(len([e for e in error_mgr.errors if e.step in ("dns_cache_baseline", "dns_cache_poll")]), 1)

            mock_dns.side_effect = None
            mock_dns.return_value = "Record Name: example.com\nA (Host) Record: 93.184.216.34\n"
            for _ in range(50):
                if agent._dns_failures == 0 and not agent._dns_error_reported:
                    break
                await asyncio.sleep(0.01)

            self.assertEqual(agent._dns_failures, 0)
            self.assertFalse(agent._dns_error_reported)
            self.assertIn("DNS cache poll at", agent._last_dns_success)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def test_netview_system_agent_wiring(self):
        app = NetScopeApp(no_tshark=True, no_esp=True)
        await app._start_agents()
        self.assertIsNotNone(app.system_agent)
        assert app.system_agent is not None
        self.assertIs(app.system_agent.error_mgr, app.error_mgr)
        assert app.system_agent.error_mgr is not None

        await app.system_agent.error_mgr.record(
            agent="System",
            step="netstat_poll",
            message="Simulated netstat failure",
        )
        self.assertFalse(app.error_mgr.error_queue.empty())
        queued_err = await app.error_mgr.error_queue.get()
        self.assertEqual(queued_err.agent, "System")
        self.assertEqual(queued_err.step, "netstat_poll")

        await app._retry_system()
        self.assertIsNotNone(app.system_agent)
        assert app.system_agent is not None
        self.assertIs(app.system_agent.error_mgr, app.error_mgr)

        await app._stop_agents()

    async def test_pause_session_drain_and_no_queue_growth(self):
        app = NetScopeApp(no_tshark=True, no_esp=True)
        await app._start_agents()

        ev = NetEvent(source=Source.PC, who="test", where="test", what="test", alert_level=AlertLevel.INFO)
        app._events.append(ev)
        initial_event_count = len(app._events)

        app._pause_session()
        self.assertTrue(app._session_paused)
        self.assertTrue(app.paused)

        app.esp_agent = ESPAgent(app.event_engine.input_queue, error_mgr=app.error_mgr, port="COM3")
        app.esp_agent.paused = True
        app.esp_agent.status.connected = True

        esp_lines = [
            b"EVT:BEACON MAC:AA:BB:CC:DD:EE:FF RSSI:-50 CHAN:1 SSID:TestNet\r\n",
            b"EVT:BEACON MAC:11:22:33:44:55:66 RSSI:-60 CHAN:6 SSID:Other\r\n",
        ]
        esp_idx = 0

        def mock_esp_readline():
            nonlocal esp_idx
            if esp_idx < len(esp_lines):
                line = esp_lines[esp_idx]
                esp_idx += 1
                return line
            app.esp_agent._stopping = True
            return b""

        mock_esp_ser = MagicMock()
        mock_esp_ser.readline = mock_esp_readline
        app.esp_agent._serial = mock_esp_ser

        await app.esp_agent._read_loop()
        self.assertEqual(app.esp_agent.discarded_count, 2)

        app.capture_agent = CaptureAgent(app.event_engine.input_queue, error_mgr=app.error_mgr)
        app.capture_agent._tshark_path = "tshark"
        app.capture_agent.paused = True

        tshark_lines = [
            "0.1|192.168.1.10|1.1.1.1|1234|53|||DNS|query example.com\n",
            "0.2|192.168.1.10|1.1.1.1|1234|53|||DNS|query test.org\n",
        ]
        ts_idx = 0

        def mock_ts_readline():
            nonlocal ts_idx
            if ts_idx < len(tshark_lines):
                line = tshark_lines[ts_idx]
                ts_idx += 1
                return line
            app.capture_agent._stopping = True
            return ""

        mock_proc = MagicMock()
        mock_proc.stdout.readline = mock_ts_readline
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.readline.return_value = ""
        mock_proc.poll.return_value = 0
        mock_proc.wait.return_value = 0

        input_q_size = app.event_engine.input_queue.qsize()
        output_q_size = app.event_engine.output_queue.qsize()

        with patch("subprocess.Popen", return_value=mock_proc):
            await app.capture_agent._capture_loop()
        self.assertEqual(app.capture_agent.discarded_count, 2)

        self.assertEqual(app.event_engine.input_queue.qsize(), input_q_size)
        self.assertEqual(app.event_engine.output_queue.qsize(), output_q_size)
        self.assertEqual(len(app._events), initial_event_count)

        app._resume_session()
        self.assertFalse(app._session_paused)
        self.assertFalse(app.paused)

        await app._stop_agents()

    async def test_retry_failure_leaves_session_halted(self):
        app = NetScopeApp(no_tshark=True, no_esp=False)
        with patch.object(ESPAgent, "start", return_value=None):
            await app._start_agents()

        app._pause_session()
        self.assertTrue(app._session_paused)

        with patch.object(ESPAgent, "start", side_effect=RuntimeError("COM port busy")):
            success = await app._retry_esp()
            self.assertFalse(success)
            self.assertTrue(app._session_paused)
            self.assertTrue(app.paused)

        async def mock_start_connected(self_agent):
            self_agent.status.connected = True

        with patch.object(ESPAgent, "start", mock_start_connected):
            success = await app._retry_esp()
            self.assertTrue(success)
            app._resume_session()
            self.assertFalse(app._session_paused)

        await app._stop_agents()

    async def test_watchdog_resets_on_resume_without_false_timeout(self):
        error_mgr = ErrorManager()
        queue: asyncio.Queue = asyncio.Queue()
        agent = ESPAgent(output_queue=queue, error_mgr=error_mgr, port="COM3")
        agent.status.connected = True
        agent.paused = True
        agent._last_heartbeat_time = time.time() - 10.0

        watchdog_task = asyncio.create_task(agent._heartbeat_watchdog())
        await asyncio.sleep(0.2)

        self.assertEqual(len(error_mgr.errors), 0)
        self.assertTrue(agent.status.connected)

        agent.resume()
        self.assertFalse(agent.paused)
        self.assertGreater(agent._last_heartbeat_time, time.time() - 1.0)

        await asyncio.sleep(0.2)
        self.assertEqual(len(error_mgr.errors), 0)

        await agent.stop()
        try:
            await watchdog_task
        except asyncio.CancelledError:
            pass

    async def test_error_manager_drain_agent_errors(self):
        error_mgr = ErrorManager()
        await error_mgr.record(agent="ESP32", step="step1", message="msg1")
        await error_mgr.record(agent="ESP32", step="step2", message="msg2")
        await error_mgr.record(agent="System", step="step3", message="msg3")

        self.assertEqual(error_mgr.error_queue.qsize(), 3)
        self.assertEqual(len(error_mgr.errors), 3)

        drained = error_mgr.drain_agent_errors("ESP32")
        self.assertEqual(len(drained), 2)
        self.assertTrue(all(e.resolved for e in drained))
        self.assertEqual(error_mgr.error_queue.qsize(), 1)

        remaining_err = await error_mgr.error_queue.get()
        self.assertEqual(remaining_err.agent, "System")
        self.assertEqual(len(error_mgr.errors), 3)

    async def test_warning_does_not_pause_session(self):
        app = NetScopeApp(no_tshark=True, no_esp=True)
        await app._start_agents()
        self.assertFalse(app._session_paused)

        while not app.event_engine.input_queue.empty():
            await app.event_engine.input_queue.get()

        assert app.system_agent is not None
        await app.system_agent._emit_status("transient warning", "warning")

        raw = await asyncio.wait_for(app.event_engine.input_queue.get(), timeout=1.0)
        self.assertEqual(raw.get("level"), "warning")

        self.assertFalse(app._session_paused)
        self.assertTrue(app.error_mgr.error_queue.empty())

        await app._stop_agents()

    async def test_quit_stops_all_agents_and_tasks(self):
        app = NetScopeApp(no_tshark=True, no_esp=True)
        await app._start_agents()

        self.assertTrue(app.system_agent.status.connected)
        await app._stop_agents()

        self.assertFalse(app.system_agent.status.connected)
        self.assertFalse(app.event_engine._running)


if __name__ == "__main__":
    unittest.main()
