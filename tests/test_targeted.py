import asyncio
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netscope.error_manager import ErrorManager
from netscope.esp_agent import ESPAgent
from netscope.netview import NetScopeApp
from netscope.system_agent import SystemAgent


async def test_watchdog_real_loop():
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

    assert not agent.status.connected
    assert len(error_mgr.errors) == 1
    assert error_mgr.errors[0].step == "heartbeat_watchdog"
    assert error_mgr.errors[0].error_type == "HeartbeatTimeout"

    await agent.stop()
    try:
        await watchdog_task
    except asyncio.CancelledError:
        pass


async def test_read_loop_heartbeat_vs_beacon():
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
    assert agent._last_heartbeat_time == initial_time

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
    assert agent._last_heartbeat_time > initial_time


async def test_read_loop_step_context_correlation():
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

    assert len(error_mgr.errors) == 5
    assert error_mgr.errors[0].step == "board_flash-size"
    assert error_mgr.errors[1].step == "board_board_operation"
    assert error_mgr.errors[2].step == "board_board_operation"
    assert error_mgr.errors[3].step == "board_board_operation"
    assert error_mgr.errors[4].step == "board_board_operation"
    assert agent._last_step_context == ""


async def test_netstat_real_loop():
    error_mgr = ErrorManager()
    queue: asyncio.Queue = asyncio.Queue()
    agent = SystemAgent(output_queue=queue, poll_interval=0.01, error_mgr=error_mgr)

    with patch.object(SystemAgent, "_run_netstat", side_effect=RuntimeError("netstat failed: exit code 1")) as mock_ns:
        task = asyncio.create_task(agent._netstat_loop())
        for _ in range(50):
            if agent._netstat_failures >= 3 and agent._netstat_error_reported:
                break
            await asyncio.sleep(0.01)

        assert agent._netstat_failures >= 3
        assert agent._netstat_error_reported is True
        assert len(error_mgr.errors) == 1
        assert error_mgr.errors[0].step == "netstat_poll"
        assert error_mgr.errors[0].last_success == "None confirmed"

        await asyncio.sleep(0.05)
        assert len(error_mgr.errors) == 1

        mock_ns.side_effect = None
        mock_ns.return_value = "TCP 192.168.1.50:5000 1.2.3.4:443 ESTABLISHED 100\n"
        for _ in range(50):
            if agent._netstat_failures == 0 and not agent._netstat_error_reported:
                break
            await asyncio.sleep(0.01)

        assert agent._netstat_failures == 0
        assert agent._netstat_error_reported is False
        assert "netstat poll at" in agent._last_netstat_success

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def test_dns_real_loop():
    error_mgr = ErrorManager()
    queue: asyncio.Queue = asyncio.Queue()
    agent = SystemAgent(output_queue=queue, poll_interval=0.01, error_mgr=error_mgr)

    with patch.object(SystemAgent, "_run_dns_cache", side_effect=RuntimeError("ipconfig failed: exit code 2")) as mock_dns:
        task = asyncio.create_task(agent._dns_loop())
        for _ in range(50):
            if agent._dns_failures >= 1:
                break
            await asyncio.sleep(0.01)

        assert agent._dns_failures >= 1
        status_evts = []
        while not queue.empty():
            status_evts.append(await queue.get())
        assert any("DNS cache baseline error" in e.get("message", "") for e in status_evts)

        for _ in range(50):
            if agent._dns_failures >= 3 and agent._dns_error_reported:
                break
            await asyncio.sleep(0.01)

        assert agent._dns_failures >= 3
        assert agent._dns_error_reported is True
        dns_errors = [e for e in error_mgr.errors if e.step in ("dns_cache_baseline", "dns_cache_poll")]
        assert len(dns_errors) == 1
        assert dns_errors[0].last_success == "None confirmed"

        await asyncio.sleep(0.05)
        assert len([e for e in error_mgr.errors if e.step in ("dns_cache_baseline", "dns_cache_poll")]) == 1

        mock_dns.side_effect = None
        mock_dns.return_value = "Record Name: example.com\nA (Host) Record: 93.184.216.34\n"
        for _ in range(50):
            if agent._dns_failures == 0 and not agent._dns_error_reported:
                break
            await asyncio.sleep(0.01)

        assert agent._dns_failures == 0
        assert agent._dns_error_reported is False
        assert "DNS cache poll at" in agent._last_dns_success

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def test_netview_system_agent_wiring():
    app = NetScopeApp(no_tshark=True, no_esp=True)
    await app._start_agents()
    assert app.system_agent is not None
    assert app.system_agent.error_mgr is app.error_mgr

    await app.system_agent.error_mgr.record(
        agent="System",
        step="netstat_poll",
        message="Simulated netstat failure",
    )
    assert not app.error_mgr.error_queue.empty()
    queued_err = await app.error_mgr.error_queue.get()
    assert queued_err.agent == "System"
    assert queued_err.step == "netstat_poll"

    await app._retry_system()
    assert app.system_agent is not None
    assert app.system_agent.error_mgr is app.error_mgr

    await app._stop_agents()


async def main():
    await test_watchdog_real_loop()
    await test_read_loop_heartbeat_vs_beacon()
    await test_read_loop_step_context_correlation()
    await test_netstat_real_loop()
    await test_dns_real_loop()
    await test_netview_system_agent_wiring()
    print("ALL REAL LOOP CHECKS PASSED SUCCESSFULLY")


if __name__ == "__main__":
    asyncio.run(main())
