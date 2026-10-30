"""Event engine -- transforms raw agent data into human-readable NetEvents."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from rich.markup import escape

from .models import AlertLevel, NetEvent, Source


_PORT_NAMES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-server",
    68: "DHCP-client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5353: "mDNS",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    8883: "MQTT-TLS",
}


def _describe_port(port: int) -> str:
    """Return a human name for a well-known port, or 'port NNNNN'."""
    name = _PORT_NAMES.get(port)
    return name if name else f"port {port}"


def _alert_for_port(port: int) -> AlertLevel:
    """Assign alert level based on destination port."""
    if port in (23, 21):
        return AlertLevel.WARNING
    if port in (3389,):
        return AlertLevel.NOTICE
    return AlertLevel.INFO


class EventEngine:
    """Receives raw dicts from agents, emits NetEvents on an output queue."""

    def __init__(self) -> None:
        self.input_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.output_queue: asyncio.Queue[NetEvent] = asyncio.Queue()
        self._running = False
        self.paused = False
        self.discarded_count = 0
        self._task: asyncio.Task[None] | None = None

    def pause(self) -> None:
        self.paused = True
        self.discarded_count += self._drain_queue(self.input_queue)
        self.discarded_count += self._drain_queue(self.output_queue)

    def resume(self) -> None:
        self.paused = False
        self.discarded_count = 0

    @staticmethod
    def _drain_queue(queue: asyncio.Queue[Any]) -> int:
        drained = 0
        while True:
            try:
                queue.get_nowait()
                drained += 1
            except asyncio.QueueEmpty:
                return drained

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        while self._running:
            if self.paused:
                await asyncio.sleep(0.1)
                continue
            try:
                raw = await asyncio.wait_for(self.input_queue.get(), timeout=0.5)
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            if self.paused:
                self.discarded_count += 1
                continue
            try:
                events = self._transform(raw)
                for ev in events:
                    await self.output_queue.put(ev)
            except Exception:
                await self.output_queue.put(NetEvent(
                    source=Source.SYSTEM,
                    who="EventEngine",
                    where="internal",
                    what=f"Failed to parse raw event: {str(raw)[:120]}",
                    alert_level=AlertLevel.WARNING,
                    raw_data=raw,
                ))



    def _transform(self, raw: dict[str, Any]) -> list[NetEvent]:
        source_type = raw.get("_source", "")
        if source_type == "tshark":
            return self._transform_tshark(raw)
        elif source_type == "system_conn":
            return self._transform_system_conn(raw)
        elif source_type == "system_dns":
            return self._transform_system_dns(raw)
        elif source_type == "esp32":
            return self._transform_esp32(raw)
        elif source_type == "status":
            return self._transform_status(raw)
        else:
            return [NetEvent(
                source=Source.SYSTEM,
                who="unknown",
                where="unknown",
                what=f"Unrecognised event type: {source_type}",
                alert_level=AlertLevel.WARNING,
                raw_data=raw,
            )]



    def _transform_tshark(self, raw: dict[str, Any]) -> list[NetEvent]:
        proto = raw.get("protocol", "TCP").upper()
        src = raw.get("src", "?")
        dst = raw.get("dst", "?")
        src_port = raw.get("src_port", 0)
        dst_port = raw.get("dst_port", 0)
        info = raw.get("info", "")

        try:
            dst_port_int = int(dst_port)
        except (ValueError, TypeError):
            dst_port_int = 0
        try:
            src_port_int = int(src_port)
        except (ValueError, TypeError):
            src_port_int = 0


        if proto == "DNS" or dst_port_int == 53 or src_port_int == 53:
            domain = self._extract_dns_domain(info)
            what = f"DNS query -> {domain}" if domain else "DNS traffic"
            return [NetEvent(
                source=Source.TSHARK, who=src, where=dst,
                what=what, alert_level=AlertLevel.INFO, raw_data=raw,
            )]

        port_desc = _describe_port(dst_port_int)
        alert = _alert_for_port(dst_port_int)
        what = f"{proto} -> {port_desc}"
        if info:
            what += f" ({info[:60]})"

        return [NetEvent(
            source=Source.TSHARK, who=src, where=f"{dst}:{dst_port}",
            what=what, alert_level=alert, raw_data=raw,
        )]

    @staticmethod
    def _extract_dns_domain(info: str) -> str:
        m = re.search(r'(?:Standard query|query)\s+\S+\s+(\S+)', info)
        if m:
            return m.group(1)
        parts = info.split()
        for p in parts:
            if "." in p and not p.replace(".", "").isdigit():
                return p
        return ""



    def _transform_system_conn(self, raw: dict[str, Any]) -> list[NetEvent]:
        proc = raw.get("process", "unknown")
        pid = raw.get("pid", "")
        remote = raw.get("remote", "?:?")
        state = raw.get("state", "")
        proto = raw.get("proto", "TCP")

        who = f"{proc}" if not pid else f"{proc} (pid {pid})"

        parts = remote.rsplit(":", 1)
        try:
            remote_port = int(parts[1]) if len(parts) > 1 else 0
        except ValueError:
            remote_port = 0

        port_desc = _describe_port(remote_port)
        alert = _alert_for_port(remote_port)
        what = f"{proto} {state} -> {port_desc}" if state else f"{proto} -> {port_desc}"

        return [NetEvent(
            source=Source.PC, who=who, where=remote,
            what=what, alert_level=alert, raw_data=raw,
        )]



    def _transform_system_dns(self, raw: dict[str, Any]) -> list[NetEvent]:
        domain = raw.get("domain", "?")
        ip = raw.get("ip", "?")
        record_type = raw.get("type", "A")

        return [NetEvent(
            source=Source.PC, who="DNS-cache", where=ip,
            what=f"Cached {record_type} record: {domain}",
            alert_level=AlertLevel.INFO, raw_data=raw,
        )]



    def _transform_esp32(self, raw: dict[str, Any]) -> list[NetEvent]:
        evt_type = str(raw.get("type", "unknown")).lower()
        mac = str(raw.get("mac", "??:??:??:??:??:??")).upper()
        src = str(raw.get("src", mac)).upper()
        dst = str(raw.get("dst", "unknown destination")).upper()
        bssid = str(raw.get("bssid", "unknown BSSID")).upper()
        rssi = str(raw.get("rssi", "?"))
        channel = str(raw.get("channel", "?"))
        ssid = escape(str(raw.get("ssid", "")))

        if dst == "FF:FF:FF:FF:FF:FF":
            destination = "broadcast"
        elif dst == "00:00:00:00:00:00":
            destination = "unspecified"
        else:
            destination = dst
        ap = bssid if bssid != "00:00:00:00:00:00" else "unknown AP"
        signal = f"RSSI {rssi} dBm, channel {channel}"

        if evt_type in ("probe", "probe_req"):
            target = f" for network \"{ssid}\"" if ssid else " (network name not advertised)"
            return [NetEvent(
                source=Source.ESP32, who=f"Device {src}",
                where=f"{destination} / BSSID {ap}",
                what=f"Searching{target}; {signal}",
                alert_level=AlertLevel.INFO, raw_data=raw,
            )]
        elif evt_type in ("probe_resp",):
            network = f" for network \"{ssid}\"" if ssid else ""
            return [NetEvent(
                source=Source.ESP32, who=f"AP {ssid or ap} ({src})",
                where=f"{destination} / BSSID {ap}",
                what=f"Replies to a Wi-Fi search{network}; {signal}",
                alert_level=AlertLevel.INFO, raw_data=raw,
            )]
        elif evt_type in ("beacon",):
            network = f"network \"{ssid}\"" if ssid else "hidden network"
            return [NetEvent(
                source=Source.ESP32, who=f"AP {ssid or ap} ({src})",
                where=f"{destination} / BSSID {ap}",
                what=f"Advertises {network}; {signal}",
                alert_level=AlertLevel.INFO, raw_data=raw,
            )]
        elif evt_type in ("assoc_req", "assoc"):
            network = f"network \"{ssid}\"" if ssid else f"AP {ap}"
            return [NetEvent(
                source=Source.ESP32, who=f"Device {src}",
                where=f"AP {ap} ({destination})",
                what=f"Requests association with {network}; not yet confirmed; {signal}",
                alert_level=AlertLevel.NOTICE, raw_data=raw,
            )]
        elif evt_type in ("assoc_resp",):
            status = str(raw.get("status", "unknown"))
            outcome = "accepted" if status == "0" else "rejected" if status.isdigit() else "response status unavailable"
            return [NetEvent(
                source=Source.ESP32, who=f"AP {ap} ({src})",
                where=f"Device {destination}",
                what=f"Association {outcome} (status {status}); {signal}",
                alert_level=AlertLevel.NOTICE, raw_data=raw,
            )]
        elif evt_type in ("new_device",):
            observed_bssid = str(raw.get("bssid", "")).upper()
            location = f"BSSID {observed_bssid}" if observed_bssid != "00:00:00:00:00:00" else "2.4 GHz air"
            return [NetEvent(
                source=Source.ESP32, who=f"Device {mac}", where=location,
                what=f"First Wi-Fi frame from this MAC observed; connection state not confirmed; {signal}",
                alert_level=AlertLevel.NOTICE, raw_data=raw,
            )]
        elif evt_type == "deauth":
            reason = raw.get("reason", "")
            return [NetEvent(
                source=Source.ESP32, who=f"{src}",
                where=f"{destination} / BSSID {ap}",
                what=f"Sends a disconnect (deauthentication) frame; reason {reason or 'unknown'}; {signal}",
                alert_level=AlertLevel.WARNING, raw_data=raw,
            )]
        elif evt_type == "data":
            direction = str(raw.get("direction", "DIRECT"))
            frame_len = str(raw.get("length", "unknown"))
            protected = str(raw.get("protected", "0")) == "1"
            retry = str(raw.get("retry", "0")) == "1"
            sequence = str(raw.get("sequence", "unknown"))
            subtype_raw = str(raw.get("subtype", "unknown"))
            try:
                subtype = int(subtype_raw)
            except ValueError:
                subtype = -1
            subtype_names = {
                0: "Data",
                1: "Data + CF-Ack",
                2: "Data + CF-Poll",
                3: "Data + CF-Ack/Poll",
                4: "Null data (no payload)",
                5: "CF-Ack (no payload)",
                6: "CF-Poll (no payload)",
                7: "CF-Ack/Poll (no payload)",
                8: "QoS data",
                9: "QoS data + CF-Ack",
                10: "QoS data + CF-Poll",
                11: "QoS data + CF-Ack/Poll",
                12: "QoS Null (no payload)",
            }
            subtype_name = subtype_names.get(subtype, f"data subtype {subtype_raw}")
            no_payload = subtype in {4, 5, 6, 7, 12, 13, 14, 15}
            payload_text = (
                "no user payload in this frame"
                if no_payload
                else "encrypted payload; contents unavailable"
                if protected
                else "payload not decoded"
            )
            retry_text = "; retransmission flag set" if retry else ""
            sequence_text = f"; sequence {sequence}" if sequence != "unknown" else ""
            try:
                qos_tid = int(str(raw.get("qos_tid", "255")))
            except ValueError:
                qos_tid = 255
            qos_text = f"; QoS priority/TID {qos_tid}" if 0 <= qos_tid <= 15 else ""
            power_save_text = "; power-save flag set" if str(raw.get("power_save", "0")) == "1" else ""

            if direction == "CLIENT_TO_AP":
                who = f"Client {src}"
                where = f"AP {ap}"
                action = "Sends a frame to the access point"
            elif direction == "AP_TO_CLIENT":
                who = f"AP {ap}"
                where = f"Client {destination}"
                action = "Sends a frame to a client"
            elif direction == "WDS_HOP":
                who = f"Radio {src}"
                where = f"Next hop {destination}"
                action = "Forwards a WDS frame; endpoints and AP are unknown"
            else:
                who = f"Device {src}"
                where = destination
                action = "Sends a direct Wi-Fi frame"

            return [NetEvent(
                source=Source.ESP32, who=who, where=where,
                what=f"{action}; {subtype_name}; {frame_len}-byte 802.11 frame; {payload_text}{qos_text}{retry_text}{power_save_text}{sequence_text}; {signal}; sample limited to 10 frames/s",
                alert_level=AlertLevel.INFO, raw_data=raw,
            )]
        elif evt_type == "heartbeat":
            uptime = raw.get("uptime", "0")
            frames = raw.get("frames", "0")
            macs = raw.get("macs", "0")
            dropped = raw.get("dropped", "0")
            scanning = raw.get("scanning", "1")
            status_text = "scanning" if scanning == "1" else "idle"
            dropped_info = f", Dropped: {dropped}" if dropped != "0" else ""
            alert = AlertLevel.WARNING if dropped != "0" else AlertLevel.INFO
            return [NetEvent(
                source=Source.ESP32, who="ESP32-Heartbeat", where="UART",
                what=f"Status: {status_text}, Uptime: {uptime}s, Frames: {frames}, MACs: {macs}{dropped_info}",
                alert_level=alert, raw_data=raw,
            )]
        elif evt_type == "stats":
            total = raw.get("total_frames", "0")
            unique = raw.get("unique_macs", "0")
            dropped = raw.get("dropped", "0")
            uptime = raw.get("uptime", "0")
            dropped_info = f", Dropped: {dropped}" if dropped != "0" else ""
            return [NetEvent(
                source=Source.ESP32, who="ESP32-Stats", where="local",
                what=f"Frames: {total}, Unique MACs: {unique}{dropped_info}, Uptime: {uptime}s",
                alert_level=AlertLevel.INFO, raw_data=raw,
            )]
        else:
            return [NetEvent(
                source=Source.ESP32, who=mac, where=f"ch{channel}",
                what=f"{evt_type} RSSI {rssi}",
                alert_level=AlertLevel.INFO, raw_data=raw,
            )]



    def _transform_status(self, raw: dict[str, Any]) -> list[NetEvent]:
        src = raw.get("agent", "SYSTEM")
        source_map = {
            "tshark": Source.TSHARK,
            "esp32": Source.ESP32,
            "system": Source.PC,
        }
        source = source_map.get(src.lower(), Source.SYSTEM)
        level_str = raw.get("level", "info").lower()
        level_map = {
            "info": AlertLevel.INFO,
            "notice": AlertLevel.NOTICE,
            "warning": AlertLevel.WARNING,
            "error": AlertLevel.ERROR,
            "critical": AlertLevel.CRITICAL,
        }
        level = level_map.get(level_str, AlertLevel.INFO)

        return [NetEvent(
            source=source,
            who=raw.get("agent", "SYSTEM"),
            where="status",
            what=raw.get("message", "no message"),
            alert_level=level,
            raw_data=raw,
        )]
