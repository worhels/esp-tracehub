from __future__ import annotations

import struct
import time
from pathlib import Path


class PcapWriter:
    LINKTYPE_IEEE802_11_RADIOTAP = 127

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = path.open("wb")
        self._file.write(
            struct.pack(
                "<IHHIIII",
                0xA1B2C3D4,
                2,
                4,
                0,
                0,
                65535,
                self.LINKTYPE_IEEE802_11_RADIOTAP,
            )
        )
        self.frames_written = 0
        self._closed = False

    def write_frame(
        self,
        frame: bytes,
        channel: int,
        rssi: int,
        timestamp: float | None = None,
    ) -> None:
        if self._closed:
            raise ValueError("PCAP writer is closed")
        if not frame or len(frame) > 65535:
            raise ValueError("Invalid 802.11 frame length")
        if not 1 <= channel <= 14 or not -128 <= rssi <= 127:
            raise ValueError("Invalid Wi-Fi radio metadata")
        captured_at = time.time() if timestamp is None else timestamp
        seconds = int(captured_at)
        microseconds = int((captured_at - seconds) * 1_000_000)
        frequency = 2484 if channel == 14 else 2407 + channel * 5
        radiotap = struct.pack("<BBHI", 0, 0, 16, 0x2A)
        radiotap += struct.pack("<B", 0x10)
        radiotap += b"\x00"
        radiotap += struct.pack("<HHb", frequency, 0x0080, rssi)
        radiotap += b"\x00"
        packet = radiotap + frame
        self._file.write(struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)))
        self._file.write(packet)
        self._file.flush()
        self.frames_written += 1

    def close(self) -> None:
        if not self._closed:
            self._file.close()
            self._closed = True

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
