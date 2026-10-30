# ESP TraceHub

ESP TraceHub is an experimental ESP32-S3 Wi-Fi sensor with a live Windows monitoring interface. The ESP reports nearby 2.4 GHz Wi-Fi frames over USB serial. The host application can also display local Windows connection data and packets captured by TShark.

The terminal interface is still named NETSCOPE in the application.

## Current capabilities

- ESP32-S3 scans 2.4 GHz Wi-Fi management frames while hopping channels 1–13.
- ESP events are sent over UART through a bounded FreeRTOS queue. The firmware reports queue drops and a periodic heartbeat.
- The Windows host application displays ESP, local connection and TShark events in a Textual terminal interface.
- Events can be exported as TXT or JSON.
- The AP marked as **My router** can be captured on its current 2.4 GHz channel as a local raw 802.11 PCAP for Wireshark. Raw capture is BSSID-filtered and does not store Wi-Fi passwords.

## Limits and work in progress

- A MAC seen by the ESP means a Wi-Fi frame was observed nearby. It does not prove that the device joined a particular router.
- The ESP sensor covers 2.4 GHz management frames. It does not decode encrypted traffic or provide a complete router client list.
- Raw ESP capture is limited by the ESP32-S3 radio, channel, UART bandwidth and queue capacity. Dropped frames are possible; the capture is an experiment, not a lossless survey. Wireshark decryption requires the appropriate keys and captured handshake material for the user's own network. TLS-protected application content remains encrypted.
- TShark captures packets visible to the selected host interface. It does not automatically see all traffic on the local network.
- The system agent currently uses Windows commands. A second-computer agent and multi-host transport are not implemented.
- The error dialog currently pauses event display. It does not yet stop every collector while waiting for a user decision.
- Process-to-packet correlation and connection-session grouping are not implemented.
- The raw-capture firmware has been built, packaged and flashed on an ESP32-S3. A physical capture was saved as a Wireshark-readable PCAP.

## Run the host monitor

Use Windows PowerShell from the project directory. Python dependencies are listed in `requirements.txt`.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
.\run_netscope.ps1 -Port COMx
```

To run without the ESP and TShark sources:

```powershell
.\run_netscope.ps1 -NoEsp -NoTshark
```

Wireshark is optional. TShark must be installed and available on `PATH` for packet capture.

Raw captures from the AP marked **My router** are saved outside the repository under `%LOCALAPPDATA%\ESP TraceHub\captures` and can be opened directly in Wireshark. Capture files contain nearby radio traffic for that BSSID; keep them private and delete them when no longer needed.

## Build and flash the firmware

Open a PowerShell environment configured for ESP-IDF 6.1, then run:

```powershell
idf.py build
idf.py -p COMx flash
```

The `firmware` directory contains the latest packaged bootloader, partition table and application image from a successful ESP-IDF build. `firmware/sha256.json` contains their SHA-256 checksums.

To use the manual UART console:

```powershell
.\console.ps1 -Port COMx
```

The firmware console supports `help`, `status`, `wifi-scan`, `wifi-status`, `wifi-stop`, `flash-check`, `usb-check`, `retry` and `cancel`.

## Restore a personal firmware backup

This repository does not contain a full-flash backup. Use only a backup made from your own board, and keep it outside the public repository.

```powershell
$backupPath = 'C:\path\to\your-original-flash.bin'
python -m esptool --chip esp32s3 --port COMx write-flash 0x0 $backupPath
```

## Project layout

- `main/` — ESP-IDF firmware.
- `netscope/` — Python host monitor and event processing.
- `firmware/` — packaged firmware images and checksum manifest.
- `sdkconfig.defaults` — project defaults for ESP-IDF.
