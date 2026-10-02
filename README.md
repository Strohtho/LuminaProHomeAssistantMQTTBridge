# Leviton Lumina Pro & Omni to Home Assistant MQTT Bridge

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Home Assistant](https://img.shields.io/badge/Home%20Assistant-MQTT%20Discovery-41BDF5.svg)](https://www.home-assistant.io/)
[![Protocol](https://img.shields.io/badge/Protocol-OmniLink%20I%20%2F%20II%20UDP-orange.svg)](https://www.leviton.com/)
[![OS](https://img.shields.io/badge/Target-Debian%20%2F%20Proxmox%20VE-D70A53.svg)](https://www.debian.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An asynchronous, bidirectional network bridge connecting legacy **Leviton Lumina Pro**, **Lumina**, and **HAI OmniPro II / Omni IIe** automation controllers to **Home Assistant** over **MQTT** with **Automatic Discovery**. 

Designed for bare-metal Debian hosts and Debian LXC containers / VMs running on **Proxmox VE**.

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Deep Dive: "Why It Is The Way It Is"](#deep-dive-why-it-is-the-way-it-is)
   - [OmniLink 1 vs. OmniLink 2 over UDP: The 0x15 Collision Trap](#1-omnilink-1-vs-omnilink-2-over-udp-the-0x15-collision-trap)
   - [Why UDP 4369 Polling Beats Legacy TCP Sockets](#2-why-udp-4369-polling-beats-legacy-tcp-sockets)
   - [Proprietary AES-128 ECB Sequence Masking](#3-proprietary-aes-128-ecb-sequence-masking)
   - [Motorized Window Actuator Safety & Relay Interlocking](#4-motorized-window-actuator-safety--relay-interlocking)
   - [Why Physical Window Contact Sensors Were Decoupled](#5-why-physical-window-contact-sensors-were-decoupled)
   - [Auxiliary Temperature and Humidity Scaling](#6-auxiliary-temperature-and-humidity-scaling)
   - [Hi-Fi 2 Multi-Room Audio Architecture](#7-hi-fi-2-multi-room-audio-architecture)
4. [Hardware & Network Prerequisites](#hardware--network-prerequisites)
   - [Compatible Panels](#compatible-panels)
   - [Locating Controller Encryption Keys](#locating-controller-encryption-keys)
5. [Installation & Deployment (Debian / Proxmox VE)](#installation--deployment-debian--proxmox-ve)
   - [1-Command Automated Install](#1-1-command-automated-install)
   - [Proxmox LXC Container Setup](#2-proxmox-lxc-container-setup)
   - [Configuration Reference (`config.json`)](#3-configuration-reference-configjson)
   - [Service Management](#4-service-management)
   - [1-Command Updates (`update.sh`)](#5-1-command-updates-updatesh)
6. [Home Assistant Integration](#home-assistant-integration)
   - [MQTT Auto-Discovery Entities](#mqtt-auto-discovery-entities)
   - [Unified Media Player Cards (`media_player` Template)](#unified-media-player-cards-media_player-template)
7. [Protocol Specification & Developer Cheatsheet](#protocol-specification--developer-cheatsheet)
8. [Troubleshooting & Diagnostics](#troubleshooting--diagnostics)
9. [Developer & Agent Handover Notes](AGENT_NOTES.md)

---

## Project Overview

For over two decades, **HAI (Home Automation, Inc.)** and subsequently **Leviton** manufactured some of the most reliable and electrically robust hardwired automation and security controllers in the industry: the **Lumina**, **Lumina Pro**, **Omni II**, **Omni IIe**, and **OmniPro II**. These systems control:
- High-voltage lighting and auxiliary relays (Units).
- Security, motion, and window perimeter detection (Zones).
- Analog environmental monitoring: indoor/outdoor temperature, humidity, and freeze sensors (Aux Sensors).
- Multi-room distributed audio systems (**HAI Hi-Fi 2**).

However, Leviton has formally discontinued the product line. Cloud access, the mobile app (Snap-Link), and the proprietary configuration software (**PC Access 3**) are frozen in time, leaving homeowners stranded with isolated, closed-off installations.

**This bridge solves the problem completely.** It runs locally on your home network, directly speaks the low-level binary Omni-Link UDP protocol to the controller board, and translates all states, sensors, and commands into standard Home Assistant MQTT topics with native Auto-Discovery.

### Key Capabilities
- **Local-Only & Cloud-Free**: Zero cloud dependencies, zero telemetry, zero latency.
- **Bi-Directional State Synchronization**: Changes made via wall touchscreens (OmniTouch), keypads, or automation schedules instantly reflect in Home Assistant, and Home Assistant commands execute on the controller in milliseconds.
- **Hardware-Protected Actuator Control**: Built-in 500ms safety dead-time interlocks and runtime watchdogs protect dual-winding motorized window openers from short circuits.
- **Complete Hi-Fi 2 Integration**: Native control of power, source selection, volume sliders (0–100%), and mute states across all audio zones.
- **Resilient Watchdog**: Automatic keep-alive pings, session re-negotiation, and automatic re-discovery upon Home Assistant restart.

---

## System Architecture

```text
┌────────────────────────────────────────────────────────┐
│              Leviton Lumina Pro / Omni Panel           │
│   - Security Zones (Motion PIRs, Door/Window loops)    │
│   - Auxiliary Sensors (Indoor/Outdoor Temp, Humidity)  │
│   - Relays / Units (Motorized Window Actuators)        │
│   - Serial Multi-Room Audio (HAI Hi-Fi 2 Matrix)       │
└───────────────────────────┬────────────────────────────┘
                            │
                            │ UDP Port 4369
                            │ - AES-128 ECB + Sequence Masking
                            │ - Omni-Link 1 Binary Wire Protocol
                            ▼
┌────────────────────────────────────────────────────────┐
│          Debian Host / Proxmox VE LXC Container        │
│                 (/opt/lumina-bridge)                   │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ lumina_bridge.py (AsyncIO Daemon)                │  │
│  │  ├─ Transport: UDP Datagram Protocol (Port 4369) │  │
│  │  ├─ Cryptography: AES-128 + Sequence XOR Unmask  │  │
│  │  ├─ Session Manager: Handshake & Keep-Alive      │  │
│  │  ├─ Safety Engine: Relay dead-time interlock     │  │
│  │  ├─ Polling Engine: High-frequency V1 requests   │  │
│  │  └─ MQTT Engine: paho-mqtt + Auto-Discovery      │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  Systemd Service: lumina-bridge.service                │
└───────────────────────────┬────────────────────────────┘
                            │
                            │ TCP Port 1883 (MQTT)
                            │ Standard JSON State & Command Payloads
                            ▼
┌────────────────────────────────────────────────────────┐
│             Home Assistant Core / OS                   │
│                                                        │
│  - MQTT Integration (Automatic Device Registry)        │
│  - Covers: Motorized Windows (Open/Close/Stop)         │
│  - Binary Sensors: Motion Detectors (PIR)              │
│  - Sensors: Temperature (°F) & Humidity (%)            │
│  - Media Players: Hi-Fi 2 Multi-Zone Audio Cards       │
└────────────────────────────────────────────────────────┘
```

---

## Deep Dive: "Why It Is The Way It Is"

Most open-source integrations for HAI/Leviton panels fail in production because they treat the controller like a standard TCP socket and assume OmniLink 2 documentation applies universally. This bridge was built by **reverse-engineering the Leviton PC Access binary (`PCA3D_EN.cs`)** and testing directly on live hardware.

### 1. OmniLink 1 vs. OmniLink 2 over UDP: The 0x15 Collision Trap
In Leviton’s official PC Access codebase (`clsOmniLinkConnection.ConnectionProtocol()`), the controller’s network stack behaves fundamentally differently depending on transport:
- **TCP (Port 4369)** defaults to **OmniLink 2**.
- **UDP (Port 4369)** defaults strictly to **OmniLink 1**.

This introduces a fatal trap: **Opcode `0x15` is overloaded across protocol versions.**
- In **OmniLink 2**, opcode `0x15` is `clsOL2EnableNotifications` (`Enable Notifications`).
- In **OmniLink 1**, opcode `0x15` is `RequestZoneStatus` (`Request Zone Status`).

When standard OmniLink 2 libraries connect over UDP and attempt to enable push notifications by sending `[0x15, 0x01]`, the Lumina firmware treats the 2-byte payload as an invalid OmniLink 1 zone request. The controller immediately rejects the packet and sends back `0x06` (`NAK`), refusing to push real-time events.

**Why this bridge is different:**
This bridge fully honors the **OmniLink 1 UDP architecture**. It uses:
- Opcode `0x15` for zone status polling (returning Opcode `0x16`).
- Opcode `0x19` for auxiliary sensor status polling (returning Opcode `0x1A`).
- Opcode `0x31` for audio zone status polling (returning Opcode `0x32`).
- Opcode `0x17` for unit status polling (returning Opcode `0x18`).
- Opcode `0x05` (`ACK`) as a lightweight session keep-alive ping.

### 2. Why UDP 4369 Polling Beats Legacy TCP Sockets
The Ethernet daughterboards on Leviton Lumina and Omni panels (such as the 20A04-1) have extremely limited microcontroller RAM and socket tables. Over TCP:
- Half-open TCP connections (caused by router reboots, network drops, or client restarts) linger in `CLOSE_WAIT` on the board, exhausting the single available socket and requiring a hard power-cycle of the panel.
- TCP connections often drop after minutes of inactivity.

Over **UDP**, the connection is completely stateless. The controller allocates an active session ID during the cryptographic handshake. If a packet is lost or network routing temporarily drops, the bridge seamlessly re-requests a session without hanging the controller’s socket stack. Polling the board every 3 seconds generates negligible network overhead (a single 20-byte datagram every 3s) while guaranteeing sub-second response times in Home Assistant.

### 3. Proprietary AES-128 ECB Sequence Masking
Leviton did not implement standard TLS or plain AES encryption. In OmniLink UDP:
1. Every encrypted packet is wrapped with an outer header:
   ```text
   [Length High, Length Low, 0x10, Seq High, Seq Low, Encrypted Payload..., CRC16 High, CRC16 Low]
   ```
2. The payload is encrypted with AES-128 in **ECB mode**.
3. **Sequence Masking**: Before encryption, **bytes 0 and 1 of every 16-byte cipher block** are XORed with the packet sequence number:
   ```python
   # Mask before encryption:
   block[0] ^= (seq >> 8) & 0xFF
   block[1] ^= seq & 0xFF
   ```
4. Upon receiving a response, after AES decryption, bytes 0 and 1 of every block must be unmasked with the packet's received sequence number:
   ```python
   # Unmask after decryption:
   unmasked_block[0] ^= (seq >> 8) & 0xFF
   unmasked_block[1] ^= seq & 0xFF
   ```
Without this sequence masking step, decrypted packets result in corrupted message lengths and garbage opcodes.

### 4. Motorized Window Actuator Safety & Relay Interlocking
Motorized window actuators (such as Somfy, Ultraflex, Truth Hardware, or Linak linear actuators) operate using bidirectional DC or dual-winding AC motors. On Leviton panels, each window is wired to **two distinct relay units**:
- One relay for **Open** (e.g., Unit 265).
- One relay for **Close** (e.g., Unit 257).

> [!CAUTION]
> **Hardware Danger**: If both the Open and Close relays are energized at the same time (e.g., a user presses "Open" while an automation is closing the window), the motor windings will dead-short, stripping mechanical drive gears, tripping breakers, or destroying the Leviton output relay board.

To prevent hardware damage under all circumstances, the bridge implements a **hardware-guarded software interlock**:
1. When a movement command is received (e.g. `OPEN`), the bridge immediately commands the opposing relay (e.g. `CLOSE`) to turn `OFF`.
2. The bridge introduces a mandatory **500ms safety dead-time delay** before energizing the target relay.
3. A background task watchdog monitors the movement duration. Once `runtime_sec` (e.g. 60s) has elapsed, the bridge automatically turns the active relay `OFF`.
4. If a user presses `STOP` in Home Assistant, both relays are immediately de-energized.

### 5. Why Physical Window Contact Sensors Were Decoupled
In real-world homes, magnetic reed switches mounted on motorized window frames frequently degrade over time, loosen, or misalign due to thermal expansion/contraction of the building frame.
- When an opener was previously tied directly to its physical magnetic contact sensor, a stuck or flaky contact sensor would cause Home Assistant to report the window as permanently "unknown" or "closed" even while open, or cause the actuator to stop prematurely.
- **The Solution**: Actuator units operate purely based on motor runtime with clean, predictable optimistic state tracking in Home Assistant. 
- Furthermore, the bridge automatically publishes an empty payload (`""`) to the MQTT Auto-Discovery topics of old contact sensors upon startup, permanently unregistering ghost entities from Home Assistant without requiring manual database editing.

### 6. Auxiliary Temperature and Humidity Scaling
Leviton temperature and humidity sensors (Part # 31A00-1 indoor, 31A00-2 outdoor, 31A00-8 extended range) return a raw 8-bit analog loop value ($0 \dots 255$).

Reverse-engineering `PCA3D_EN.cs` confirms the exact formula used by Leviton touchscreens and PC Access:
$$\text{Temperature }(^\circ\text{F}) = (\text{raw\_value} \times 0.9) - 40.0$$

- Example: Raw value `116` $\rightarrow$ $(116 \times 0.9) - 40.0 = 104.4 - 40.0 = \mathbf{64.4^\circ\text{F}}$.
- For humidity sensors, the raw value corresponds directly to relative humidity percentage ($0 \dots 100\%$).

### 7. Hi-Fi 2 Multi-Room Audio Architecture
Leviton's **Hi-Fi 2** is a high-power distributed audio matrix amplifier connected to the Lumina controller via RS-232 serial. 

The bridge maps audio zones using OmniLink 1 audio commands (Opcode `0x0F`):
- **Power**: Opcode `0x0F`, Command `0x50` (OFF) / `0x51` (ON), Target = Zone ID.
- **Source Selection**: Opcode `0x0F`, Command `0x52`, Param = Source ID ($1 \dots 4$), Target = Zone ID.
- **Volume**: Opcode `0x0F`, Command `0x53`, Param = Volume ($0 \dots 100$), Target = Zone ID.
- **Mute**: Opcode `0x0F`, Command `0x54`, Param = `1` (Muted) / `0` (Unmuted), Target = Zone ID.

To make this seamless in Home Assistant, the bridge publishes discrete MQTT entities for each control and provides a drop-in template ([`homeassistant_template_media_players.yaml`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/homeassistant_template_media_players.yaml)) that binds them into standard, beautiful Home Assistant `media_player` cards.

---

## Hardware & Network Prerequisites

### Compatible Panels
- Leviton Lumina & Lumina Pro (Firmware 2.x and 3.x)
- HAI Omni II, Omni IIe, and OmniPro II (Firmware 2.x and 3.x)
- Leviton / HAI Hi-Fi 2 Multi-Room Audio System (integrated via controller serial port)

### Locating Controller Encryption Keys
Omni-Link II uses two 16-byte (128-bit) encryption keys. This bridge requires **Key 1**.

#### From an OmniTouch / LuminaTouch Touchscreen:
1. Tap the touchscreen and go to **Setup** $\rightarrow$ **Network** (or **System Info**).
2. Look for **Key 1** and **Key 2**.
3. It will display 8 pairs of hexadecimal bytes separated by hyphens:
   ```text
   Key 1: 11-11-11-11-11-11-11-11
   Key 2: 11-11-11-11-11-11-11-11
   ```
4. Merge both halves into a single **32-character hexadecimal string** without hyphens:
   ```text
   11111111111111111111111111111111
   ```

#### From PC Access 3:
1. Open PC Access 3 and load your `.pca` file.
2. Navigate to **Setup** $\rightarrow$ **Network**.
3. Copy **Encryption Key 1**.

---

## Installation & Deployment (Debian / Proxmox VE)

### 1. 1-Command Automated Install
Log into your Debian host or Proxmox container as `root`:

```bash
sudo git clone https://github.com/Strohtho/LuminaProHomeAssistantMQTTBridge.git /opt/lumina-bridge
cd /opt/lumina-bridge
sudo ./install.sh
```

The installer automatically:
- Installs necessary system packages (`python3`, `python3-venv`, `python3-pip`, `git`, `curl`).
- Creates a dedicated system user (`lumina`).
- Creates an isolated Python virtual environment (`/opt/lumina-bridge/venv`).
- Installs dependencies (`paho-mqtt`, `pycryptodome`).
- Copies `config.example.json` $\rightarrow$ `config.json` (if not already present).
- Installs and enables the `lumina-bridge.service` systemd unit.

### 2. Proxmox LXC Container Setup
If deploying inside Proxmox VE, an unprivileged Debian 12 (Bookworm) LXC container is recommended:
- **Cores**: 1
- **RAM**: 256 MB (bridge consumes $<30\text{ MB}$)
- **Disk**: 4 GB
- **Network**: Bridged to LAN (`vmbr0`) with a static IP.
- **Firewall**: Ensure UDP port `4369` (to Lumina) and TCP port `1883` (to MQTT) are open.

> [!NOTE]
> If Git displays a `fatal: detected dubious ownership in repository` warning, run:
> ```bash
> git config --global --add safe.directory /opt/lumina-bridge
> ```

### 3. Configuration Reference (`config.json`)
Edit `/opt/lumina-bridge/config.json`:

```bash
sudo nano /opt/lumina-bridge/config.json
```

```json
{
  "lumina": {
    "host": "192.168.187.5",
    "port": 4369,
    "key": "11111111111111111111111111111111",
    "poll_interval": 3.0,
    "keep_alive_interval": 20
  },
  "mqtt": {
    "host": "192.168.187.143",
    "port": 1883,
    "username": "homeassistant",
    "password": "your_secure_password",
    "discovery_prefix": "homeassistant",
    "state_prefix": "lumina"
  },
  "motion_zones": [
    { "zone": 1, "name": "Living Room Motion" },
    { "zone": 2, "name": "Kitchen Motion" },
    { "zone": 3, "name": "Hallway Motion" }
  ],
  "aux_sensors": [
    { "sensor": 1, "name": "Indoor Temperature", "type": "temperature" },
    { "sensor": 2, "name": "Indoor Humidity", "type": "humidity" },
    { "sensor": 3, "name": "Outdoor Temperature", "type": "temperature" }
  ],
  "windows": [
    {
      "id": "living_room_window",
      "name": "Living Room Window",
      "open_unit": 265,
      "close_unit": 257,
      "runtime_sec": 60
    }
  ],
  "audio_zones": [
    { "zone": 1, "name": "Living Room Audio" },
    { "zone": 2, "name": "Dining Room Audio" },
    { "zone": 3, "name": "Bathroom Audio" },
    { "zone": 4, "name": "Bedroom Audio" }
  ],
  "audio_sources": [
    { "id": 1, "name": "Living Room" },
    { "id": 2, "name": "Office" },
    { "id": 3, "name": "Bathroom" },
    { "id": 4, "name": "Bedroom" }
  ]
}
```

### 4. Service Management

| Action | Command |
|---|---|
| **Start Service** | `sudo systemctl start lumina-bridge.service` |
| **Stop Service** | `sudo systemctl stop lumina-bridge.service` |
| **Restart Service** | `sudo systemctl restart lumina-bridge.service` |
| **Check Status** | `sudo systemctl status lumina-bridge.service` |
| **Stream Live Logs** | `sudo journalctl -u lumina-bridge.service -f` |

### 5. 1-Command Updates (`update.sh`)
When updates are pushed to the GitHub repository, update your production bridge with a single command:

```bash
cd /opt/lumina-bridge
sudo ./update.sh
```
This script pulls new code, refreshes dependencies, adjusts permissions, restarts the systemd daemon, and confirms service health.

---

## Home Assistant Integration

### MQTT Auto-Discovery Entities
When the bridge starts, it publishes MQTT discovery topics. In Home Assistant, open:
**Settings** $\rightarrow$ **Devices & Services** $\rightarrow$ **MQTT** $\rightarrow$ **Devices** $\rightarrow$ **Leviton Lumina Pro**.

The following entities appear automatically:
- **Motorized Covers**: `cover.living_room_window`, etc. (Supports `OPEN`, `CLOSE`, and `STOP`).
- **Motion Sensors**: `binary_sensor.living_room_motion` (Device class: `motion`).
- **Temperature & Humidity**: `sensor.indoor_temperature` (°F), `sensor.indoor_humidity` (%).
- **Audio Zone Controls**:
  - `switch.<zone>_audio_power`
  - `number.<zone>_audio_volume` (0–100 slider)
  - `switch.<zone>_audio_mute`
  - `select.<zone>_audio_source` (Dropdown selector)

### Unified Media Player Cards (`media_player` Template)
Rather than managing 4 separate controls per audio zone, you can combine them into a native Home Assistant `media_player` entity using the included [`homeassistant_template_media_players.yaml`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/homeassistant_template_media_players.yaml).

#### Setup Instructions:
1. Copy `homeassistant_template_media_players.yaml` to your Home Assistant configuration directory (e.g. `/config/homeassistant_template_media_players.yaml`).
2. Add this line to your Home Assistant `configuration.yaml`:
   ```yaml
   media_player: !include homeassistant_template_media_players.yaml
   ```
3. In Home Assistant, go to **Developer Tools** $\rightarrow$ **YAML** $\rightarrow$ Click **Template Entities** (or restart Home Assistant).
4. You now have fully integrated media players:
   - `media_player.living_room_audio`
   - `media_player.dining_room_audio`
   - `media_player.bathroom_audio`
   - `media_player.bedroom_audio`

---

## Protocol Specification & Developer Cheatsheet

### Omni-Link UDP Wire Structure
All UDP datagrams exchanged on port 4369 follow this structure:

| Field | Size | Description |
|---|---|---|
| `Length` | 2 bytes (Big Endian) | Total length of following packet data + CRC |
| `Type` | 1 byte | `0x01` (Session Req), `0x02` (Session Ack), `0x03` (Session Auth), `0x04` (Auth Ack), `0x10` (Encrypted Omni-Link) |
| `Sequence` | 2 bytes (Big Endian) | Rolling 16-bit sequence number ($1 \dots 65535$) |
| `Payload` | Variable | Raw or AES-128 encrypted data |
| `CRC16` | 2 bytes (Big Endian) | Standard CRC-16-CCITT over entire packet |

### Session Handshake Sequence
```text
Client                                             Lumina Controller
  │                                                        │
  │─── 0x01: Request New Session [0x05, 0x38, 0x01, seq] ─▶│
  │                                                        │
  │◀── 0x02: Acknowledge Session [5-byte Session ID] ──────│
  │                                                        │
  │ (Derive Temporary Key: ControllerKey[11..15] ^ SessionID)
  │                                                        │
  │─── 0x03: Authenticate Session (AES encrypted) ────────▶│
  │                                                        │
  │◀── 0x04: Session Authorized ───────────────────────────│
  │                                                        │
  │         [Secure Session Established]                   │
  │                                                        │
  │─── 0x10: OmniLink V1 Zone Status Request (0x15) ──────▶│
  │◀── 0x10: OmniLink V1 Zone Status Reply (0x16) ─────────│
```

### OmniLink 1 Request & Reply Opcodes

| Opcode | Name | Purpose | Response Format |
|---|---|---|---|
| `0x05` | `Acknowledge` | Keep-alive watchdog ping | `0x05` |
| `0x06` | `Negative Acknowledge` | Controller rejection / error | None |
| `0x0F` | `Unit / Audio Command` | Execute relay or audio command | `0x05` |
| `0x15` | `Request Zone Status` | Query status of zones ($1 \dots 16$) | `0x16` (2 bytes/zone: `[status, loop]`) |
| `0x17` | `Request Unit Status` | Query status of output units | `0x18` (1 byte/unit: `0=OFF, 1=ON`) |
| `0x19` | `Request Aux Status` | Query temperature/humidity aux loops | `0x1A` (4 bytes/aux: `[status, raw, low, high]`) |
| `0x31` | `Request Audio Status` | Query Hi-Fi 2 audio zones | `0x32` (4 bytes/zone: `[power, source, volume, mute]`) |

---

## Troubleshooting & Diagnostics

### 1. View Detailed Logs
The bridge provides rich, informative logging:
```bash
sudo journalctl -u lumina-bridge.service -f -o cat
```

### 2. Common Issues & Solutions

#### Problem: Infinite `Session inactive, re-requesting session...` loop
- **Root Cause**: The encryption key in `config.json` does not match the controller's key.
- **Fix**: Check `Setup` $\rightarrow$ `Network` on the physical touchscreen. Ensure Key 1 and Key 2 are concatenated into a 32-character hex string without hyphens or spaces.

#### Problem: `fatal: detected dubious ownership in repository` during git pull
- **Root Cause**: Repository cloned as `root` but accessed by another user.
- **Fix**: Run `git config --global --add safe.directory /opt/lumina-bridge`.

#### Problem: Entities show `unknown` in Home Assistant
- **Root Cause**: MQTT discovery payload sent before the bridge completed its first query pass.
- **Fix**: The bridge automatically updates states every 3 seconds. Allow 5 seconds after startup for initial states to populate.

#### Problem: Motorized windows stop before fully opening/closing
- **Root Cause**: `runtime_sec` in `config.json` is set lower than the physical time required for the actuator to traverse.
- **Fix**: Time your window's full traverse with a stopwatch and set `runtime_sec` to that value plus 5 seconds (e.g. `65`).

---

## Contributing & License
Contributions, issue reports, and protocol test logs on other Omni/Lumina firmware versions are welcome!

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.
