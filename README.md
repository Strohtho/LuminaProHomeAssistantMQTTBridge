# Leviton Lumina Pro to Home Assistant MQTT Bridge

A high-performance, asynchronous bridge connecting a **Leviton Lumina Pro** automation controller over **Omni-Link II UDP** to **Home Assistant** via MQTT. Designed for bare-metal Debian or Debian VMs/LXC containers running on **Proxmox VE**.

---

## Architecture

```text
┌────────────────────────────────┐
│   Leviton Lumina Pro Panel     │
│   (Firmware 2.14 / Omni-Link)  │
└───────────────┬────────────────┘
                │
                │ UDP Port 4369 (AES-128 ECB Session Handshake)
                ▼
┌────────────────────────────────┐
│      Debian on Proxmox VE      │
│     (/opt/lumina-bridge)       │
│  - Python 3 AsyncIO Service    │
│  - Window Relay Interlocking   │
│  - Keep-Alive Watchdog         │
└───────────────┬────────────────┘
                │
                │ TCP Port 1883 (MQTT with Auto-Discovery)
                ▼
┌────────────────────────────────┐
│  Home Assistant / Mosquitto    │
│  - Covers (Motorized Windows)  │
│  - Binary Sensors (Contacts)   │
│  - Sensors (Temp, Humidity)    │
│  - Template Media Players      │
└────────────────────────────────┘
```

---

## Features

- **Omni-Link II Protocol Engine**:
  - Implements the exact cryptographic handshake (Opcode `0x01` / `0x03`) and sequence masking reverse-engineered from HAI PC Access 3.
  - Built-in AES-128 ECB encryption (supports both native `PyCryptodome` and an internal pure-Python fallback).
  - Background keep-alive ping loop (every 20s) and periodic status poll (every 10s).
  - Listens for controller real-time event notifications (`0x15` / `0x23` / `0x3B`).

- **Sensors & Zones**:
  - **Temperature**: Converts raw loop values to accurate Fahrenheit (`-40.0 + 0.5 * raw`).
  - **Humidity**: Reports relative humidity (0–100%).
  - **Motion**: Tripped loop reporting (`ON`/`OFF`) for passive infrared motion sensors.
  - **Window Contacts**: Discrete `binary_sensor` entities (`device_class: window`) showing open/closed state.

- **Motorized Window Covers**:
  - Controls 7 motorized window actuators using pairs of open/close relay units.
  - **Hardware protection & interlocking**: Turns off the opposing relay and inserts a 500ms safety delay before energizing any movement relay.
  - **Runtime watchdog**: Automatically turns off the motor relay after the configured duration (default: 60s).
  - **Early contact stop**: Shuts off relay early when the physical contact sensor registers closed.

- **Multi-Zone Audio (HAI Hi-Fi 2)**:
  - Supports 4 audio zones (Living, Dining, Bath, Bed) and 4 sources (Living, Office, Bath, Bed).
  - Exposes discrete MQTT entities: Power Switch, Volume Number slider (0–100%), Mute Switch, and Source Select dropdown.
  - Provides a ready-to-use [`homeassistant_template_media_players.yaml`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/homeassistant_template_media_players.yaml) for first-class `media_player` Lovelace cards.

- **Home Assistant Auto-Discovery**:
  - Automatically registers all entities under a single device: **"Leviton Lumina Pro"**.
  - Subscribes to Home Assistant birth messages (`homeassistant/status`); automatically re-publishes discovery and device states if Home Assistant restarts.

---

## Requirements

### Debian / Proxmox Host
- **Debian 11 (Bullseye)** or **Debian 12 (Bookworm)** (runs great inside a Proxmox LXC container or Debian VM).
- Network access to:
  - Lumina Pro controller on **UDP port 4369**.
  - MQTT broker (e.g., Mosquitto) on **TCP port 1883**.

---

## Quick Installation on Debian / Proxmox

### 1. Clone into `/opt/lumina-bridge`
```bash
sudo git clone https://github.com/Strohtho/LuminaProHomeAssistantMQTTBridge.git /opt/lumina-bridge
cd /opt/lumina-bridge
```

### 2. Run the Automated Installer
```bash
sudo ./install.sh
```
The installer automatically:
- Installs all system dependencies (`python3`, `python3-venv`, `python3-pip`, `git`, `curl`).
- Creates a dedicated system user (`lumina`).
- Creates an isolated Python virtual environment (`/opt/lumina-bridge/venv`).
- Installs Python dependencies (`paho-mqtt`, `pycryptodome`).
- Copies `config.example.json` to `config.json` (if not already present).
- Configures and enables the systemd service (`lumina-bridge.service`).

### 3. Configure Your Credentials
Edit `config.json` with your real controller key and MQTT details:
```bash
sudo nano /opt/lumina-bridge/config.json
```
- **`lumina.host`**: IP address of your Lumina Pro board (e.g. `192.168.187.5`).
- **`lumina.key`**: 16-byte (32-character hex) network encryption key from PC Access (Setup → Network).
- **`mqtt.host`**: IP of your MQTT broker (e.g. `192.168.187.143` or `127.0.0.1`).
- **`mqtt.username` / `mqtt.password`**: Your MQTT broker credentials.

### 4. Start the Service
```bash
sudo systemctl start lumina-bridge.service
```

---

## Service Management & Monitoring

| Task | Command |
|---|---|
| **View live logs** | `sudo journalctl -u lumina-bridge.service -f` |
| **Check service status** | `sudo systemctl status lumina-bridge.service` |
| **Restart service** | `sudo systemctl restart lumina-bridge.service` |
| **Stop service** | `sudo systemctl stop lumina-bridge.service` |

---

## Easy 1-Step Updates

When you push new features or fixes to GitHub, updating your Debian install takes a single command:

```bash
cd /opt/lumina-bridge
sudo ./update.sh
```
`update.sh` automatically:
1. Pulls the latest commits from GitHub while preserving your local `config.json`.
2. Updates any Python package requirements in the virtual environment.
3. Updates file permissions.
4. Restarts `lumina-bridge.service` and displays the running status.

---

## Home Assistant Setup

### Automatic MQTT Discovery
Once the bridge connects to your MQTT broker, all sensors, window covers, window contact sensors, and audio controls are automatically discovered in Home Assistant under:
**Settings → Devices & Services → MQTT → Devices → Leviton Lumina Pro**.

### Unified Media Player Cards
To combine the audio switches, volume sliders, and source selectors into unified `media_player` entities:

1. Copy [`homeassistant_template_media_players.yaml`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/homeassistant_template_media_players.yaml) into your Home Assistant config directory (e.g., `/config/`).
2. Add this line to your `configuration.yaml`:
   ```yaml
   media_player: !include homeassistant_template_media_players.yaml
   ```
3. Restart Home Assistant or reload Template Entities (**Developer Tools → YAML → Template Entities**).
4. You will now have:
   - `media_player.living_audio`
   - `media_player.dining_audio`
   - `media_player.bath_audio`
   - `media_player.bed_audio`

---

## Proxmox & Network Tips

1. **LXC Container vs VM**:
   - If using a **Proxmox LXC container**, ensure the container is connected to your LAN bridge (`vmbr0`) with a static IP on the same subnet as the Lumina Pro board.
   - Unprivileged containers work without issues since no special device passthrough is required (pure network sockets).
2. **Proxmox Firewall**:
   - If you have the Proxmox firewall enabled on the container or host, make sure outbound UDP traffic to the Lumina Pro (port `4369`) and inbound return traffic are permitted.
3. **Controller Encryption Key**:
   - The key must be entered as 32 hexadecimal characters (16 bytes), without hyphens or spaces.
   - In Leviton PC Access 3, find this under **Setup → Network → Encryption Key 1**.
