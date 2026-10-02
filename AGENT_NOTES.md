# Agent Handover & Architecture Notes

> **Purpose**: This document is an exhaustive handover briefing for any AI agent or developer picking up work on this repository. It covers the system architecture, how the hardware and protocols function, the subtle traps and "walls" already hit (and solved), and where to find key reference materials.
> 
> *Future agents: When you solve new architectural hurdles, discover new opcode behaviors, or add major subsystems, please document them in this file!*

---

## 1. System Overview & Deployment Environment

- **Repository**: `https://github.com/Strohtho/LuminaProHomeAssistantMQTTBridge.git`
- **Target Host**: Debian 12 (Bookworm) running inside an unprivileged LXC container (or VM) on **Proxmox VE**.
- **Installation Path**: `/opt/lumina-bridge`
- **Daemon / Service**: `systemd` unit `lumina-bridge.service`, running under dedicated user `lumina`.
- **Python Environment**: Isolated virtualenv at `/opt/lumina-bridge/venv` using Python 3.11+.
- **Physical Hardware**:
  - **Controller**: Leviton Lumina Pro (or HAI OmniPro II / Omni IIe family) with an embedded Ethernet daughterboard (part # 20A04-1).
  - **Port**: UDP Port `4369`.
  - **Audio System**: Leviton / HAI Hi-Fi 2 distributed audio matrix amplifier connected via serial port to the controller.
  - **Window Actuators**: Somfy/Ultraflex/Truth Hardware dual-relay motorized openers connected to Leviton output relays (Units).
  - **Environmental Probes**: Leviton indoor/outdoor temperature and humidity probes (Part # 31A00-1 / 31A00-2) connected to Auxiliary Sensor loops.

---

## 2. Hard Walls Hit & Lessons Learned (DO NOT REPEAT THESE MISTAKES)

### 🧱 Wall 1: The UDP vs. TCP Protocol Identity Crisis (The 0x15 Collision Trap)
- **The Pitfall**: Most public Omni-Link documentation covers **OmniLink 2 (TCP)**. When we initially connected over UDP, we attempted to enable asynchronous push notifications by sending `clsOL2EnableNotifications` (`0x15, 0x01`).
- **What Happened**: The controller immediately rejected the packet with `0x06` (`NAK`), dropped the session, and repeatedly disconnected.
- **The Discovery**: In Leviton's official PC Access codebase (`PCA3D_EN.cs` $\rightarrow$ `clsOmniLinkConnection.ConnectionProtocol()`):
  - **TCP (Port 4369)** uses **OmniLink 2**.
  - **UDP (Port 4369)** defaults strictly to **OmniLink 1**.
  - **Opcode `0x15` is overloaded!** In OmniLink 2, `0x15` is *Enable Notifications*. In OmniLink 1, `0x15` is *Request Zone Status* (`clsOL1RequestZoneStatus`).
  - When the controller received `[0x15, 0x01]` over UDP, it parsed it as a truncated, malformed OmniLink 1 zone request and threw a NAK.
- **The Fix**: **Do not attempt to enable async push notifications over UDP.** UDP is an OmniLink 1 polling interface. The bridge queries status periodically using V1 request opcodes:
  - `0x15` $\rightarrow$ Zone Status (returns `0x16`)
  - `0x19` $\rightarrow$ Aux Sensor Status (returns `0x1A`)
  - `0x31` $\rightarrow$ Audio Zone Status (returns `0x32`)
  - `0x17` $\rightarrow$ Unit Status (returns `0x18`)
  - `0x05` $\rightarrow$ Keep-alive watchdog ping

---

### 🧱 Wall 2: Fragile TCP Socket Tables on Legacy Hardware
- **The Question**: Why not just switch to TCP and use OmniLink 2?
- **The Reality**: The 20A04-1 Ethernet daughterboard has an extremely limited 8-bit/16-bit embedded network stack with a tiny socket table (often only 1 or 2 concurrent sockets).
  - If a client connection drops abruptly (e.g., container reboot, network switch blip, bridge restart), the controller's TCP socket gets trapped in `CLOSE_WAIT` or `FIN_WAIT_2` indefinitely.
  - When that happens, **all TCP connections are refused until someone physically power-cycles the Leviton panel**.
- **The Fix**: **Stay on UDP port 4369.** UDP is completely stateless at the socket layer. If the bridge or container restarts, a new session is established in $<100\text{ms}$ with zero socket exhaustion on the panel. High-frequency polling (every 3 seconds) generates trivial network overhead (one 20-byte datagram every 3s) and provides rock-solid reliability.

---

### 🧱 Wall 3: Proprietary AES-128 ECB Sequence Masking
- **The Pitfall**: Decrypted packets returned corrupted lengths or garbage opcodes.
- **The Discovery**: Leviton's UDP protocol does not use vanilla AES-128 ECB. They implemented custom block masking:
  - **Before encryption**: Bytes 0 and 1 of *every* 16-byte cipher block are XORed with the packet's 16-bit sequence number:
    ```python
    block[0] ^= (seq >> 8) & 0xFF
    block[1] ^= seq & 0xFF
    ```
  - **After decryption**: Bytes 0 and 1 of *every* 16-byte block must be unmasked with the received packet's sequence number before parsing length or opcodes.
- **The Fix**: Implemented in `LuminaController._encrypt_payload` and `LuminaController._decrypt_payload`.

---

### 🧱 Wall 4: Session Key Derivation Math
- **The Pitfall**: The controller rejected the authentication packet (`0x03`).
- **The Discovery**: The 16-byte controller key entered in `config.json` is **not** used directly to encrypt session messages.
  1. The client sends `0x01` (Request New Session).
  2. The controller returns `0x02` (Acknowledge New Session) with a **5-byte Session ID**.
  3. The **Session Key** is derived by XORing the last 5 bytes of the Controller Key with the 5-byte Session ID:
     ```python
     temp_key = key[:11] + bytes([key[i] ^ session_id[i - 11] for i in range(11, 16)])
     ```
  4. The client then encrypts and sends `0x03` (Authenticate Session) using this temporary session key.
  5. The controller validates and returns `0x04` (Session Authorized).

---

### 🧱 Wall 5: Touchscreen Key Formatting
- **The Pitfall**: Users copying the key from an OmniTouch/LuminaTouch screen see:
  ```text
  Key 1: 11-11-11-11-11-11-11-11
  Key 2: 11-11-11-11-11-11-11-11
  ```
  Users often enter only Key 1 or include hyphens.
- **The Reality**: Key 1 and Key 2 on the screen are each 8 bytes (16 hex chars). Together they make up the **16-byte (32-character hex)** network encryption key.
- **The Rule**: `config.json` requires all 32 hex characters without spaces or hyphens: `"11111111111111111111111111111111"`.

---

### 🧱 Wall 6: Motorized Window Actuator Hardware Burnout Risk
- **The Hardware**: Motorized window openers (Somfy, Ultraflex, Truth) use dual-winding motors driven by two separate Leviton relay units (e.g. Unit 265 for Open, Unit 257 for Close).
- **The Danger**: **Never energize both relays at once.** Energizing both windings dead-shorts the motor, stripping the gears or frying the Leviton output relay board.
- **The Architecture**:
  1. The bridge maintains a per-window `asyncio.Task` lock.
  2. Before energizing a relay, it **explicitly turns OFF the opposing relay**.
  3. It enforces a **mandatory 500ms safety dead-time** (`await asyncio.sleep(0.5)`) before turning ON the target relay.
  4. It spawns a watchdog timer that shuts the relay OFF after `runtime_sec` (default 60s).
  5. Pressing `STOP` in Home Assistant immediately de-energizes both relays.

---

### 🧱 Wall 7: Flaky Physical Magnetic Window Contact Sensors
- **The Pitfall**: Motorized windows had magnetic reed switches mounted on the sash (Zones 48–60).
- **The Problem**: Over years of building settling and thermal shifts, these reed switches degraded or misaligned, reporting "open" when closed or getting stuck in "unknown". Coupling the window cover logic to these sensors caused Home Assistant covers to fail or stop prematurely.
- **The Fix**:
  - We **completely decoupled** the window covers from the contact sensors. The covers operate on motor runtime duration with clean optimistic state tracking.
  - In `lumina_bridge.py`, the bridge actively sends empty discovery payloads (`""`) for retired contact sensors (`lumina_window_*_contact`) upon startup to permanently delete orphan entities from Home Assistant.
  - Redundant polling for zones 48–60 was removed, cutting polling latency.

---

### 🧱 Wall 8: Analog Temperature Sensor Scaling Formula
- **The Pitfall**: The raw loop value from Leviton temperature probes (Part # 31A00-1 / 31A00-2) is an 8-bit integer ($0 \dots 255$). Standard $0.5^\circ$ scaling produced incorrect temperatures.
- **The Formula from `PCA3D_EN.cs`**:
  $$\text{Temperature }(^\circ\text{F}) = (\text{raw\_value} \times 0.9) - 40.0$$
  - Example: Raw `116` $\rightarrow$ $(116 \times 0.9) - 40.0 = \mathbf{64.4^\circ\text{F}}$.
  - Humidity sensors: Raw value is directly relative humidity ($0 \dots 100\%$).

---

## 3. Codebase Map

| File | Purpose |
|---|---|
| [`lumina_bridge.py`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/lumina_bridge.py) | **The Core Service**. Contains `LuminaController` (UDP protocol, AES encryption, sequence unmasking, polling) and `LuminaBridge` (MQTT broker client, Home Assistant Auto-Discovery, command routing, safety interlocks). |
| [`PCA3D_EN.cs`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/PCA3D_EN.cs) | **The Bible (Decompiled PC Access 3)**. 5.3 MB of decompiled C# containing exact packet structures, opcode definitions, and hardware behavior. Use `grep_search` on this file when investigating any protocol question. |
| [`config.json`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/config.json) / [`config.example.json`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/config.example.json) | Production and template configuration files (IPs, credentials, zones, units, audio zones). |
| [`homeassistant_template_media_players.yaml`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/homeassistant_template_media_players.yaml) | Companion YAML for Home Assistant `media_player` template entities that bind discrete MQTT switches, sliders, and selects into unified cards. |
| [`install.sh`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/install.sh) | Automated 1-step installer for Debian/Proxmox (creates user, venv, installs requirements, sets up systemd service). |
| [`update.sh`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/update.sh) | 1-step update script for production host (pulls git, updates venv, restarts systemd service). |
| [`lumina-bridge.service`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/lumina-bridge.service) | Systemd unit configuration file. |
| [`README.md`](file:///c:/Users/stroh/Documents/LuminaProStuff/LuminaProHomeAssistantMQTTBridge/README.md) | User-facing documentation with architecture diagrams, setup guide, and developer cheatsheet. |

---

## 4. Key Protocol Details for OmniLink 1 over UDP

### Outer UDP Datagram Framing
```text
Offset  Bytes  Description
0..1      2    Length of (Type + Seq + Payload + CRC16) [Big Endian]
2         1    Packet Type (0x01=ReqSession, 0x02=AckSession, 0x03=Auth, 0x04=AuthAck, 0x10=Encrypted)
3..4      2    Sequence Number (1..65535) [Big Endian]
5..N      Var  Payload (AES-128 ECB encrypted if Type == 0x10)
N+1..N+2  2    CRC-16-CCITT (Polynomial 0x1021, Init 0x0000)
```

### Inner OmniLink Message Framing (Inside Decrypted Payload)
```text
Offset  Bytes  Description
0         1    OmniLink Message Length (excluding length byte)
1         1    OmniLink Opcode (e.g. 0x15, 0x16, 0x19, 0x1A, 0x31, 0x32, 0x0F)
2..M      Var  Message Data
```

### Opcodes in Active Use

| Opcode | Name | Direction | Payload Structure / Meaning |
|---|---|---|---|
| `0x01` | Request Session | Client $\rightarrow$ Board | `[0x05, 0x38, 0x01, seq_hi, seq_lo]` |
| `0x02` | Ack Session | Board $\rightarrow$ Client | 5 bytes containing `SessionID` |
| `0x03` | Authenticate | Client $\rightarrow$ Board | Encrypted session auth packet |
| `0x04` | Auth Acknowledged | Board $\rightarrow$ Client | Session established and ready for traffic |
| `0x05` | ACK | Bi-directional | Used for keep-alive pings and command acknowledgments |
| `0x06` | NAK | Board $\rightarrow$ Client | Request rejected / invalid opcode / malformed payload |
| `0x0F` | Unit / Audio Command | Client $\rightarrow$ Board | `struct.pack(">BBBH", 0x0F, cmd, param, target)` |
| `0x15` | Request Zone Status | Client $\rightarrow$ Board | `[0x04, 0x15, start_zone, end_zone]` |
| `0x16` | Zone Status Data | Board $\rightarrow$ Client | 2 bytes per zone: `[status_bits, loop_reading]` |
| `0x17` | Request Unit Status | Client $\rightarrow$ Board | `[0x04, 0x17, start_unit, end_unit]` |
| `0x18` | Unit Status Data | Board $\rightarrow$ Client | 1 byte per unit: `0=OFF, 1=ON` |
| `0x19` | Request Aux Status | Client $\rightarrow$ Board | `[0x04, 0x19, start_aux, end_aux]` |
| `0x1A` | Aux Status Data | Board $\rightarrow$ Client | 4 bytes per sensor: `[status, raw_temp, low_set, high_set]` |
| `0x31` | Request Audio Status | Client $\rightarrow$ Board | `[0x04, 0x31, start_zone, end_zone]` |
| `0x32` | Audio Status Data | Board $\rightarrow$ Client | 4 bytes per zone: `[power, source, volume, mute]` |

---

## 5. Helpful Commands on the Production Debian Host

```bash
# View real-time logs with clean formatting
sudo journalctl -u lumina-bridge.service -f -o cat

# Check service status and memory usage
sudo systemctl status lumina-bridge.service

# Restart the bridge after editing config.json
sudo systemctl restart lumina-bridge.service

# Update from GitHub in 1 command
cd /opt/lumina-bridge && sudo ./update.sh

# If git complains about dubious ownership:
git config --global --add safe.directory /opt/lumina-bridge
```

---

## 6. Ideas for Future Agents (Potential Expansions)

If the user asks for more features, here is what can easily be added next using the existing V1 architecture:

1. **Thermostat Integration**:
   - V1 Opcode `0x23` (`RequestThermostatStatus`) and `0x24` (`ThermostatStatusData`).
   - Supports mode (Off/Heat/Cool/Auto), fan status, current temp, heat setpoint, cool setpoint.
2. **Lighting Scene Triggers**:
   - V1 Opcode `0x0F` supports executing buttons/macros (`cmd=0x01`, `target=button_id`).
   - Can be exposed as Home Assistant buttons or scenes.
3. **Security Partition Status**:
   - V1 Opcode `0x1B` (`RequestAreaStatus`) and `0x1C` (`AreaStatusData`).
   - Supports arming states (Disarmed, Day, Night, Away, Vacation).
4. **Local Web Debugger / Packet Inspector**:
   - An optional lightweight `aiohttp` web server running inside the bridge on port 8080 showing live UDP packet counts, loop times, and decoded zone readings.
