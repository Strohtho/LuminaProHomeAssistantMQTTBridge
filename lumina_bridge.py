#!/usr/bin/env python3
"""
Leviton Lumina Pro to Home Assistant MQTT Bridge
=================================================
Reverse-engineered Omni-Link II UDP protocol implementation extracted directly
from HAI/Leviton PC Access 3 (PCA3D_EN.cs).

Features:
- Non-blocking UDP transport using asyncio.DatagramProtocol on port 4369.
- Omni-Link II session handshake, AES-128 ECB encryption, and sequence masking.
- Automatic session keep-alive watchdog and re-handshake on timeout/NAK.
- Asynchronous notification streaming and periodic status polling.
- Home Assistant MQTT auto-discovery for:
    * Environmental & Motion Sensors (Temp Dining, Hum Dining, 3 Motion loops)
    * 7 Motorized Window Covers with software interlocking and runtime protection
    * 4 HAI Hi-Fi 2 Audio Zones (Power, Volume, Mute, Source Select)
- Single device linkage: "Leviton Lumina Pro" (identifiers: ["lumina_pro_main_panel"]).
- Graceful shutdown with session cleanup (SIGINT/SIGTERM).
"""

import argparse
import asyncio
import json
import logging
import signal
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple, Any

# ---------------------------------------------------------------------------
# Cryptography: PyCryptodome with Built-in Pure-Python AES-128 ECB Fallback
# ---------------------------------------------------------------------------
try:
    from Cryptodome.Cipher import AES as NativeAES
except ImportError:
    try:
        from Crypto.Cipher import AES as NativeAES
    except ImportError:
        NativeAES = None

# S-Box for AES
_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

_INV_SBOX = [0] * 256
for _i, _s in enumerate(_SBOX):
    _INV_SBOX[_s] = _i

_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def _mul(a: int, b: int) -> int:
    res = 0
    while b > 0:
        if b & 1:
            res ^= a
        a = _xtime(a)
        b >>= 1
    return res


def _aes_key_expansion(key: bytes) -> List[int]:
    w = list(key)
    for i in range(16, 176, 4):
        t = w[i - 4 : i]
        if i % 16 == 0:
            t = [_SBOX[t[1]], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            t[0] ^= _RCON[i // 16]
        for j in range(4):
            w.append(w[i - 16 + j] ^ t[j])
    return w


def _aes_encrypt_block(block: bytes, w: List[int]) -> bytes:
    state = list(block)
    for i in range(16):
        state[i] ^= w[i]
    for rnd in range(1, 10):
        state = [_SBOX[x] for x in state]
        state = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11]
        ]
        new_state = [0] * 16
        for c in range(4):
            idx = c * 4
            s0, s1, s2, s3 = state[idx], state[idx + 1], state[idx + 2], state[idx + 3]
            new_state[idx] = _xtime(s0) ^ _xtime(s1) ^ s1 ^ s2 ^ s3
            new_state[idx + 1] = s0 ^ _xtime(s1) ^ _xtime(s2) ^ s2 ^ s3
            new_state[idx + 2] = s0 ^ s1 ^ _xtime(s2) ^ _xtime(s3) ^ s3
            new_state[idx + 3] = _xtime(s0) ^ s0 ^ s1 ^ s2 ^ _xtime(s3)
        state = new_state
        kw = w[rnd * 16 : (rnd + 1) * 16]
        for i in range(16):
            state[i] ^= kw[i]
    state = [_SBOX[x] for x in state]
    state = [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ]
    kw = w[160:176]
    for i in range(16):
        state[i] ^= kw[i]
    return bytes(state)


def _aes_decrypt_block(block: bytes, w: List[int]) -> bytes:
    state = list(block)
    kw = w[160:176]
    for i in range(16):
        state[i] ^= kw[i]
    for rnd in range(9, 0, -1):
        state = [
            state[0], state[13], state[10], state[7],
            state[4], state[1], state[14], state[11],
            state[8], state[5], state[2], state[15],
            state[12], state[9], state[6], state[3]
        ]
        state = [_INV_SBOX[x] for x in state]
        kw = w[rnd * 16 : (rnd + 1) * 16]
        for i in range(16):
            state[i] ^= kw[i]
        new_state = [0] * 16
        for c in range(4):
            idx = c * 4
            s0, s1, s2, s3 = state[idx], state[idx + 1], state[idx + 2], state[idx + 3]
            new_state[idx] = _mul(s0, 0x0E) ^ _mul(s1, 0x0B) ^ _mul(s2, 0x0D) ^ _mul(s3, 0x09)
            new_state[idx + 1] = _mul(s0, 0x09) ^ _mul(s1, 0x0E) ^ _mul(s2, 0x0B) ^ _mul(s3, 0x0D)
            new_state[idx + 2] = _mul(s0, 0x0D) ^ _mul(s1, 0x09) ^ _mul(s2, 0x0E) ^ _mul(s3, 0x0B)
            new_state[idx + 3] = _mul(s0, 0x0B) ^ _mul(s1, 0x0D) ^ _mul(s2, 0x09) ^ _mul(s3, 0x0E)
        state = new_state
    state = [
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3]
    ]
    state = [_INV_SBOX[x] for x in state]
    kw = w[0:16]
    for i in range(16):
        state[i] ^= kw[i]
    return bytes(state)


def aes_encrypt_ecb(key: bytes, data: bytes) -> bytes:
    if NativeAES is not None:
        cipher = NativeAES.new(key, NativeAES.MODE_ECB)
        return cipher.encrypt(data)
    w = _aes_key_expansion(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out.extend(_aes_encrypt_block(data[i : i + 16], w))
    return bytes(out)


def aes_decrypt_ecb(key: bytes, data: bytes) -> bytes:
    if NativeAES is not None:
        cipher = NativeAES.new(key, NativeAES.MODE_ECB)
        return cipher.decrypt(data)
    w = _aes_key_expansion(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out.extend(_aes_decrypt_block(data[i : i + 16], w))
    return bytes(out)


# ---------------------------------------------------------------------------
# Omni-Link II CRC-16 Calculation (clsUtil.CRC16Add / polynomial 0xA001)
# ---------------------------------------------------------------------------
def crc16_add(b: int, crc: int) -> int:
    crc ^= b
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0xA001
        else:
            crc >>= 1
    return crc & 0xFFFF


def calculate_omnilink_crc16(data: bytes) -> int:
    """Calculates CRC-16 over bytes (starts with MessageLength, excludes StartChar 0x5A)."""
    crc = 0
    for b in data:
        crc = crc16_add(b, crc)
    return crc


# ---------------------------------------------------------------------------
# Protocol Constants & Enums (Extracted from PCA3D_EN.cs)
# ---------------------------------------------------------------------------
OMNILINK_START_CHAR = 0x5A  # enuOmniLinkMessageFormat.NonAddressable (90)

# enuOmniLinkPacketType
PKT_CLIENT_REQUEST_NEW_SESSION = 0x01
PKT_CONTROLLER_ACK_NEW_SESSION = 0x02
PKT_CLIENT_REQUEST_SECURE_SESSION = 0x03
PKT_CONTROLLER_ACK_SECURE_SESSION = 0x04
PKT_CLIENT_SESSION_TERMINATED = 0x05
PKT_CONTROLLER_SESSION_TERMINATED = 0x06
PKT_CONTROLLER_CANNOT_START = 0x07
PKT_OMNILINK_MESSAGE = 0x10  # 16
PKT_OMNILINK_UNENCRYPTED = 0x11  # 17

# enuOmniLink2MessageType
MSG_ACK = 0x01
MSG_NAK = 0x02
MSG_COMMAND = 0x14  # 20
MSG_ENABLE_NOTIFICATIONS = 0x15  # 21 in PCA3D_EN.cs
MSG_REQUEST_STATUS = 0x22  # 34
MSG_STATUS_REPORT = 0x23  # 35
MSG_SYSTEM_EVENTS = 0x37  # 55
MSG_REQUEST_EXT_STATUS = 0x3A  # 58
MSG_EXT_STATUS_REPORT = 0x3B  # 59

# enuObjectType
OBJ_ZONE = 0x01
OBJ_UNIT = 0x02
OBJ_AUDIO_ZONE = 0x0A  # 10 in decimal

# enuUnitCommand
CMD_UNIT_OFF = 0x00
CMD_UNIT_ON = 0x01
CMD_AUDIO_ZONE = 112  # 0x70 in PCA3D_EN.cs
CMD_AUDIO_VOLUME = 113  # 0x71 in PCA3D_EN.cs
CMD_AUDIO_SOURCE = 114  # 0x72 in PCA3D_EN.cs

# enuAudioStatus
AUDIO_STATUS_OFF = 0
AUDIO_STATUS_ON = 1
AUDIO_STATUS_MUTE_OFF = 2
AUDIO_STATUS_MUTE_ON = 3


# ---------------------------------------------------------------------------
# Asynchronous UDP Protocol Layer (asyncio.DatagramProtocol)
# ---------------------------------------------------------------------------
class LuminaDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, message_callback, error_callback):
        self.message_callback = message_callback
        self.error_callback = error_callback
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        self.message_callback(data, addr)

    def error_received(self, exc: Exception):
        self.error_callback(exc)

    def connection_lost(self, exc: Optional[Exception]):
        if exc:
            self.error_callback(exc)


# ---------------------------------------------------------------------------
# Leviton Lumina Pro Protocol Engine
# ---------------------------------------------------------------------------
class LuminaController:
    def __init__(self, config: dict, on_status_update=None):
        self.logger = logging.getLogger("LuminaController")
        self.cfg = config.get("lumina", {})
        self.host = self.cfg.get("host", "192.168.187.5")
        self.port = int(self.cfg.get("port", 4369))
        key_hex = self.cfg.get("key", "11111111111111111111111111111111")
        self.controller_key = bytes.fromhex(key_hex)
        if len(self.controller_key) != 16:
            raise ValueError(f"Controller key must be 16 bytes (32 hex characters), got {len(self.controller_key)}")

        self.keepalive_interval = float(self.cfg.get("keepalive_interval_sec", 20.0))
        self.poll_interval = float(self.cfg.get("poll_interval_sec", 10.0))
        self.recv_timeout = float(self.cfg.get("receive_timeout_sec", 3.0))
        self.max_retries = int(self.cfg.get("max_retries", 5))

        self.on_status_update = on_status_update
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[LuminaDatagramProtocol] = None

        self._seq = 1
        self._session_id: Optional[bytes] = None
        self._session_key: Optional[bytes] = None
        self._online_secure = False
        self._pending_requests: Dict[int, asyncio.Future] = {}
        self._running = False
        self._handshake_lock = asyncio.Lock()
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                self._loop = None

    @property
    def is_connected(self) -> bool:
        return self._online_secure

    def _next_seq(self) -> int:
        seq = self._seq
        self._seq = (self._seq + 1) & 0xFFFF
        if self._seq == 0:
            self._seq = 1
        return seq

    async def start(self):
        """Initializes UDP transport and establishes secure session."""
        self._running = True
        if self._loop is None:
            self._loop = asyncio.get_running_loop()
        self.logger.info("Initializing UDP transport to Lumina Pro at %s:%d", self.host, self.port)
        self.transport, self.protocol = await self._loop.create_datagram_endpoint(
            lambda: LuminaDatagramProtocol(self._on_datagram, self._on_udp_error),
            remote_addr=(self.host, self.port)
        )
        await self._establish_session()
        asyncio.create_task(self._watchdog_loop())
        asyncio.create_task(self._polling_loop())

    async def stop(self):
        """Gracefully terminates session and closes socket."""
        self._running = False
        if self._online_secure and self.transport:
            try:
                seq = self._next_seq()
                term_pkt = struct.pack(">HBB", seq, PKT_CLIENT_SESSION_TERMINATED, 0x00)
                self.transport.sendto(term_pkt)
                self.logger.info("Sent ClientSessionTerminated to controller")
            except Exception as e:
                self.logger.debug("Error sending session termination: %s", e)
        if self.transport:
            self.transport.close()
        self._online_secure = False

    def _on_udp_error(self, exc: Exception):
        self.logger.warning("UDP Transport error: %s", exc)

    def _on_datagram(self, data: bytes, addr: Tuple[str, int]):
        if len(data) < 4:
            return
        seq_num, pkt_type, reserved = struct.unpack(">HBB", data[:4])
        if reserved != 0:
            return

        payload = data[4:]
        # Unsolicited event packets from controller arrive with SequenceNumber == 0
        if seq_num == 0:
            if pkt_type == PKT_OMNILINK_MESSAGE and self._session_key:
                msg = self._decrypt_omnilink_message(0, payload)
                if msg:
                    self._handle_omnilink_message(msg)
            return

        # Check for matching pending request
        future = self._pending_requests.get(seq_num)
        if future and not future.done():
            future.set_result((pkt_type, payload))

    async def _establish_session(self) -> bool:
        async with self._handshake_lock:
            self._online_secure = False
            self.logger.info("Starting Omni-Link II session handshake...")

            for attempt in range(1, self.max_retries + 1):
                try:
                    # 1. Client Request New Session (Opcode 0x01)
                    seq1 = self._next_seq()
                    pkt1 = struct.pack(">HBB", seq1, PKT_CLIENT_REQUEST_NEW_SESSION, 0x00)
                    fut1 = self._loop.create_future()
                    self._pending_requests[seq1] = fut1
                    self.transport.sendto(pkt1)

                    pkt_type1, payload1 = await asyncio.wait_for(fut1, timeout=self.recv_timeout)
                    self._pending_requests.pop(seq1, None)

                    if pkt_type1 != PKT_CONTROLLER_ACK_NEW_SESSION or len(payload1) < 7:
                        self.logger.warning("Handshake attempt %d: Invalid ack new session reply (type=%s)", attempt, pkt_type1)
                        await asyncio.sleep(1.5)
                        continue

                    # Protocol validation: bytes 0..1 in payload must be 0x00, 0x01
                    if payload1[0] != 0x00 or payload1[1] != 0x01:
                        self.logger.error("Controller returned unsupported protocol version: %02X %02X", payload1[0], payload1[1])
                        await asyncio.sleep(2.0)
                        continue

                    # Extract 5-byte Session ID (bytes 2..6 of payload = bytes 6..10 of UDP packet)
                    session_id = payload1[2:7]
                    self._session_id = session_id

                    # Derive Session Key: ControllerKey[11..15] ^ SessionID[0..4]
                    session_key = bytearray(self.controller_key)
                    for j in range(5):
                        session_key[11 + j] ^= session_id[j]
                    self._session_key = bytes(session_key)

                    # 2. Client Request Secure Session (Opcode 0x03)
                    seq2 = self._next_seq()
                    # Pad SessionID (5 bytes) with zeros to 16 bytes
                    sec_block = bytearray(session_id + bytes(11))
                    # Mask block 0 with sequence number
                    sec_block[0] ^= (seq2 >> 8) & 0xFF
                    sec_block[1] ^= seq2 & 0xFF
                    enc_block = aes_encrypt_ecb(self._session_key, bytes(sec_block))

                    pkt2 = struct.pack(">HBB", seq2, PKT_CLIENT_REQUEST_SECURE_SESSION, 0x00) + enc_block
                    fut2 = self._loop.create_future()
                    self._pending_requests[seq2] = fut2
                    self.transport.sendto(pkt2)

                    pkt_type2, payload2 = await asyncio.wait_for(fut2, timeout=self.recv_timeout)
                    self._pending_requests.pop(seq2, None)

                    if pkt_type2 == PKT_CONTROLLER_ACK_SECURE_SESSION:
                        self._online_secure = True
                        self.logger.info("Omni-Link II secure session ESTABLISHED successfully!")
                        # Enable real-time notifications
                        await self.enable_notifications(True)
                        # Trigger immediate initial status poll
                        await self.request_initial_statuses()
                        return True
                    elif pkt_type2 == PKT_CONTROLLER_SESSION_TERMINATED:
                        self.logger.error("Controller terminated session: Invalid encryption key!")
                    elif pkt_type2 == PKT_CONTROLLER_CANNOT_START:
                        self.logger.warning("Controller reported: Cannot start new session (busy)")

                except asyncio.TimeoutError:
                    self.logger.warning("Handshake attempt %d timed out waiting for reply", attempt)
                except Exception as e:
                    self.logger.error("Handshake attempt %d encountered exception: %s", attempt, e)

                await asyncio.sleep(2.0)

            self.logger.error("Failed to establish secure session after %d attempts", self.max_retries)
            return False

    def _encrypt_omnilink_message(self, seq: int, payload: bytes) -> bytes:
        """Packs application payload into framed OmniLink non-addressable packet and encrypts it."""
        msg_len = len(payload)
        # CRC calculated over [MessageLength, Payload...]
        crc_data = bytes([msg_len]) + payload
        crc = calculate_omnilink_crc16(crc_data)

        # Raw frame: [0x5A, Length, Data..., CRC_Low, CRC_High]
        raw = bytes([OMNILINK_START_CHAR, msg_len]) + payload + bytes([crc & 0xFF, (crc >> 8) & 0xFF])

        # Zero pad to multiple of 16
        pad_len = (16 - (len(raw) % 16)) % 16
        padded = bytearray(raw + bytes(pad_len))

        # Mask each 16-byte block with sequence number
        seq_h = (seq >> 8) & 0xFF
        seq_l = seq & 0xFF
        for offset in range(0, len(padded), 16):
            padded[offset] ^= seq_h
            padded[offset + 1] ^= seq_l

        enc = aes_encrypt_ecb(self._session_key, bytes(padded))
        return struct.pack(">HBB", seq, PKT_OMNILINK_MESSAGE, 0x00) + enc

    def _decrypt_omnilink_message(self, seq: int, data: bytes) -> Optional[bytes]:
        """Decrypts and verifies CRC of an incoming OmniLink application frame."""
        if not self._session_key or len(data) < 16 or len(data) % 16 != 0:
            return None

        dec = bytearray(aes_decrypt_ecb(self._session_key, data))
        seq_h = (seq >> 8) & 0xFF
        seq_l = seq & 0xFF
        for offset in range(0, len(dec), 16):
            dec[offset] ^= seq_h
            dec[offset + 1] ^= seq_l

        # Frame structure: [StartChar, Length, Data..., CRC_Low, CRC_High, (Padding)]
        if len(dec) < 4:
            return None
        start_char = dec[0]
        if start_char not in (0x5A, 0x21):
            return None

        msg_len = dec[1]
        if len(dec) < 2 + msg_len + 2:
            return None

        payload = bytes(dec[2 : 2 + msg_len])
        crc_recv = dec[2 + msg_len] | (dec[2 + msg_len + 1] << 8)
        crc_calc = calculate_omnilink_crc16(bytes([msg_len]) + payload)

        if crc_recv != crc_calc:
            self.logger.warning("OmniLink CRC mismatch: received 0x%04X, calculated 0x%04X", crc_recv, crc_calc)
            return None

        return payload

    async def send_message(self, payload: bytes, expect_reply: bool = True) -> Optional[bytes]:
        """Sends an encrypted OmniLink message with sequence matching and automatic retry."""
        if not self._online_secure:
            if not await self._establish_session():
                return None

        for attempt in range(1, self.max_retries + 1):
            seq = self._next_seq()
            pkt = self._encrypt_omnilink_message(seq, payload)

            if not expect_reply:
                self.transport.sendto(pkt)
                return None

            fut = self._loop.create_future()
            self._pending_requests[seq] = fut
            self.transport.sendto(pkt)

            try:
                pkt_type, resp_payload = await asyncio.wait_for(fut, timeout=self.recv_timeout)
                self._pending_requests.pop(seq, None)

                if pkt_type == PKT_OMNILINK_MESSAGE:
                    msg = self._decrypt_omnilink_message(seq, resp_payload)
                    if msg:
                        self._handle_omnilink_message(msg)
                        return msg
                elif pkt_type == PKT_CONTROLLER_SESSION_TERMINATED:
                    self.logger.warning("Controller terminated session during send; re-handshaking...")
                    self._online_secure = False
                    await self._establish_session()
            except asyncio.TimeoutError:
                self._pending_requests.pop(seq, None)
                self.logger.debug("Request seq=%d timed out (attempt %d/%d)", seq, attempt, self.max_retries)
            except Exception as e:
                self._pending_requests.pop(seq, None)
                self.logger.error("Error during send_message: %s", e)

            await asyncio.sleep(0.5)

        self.logger.warning("Message send failed after %d retries; marking session offline", self.max_retries)
        self._online_secure = False
        return None

    async def enable_notifications(self, enable: bool = True):
        """Enables real-time asynchronous notifications on the Lumina Pro controller."""
        self.logger.info("Enabling real-time notifications...")
        # Exact wire format from clsOL2EnableNotifications in PCA3D_EN.cs (MessageType 0x15, Data 0x01)
        payload_15 = bytes([MSG_ENABLE_NOTIFICATIONS, 0x01 if enable else 0x00])
        await self.send_message(payload_15, expect_reply=False)
        # Also send opcode 0x38 as compatibility fallback
        payload_38 = bytes([0x38, 0x01 if enable else 0x00])
        await self.send_message(payload_38, expect_reply=False)

    async def request_status(self, obj_type: int, start_num: int, end_num: int):
        """Requests status report for a range of objects (Opcode 0x22)."""
        payload = struct.pack(">BBHH", MSG_REQUEST_STATUS, obj_type, start_num, end_num)
        await self.send_message(payload, expect_reply=True)

    async def send_command(self, cmd: int, param: int, target: int):
        """Dispatches direct command (Opcode 0x14 - clsOL2MsgCommand)."""
        payload = struct.pack(">BBBH", MSG_COMMAND, cmd, param, target)
        self.logger.debug("Dispatching command: cmd=%d, param=%d, target=%d (payload: %s)", cmd, param, target, payload.hex())
        await self.send_message(payload, expect_reply=False)

    async def request_initial_statuses(self):
        """Queries initial status for all active sensors, window contacts, and audio zones."""
        self.logger.info("Querying initial object statuses from controller...")
        # Zones 1 to 16 (covers Temp 1, Hum 2, Motion 8, 9, 10)
        await self.request_status(OBJ_ZONE, 1, 16)
        # Zones 48 to 60 (covers Window contact sensors 49..55)
        await self.request_status(OBJ_ZONE, 48, 60)
        # Audio Zones 1 to 4 (covers Living, Dining, Bath, Bed)
        await self.request_status(OBJ_AUDIO_ZONE, 1, 4)

    async def _watchdog_loop(self):
        """Periodic keep-alive watchdog matching clsOmniLinkConnection.WatchdogTimeout."""
        while self._running:
            await asyncio.sleep(self.keepalive_interval)
            if self._online_secure:
                # Send clsOL2MsgAcknowledge (MessageType 0x01)
                ack_payload = bytes([MSG_ACK])
                await self.send_message(ack_payload, expect_reply=False)
            else:
                await self._establish_session()

    async def _polling_loop(self):
        """Periodic background status poll to ensure state integrity over UDP."""
        while self._running:
            await asyncio.sleep(self.poll_interval)
            if self._online_secure:
                await self.request_status(OBJ_ZONE, 1, 16)
                await self.request_status(OBJ_ZONE, 48, 60)
                await self.request_status(OBJ_AUDIO_ZONE, 1, 4)

    def _handle_omnilink_message(self, msg: bytes):
        """Parses decoded Omni-Link II message payloads."""
        if not msg:
            return
        msg_type = msg[0]

        # Status Report (0x23)
        if msg_type == MSG_STATUS_REPORT:
            self._parse_status_report(msg)
        # Extended Status Report (0x3B)
        elif msg_type == MSG_EXT_STATUS_REPORT:
            self._parse_ext_status_report(msg)
        # System Events (0x37)
        elif msg_type == MSG_SYSTEM_EVENTS and len(msg) >= 3:
            event_code = (msg[1] << 8) | msg[2]
            self.logger.debug("Received System Event notification: 0x%04X", event_code)

    def _parse_status_report(self, msg: bytes):
        """Unpacks standard status reports (clsOL2MsgStatus)."""
        if len(msg) < 2:
            return
        obj_type = msg[1]
        data = msg[2:]

        # Zones (4 bytes per record)
        if obj_type == OBJ_ZONE:
            for i in range(0, len(data), 4):
                if i + 4 > len(data):
                    break
                obj_num = (data[i] << 8) | data[i + 1]
                status_byte = data[i + 2]
                analog_loop = data[i + 3]
                if self.on_status_update:
                    self.on_status_update("zone", obj_num, {"status": status_byte, "loop": analog_loop})

        # Audio Zones (6 bytes per record)
        elif obj_type == OBJ_AUDIO_ZONE:
            for i in range(0, len(data), 6):
                if i + 6 > len(data):
                    break
                obj_num = (data[i] << 8) | data[i + 1]
                power = data[i + 2] != 0
                source = data[i + 3]
                volume = data[i + 4]
                mute = data[i + 5] != 0
                if self.on_status_update:
                    self.on_status_update("audio", obj_num, {
                        "power": power,
                        "source": source,
                        "volume": volume,
                        "mute": mute
                    })

        # Units (5 bytes per record)
        elif obj_type == OBJ_UNIT:
            for i in range(0, len(data), 5):
                if i + 5 > len(data):
                    break
                obj_num = (data[i] << 8) | data[i + 1]
                status = data[i + 2]
                if self.on_status_update:
                    self.on_status_update("unit", obj_num, {"status": status})

    def _parse_ext_status_report(self, msg: bytes):
        """Unpacks extended status reports (clsOL2MsgExtendedStatus)."""
        if len(msg) < 3:
            return
        obj_type = msg[1]
        obj_len = msg[2]
        if obj_len == 0:
            return
        data = msg[3:]

        if obj_type == OBJ_ZONE and obj_len >= 4:
            for i in range(0, len(data), obj_len):
                if i + obj_len > len(data):
                    break
                obj_num = (data[i] << 8) | data[i + 1]
                status_byte = data[i + 2]
                analog_loop = data[i + 3]
                if self.on_status_update:
                    self.on_status_update("zone", obj_num, {"status": status_byte, "loop": analog_loop})

        elif obj_type == OBJ_AUDIO_ZONE and obj_len >= 6:
            for i in range(0, len(data), obj_len):
                if i + obj_len > len(data):
                    break
                obj_num = (data[i] << 8) | data[i + 1]
                power = data[i + 2] != 0
                source = data[i + 3]
                volume = data[i + 4]
                mute = data[i + 5] != 0
                if self.on_status_update:
                    self.on_status_update("audio", obj_num, {
                        "power": power,
                        "source": source,
                        "volume": volume,
                        "mute": mute
                    })


# ---------------------------------------------------------------------------
# Motorized Window Actuator Controller (Software Interlocking & Timers)
# ---------------------------------------------------------------------------
class WindowActuator:
    def __init__(self, key: str, config: dict, lumina: LuminaController, publish_callback):
        self.key = key
        self.name = config.get("name", key)
        self.contact_zone = int(config["contact_zone"])
        self.open_unit = int(config["open_unit"])
        self.close_unit = int(config["close_unit"])
        self.runtime = float(config.get("runtime_sec", 60.0))

        self.lumina = lumina
        self.publish = publish_callback
        self.logger = logging.getLogger(f"WindowActuator.{key}")

        self.state = "closed"
        self._motion_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    def update_contact(self, status_byte: int):
        """Called when zone contact sensor updates."""
        # Bit 0 = 0 means loop is secure/closed. Bit 0 = 1 means tripped/open.
        is_closed = (status_byte & 0x01) == 0

        # If currently moving, stop early if contact becomes closed during closing
        if self.state == "closing" and is_closed:
            self.logger.info("%s reached closed position; turning off relay early", self.name)
            if self._motion_task and not self._motion_task.done():
                self._motion_task.cancel()
            asyncio.create_task(self._finish_stop("closed"))
            return

        # If not moving, sync state with physical contact
        if self.state not in ("opening", "closing"):
            new_state = "closed" if is_closed else "open"
            if new_state != self.state:
                self.state = new_state
                self.publish(f"lumina/cover/{self.key}/state", self.state)

    async def handle_command(self, cmd: str):
        cmd = cmd.strip().upper()
        async with self._lock:
            if cmd == "OPEN":
                await self._execute_open()
            elif cmd == "CLOSE":
                await self._execute_close()
            elif cmd == "STOP":
                await self._execute_stop()

    async def _execute_open(self):
        self.logger.info("Opening %s...", self.name)
        if self._motion_task and not self._motion_task.done():
            self._motion_task.cancel()

        # Interlock: Ensure closing relay is OFF
        await self.lumina.send_command(CMD_UNIT_OFF, 0, self.close_unit)
        # 0.5s safety interlock delay
        await asyncio.sleep(0.5)

        # Pulse target open relay ON
        await self.lumina.send_command(CMD_UNIT_ON, 0, self.open_unit)
        self.state = "opening"
        self.publish(f"lumina/cover/{self.key}/state", self.state)

        self._motion_task = asyncio.create_task(self._runtime_watcher("open", self.open_unit))

    async def _execute_close(self):
        self.logger.info("Closing %s...", self.name)
        if self._motion_task and not self._motion_task.done():
            self._motion_task.cancel()

        # Interlock: Ensure opening relay is OFF
        await self.lumina.send_command(CMD_UNIT_OFF, 0, self.open_unit)
        # 0.5s safety interlock delay
        await asyncio.sleep(0.5)

        # Pulse target close relay ON
        await self.lumina.send_command(CMD_UNIT_ON, 0, self.close_unit)
        self.state = "closing"
        self.publish(f"lumina/cover/{self.key}/state", self.state)

        self._motion_task = asyncio.create_task(self._runtime_watcher("closed", self.close_unit))

    async def _execute_stop(self):
        self.logger.info("Stopping %s...", self.name)
        if self._motion_task and not self._motion_task.done():
            self._motion_task.cancel()
        await self.lumina.send_command(CMD_UNIT_OFF, 0, self.open_unit)
        await self.lumina.send_command(CMD_UNIT_OFF, 0, self.close_unit)
        self.state = "stopped"
        self.publish(f"lumina/cover/{self.key}/state", self.state)

    async def _finish_stop(self, final_state: str):
        await self.lumina.send_command(CMD_UNIT_OFF, 0, self.open_unit)
        await self.lumina.send_command(CMD_UNIT_OFF, 0, self.close_unit)
        self.state = final_state
        self.publish(f"lumina/cover/{self.key}/state", self.state)

    async def _runtime_watcher(self, final_state: str, active_unit: int):
        try:
            await asyncio.sleep(self.runtime)
            self.logger.info("%s runtime (%ds) elapsed; turning off relay %d", self.name, int(self.runtime), active_unit)
            await self.lumina.send_command(CMD_UNIT_OFF, 0, active_unit)
            self.state = final_state
            self.publish(f"lumina/cover/{self.key}/state", self.state)
        except asyncio.CancelledError:
            await self.lumina.send_command(CMD_UNIT_OFF, 0, active_unit)


# ---------------------------------------------------------------------------
# Home Assistant MQTT Bridge Service (paho-mqtt v2)
# ---------------------------------------------------------------------------
class LuminaMqttBridge:
    def __init__(self, config_path: str):
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = json.load(f)

        self.logger = logging.getLogger("LuminaBridge")
        self.mqtt_cfg = self.config.get("mqtt", {})
        self.disc_prefix = self.mqtt_cfg.get("discovery_prefix", "homeassistant")
        self.base_topic = self.mqtt_cfg.get("base_topic", "lumina")
        self.avail_topic = f"{self.base_topic}/status"

        self.lumina = LuminaController(self.config, on_status_update=self._on_lumina_status)
        self.windows: Dict[str, WindowActuator] = {}
        self.audio_zones = self.config.get("audio_zones", {})
        self.audio_sources = self.config.get("audio_sources", {})
        self.source_id_to_name = {int(k): v for k, v in self.audio_sources.items()}
        self.source_name_to_id = {v: int(k) for k, v in self.audio_sources.items()}
        self.sensors = self.config.get("sensors", {})

        self.mqtt_client = None
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                self._loop = None
        self._init_windows()

    def _init_windows(self):
        for key, wcfg in self.config.get("windows", {}).items():
            actuator = WindowActuator(key, wcfg, self.lumina, self.publish_mqtt)
            self.windows[key] = actuator

    def publish_mqtt(self, topic: str, payload: str, retain: bool = False):
        if self.mqtt_client:
            self.mqtt_client.publish(topic, payload, qos=1, retain=retain)

    def _on_lumina_status(self, entity_type: str, obj_num: int, data: dict):
        """Dispatches status updates from Lumina controller to MQTT."""
        if entity_type == "zone":
            # Check sensors
            for s_key, scfg in self.sensors.items():
                if int(scfg["zone"]) == obj_num:
                    stype = scfg.get("type", "")
                    loop_val = data.get("loop", 0)
                    status_byte = data.get("status", 0)

                    if stype == "temperature_er":
                        # Raw loop conversion formula to Fahrenheit: Temp_F = -40.0 + (0.5 * loop_val)
                        temp_f = -40.0 + (0.5 * loop_val)
                        self.publish_mqtt(f"{self.base_topic}/zone/{obj_num}/temperature", f"{temp_f:.1f}")
                    elif stype == "humidity":
                        # Humidity: raw loop value = percentage 0-100%
                        self.publish_mqtt(f"{self.base_topic}/zone/{obj_num}/humidity", str(loop_val))
                    elif stype == "motion":
                        # Motion: Bit 0 of status byte = tripped/not ready
                        tripped = (status_byte & 0x01) != 0
                        self.publish_mqtt(f"{self.base_topic}/zone/{obj_num}/state", "ON" if tripped else "OFF")

            # Check window contacts
            for w in self.windows.values():
                if w.contact_zone == obj_num:
                    w.update_contact(data.get("status", 0))

        elif entity_type == "audio":
            zone_id_str = str(obj_num)
            if zone_id_str in self.audio_zones:
                power = data.get("power", False)
                source_id = data.get("source", 1)
                volume = data.get("volume", 0)
                mute = data.get("mute", False)

                self.publish_mqtt(f"{self.base_topic}/audio/{obj_num}/power/state", "ON" if power else "OFF")
                self.publish_mqtt(f"{self.base_topic}/audio/{obj_num}/volume/state", str(volume))
                self.publish_mqtt(f"{self.base_topic}/audio/{obj_num}/mute/state", "ON" if mute else "OFF")

                src_name = self.source_id_to_name.get(source_id, f"Source {source_id}")
                self.publish_mqtt(f"{self.base_topic}/audio/{obj_num}/source/state", src_name)

    def _setup_mqtt(self):
        import paho.mqtt.client as mqtt

        # Paho-MQTT v2 compatibility with fallback
        try:
            from paho.mqtt.enums import CallbackAPIVersion
            self.mqtt_client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=self.mqtt_cfg.get("client_id", "lumina_pro_bridge"))
        except (ImportError, AttributeError):
            self.mqtt_client = mqtt.Client(client_id=self.mqtt_cfg.get("client_id", "lumina_pro_bridge"))

        user = self.mqtt_cfg.get("username")
        pw = self.mqtt_cfg.get("password")
        if user and pw:
            self.mqtt_client.username_pw_set(user, pw)

        self.mqtt_client.will_set(self.avail_topic, "offline", qos=1, retain=True)

        def on_connect(client, userdata, flags, rc, properties=None):
            if rc == 0:
                self.logger.info("Connected to MQTT Broker!")
                self.publish_mqtt(self.avail_topic, "online", retain=True)
                self.publish_discovery()
                self._subscribe_topics()
            else:
                self.logger.error("Failed to connect to MQTT broker, return code %d", rc)

        def on_message(client, userdata, msg):
            asyncio.run_coroutine_threadsafe(self._handle_mqtt_message(msg.topic, msg.payload.decode("utf-8")), self._loop)

        self.mqtt_client.on_connect = on_connect
        self.mqtt_client.on_message = on_message

        m_host = self.mqtt_cfg.get("host", "127.0.0.1")
        m_port = int(self.mqtt_cfg.get("port", 1883))
        self.logger.info("Connecting to MQTT broker at %s:%d...", m_host, m_port)
        self.mqtt_client.connect(m_host, m_port, keepalive=60)
        self.mqtt_client.loop_start()

    def _subscribe_topics(self):
        # Subscribe to cover command topics
        for w_key in self.windows.keys():
            t = f"{self.base_topic}/cover/{w_key}/set"
            self.mqtt_client.subscribe(t, qos=1)

        # Subscribe to audio command topics
        for z_id in self.audio_zones.keys():
            self.mqtt_client.subscribe(f"{self.base_topic}/audio/{z_id}/power/set", qos=1)
            self.mqtt_client.subscribe(f"{self.base_topic}/audio/{z_id}/volume/set", qos=1)
            self.mqtt_client.subscribe(f"{self.base_topic}/audio/{z_id}/mute/set", qos=1)
            self.mqtt_client.subscribe(f"{self.base_topic}/audio/{z_id}/source/set", qos=1)

    async def _handle_mqtt_message(self, topic: str, payload: str):
        payload = payload.strip()
        parts = topic.split("/")

        # Cover command: lumina/cover/{key}/set
        if len(parts) >= 4 and parts[1] == "cover" and parts[3] == "set":
            w_key = parts[2]
            if w_key in self.windows:
                await self.windows[w_key].handle_command(payload)

        # Audio command: lumina/audio/{zone_id}/{param}/set
        elif len(parts) >= 5 and parts[1] == "audio" and parts[4] == "set":
            zone_id = int(parts[2])
            param = parts[3]

            if param == "power":
                val = AUDIO_STATUS_ON if payload.upper() == "ON" else AUDIO_STATUS_OFF
                await self.lumina.send_command(CMD_AUDIO_ZONE, val, zone_id)
            elif param == "mute":
                val = AUDIO_STATUS_MUTE_ON if payload.upper() == "ON" else AUDIO_STATUS_MUTE_OFF
                await self.lumina.send_command(CMD_AUDIO_ZONE, val, zone_id)
            elif param == "volume":
                try:
                    vol = max(0, min(100, int(float(payload))))
                    await self.lumina.send_command(CMD_AUDIO_VOLUME, vol, zone_id)
                except ValueError:
                    self.logger.warning("Invalid volume payload: %s", payload)
            elif param == "source":
                src_id = self.source_name_to_id.get(payload)
                if src_id is not None:
                    await self.lumina.send_command(CMD_AUDIO_SOURCE, src_id, zone_id)
                else:
                    self.logger.warning("Unknown audio source name: %s", payload)

    def publish_discovery(self):
        """Auto-publishes Home Assistant discovery configurations for all entities."""
        self.logger.info("Publishing Home Assistant MQTT discovery payloads...")

        device_info = {
            "identifiers": ["lumina_pro_main_panel"],
            "name": "Leviton Lumina Pro",
            "manufacturer": "Leviton / HAI",
            "model": "Lumina Pro (FW 2.14)",
            "sw_version": "2.14"
        }

        # 1. Environmental & Motion Sensors
        for s_key, scfg in self.sensors.items():
            zone = int(scfg["zone"])
            name = scfg.get("name", s_key)
            stype = scfg.get("type", "")

            if stype == "temperature_er":
                disc_topic = f"{self.disc_prefix}/sensor/lumina/temp_dining/config"
                payload = {
                    "name": name,
                    "unique_id": f"lumina_zone_{zone}_temperature",
                    "state_topic": f"{self.base_topic}/zone/{zone}/temperature",
                    "unit_of_measurement": "°F",
                    "device_class": "temperature",
                    "state_class": "measurement",
                    "availability_topic": self.avail_topic,
                    "device": device_info
                }
                self.publish_mqtt(disc_topic, json.dumps(payload), retain=True)

            elif stype == "humidity":
                disc_topic = f"{self.disc_prefix}/sensor/lumina/hum_dining/config"
                payload = {
                    "name": name,
                    "unique_id": f"lumina_zone_{zone}_humidity",
                    "state_topic": f"{self.base_topic}/zone/{zone}/humidity",
                    "unit_of_measurement": "%",
                    "device_class": "humidity",
                    "state_class": "measurement",
                    "availability_topic": self.avail_topic,
                    "device": device_info
                }
                self.publish_mqtt(disc_topic, json.dumps(payload), retain=True)

            elif stype == "motion":
                disc_topic = f"{self.disc_prefix}/binary_sensor/lumina/{s_key}/config"
                payload = {
                    "name": name,
                    "unique_id": f"lumina_zone_{zone}_motion",
                    "state_topic": f"{self.base_topic}/zone/{zone}/state",
                    "payload_on": "ON",
                    "payload_off": "OFF",
                    "device_class": "motion",
                    "availability_topic": self.avail_topic,
                    "device": device_info
                }
                self.publish_mqtt(disc_topic, json.dumps(payload), retain=True)

        # 2. Motorized Window Actuators (7 Covers)
        for w_key, wcfg in self.config.get("windows", {}).items():
            name = wcfg.get("name", w_key)
            disc_topic = f"{self.disc_prefix}/cover/lumina/{w_key}/config"
            payload = {
                "name": name,
                "unique_id": f"lumina_cover_{w_key}",
                "command_topic": f"{self.base_topic}/cover/{w_key}/set",
                "state_topic": f"{self.base_topic}/cover/{w_key}/state",
                "payload_open": "OPEN",
                "payload_close": "CLOSE",
                "payload_stop": "STOP",
                "state_open": "open",
                "state_opening": "opening",
                "state_closed": "closed",
                "state_closing": "closing",
                "state_stopped": "stopped",
                "device_class": "window",
                "availability_topic": self.avail_topic,
                "device": device_info
            }
            self.publish_mqtt(disc_topic, json.dumps(payload), retain=True)

        # 3. HAI Hi-Fi 2 Audio System (4 Zones)
        source_options = [self.source_id_to_name[i] for i in sorted(self.source_id_to_name.keys())]

        for z_id_str, zcfg in self.audio_zones.items():
            z_id = int(z_id_str)
            z_name = zcfg.get("name", f"Audio Zone {z_id}")
            slug = zcfg.get("slug", f"audio_{z_id}")

            # Power Switch
            disc_power = f"{self.disc_prefix}/switch/lumina/{slug}_power/config"
            payload_power = {
                "name": f"{z_name} Power",
                "unique_id": f"lumina_audio_{z_id}_power",
                "command_topic": f"{self.base_topic}/audio/{z_id}/power/set",
                "state_topic": f"{self.base_topic}/audio/{z_id}/power/state",
                "payload_on": "ON",
                "payload_off": "OFF",
                "availability_topic": self.avail_topic,
                "device": device_info
            }
            self.publish_mqtt(disc_power, json.dumps(payload_power), retain=True)

            # Volume Number
            disc_vol = f"{self.disc_prefix}/number/lumina/{slug}_volume/config"
            payload_vol = {
                "name": f"{z_name} Volume",
                "unique_id": f"lumina_audio_{z_id}_volume",
                "command_topic": f"{self.base_topic}/audio/{z_id}/volume/set",
                "state_topic": f"{self.base_topic}/audio/{z_id}/volume/state",
                "min": 0,
                "max": 100,
                "step": 1,
                "unit_of_measurement": "%",
                "availability_topic": self.avail_topic,
                "device": device_info
            }
            self.publish_mqtt(disc_vol, json.dumps(payload_vol), retain=True)

            # Mute Switch
            disc_mute = f"{self.disc_prefix}/switch/lumina/{slug}_mute/config"
            payload_mute = {
                "name": f"{z_name} Mute",
                "unique_id": f"lumina_audio_{z_id}_mute",
                "command_topic": f"{self.base_topic}/audio/{z_id}/mute/set",
                "state_topic": f"{self.base_topic}/audio/{z_id}/mute/state",
                "payload_on": "ON",
                "payload_off": "OFF",
                "availability_topic": self.avail_topic,
                "device": device_info
            }
            self.publish_mqtt(disc_mute, json.dumps(payload_mute), retain=True)

            # Source Select
            disc_src = f"{self.disc_prefix}/select/lumina/{slug}_source/config"
            payload_src = {
                "name": f"{z_name} Source",
                "unique_id": f"lumina_audio_{z_id}_source",
                "command_topic": f"{self.base_topic}/audio/{z_id}/source/set",
                "state_topic": f"{self.base_topic}/audio/{z_id}/source/state",
                "options": source_options,
                "availability_topic": self.avail_topic,
                "device": device_info
            }
            self.publish_mqtt(disc_src, json.dumps(payload_src), retain=True)

    async def run(self):
        if self._loop is None:
            self._loop = asyncio.get_running_loop()
        self._setup_mqtt()
        await self.lumina.start()

    async def stop(self):
        self.logger.info("Stopping bridge service...")
        self.publish_mqtt(self.avail_topic, "offline", retain=True)
        await self.lumina.stop()
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()


# ---------------------------------------------------------------------------
# Main Execution & Signal Handling
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Leviton Lumina Pro to MQTT Home Assistant Bridge")
    parser.add_argument("-c", "--config", default="config.json", help="Path to config.json file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s"
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    bridge = LuminaMqttBridge(args.config)

    async def shutdown(sig_name):
        logging.info("Received signal %s; shutting down cleanly...", sig_name)
        await bridge.stop()
        tasks = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task(loop)]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        loop.stop()

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(s.name)))
        except NotImplementedError:
            # Signal handling on Windows platform
            pass

    try:
        loop.create_task(bridge.run())
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        loop.close()
        logging.info("Bridge stopped cleanly.")


if __name__ == "__main__":
    main()
