// SPDX-License-Identifier: BSD-3-Clause
//! Trezor-Host Protocol (THP) — foundation layer for 2025+ Trezor models (Safe 5/7, T3W1) that
//! speak only the new encrypted protocol and reject the legacy Codec-v1 client with
//! `Failure_InvalidProtocol`.
//!
//! STATUS: WORK IN PROGRESS — NOT yet wired into the wallet's hardware flow. This module implements
//! the deterministic, unit-testable pieces of THP so the highest-risk correctness code (framing +
//! Noise-XX crypto) can be verified without hardware:
//!   * transport packet segmentation / reassembly with CRC-32/IEEE (L2),
//!   * the THP-specific HKDF and the Noise_XX_25519_AESGCM_SHA256 symmetric-state math (L3 host side).
//!
//! Still required before a real 2025+ Trezor can connect (each needs the physical device to test):
//!   * raw USB (WebUSB interface) transport + the Alternating-Bit ACK/sync sub-layer,
//!   * channel allocation (parse `ThpDeviceProperties`),
//!   * CodeEntry pairing (CPace over Curve25519 + Elligator2) with a new UI to enter the 6-digit
//!     code shown on the device, plus pairing-credential storage,
//!   * session creation with the BIP39 passphrase and the encrypted Ethereum message exchange.
//!
//! Spec: https://docs.trezor.io/trezor-firmware/common/thp/specification.html

#![allow(dead_code)] // scaffolding — consumed as the remaining THP stages are implemented

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// USB data-transfer packet size for all Trezor models (Section "USB packet size").
pub const USB_PACKET_SIZE: usize = 64;

/// Broadcast channel used for channel allocation requests/responses.
pub const CID_BROADCAST: u16 = 0xFFFF;

/// Control-byte constants (Section "Transport packet structure"). Only the exact-match ones are
/// listed; segmenting/handshake control bytes carry sub-fields and are built where used.
pub mod control {
    pub const CHANNEL_ALLOCATION_REQUEST: u8 = 0x40;
    pub const CHANNEL_ALLOCATION_RESPONSE: u8 = 0x41;
    pub const TRANSPORT_ERROR: u8 = 0x42;
    pub const PING: u8 = 0x43;
    pub const PONG: u8 = 0x44;
    pub const CONTINUATION: u8 = 0x80;
    // Handshake / encrypted-transport control bytes (bits 000XX0nn, the XX are ACK/seq fields which
    // are ORed in by the sync layer): base values with those bits zeroed.
    pub const HANDSHAKE_INIT_REQUEST: u8 = 0x00;
    pub const HANDSHAKE_INIT_RESPONSE: u8 = 0x01;
    pub const HANDSHAKE_COMPLETION_REQUEST: u8 = 0x02;
    pub const HANDSHAKE_COMPLETION_RESPONSE: u8 = 0x03;
    pub const ENCRYPTED_TRANSPORT: u8 = 0x04;
    pub const ACK: u8 = 0x20;
}

/// Noise protocol name for THP (Section "Common definitions"): the ASCII name padded to 32 bytes
/// with four trailing NULs (`Noise_XX_25519_AESGCM_SHA256` is 28 bytes + 4 NULs = 32).
pub fn protocol_name() -> [u8; 32] {
    let mut out = [0u8; 32];
    let name = b"Noise_XX_25519_AESGCM_SHA256";
    out[..name.len()].copy_from_slice(name);
    out
}

// -------------------------------------------------------------------------------------------------
// L2 — CRC-32/IEEE error detection
// -------------------------------------------------------------------------------------------------

/// CRC-32/IEEE (poly 0x04C11DB7, reversed 0xEDB88320; init/xorout 0xFFFFFFFF; reflected in/out) as
/// specified in the "Error detection layer" section. Verified against the standard "123456789"
/// check value 0xCBF43926 in the tests.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// -------------------------------------------------------------------------------------------------
// L2 — Segmenting layer (initiation + continuation packets)
// -------------------------------------------------------------------------------------------------

/// Segment a transport payload into 64-byte USB packets for channel `cid` with the given
/// `control_byte`. The CRC-32 (computed over the initiation header + payload, per spec) is appended
/// to the payload before segmentation; the final packet is zero-padded.
pub fn segment(control_byte: u8, cid: u16, payload: &[u8]) -> Vec<[u8; USB_PACKET_SIZE]> {
    // length field = size of "transport payload with CRC" = payload + 4 CRC bytes.
    let length = (payload.len() as u16).wrapping_add(4);

    // CRC is computed over: control_byte || cid(BE) || length(BE) || payload.
    let mut crc_input = Vec::with_capacity(5 + payload.len());
    crc_input.push(control_byte);
    crc_input.extend_from_slice(&cid.to_be_bytes());
    crc_input.extend_from_slice(&length.to_be_bytes());
    crc_input.extend_from_slice(payload);
    let crc = crc32(&crc_input);

    // transport payload with CRC
    let mut body = Vec::with_capacity(payload.len() + 4);
    body.extend_from_slice(payload);
    body.extend_from_slice(&crc.to_be_bytes());

    let mut packets = Vec::new();
    let mut off = 0usize;

    // Initiation packet: [control(1), cid(2), length(2), body...]
    let mut init = [0u8; USB_PACKET_SIZE];
    init[0] = control_byte;
    init[1..3].copy_from_slice(&cid.to_be_bytes());
    init[3..5].copy_from_slice(&length.to_be_bytes());
    let first = std::cmp::min(USB_PACKET_SIZE - 5, body.len());
    init[5..5 + first].copy_from_slice(&body[..first]);
    packets.push(init);
    off += first;

    // Continuation packets: [0x80, cid(2), body...]
    while off < body.len() {
        let mut cont = [0u8; USB_PACKET_SIZE];
        cont[0] = control::CONTINUATION;
        cont[1..3].copy_from_slice(&cid.to_be_bytes());
        let n = std::cmp::min(USB_PACKET_SIZE - 3, body.len() - off);
        cont[3..3 + n].copy_from_slice(&body[off..off + n]);
        packets.push(cont);
        off += n;
    }
    packets
}

/// A reassembled transport payload (control byte + CID + payload with the CRC already validated and
/// stripped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportMessage {
    pub control_byte: u8,
    pub cid: u16,
    pub payload: Vec<u8>,
}

/// Reassemble a full transport message from its 64-byte packets (single channel). Validates the
/// CRC and returns the payload with the CRC stripped. Errors on truncation / CRC mismatch.
pub fn reassemble(packets: &[[u8; USB_PACKET_SIZE]]) -> Result<TransportMessage, String> {
    let init = packets.first().ok_or("no packets")?;
    let control_byte = init[0];
    if control_byte & control::CONTINUATION != 0 {
        return Err("first packet is not an initiation packet".into());
    }
    let cid = u16::from_be_bytes([init[1], init[2]]);
    let length = u16::from_be_bytes([init[3], init[4]]) as usize; // payload+CRC size

    let mut body = Vec::with_capacity(length);
    body.extend_from_slice(&init[5..]);
    for p in &packets[1..] {
        if p[0] != control::CONTINUATION {
            return Err("expected a continuation packet".into());
        }
        body.extend_from_slice(&p[3..]);
    }
    if body.len() < length {
        return Err("incomplete transport payload".into());
    }
    body.truncate(length); // drop padding
    if length < 4 {
        return Err("payload shorter than CRC".into());
    }
    let (payload, crc_bytes) = body.split_at(length - 4);

    // Recompute the CRC over control||cid||length||payload and compare.
    let mut crc_input = Vec::with_capacity(5 + payload.len());
    crc_input.push(control_byte);
    crc_input.extend_from_slice(&cid.to_be_bytes());
    crc_input.extend_from_slice(&(length as u16).to_be_bytes());
    crc_input.extend_from_slice(payload);
    let want = u32::from_be_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
    if crc32(&crc_input) != want {
        return Err("CRC mismatch".into());
    }
    Ok(TransportMessage { control_byte, cid, payload: payload.to_vec() })
}

// -------------------------------------------------------------------------------------------------
// L3 — Noise_XX_25519_AESGCM_SHA256 crypto helpers
// -------------------------------------------------------------------------------------------------

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// THP's HKDF (Section "Common definitions"): returns (output_1, output_2).
///   temp_key = HMAC(ck, input); o1 = HMAC(temp, 0x01); o2 = HMAC(temp, o1 || 0x02).
pub fn hkdf(ck: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac_sha256(ck, input);
    let o1 = hmac_sha256(&temp, &[0x01]);
    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(&o1);
    buf[32] = 0x02;
    let o2 = hmac_sha256(&temp, &buf);
    (o1, o2)
}

/// IV = 0^96 (all-zero 12-byte nonce).
fn iv_zero() -> [u8; 12] {
    [0u8; 12]
}

/// IV = 0^95 || 1 (12-byte big-endian nonce equal to 1).
fn iv_one() -> [u8; 12] {
    let mut n = [0u8; 12];
    n[11] = 1;
    n
}

/// AES-256-GCM encrypt with a 12-byte IV and associated data, returning ciphertext || 16-byte tag.
pub fn aes_gcm_encrypt(key: &[u8; 32], iv: &[u8; 12], ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(iv), Payload { msg: plaintext, aad: ad })
        .expect("aes-gcm encrypt")
}

/// AES-256-GCM decrypt (ciphertext || tag). Returns None on authentication failure.
pub fn aes_gcm_decrypt(key: &[u8; 32], iv: &[u8; 12], ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(Nonce::from_slice(iv), Payload { msg: ciphertext, aad: ad }).ok()
}

/// Raw X25519 scalar multiplication (RFC 7748), as used throughout the handshake (incl. with the
/// masked static key, whose "scalar" is a SHA-256 digest).
pub fn x25519(scalar: [u8; 32], point: [u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(scalar, point)
}

/// Host-side Noise-XX handshake state machine (Section "Host's state machine"). Deterministic given
/// the device's ephemeral/static responses; the transport (USB + ACK) that carries these messages
/// is a separate, hardware-dependent layer not yet implemented.
pub struct HostHandshake {
    h: [u8; 32],  // running handshake hash
    ck: [u8; 32], // chaining key
    k: [u8; 32],  // current symmetric key
    eph_priv: [u8; 32],
    eph_pub: [u8; 32],
}

impl HostHandshake {
    /// HH0: begin the handshake, producing the `HandshakeInitiationRequest` payload
    /// (`host_ephemeral_pubkey || try_to_unlock`). `device_properties` is the raw
    /// `ThpDeviceProperties` bytes received in the channel-allocation response.
    pub fn start(eph_priv: [u8; 32], device_properties: &[u8], try_to_unlock: u8) -> (Self, Vec<u8>) {
        let eph_pub = x25519(eph_priv, X25519_BASEPOINT);
        let mut req = Vec::with_capacity(33);
        req.extend_from_slice(&eph_pub);
        req.push(try_to_unlock);
        // h starts folding in the transcript; steps 1-4 of HH1 also run on the device side (TH1).
        let h0 = sha256(&[&protocol_name(), device_properties]);
        let h1 = sha256(&[&h0, &eph_pub]);
        let h2 = sha256(&[&h1, &[try_to_unlock]]);
        (
            Self { h: h2, ck: [0u8; 32], k: [0u8; 32], eph_priv, eph_pub },
            req,
        )
    }

    /// HH1: process `HandshakeInitiationResponse` (trezor_ephemeral_pubkey ||
    /// encrypted_trezor_static_pubkey(48) || tag(16)) and produce the
    /// `HandshakeCompletionRequest` payload, given the host's static key pair and an optional
    /// pairing credential. Returns (completion_request_bytes, trezor_masked_static_pubkey).
    pub fn respond(
        &mut self,
        response: &[u8],
        host_static_priv: [u8; 32],
        host_static_pub: [u8; 32],
        host_pairing_credential: Option<&[u8]>,
    ) -> Result<Vec<u8>, String> {
        if response.len() < 32 + 48 + 16 {
            return Err("short handshake init response".into());
        }
        let trezor_eph_pub: [u8; 32] = response[0..32].try_into().unwrap();
        let enc_static = &response[32..80];
        let tag = &response[80..96];

        self.h = sha256(&[&self.h, &trezor_eph_pub]);
        let (ck, k) = hkdf(&protocol_name(), &x25519(self.eph_priv, trezor_eph_pub));
        self.ck = ck;
        self.k = k;
        let masked_static = aes_gcm_decrypt(&self.k, &iv_zero(), &self.h, enc_static)
            .ok_or("decrypt trezor static failed")?;
        let masked_static: [u8; 32] =
            masked_static.as_slice().try_into().map_err(|_| "bad masked static len")?;
        self.h = sha256(&[&self.h, enc_static]);
        let (ck, k) = hkdf(&self.ck, &x25519(self.eph_priv, masked_static));
        self.ck = ck;
        self.k = k;
        // tag authenticates the empty string
        let empty = aes_gcm_decrypt(&self.k, &iv_zero(), &self.h, tag).ok_or("bad handshake tag")?;
        if !empty.is_empty() {
            return Err("handshake tag payload not empty".into());
        }
        self.h = sha256(&[&self.h, tag]);

        // Encrypt host static pubkey (IV = 0^95||1)
        let enc_host_static = aes_gcm_encrypt(&self.k, &iv_one(), &self.h, &host_static_pub);
        self.h = sha256(&[&self.h, &enc_host_static]);
        let (ck, k) = hkdf(&self.ck, &x25519(host_static_priv, trezor_eph_pub));
        self.ck = ck;
        self.k = k;
        // Noise payload: ThpHandshakeCompletionReqNoisePayload { host_pairing_credential = 1 }
        let payload_binary = match host_pairing_credential {
            Some(cred) => proto_bytes_field(1, cred),
            None => Vec::new(),
        };
        let enc_payload = aes_gcm_encrypt(&self.k, &iv_zero(), &self.h, &payload_binary);
        self.h = sha256(&[&self.h, &enc_payload]);

        let mut out = Vec::with_capacity(enc_host_static.len() + enc_payload.len());
        out.extend_from_slice(&enc_host_static);
        out.extend_from_slice(&enc_payload);
        Ok(out)
    }

    /// The handshake hash, used as the transcript binder by the CodeEntry/QrCode pairing methods.
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.h
    }

    /// HH2/HH3: derive the traffic keys after the completion response. Returns (key_request,
    /// key_response); request messages (host->Trezor) use key_request, responses use key_response.
    pub fn traffic_keys(&self) -> ([u8; 32], [u8; 32]) {
        hkdf(&self.ck, &[])
    }
}

/// Curve25519 base point u=9.
const X25519_BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// Encode a single protobuf (proto2 wire) length-delimited bytes field: tag = (field<<3)|2.
fn proto_bytes_field(field: u32, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    let tag = (field << 3) | 2;
    write_varint(&mut out, tag as u64);
    write_varint(&mut out, value.len() as u64);
    out.extend_from_slice(value);
    out
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn read_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let b = *data.get(*pos)?;
        *pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

/// A decoded protobuf field value (only the wire types THP/Ethereum messages use).
#[derive(Debug, Clone)]
pub enum WireVal {
    Varint(u64),
    Bytes(Vec<u8>),
}

/// Minimal proto2 decoder: returns (field_number, value) pairs. Handles wire types 0 (varint) and
/// 2 (length-delimited); skips 5 (32-bit) and 1 (64-bit) so unknown fields don't abort parsing.
pub fn proto_decode(data: &[u8]) -> Vec<(u32, WireVal)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let Some(tag) = read_varint(data, &mut pos) else { break };
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        match wire {
            0 => {
                let Some(v) = read_varint(data, &mut pos) else { break };
                out.push((field, WireVal::Varint(v)));
            }
            2 => {
                let Some(len) = read_varint(data, &mut pos) else { break };
                let len = len as usize;
                if pos + len > data.len() {
                    break;
                }
                out.push((field, WireVal::Bytes(data[pos..pos + len].to_vec())));
                pos += len;
            }
            5 => pos += 4,
            1 => pos += 8,
            _ => break,
        }
    }
    out
}

/// proto2 length-delimited string field.
pub fn proto_string_field(field: u32, value: &str) -> Vec<u8> {
    proto_bytes_field(field, value.as_bytes())
}

/// proto2 varint field.
pub fn proto_varint_field(field: u32, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, ((field as u64) << 3) | 0); // wire type 0
    write_varint(&mut out, value);
    out
}

// -------------------------------------------------------------------------------------------------
// Wire message-type identifiers (from messages.proto / messages-thp.proto)
// -------------------------------------------------------------------------------------------------

/// Trezor wire message-type IDs used by the THP flow.
pub mod msgtype {
    // Common (messages.proto)
    pub const FAILURE: u16 = 3;
    pub const SUCCESS: u16 = 2;
    pub const BUTTON_REQUEST: u16 = 26;
    pub const BUTTON_ACK: u16 = 27;
    // THP (messages-thp.proto)
    pub const THP_CREATE_NEW_SESSION: u16 = 1000;
    pub const THP_PAIRING_REQUEST: u16 = 1008;
    pub const THP_PAIRING_REQUEST_APPROVED: u16 = 1009;
    pub const THP_SELECT_METHOD: u16 = 1010;
    pub const THP_PAIRING_PREPARATIONS_FINISHED: u16 = 1011;
    pub const THP_CREDENTIAL_REQUEST: u16 = 1016;
    pub const THP_CREDENTIAL_RESPONSE: u16 = 1017;
    pub const THP_END_REQUEST: u16 = 1018;
    pub const THP_END_RESPONSE: u16 = 1019;
    pub const THP_CODE_ENTRY_COMMITMENT: u16 = 1024;
    pub const THP_CODE_ENTRY_CHALLENGE: u16 = 1025;
    pub const THP_CODE_ENTRY_CPACE_TREZOR: u16 = 1026;
    pub const THP_CODE_ENTRY_CPACE_HOST_TAG: u16 = 1027;
    pub const THP_CODE_ENTRY_SECRET: u16 = 1028;
    // Ethereum (messages-ethereum.proto)
    pub const ETHEREUM_GET_ADDRESS: u16 = 56;
    pub const ETHEREUM_ADDRESS: u16 = 57;
    pub const ETHEREUM_SIGN_TX_EIP1559: u16 = 452;
    pub const ETHEREUM_TX_REQUEST: u16 = 59;
    pub const ETHEREUM_TX_ACK: u16 = 60;
}

/// Numeric pairing-method identifiers (ThpPairingMethod).
pub mod pairing_method {
    pub const SKIP_PAIRING: u32 = 1;
    pub const CODE_ENTRY: u32 = 2;
    pub const QR_CODE: u32 = 3;
    pub const NFC: u32 = 4;
}

// -------------------------------------------------------------------------------------------------
// L2.4 — Channel allocation
// -------------------------------------------------------------------------------------------------

/// Trezor device properties advertised in `ChannelAllocationResponse` (`ThpDeviceProperties`).
#[derive(Debug, Clone, Default)]
pub struct DeviceProperties {
    pub internal_model: String,
    pub model_variant: u32,
    pub protocol_version_major: u32,
    pub protocol_version_minor: u32,
    pub pairing_methods: Vec<u32>,
    pub raw: Vec<u8>, // exact bytes, needed verbatim as the handshake transcript prefix
}

/// Build the `ChannelAllocationRequest` transport payload (an 8-byte random nonce).
pub fn channel_allocation_request(nonce: [u8; 8]) -> Vec<u8> {
    nonce.to_vec()
}

/// Parse a `ChannelAllocationResponse` payload: nonce(8) || cid(2) || device_properties(var).
/// Returns (nonce, cid, device_properties).
pub fn parse_channel_allocation_response(payload: &[u8]) -> Result<([u8; 8], u16, DeviceProperties), String> {
    if payload.len() < 10 {
        return Err("short channel allocation response".into());
    }
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&payload[..8]);
    let cid = u16::from_be_bytes([payload[8], payload[9]]);
    let raw = payload[10..].to_vec();
    let mut props = DeviceProperties { raw: raw.clone(), ..Default::default() };
    for (field, val) in proto_decode(&raw) {
        match (field, val) {
            (1, WireVal::Bytes(b)) => props.internal_model = String::from_utf8_lossy(&b).into_owned(),
            (2, WireVal::Varint(v)) => props.model_variant = v as u32,
            (3, WireVal::Varint(v)) => props.protocol_version_major = v as u32,
            (4, WireVal::Varint(v)) => props.protocol_version_minor = v as u32,
            (5, WireVal::Varint(v)) => props.pairing_methods.push(v as u32),
            _ => {}
        }
    }
    Ok((nonce, cid, props))
}

// -------------------------------------------------------------------------------------------------
// L4 — Application layer framing + encrypted transport
// -------------------------------------------------------------------------------------------------

/// Build the application-layer plaintext: session_id(1) || message_type(2 BE) || protobuf.
pub fn app_frame(session_id: u8, message_type: u16, protobuf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + protobuf.len());
    out.push(session_id);
    out.extend_from_slice(&message_type.to_be_bytes());
    out.extend_from_slice(protobuf);
    out
}

/// Parse an application-layer plaintext into (session_id, message_type, protobuf).
pub fn parse_app_frame(data: &[u8]) -> Result<(u8, u16, &[u8]), String> {
    if data.len() < 3 {
        return Err("short app frame".into());
    }
    Ok((data[0], u16::from_be_bytes([data[1], data[2]]), &data[3..]))
}

/// The post-handshake encrypted channel. Request messages (host->Trezor) use `key_request`; response
/// messages (Trezor->host) use `key_response`. Per the spec the response nonce starts at 1 (nonce 0
/// of key_response encrypted the handshake `trezor_state`), the request nonce starts at 0. Each
/// direction increments its own 96-bit big-endian counter by one per message.
///
/// NOTE (UNVERIFIED without hardware): the AES-GCM associated-data for application messages is taken
/// as empty here (Noise transport messages carry no AAD); confirm against a real device.
pub struct EncryptedChannel {
    pub key_request: [u8; 32],
    pub key_response: [u8; 32],
    pub nonce_request: u64,
    pub nonce_response: u64,
}

fn nonce_be(counter: u64) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[4..].copy_from_slice(&counter.to_be_bytes());
    iv
}

impl EncryptedChannel {
    pub fn new(key_request: [u8; 32], key_response: [u8; 32]) -> Self {
        Self { key_request, key_response, nonce_request: 0, nonce_response: 1 }
    }

    /// Encrypt an application message (host->Trezor). Returns ciphertext||tag to be segmented with
    /// the `encrypted_transport` control byte.
    pub fn encrypt_request(&mut self, app_plaintext: &[u8]) -> Vec<u8> {
        let ct = aes_gcm_encrypt(&self.key_request, &nonce_be(self.nonce_request), &[], app_plaintext);
        self.nonce_request += 1;
        ct
    }

    /// Decrypt a response message (Trezor->host).
    pub fn decrypt_response(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let pt = aes_gcm_decrypt(&self.key_response, &nonce_be(self.nonce_response), &[], ciphertext)?;
        self.nonce_response += 1;
        Some(pt)
    }
}

// -------------------------------------------------------------------------------------------------
// Ethereum application messages (built on the trezor protobuf wire format)
// -------------------------------------------------------------------------------------------------

/// Encode `EthereumGetAddress { address_n: m/44'/60'/0'/0/index, show_display: false }`. `address_n`
/// is repeated uint32 (field 1); Trezor accepts packed or unpacked — we emit unpacked for safety.
pub fn ethereum_get_address(path: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for &p in path {
        out.extend_from_slice(&proto_varint_field(1, p as u64));
    }
    out
}

/// Parse `EthereumAddress { address = 2 (string) }` (newer firmware) or `_old_address = 1 (bytes)`.
pub fn parse_ethereum_address(protobuf: &[u8]) -> Option<String> {
    let mut addr = None;
    for (field, val) in proto_decode(protobuf) {
        if let WireVal::Bytes(b) = val {
            if field == 2 {
                return Some(String::from_utf8_lossy(&b).into_owned());
            }
            if field == 1 && addr.is_none() {
                addr = Some(format!("0x{}", hex::encode(&b)));
            }
        }
    }
    addr
}

// -------------------------------------------------------------------------------------------------
// CodeEntry pairing — CPACE-X25519-SHA512 with an Elligator2 generator map
// -------------------------------------------------------------------------------------------------

/// CPace generator from the 6-digit pairing `code` and the handshake hash, per the spec's TP2/HP4.
/// pregenerator = SHA-512(prefix || code_ascii || padding || handshake_hash || 0x00)[:32];
/// generator = ELLIGATOR2(pregenerator).
///
/// NOTE (UNVERIFIED without hardware): the Elligator2 variant (RFC9380 vs legacy map) that Trezor's
/// CPace uses is not pinned by the public spec; RFC9380 is used here and must be confirmed on-device.
pub fn cpace_generator(code: &str, handshake_hash: &[u8; 32]) -> Result<[u8; 32], String> {
    use curve25519_elligator2::{MapToPointVariant, RFC9380};
    use sha2::Sha512;
    // prefix = 0x08 "CPace255" 0x06
    const PREFIX: [u8; 10] = [0x08, 0x43, 0x50, 0x61, 0x63, 0x65, 0x32, 0x35, 0x35, 0x06];
    // padding = 0x6f || 0x00*111 || 0x20
    let mut padding = Vec::with_capacity(113);
    padding.push(0x6f);
    padding.extend(std::iter::repeat(0u8).take(111));
    padding.push(0x20);

    let mut hasher = Sha512::new();
    hasher.update(PREFIX);
    hasher.update(code.as_bytes());
    hasher.update(&padding);
    hasher.update(handshake_hash);
    hasher.update([0x00]);
    let digest = hasher.finalize();
    let mut pregen = [0u8; 32];
    pregen.copy_from_slice(&digest[..32]);

    let point = RFC9380::from_representative(&pregen)
        .into_option()
        .ok_or("elligator2: non-representable pregenerator")?;
    Ok(point.to_montgomery().to_bytes())
}

/// Host side of CPace CodeEntry: given the generator and Trezor's CPace public key, produce
/// (cpace_host_public_key, tag) where tag = SHA-256(shared_secret).
pub fn cpace_host(
    generator: [u8; 32],
    cpace_trezor_public_key: [u8; 32],
    host_private: [u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let host_public = x25519(host_private, generator);
    let shared = x25519(host_private, cpace_trezor_public_key);
    (host_public, sha256(&[&shared]))
}

// -------------------------------------------------------------------------------------------------
// L1 — USB transport (rusb) + the first hardware-testable milestone: channel allocation
// -------------------------------------------------------------------------------------------------
//
// Constants match trezor-client's proven WebUSB transport: VID:PID 1209:53C1, config 0, interface 0,
// endpoint 1 (OUT 0x01 / IN 0x81), 64-byte interrupt transfers.
pub mod usb {
    use super::{control, TransportMessage, USB_PACKET_SIZE};
    use rusb::{DeviceHandle, GlobalContext};
    use std::time::Duration;

    const VID: u16 = 0x1209;
    const PID: u16 = 0x53C1;
    const INTERFACE: u8 = 0;
    const EP_OUT: u8 = 0x01;
    const EP_IN: u8 = 0x81;
    const TIMEOUT: Duration = Duration::from_millis(3000);

    /// A raw 64-byte-packet USB link to a THP Trezor.
    pub struct UsbLink {
        handle: DeviceHandle<GlobalContext>,
    }

    impl UsbLink {
        /// Open the first connected THP Trezor (1209:53C1) and claim its main interface.
        pub fn open() -> Result<Self, String> {
            let mut handle = rusb::open_device_with_vid_pid(VID, PID)
                .ok_or("no THP Trezor (1209:53C1) found — plug it in and unlock it")?;
            // On Linux, detach any kernel driver; harmless/no-op on Windows (WinUSB) and macOS.
            let _ = handle.set_auto_detach_kernel_driver(true);
            handle
                .claim_interface(INTERFACE)
                .map_err(|e| format!("claim interface 0 (close Trezor Suite/Bridge?): {e}"))?;
            Ok(Self { handle })
        }

        pub fn write_packet(&self, pkt: &[u8; USB_PACKET_SIZE]) -> Result<(), String> {
            self.handle
                .write_interrupt(EP_OUT, pkt, TIMEOUT)
                .map(|_| ())
                .map_err(|e| format!("usb write: {e}"))
        }

        pub fn read_packet(&self) -> Result<[u8; USB_PACKET_SIZE], String> {
            let mut buf = [0u8; USB_PACKET_SIZE];
            let n = self
                .handle
                .read_interrupt(EP_IN, &mut buf, TIMEOUT)
                .map_err(|e| format!("usb read: {e}"))?;
            if n != USB_PACKET_SIZE {
                return Err(format!("short usb read: {n} bytes"));
            }
            Ok(buf)
        }

        /// Segment `payload` and send it as a full transport message on channel `cid`.
        pub fn send_message(&self, control_byte: u8, cid: u16, payload: &[u8]) -> Result<(), String> {
            for pkt in super::segment(control_byte, cid, payload) {
                self.write_packet(&pkt)?;
            }
            Ok(())
        }

        /// Read a full transport message (initiation packet + any continuation packets), validating
        /// the CRC. Does NOT handle the ABP ACK layer — used for the channel-allocation exchange,
        /// which is a single request/response on the broadcast channel with no ACKs.
        pub fn recv_message(&self) -> Result<TransportMessage, String> {
            let first = self.read_packet()?;
            if first[0] & control::CONTINUATION != 0 {
                return Err("expected an initiation packet".into());
            }
            let length = u16::from_be_bytes([first[3], first[4]]) as usize; // payload + CRC
            let mut pkts = vec![first];
            let mut have = USB_PACKET_SIZE - 5;
            while have < length {
                pkts.push(self.read_packet()?);
                have += USB_PACKET_SIZE - 3;
            }
            super::reassemble(&pkts)
        }
    }
}

/// STAGE 1-2 HARDWARE MILESTONE: open the device, allocate a channel, and report the device
/// properties. This exercises the USB transport + 64-byte framing + CRC + channel-allocation parse
/// against the real device WITHOUT any crypto or the ABP layer, so it's the safest first thing to
/// verify on a plugged-in 2025+ Trezor. Returns a human/JSON summary.
pub fn probe() -> Result<String, String> {
    let link = usb::UsbLink::open()?;
    let nonce: [u8; 8] = rand::random();
    link.send_message(control::CHANNEL_ALLOCATION_REQUEST, CID_BROADCAST, &channel_allocation_request(nonce))?;
    let resp = link.recv_message()?;
    if resp.control_byte != control::CHANNEL_ALLOCATION_RESPONSE {
        return Err(format!("unexpected control byte 0x{:02x} (wanted channel_allocation_response)", resp.control_byte));
    }
    let (echoed, cid, dp) = parse_channel_allocation_response(&resp.payload)?;
    if echoed != nonce {
        return Err("channel-allocation nonce mismatch".into());
    }
    let methods: Vec<&str> = dp
        .pairing_methods
        .iter()
        .map(|m| match *m {
            pairing_method::SKIP_PAIRING => "SkipPairing",
            pairing_method::CODE_ENTRY => "CodeEntry",
            pairing_method::QR_CODE => "QrCode",
            pairing_method::NFC => "NFC",
            _ => "?",
        })
        .collect();
    Ok(format!(
        "THP OK: model={} variant={} protocol=v{}.{} cid=0x{:04x} pairing_methods=[{}]",
        dp.internal_model, dp.model_variant, dp.protocol_version_major, dp.protocol_version_minor, cid,
        methods.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        // Standard CRC-32/IEEE check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0x0000_0000);
    }

    #[test]
    fn segment_reassemble_roundtrip_small() {
        let payload = b"hello trezor";
        let pkts = segment(control::CHANNEL_ALLOCATION_REQUEST, CID_BROADCAST, payload);
        assert_eq!(pkts.len(), 1);
        let msg = reassemble(&pkts).unwrap();
        assert_eq!(msg.control_byte, control::CHANNEL_ALLOCATION_REQUEST);
        assert_eq!(msg.cid, CID_BROADCAST);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn segment_reassemble_roundtrip_multi_packet() {
        // 300-byte payload spans an initiation + several continuation packets.
        let payload: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let pkts = segment(control::ENCRYPTED_TRANSPORT, 0x1234, &payload);
        assert!(pkts.len() > 1);
        let msg = reassemble(&pkts).unwrap();
        assert_eq!(msg.cid, 0x1234);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn reassemble_detects_corruption() {
        let payload = b"integrity matters";
        let mut pkts = segment(control::PING, 0x00AA, payload);
        pkts[0][10] ^= 0xFF; // flip a payload byte
        assert!(reassemble(&pkts).is_err());
    }

    #[test]
    fn hkdf_is_deterministic_and_distinct_outputs() {
        let (a1, a2) = hkdf(b"chaining-key", b"input-material");
        let (b1, b2) = hkdf(b"chaining-key", b"input-material");
        assert_eq!(a1, b1);
        assert_eq!(a2, b2);
        assert_ne!(a1, a2); // the two outputs must differ
    }

    #[test]
    fn aes_gcm_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let ct = aes_gcm_encrypt(&key, &iv_zero(), b"aad", b"secret");
        assert_eq!(aes_gcm_decrypt(&key, &iv_zero(), b"aad", &ct).as_deref(), Some(&b"secret"[..]));
        // wrong AAD fails authentication
        assert!(aes_gcm_decrypt(&key, &iv_zero(), b"different", &ct).is_none());
    }

    #[test]
    fn x25519_diffie_hellman_agrees() {
        let a_priv = [1u8; 32];
        let b_priv = [2u8; 32];
        let a_pub = x25519(a_priv, X25519_BASEPOINT);
        let b_pub = x25519(b_priv, X25519_BASEPOINT);
        assert_eq!(x25519(a_priv, b_pub), x25519(b_priv, a_pub));
    }

    #[test]
    fn protocol_name_is_padded_to_32() {
        let n = protocol_name();
        assert_eq!(&n[..28], b"Noise_XX_25519_AESGCM_SHA256");
        assert_eq!(&n[28..], &[0u8, 0, 0, 0]);
    }

    #[test]
    fn protobuf_bytes_field_encoding() {
        // field 1, bytes "ab" => tag 0x0A, len 0x02, 'a','b'
        assert_eq!(proto_bytes_field(1, b"ab"), vec![0x0A, 0x02, b'a', b'b']);
    }

    #[test]
    fn protobuf_decode_roundtrip() {
        let mut buf = Vec::new();
        buf.extend(proto_string_field(1, "T3W1"));
        buf.extend(proto_varint_field(3, 2));
        buf.extend(proto_varint_field(4, 1));
        buf.extend(proto_varint_field(5, pairing_method::CODE_ENTRY as u64));
        let fields = proto_decode(&buf);
        assert!(matches!(&fields[0], (1, WireVal::Bytes(b)) if b == b"T3W1"));
        assert!(matches!(fields[1], (3, WireVal::Varint(2))));
        assert!(matches!(fields[3], (5, WireVal::Varint(2))));
    }

    #[test]
    fn channel_allocation_response_parse() {
        // nonce(8) || cid(2) || ThpDeviceProperties{ internal_model="T3W1", major=2, minor=1,
        // pairing_methods=[CodeEntry] }
        let mut props = Vec::new();
        props.extend(proto_string_field(1, "T3W1"));
        props.extend(proto_varint_field(3, 2));
        props.extend(proto_varint_field(4, 1));
        props.extend(proto_varint_field(5, pairing_method::CODE_ENTRY as u64));
        let mut payload = vec![1, 2, 3, 4, 5, 6, 7, 8]; // nonce
        payload.extend_from_slice(&0xABCDu16.to_be_bytes()); // cid
        payload.extend_from_slice(&props);
        let (nonce, cid, dp) = parse_channel_allocation_response(&payload).unwrap();
        assert_eq!(nonce, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(cid, 0xABCD);
        assert_eq!(dp.internal_model, "T3W1");
        assert_eq!(dp.protocol_version_major, 2);
        assert_eq!(dp.pairing_methods, vec![pairing_method::CODE_ENTRY]);
    }

    #[test]
    fn app_frame_roundtrip() {
        let proto = ethereum_get_address(&[44 | 0x8000_0000, 60 | 0x8000_0000, 0x8000_0000, 0, 5]);
        let frame = app_frame(0, msgtype::ETHEREUM_GET_ADDRESS, &proto);
        let (sid, mt, body) = parse_app_frame(&frame).unwrap();
        assert_eq!(sid, 0);
        assert_eq!(mt, msgtype::ETHEREUM_GET_ADDRESS);
        assert_eq!(body, proto.as_slice());
    }

    #[test]
    fn ethereum_address_parse_string_and_legacy() {
        // Newer firmware: address = field 2 (string).
        let s = proto_string_field(2, "0xAbC0000000000000000000000000000000000123");
        assert_eq!(
            parse_ethereum_address(&s).as_deref(),
            Some("0xAbC0000000000000000000000000000000000123")
        );
        // Legacy: _old_address = field 1 (20 raw bytes).
        let raw = proto_bytes_field(1, &[0x11u8; 20]);
        assert_eq!(parse_ethereum_address(&raw).unwrap(), format!("0x{}", "11".repeat(20)));
    }

    #[test]
    fn encrypted_channel_request_nonce_advances() {
        // Same key both directions just to exercise the counters; a request encrypted at nonce 0
        // must decrypt with key_request @ nonce 0.
        let key = [9u8; 32];
        let mut ch = EncryptedChannel::new(key, key);
        let ct = ch.encrypt_request(b"\x00\x00\x38payload"); // arbitrary app frame bytes
        assert_eq!(ch.nonce_request, 1);
        // Decrypt manually at nonce 0 with the request key.
        let pt = aes_gcm_decrypt(&key, &nonce_be(0), &[], &ct).unwrap();
        assert_eq!(pt, b"\x00\x00\x38payload");
    }

    #[test]
    fn cpace_generator_is_deterministic_and_valid_point() {
        let hh = [0x42u8; 32];
        let g1 = cpace_generator("123456", &hh).expect("representable");
        let g2 = cpace_generator("123456", &hh).expect("representable");
        assert_eq!(g1, g2);
        // A different code yields a different generator.
        let g3 = cpace_generator("654321", &hh).expect("representable");
        assert_ne!(g1, g3);
        // The host CPace exchange is internally consistent (tag reproducible).
        let (_pub_a, tag_a) = cpace_host(g1, x25519([3u8; 32], g1), [7u8; 32]);
        let (_pub_b, tag_b) = cpace_host(g1, x25519([3u8; 32], g1), [7u8; 32]);
        assert_eq!(tag_a, tag_b);
    }
}
