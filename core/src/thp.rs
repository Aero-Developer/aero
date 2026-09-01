// SPDX-License-Identifier: BSD-3-Clause
//! Trezor-Host Protocol (THP) - foundation layer for 2025+ Trezor models (Safe 5/7, T3W1) that
//! speak only the new encrypted protocol and reject the legacy Codec-v1 client with
//! `Failure_InvalidProtocol`.
//!
//! This layer is the protocol only. `thp_conn.rs` owns the credential file, the cached connection
//! and the pairing-code prompt, and is what `hardware.rs` calls when the legacy Codec-v1 client is
//! rejected by the device.
//!
//! VERIFIED ON HARDWARE (Trezor Safe 7, `internal_model=T3W1`, protocol v2.1):
//!   * USB enumeration, 64-byte packet framing, CRC-32/IEEE, channel allocation, and
//!     `ThpDeviceProperties` parsing (via `probe()`). The device offers exactly one pairing method,
//!     CodeEntry - there is no SkipPairing, so pairing is mandatory.
//!   * the Alternating-Bit ACK/sync sub-layer and the Noise_XX_25519_AESGCM_SHA256 handshake,
//!     which completes and authenticates (via `handshake_probe()`).
//!   * CodeEntry pairing end to end, credential issuance, and credential reuse on reconnect
//!     (via `pair_probe()`). The 6-digit code derived from the device's secret reproduced the code
//!     displayed on screen exactly, which confirms the pairing method is a single byte in that hash.
//!   * `trezor_state`: 0x00 UNPAIRED observed before pairing, 0x02 PAIRED_AUTOCONNECT observed on
//!     reconnect. Note 0x02 appeared even though we do not request autoconnect: the spec's
//!     channel-replacement rule treats a credential as autoconnect when an older channel with the
//!     same host static key is still cached on the device.
//!
//!   * session creation, passphrase wallets, and Ethereum address derivation (via `address_probe()`).
//!     Session ids are chosen by the host: the device honours the id the create request is sent on,
//!     keeps concurrent sessions isolated (a standard and a passphrase wallet at once returned their
//!     own distinct addresses), and rejects ids that were never created with "Invalid session"
//!     rather than falling back to a default wallet.
//!
//!   * EIP-1559 signing (via `sign_probe()`): the signature the device returned recovered to the
//!     device's own address, which proves the transaction we encoded is the one it signed.
//!
//! Spec: https://docs.trezor.io/trezor-firmware/common/thp/specification.html

#![allow(dead_code)] // scaffolding - consumed as the remaining THP stages are implemented

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

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

    // Synchronization bits carried in the two variable bits of data-message control bytes
    // (`000XX0nn`, mask 0xE7). The spec's table shows both bits as `X` without saying which is
    // which, and the natural reading of the ack row (`0010X000`, mask 0xF7) suggests the sequence
    // bit is 0x08 - that is WRONG. Trezor's own implementation (rust/trezor-thp `control_byte.rs`)
    // defines ACK_BIT = 0x08 and SEQ_BIT = 0x10, and the ack row varies at 0x08 because an ACK
    // message carries the sequence number it is acknowledging, not a sequence number of its own.
    pub const ACK_BIT: u8 = 0x08;
    pub const SEQ_BIT: u8 = 0x10;
    pub const SYNC_MASK: u8 = ACK_BIT | SEQ_BIT;

    /// Mask/value pairs from the "Transport packet structure" table.
    pub fn is_ack(cb: u8) -> bool {
        cb & 0xF7 == ACK
    }
    pub fn is_data(cb: u8) -> bool {
        // handshake_* (0x00..=0x03) and encrypted_transport (0x04) share mask 0xE7.
        matches!(
            cb & !SYNC_MASK,
            HANDSHAKE_INIT_REQUEST
                | HANDSHAKE_INIT_RESPONSE
                | HANDSHAKE_COMPLETION_REQUEST
                | HANDSHAKE_COMPLETION_RESPONSE
                | ENCRYPTED_TRANSPORT
        ) && cb & CONTINUATION == 0
    }
    /// The sequence number a data message carries.
    pub fn seq_of(cb: u8) -> bool {
        cb & SEQ_BIT != 0
    }
    /// The sequence number an ACK is acknowledging.
    pub fn ack_of(cb: u8) -> bool {
        cb & ACK_BIT != 0
    }
    /// Control byte for a standalone ACK of sequence number `seq`.
    pub fn ack_for(seq: bool) -> u8 {
        ACK | if seq { ACK_BIT } else { 0 }
    }
    /// Control byte for a data message with base type `base` and sequence number `seq`.
    pub fn data_with_seq(base: u8, seq: bool) -> u8 {
        (base & !SYNC_MASK) | if seq { SEQ_BIT } else { 0 }
    }
}

/// Transport error codes carried by `transport_error` messages ("Allocation layer").
pub fn transport_error_name(code: u8) -> &'static str {
    match code {
        1 => "TRANSPORT_BUSY",
        2 => "UNALLOCATED_CHANNEL",
        3 => "DECRYPTION_FAILED",
        5 => "DEVICE_LOCKED (unlock the Trezor and retry)",
        _ => "unknown transport error",
    }
}

/// UNALLOCATED_CHANNEL and DECRYPTION_FAILED mean the channel is gone: the host must destroy its
/// channel context and allocate a new one rather than retrying on the dead channel.
pub fn transport_error_is_fatal(code: u8) -> bool {
    matches!(code, 2 | 3)
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
// L2 - CRC-32/IEEE error detection
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
// L2 - Segmenting layer (initiation + continuation packets)
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
// L3 - Noise_XX_25519_AESGCM_SHA256 crypto helpers
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

/// First length-delimited value for `field`, which is all the THP management messages need.
pub fn proto_first_bytes(data: &[u8], field: u32) -> Option<Vec<u8>> {
    proto_decode(data).into_iter().find_map(|(f, v)| match v {
        WireVal::Bytes(b) if f == field => Some(b),
        _ => None,
    })
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
    pub const ETHEREUM_SIGN_TX: u16 = 58;
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
// L2.4 - Channel allocation
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
// L4 - Application layer framing + encrypted transport
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
/// is repeated uint32 (field 1); Trezor accepts packed or unpacked - we emit unpacked for safety.
/// EIP-1559 transaction fields, in the shape the device's `EthereumSignTxEIP1559` expects.
pub struct Eip1559Tx<'a> {
    pub nonce: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub gas_limit: u64,
    /// Recipient as a `0x`-prefixed hex string; empty means contract creation.
    pub to: &'a str,
    pub value: u128,
    pub data: &'a [u8],
    pub chain_id: u64,
}

/// Legacy (pre-EIP-1559) transaction fields, for chains without a fee market.
pub struct LegacyTx<'a> {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: &'a str,
    pub value: u128,
    pub data: &'a [u8],
    pub chain_id: u64,
}

/// Big-endian with leading zero bytes stripped, which is how Trezor encodes these amounts.
/// Zero becomes an empty string, matching the protobuf default.
fn be_minimal(v: u128) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let first_significant = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first_significant..].to_vec()
}

/// Left-pad a signature component to 32 bytes; the device strips leading zeros.
fn pad32(v: &[u8]) -> Result<[u8; 32], String> {
    if v.len() > 32 {
        return Err(format!("signature component is {} bytes, expected at most 32", v.len()));
    }
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    Ok(out)
}

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
// CodeEntry pairing - CPACE-X25519-SHA512 with an Elligator2 generator map
// -------------------------------------------------------------------------------------------------

/// CPace generator from the 6-digit pairing `code` and the handshake hash, per the spec's TP2/HP4.
/// pregenerator = SHA-512(prefix || code_ascii || padding || handshake_hash || 0x00)[:32];
/// generator = ELLIGATOR2(pregenerator).
///
pub fn cpace_generator(code: &str, handshake_hash: &[u8; 32]) -> Result<[u8; 32], String> {
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

    Ok(elligator2_u_coordinate(&pregen))
}

/// `map_to_curve_elligator2_curve25519` from RFC 9380 Appendix G.2.1, returning only the Montgomery
/// u-coordinate - the same thing Trezor's `crypto/elligator2.c` computes, which likewise skips the
/// y-coordinate because CPace never needs it.
///
/// This is written out rather than taken from a crate because the available Elligator2 crate
/// implements the *representative* encoding used for traffic obfuscation, which is a different
/// operation and produces different points. `scripts/cpace_reference.py` is an independent
/// implementation of this same map, and the known-answer test pins the two together.
fn elligator2_u_coordinate(input: &[u8; 32]) -> [u8; 32] {
    use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
    use crypto_bigint::{Encoding, U256};

    // p = 2^255 - 19, little-endian.
    let mut p_bytes = [0xffu8; 32];
    p_bytes[0] = 0xed;
    p_bytes[31] = 0x7f;
    let p = U256::from_le_slice(&p_bytes);
    let params = DynResidueParams::new(&p);
    let res = |v: U256| DynResidue::new(&v, params);

    // Decode as Trezor's curve25519_expand does: little-endian with the high bit masked off.
    let mut masked = *input;
    masked[31] &= 0x7f;
    let u = res(U256::from_le_slice(&masked));

    let zero = res(U256::ZERO);
    let one = res(U256::ONE);
    let j = res(U256::from_u32(486662));

    let tv1 = u.mul(&u);            // u^2
    let tv1 = tv1.add(&tv1);        // Z * u^2, with Z = 2
    let xd = tv1.add(&one);         // 1 + Z * u^2

    // x1 = -J * inv0(xd). inv0(0) is defined as 0, which makes x1 zero; step 2 then sets x1 = -J.
    let xd_inv = xd.pow(&p.wrapping_sub(&U256::from_u8(2))); // Fermat inverse; 0 stays 0
    let neg_j = zero.sub(&j);
    let mut x1 = neg_j.mul(&xd_inv);
    if x1.retrieve() == U256::ZERO {
        x1 = neg_j;
    }

    // gx1 = x1^3 + J * x1^2 + x1  (K = 1)
    let x1_sq = x1.mul(&x1);
    let gx1 = x1_sq.mul(&x1).add(&j.mul(&x1_sq)).add(&x1);

    // If gx1 is a square, x = x1; otherwise x = x2 = -x1 - J.
    let legendre = gx1.pow(&p.wrapping_sub(&U256::ONE).shr_vartime(1)).retrieve();
    let is_square = legendre == U256::ZERO || legendre == U256::ONE;
    let x = if is_square { x1 } else { zero.sub(&x1).sub(&j) };

    x.retrieve().to_le_bytes()
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
// L1 - USB transport (rusb) + the first hardware-testable milestone: channel allocation
// -------------------------------------------------------------------------------------------------
//
// Nothing about the device layout is hardcoded. The 2025+ models are new enough that assuming
// trezor-client's Codec-v1 layout (1209:53C1, interface 0, interrupt endpoints 0x01/0x81) risks
// reporting "no device" for a Trezor that is plugged in and working - so instead enumerate every
// Trezor USB id, then pick the interface/endpoints out of the descriptors and honour whatever
// transfer type they declare.
pub mod usb {
    use super::{control, TransportMessage, USB_PACKET_SIZE};
    use rusb::{DeviceHandle, Direction, GlobalContext, TransferType};
    use std::time::Duration;

    /// USB vendor ids Trezor ships under: 0x1209 (pid.codes, Model T and later) and 0x534C (the
    /// original SatoshiLabs id used by the Model One).
    pub const TREZOR_VIDS: [u16; 2] = [0x1209, 0x534C];
    /// Product id of the known THP-capable/WebUSB models. Others are reported, not rejected.
    pub const PID_WEBUSB: u16 = 0x53C1;
    const TIMEOUT: Duration = Duration::from_millis(3000);

    /// A read that produced nothing within the deadline, as distinct from a broken link.
    #[derive(Debug)]
    pub enum LinkError {
        Timeout,
        Other(String),
    }

    impl std::fmt::Display for LinkError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                LinkError::Timeout => write!(f, "timed out waiting for the device"),
                LinkError::Other(e) => write!(f, "{e}"),
            }
        }
    }

    /// What enumeration found for one attached Trezor, including the data-interface layout we would
    /// actually talk over. `iface` is None when no interface exposes a usable IN/OUT pair.
    pub struct DeviceInfo {
        pub vid: u16,
        pub pid: u16,
        pub bus: u8,
        pub address: u8,
        pub product: Option<String>,
        pub iface: Option<u8>,
        pub ep_in: u8,
        pub ep_out: u8,
        pub interrupt: bool, // false => bulk endpoints
        pub open_error: Option<String>,
    }

    impl DeviceInfo {
        pub fn describe(&self) -> String {
            let mut s = format!("{:04x}:{:04x} bus {} addr {}", self.vid, self.pid, self.bus, self.address);
            if let Some(p) = &self.product {
                s.push_str(&format!(" \"{p}\""));
            }
            match self.iface {
                Some(i) => s.push_str(&format!(
                    " - interface {i}, {} endpoints out 0x{:02x} / in 0x{:02x}",
                    if self.interrupt { "interrupt" } else { "bulk" },
                    self.ep_out,
                    self.ep_in
                )),
                None => s.push_str(" - no usable data interface found"),
            }
            if let Some(e) = &self.open_error {
                s.push_str(&format!(" [cannot open: {e}]"));
            }
            s
        }
    }

    /// Enumerate every attached Trezor, reading its descriptors. Never fails on a single bad device -
    /// a device we cannot open still gets reported (with the reason), because knowing the product id
    /// is exactly what we need when a new model doesn't match the ids we expected.
    pub fn list() -> Result<Vec<DeviceInfo>, String> {
        let devices = rusb::devices().map_err(|e| format!("usb enumerate: {e}"))?;
        let mut out = Vec::new();
        for device in devices.iter() {
            let Ok(desc) = device.device_descriptor() else { continue };
            if !TREZOR_VIDS.contains(&desc.vendor_id()) {
                continue;
            }
            let mut info = DeviceInfo {
                vid: desc.vendor_id(),
                pid: desc.product_id(),
                bus: device.bus_number(),
                address: device.address(),
                product: None,
                iface: None,
                ep_in: 0,
                ep_out: 0,
                interrupt: true,
                open_error: None,
            };
            // Find the first interface exposing both an IN and an OUT endpoint of the same type.
            let config = device
                .active_config_descriptor()
                .or_else(|_| device.config_descriptor(0));
            if let Ok(config) = config {
                'ifaces: for iface in config.interfaces() {
                    for d in iface.descriptors() {
                        let (mut ep_in, mut ep_out, mut kind) = (None, None, TransferType::Interrupt);
                        for ep in d.endpoint_descriptors() {
                            match ep.transfer_type() {
                                TransferType::Interrupt | TransferType::Bulk => {}
                                _ => continue,
                            }
                            match ep.direction() {
                                Direction::In if ep_in.is_none() => {
                                    ep_in = Some(ep.address());
                                    kind = ep.transfer_type();
                                }
                                Direction::Out if ep_out.is_none() => ep_out = Some(ep.address()),
                                _ => {}
                            }
                        }
                        if let (Some(i), Some(o)) = (ep_in, ep_out) {
                            info.iface = Some(d.interface_number());
                            info.ep_in = i;
                            info.ep_out = o;
                            info.interrupt = kind == TransferType::Interrupt;
                            break 'ifaces;
                        }
                    }
                }
            }
            match device.open() {
                Ok(h) => info.product = h.read_product_string_ascii(&desc).ok(),
                Err(e) => info.open_error = Some(e.to_string()),
            }
            out.push(info);
        }
        Ok(out)
    }

    /// A raw 64-byte-packet USB link to a THP Trezor.
    pub struct UsbLink {
        handle: DeviceHandle<GlobalContext>,
        ep_in: u8,
        ep_out: u8,
        interrupt: bool,
    }

    impl UsbLink {
        /// Open the first attached Trezor that exposes a usable data interface and claim it.
        pub fn open() -> Result<Self, String> {
            let found = list()?;
            if found.is_empty() {
                return Err(format!(
                    "no Trezor found on USB (looked for vendor ids {}) - plug it in and unlock it",
                    TREZOR_VIDS.iter().map(|v| format!("{v:04x}")).collect::<Vec<_>>().join("/")
                ));
            }
            let target = found
                .iter()
                .find(|d| d.iface.is_some())
                .ok_or_else(|| {
                    format!(
                        "found a Trezor but no usable data interface: {}",
                        found.iter().map(|d| d.describe()).collect::<Vec<_>>().join("; ")
                    )
                })?;
            Self::open_info(target)
        }

        /// Open one specific enumerated device.
        pub fn open_info(info: &DeviceInfo) -> Result<Self, String> {
            let iface = info.iface.ok_or("device has no usable data interface")?;
            let devices = rusb::devices().map_err(|e| format!("usb enumerate: {e}"))?;
            let device = devices
                .iter()
                .find(|d| d.bus_number() == info.bus && d.address() == info.address)
                .ok_or("device disappeared during open")?;
            let handle = device
                .open()
                .map_err(|e| format!("open {:04x}:{:04x}: {e} (on Windows the interface needs the WinUSB driver)", info.vid, info.pid))?;
            // On Linux, detach any kernel driver; harmless/no-op on Windows (WinUSB) and macOS.
            let _ = handle.set_auto_detach_kernel_driver(true);
            handle
                .claim_interface(iface)
                .map_err(|e| format!("claim interface {iface}: {e} (close Trezor Suite/Bridge and retry)"))?;
            Ok(Self { handle, ep_in: info.ep_in, ep_out: info.ep_out, interrupt: info.interrupt })
        }

        pub fn write_packet(&self, pkt: &[u8; USB_PACKET_SIZE]) -> Result<(), String> {
            let r = if self.interrupt {
                self.handle.write_interrupt(self.ep_out, pkt, TIMEOUT)
            } else {
                self.handle.write_bulk(self.ep_out, pkt, TIMEOUT)
            };
            r.map(|_| ()).map_err(|e| format!("usb write: {e}"))
        }

        pub fn read_packet(&self) -> Result<[u8; USB_PACKET_SIZE], String> {
            self.read_packet_for(TIMEOUT).map_err(|e| e.to_string())
        }

        /// Read one packet, distinguishing "nothing arrived in time" from a real failure. The
        /// synchronization layer needs that distinction: a timeout means retransmit, anything else
        /// means give up.
        pub fn read_packet_for(&self, timeout: Duration) -> Result<[u8; USB_PACKET_SIZE], LinkError> {
            let mut buf = [0u8; USB_PACKET_SIZE];
            let n = match if self.interrupt {
                self.handle.read_interrupt(self.ep_in, &mut buf, timeout)
            } else {
                self.handle.read_bulk(self.ep_in, &mut buf, timeout)
            } {
                Ok(n) => n,
                Err(rusb::Error::Timeout) => return Err(LinkError::Timeout),
                Err(e) => return Err(LinkError::Other(format!("usb read: {e}"))),
            };
            if n != USB_PACKET_SIZE {
                return Err(LinkError::Other(format!("short usb read: {n} bytes")));
            }
            Ok(buf)
        }

        /// Read a full transport message, waiting up to `timeout` for it to *start*. Once the
        /// initiation packet has arrived the continuation packets must follow promptly, so a
        /// timeout part-way through a message is a failure rather than a retransmit signal.
        pub fn recv_message_for(&self, timeout: Duration) -> Result<TransportMessage, LinkError> {
            let first = self.read_packet_for(timeout)?;
            if first[0] & control::CONTINUATION != 0 {
                return Err(LinkError::Other("expected an initiation packet".into()));
            }
            let length = u16::from_be_bytes([first[3], first[4]]) as usize;
            let mut pkts = vec![first];
            let mut have = USB_PACKET_SIZE - 5;
            while have < length {
                let p = self.read_packet_for(TIMEOUT).map_err(|e| match e {
                    LinkError::Timeout => {
                        LinkError::Other("timed out mid-message waiting for a continuation packet".into())
                    }
                    other => other,
                })?;
                pkts.push(p);
                have += USB_PACKET_SIZE - 3;
            }
            super::reassemble(&pkts).map_err(LinkError::Other)
        }

        /// Segment `payload` and send it as a full transport message on channel `cid`.
        pub fn send_message(&self, control_byte: u8, cid: u16, payload: &[u8]) -> Result<(), String> {
            for pkt in super::segment(control_byte, cid, payload) {
                self.write_packet(&pkt)?;
            }
            Ok(())
        }

        /// Read a full transport message (initiation packet + any continuation packets), validating
        /// the CRC. Does NOT handle the ABP ACK layer - used for the channel-allocation exchange,
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

// -------------------------------------------------------------------------------------------------
// L2.5 - Synchronization layer (Alternating Bit Protocol)
// -------------------------------------------------------------------------------------------------

/// Interval before an unacknowledged message is retransmitted. The spec leaves this variable; a
/// second is long enough that a device busy with its display doesn't trigger pointless retransmits.
const RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(1000);
/// The spec allows up to 50, but that is aimed at unattended links. Five keeps a wedged device from
/// hanging the wallet UI for a minute, and still clears the spec's MIN_RETRANSMISSION_COUNT of 2.
const MAX_RETRANSMISSIONS: usize = 5;
/// Extra delay added after a TRANSPORT_BUSY error, per MAX_BUSY_BACKOFF_MS.
const MAX_BUSY_BACKOFF_MS: u64 = 500;
/// How long to wait for a device reply that may be gated on the user (PIN entry, confirmations).
/// Only the reply needs this much slack - transport ACKs come back promptly regardless of what the
/// device is showing on screen, because they are handled below the application layer.
pub const USER_INTERACTION_TIMEOUT: Duration = Duration::from_secs(300);

/// `trezor_state` reported in the handshake completion response.
///
/// The specification names these states but never gives their numeric values. This mapping is the
/// expected one and is confirmed by the first connection from an unpaired host, which must report
/// UNPAIRED - `handshake_probe` prints the raw byte so a mismatch is immediately visible.
pub mod device_state {
    pub const UNPAIRED: u8 = 0;
    pub const PAIRED: u8 = 1;
    pub const PAIRED_AUTOCONNECT: u8 = 2;

    pub fn name(state: u8) -> &'static str {
        match state {
            UNPAIRED => "UNPAIRED (pairing required)",
            PAIRED => "PAIRED (pairing can be skipped)",
            PAIRED_AUTOCONNECT => "PAIRED_AUTOCONNECT (no user confirmation needed)",
            _ => "unrecognised state",
        }
    }
}

/// A channel that has completed the Noise handshake and is ready for pairing or application traffic.
pub struct Handshaken {
    /// Traffic keys and nonces for the encrypted transport.
    pub crypto: EncryptedChannel,
    /// Binds the pairing methods to this handshake; CodeEntry derives its CPace generator from it.
    pub handshake_hash: [u8; 32],
    pub trezor_state: u8,
    pub host_static_pub: [u8; 32],
}

impl Handshaken {
    /// Whether the device recognised us and pairing can be skipped.
    pub fn is_paired(&self) -> bool {
        self.trezor_state != device_state::UNPAIRED
    }
}

/// Decode a `Failure` message into something worth showing a user.
fn describe_failure(body: &[u8]) -> String {
    let mut code = None;
    let mut message = String::new();
    for (field, val) in proto_decode(body) {
        match (field, val) {
            (1, WireVal::Varint(v)) => code = Some(v),
            (2, WireVal::Bytes(b)) => message = String::from_utf8_lossy(&b).into_owned(),
            _ => {}
        }
    }
    match (code, message.is_empty()) {
        (Some(2), _) => "cancelled on the device".into(),
        (_, false) => format!("device reported a failure: {message}"),
        (Some(c), true) => format!("device reported failure code {c}"),
        _ => "device reported an unspecified failure".into(),
    }
}

/// The result of pairing: an opaque credential that lets a later handshake skip pairing entirely.
pub struct PairingOutcome {
    pub credential: Vec<u8>,
    pub trezor_static_pubkey: Vec<u8>,
}

/// Interpret a 32-byte hash as a big-endian integer and reduce it mod 1_000_000, which is how the
/// device derives the 6-digit code it displays.
fn code_from_hash(hash: &[u8; 32]) -> u32 {
    let mut acc: u64 = 0;
    for &b in hash {
        acc = (acc * 256 + b as u64) % 1_000_000;
    }
    acc as u32
}

/// Handshake replies must arrive with the control byte the state machine expects; anything else
/// means the device is in a different state than we think.
fn expect_handshake(msg: &TransportMessage, want: u8) -> Result<(), String> {
    let got = msg.control_byte & !control::SYNC_MASK;
    if got != want {
        return Err(format!(
            "expected handshake control byte 0x{want:02x}, got 0x{got:02x}"
        ));
    }
    Ok(())
}

/// What the sync layer did with one inbound transport message.
enum Handled {
    /// The message we were waiting on has been acknowledged.
    Acked,
    /// The peer is busy; back off by this much before retransmitting.
    Busy(Duration),
    /// Buffered for the application, a duplicate, or otherwise not interesting to the sender.
    Other,
}

/// An allocated THP channel with the Alternating Bit Protocol running over it.
///
/// ABP is what makes the link reliable: every data message carries a 1-bit sequence number that
/// alternates, the peer echoes it in an ACK, and anything unacknowledged is retransmitted. Without
/// this layer nothing past channel allocation works, because the device will not proceed through
/// the handshake until its messages are acknowledged.
pub struct Channel {
    link: usb::UsbLink,
    cid: u16,
    /// Device properties from the allocation response. The raw bytes are the first thing folded
    /// into the handshake hash, so they must be kept verbatim.
    props: DeviceProperties,
    /// Sequence number for our next outgoing message.
    send_seq: bool,
    /// Sequence number we expect on the next inbound message; anything else is a duplicate.
    expect_seq: bool,
    /// Messages received while we were waiting for an ACK, delivered by the next `recv`.
    inbox: VecDeque<TransportMessage>,
    /// Next session id to hand out. Session ids are chosen by the host - see `create_session`.
    next_session_id: u8,
}

impl Channel {
    /// Allocate a channel on `link` and return it alongside the device's reported properties.
    pub fn allocate(link: usb::UsbLink) -> Result<(Self, DeviceProperties), String> {
        let nonce: [u8; 8] = rand::random();
        link.send_message(control::CHANNEL_ALLOCATION_REQUEST, CID_BROADCAST, &channel_allocation_request(nonce))?;
        let resp = link.recv_message()?;
        if resp.control_byte != control::CHANNEL_ALLOCATION_RESPONSE {
            return Err(format!(
                "unexpected control byte 0x{:02x} (wanted channel_allocation_response) - a device that \
                 ignores or rejects channel allocation is most likely speaking legacy Codec v1",
                resp.control_byte
            ));
        }
        let (echoed, cid, props) = parse_channel_allocation_response(&resp.payload)?;
        if echoed != nonce {
            return Err("channel-allocation nonce mismatch".into());
        }
        Ok((
            Self {
                link,
                cid,
                props: props.clone(),
                send_seq: false,
                expect_seq: false,
                inbox: VecDeque::new(),
                next_session_id: 1, // 0 is reserved for pairing/management traffic
            },
            props,
        ))
    }

    pub fn cid(&self) -> u16 {
        self.cid
    }

    /// Send a data message and block until the device acknowledges it, retransmitting on timeout.
    pub fn send(&mut self, base_control: u8, payload: &[u8]) -> Result<(), String> {
        let cb = control::data_with_seq(base_control, self.send_seq);
        let mut backoff = Duration::ZERO;
        for _ in 0..=MAX_RETRANSMISSIONS {
            self.link.send_message(cb, self.cid, payload)?;
            let deadline = Instant::now() + RETRANSMIT_TIMEOUT + backoff;
            backoff = Duration::ZERO;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match self.link.recv_message_for(remaining) {
                    Ok(msg) => match self.handle(msg, true)? {
                        Handled::Acked => return Ok(()),
                        Handled::Busy(d) => {
                            backoff = d;
                            break;
                        }
                        Handled::Other => {}
                    },
                    Err(usb::LinkError::Timeout) => break,
                    Err(usb::LinkError::Other(e)) => return Err(e),
                }
            }
        }
        Err(format!("device did not acknowledge the message after {MAX_RETRANSMISSIONS} retransmissions"))
    }

    /// Wait for the next application message, acknowledging it and discarding duplicates.
    ///
    /// `timeout` bounds how long we wait for the device to produce a response, which can be minutes
    /// when it is waiting for the user to confirm something on screen.
    pub fn recv(&mut self, timeout: Duration) -> Result<TransportMessage, String> {
        if let Some(m) = self.inbox.pop_front() {
            return Ok(m);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("timed out waiting for a response from the device".into());
            }
            match self.link.recv_message_for(remaining) {
                Ok(msg) => {
                    self.handle(msg, false)?;
                    if let Some(m) = self.inbox.pop_front() {
                        return Ok(m);
                    }
                }
                Err(usb::LinkError::Timeout) => {
                    return Err("timed out waiting for a response from the device".into())
                }
                Err(usb::LinkError::Other(e)) => return Err(e),
            }
        }
    }

    /// Send a message and wait for the reply - the shape almost every THP exchange takes.
    pub fn request(
        &mut self,
        base_control: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<TransportMessage, String> {
        self.send(base_control, payload)?;
        self.recv(timeout)
    }

    /// Run the Noise_XX handshake to establish the encrypted channel.
    ///
    /// `host_static_priv` must be stable across connections: the device recognises a previously
    /// paired host by its static public key, so a fresh key means a fresh pairing. `credential` is
    /// the pairing credential saved from an earlier session, if any. `try_to_unlock` asks a locked
    /// device to show its PIN screen rather than rejecting the handshake with DEVICE_LOCKED.
    pub fn handshake(
        &mut self,
        host_static_priv: [u8; 32],
        credential: Option<&[u8]>,
        try_to_unlock: bool,
    ) -> Result<Handshaken, String> {
        let host_static_pub = x25519(host_static_priv, X25519_BASEPOINT);
        let eph_priv: [u8; 32] = rand::random();
        let props_raw = self.props.raw.clone();
        let (mut hs, init_req) =
            HostHandshake::start(eph_priv, &props_raw, u8::from(try_to_unlock));

        let resp = self.request(control::HANDSHAKE_INIT_REQUEST, &init_req, USER_INTERACTION_TIMEOUT)?;
        expect_handshake(&resp, control::HANDSHAKE_INIT_RESPONSE)?;
        let completion = hs.respond(&resp.payload, host_static_priv, host_static_pub, credential)?;
        // Captured before the completion exchange: the pairing methods bind to the handshake hash
        // as it stands after the completion request has been folded in.
        let handshake_hash = hs.handshake_hash();

        let resp =
            self.request(control::HANDSHAKE_COMPLETION_REQUEST, &completion, USER_INTERACTION_TIMEOUT)?;
        expect_handshake(&resp, control::HANDSHAKE_COMPLETION_RESPONSE)?;

        let (key_request, key_response) = hs.traffic_keys();
        // Note the associated data is the empty string here, unlike the handshake messages, which
        // bind to the running handshake hash.
        let state = aes_gcm_decrypt(&key_response, &iv_zero(), &[], &resp.payload)
            .ok_or("could not decrypt the Trezor state from the handshake completion response")?;
        let trezor_state = *state.first().ok_or("empty Trezor state in completion response")?;

        Ok(Handshaken {
            crypto: EncryptedChannel::new(key_request, key_response),
            handshake_hash,
            trezor_state,
            host_static_pub,
        })
    }

    /// Run CodeEntry pairing, the only pairing method the Safe 7 offers.
    ///
    /// The device commits to a secret, we send a challenge, and it derives and displays a 6-digit
    /// code. `get_code` is called at that point to collect what the user read off the screen. Both
    /// sides then run CPace over that code: possession of the code is what proves there is no
    /// man in the middle, since an attacker relaying the handshake cannot produce a matching tag.
    ///
    /// Returns a credential to store, so subsequent connections skip pairing.
    pub fn pair_code_entry<F>(
        &mut self,
        handshake_hash: &[u8; 32],
        host_static_pub: &[u8; 32],
        crypto: &mut EncryptedChannel,
        host_name: &str,
        app_name: &str,
        get_code: F,
    ) -> Result<PairingOutcome, String>
    where
        F: FnOnce() -> Result<String, String>,
    {
        const SID: u8 = 0; // management messages ride on session 0

        // HP0 - ask to pair. The device shows a confirmation dialog and gates on a button press.
        let mut req = proto_string_field(1, host_name);
        req.extend_from_slice(&proto_string_field(2, app_name));
        self.app_send(crypto, SID, msgtype::THP_PAIRING_REQUEST, &req)?;
        self.app_expect(crypto, SID, msgtype::THP_PAIRING_REQUEST_APPROVED, USER_INTERACTION_TIMEOUT)?;

        // HP1 - choose CodeEntry.
        let select = proto_varint_field(1, pairing_method::CODE_ENTRY as u64);
        self.app_send(crypto, SID, msgtype::THP_SELECT_METHOD, &select)?;

        // HP2 - the device commits to its secret before it has seen our challenge, which is what
        // stops it from choosing a secret that produces a code of its liking.
        let commitment_body =
            self.app_expect(crypto, SID, msgtype::THP_CODE_ENTRY_COMMITMENT, USER_INTERACTION_TIMEOUT)?;
        let commitment = proto_first_bytes(&commitment_body, 1)
            .ok_or("ThpCodeEntryCommitment without a commitment field")?;

        let challenge: [u8; 16] = rand::random();
        self.app_send(crypto, SID, msgtype::THP_CODE_ENTRY_CHALLENGE, &proto_bytes_field(1, &challenge))?;

        // HP3a - the device now derives the code, displays it, and sends its CPace public key.
        let cpace_body =
            self.app_expect(crypto, SID, msgtype::THP_CODE_ENTRY_CPACE_TREZOR, USER_INTERACTION_TIMEOUT)?;
        let cpace_trezor = proto_first_bytes(&cpace_body, 1)
            .ok_or("ThpCodeEntryCpaceTrezor without a public key field")?;
        let cpace_trezor: [u8; 32] = cpace_trezor
            .as_slice()
            .try_into()
            .map_err(|_| "CPace public key from the device is not 32 bytes")?;

        // HP4 - the user reads the code off the device and types it in.
        let code = get_code()?;
        let code = code.trim().to_string();
        if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err("the pairing code must be exactly 6 digits".into());
        }
        let generator = cpace_generator(&code, handshake_hash)?;
        let cpace_host_priv: [u8; 32] = rand::random();
        let (cpace_host_pub, tag) = cpace_host(generator, cpace_trezor, cpace_host_priv);
        let mut tag_msg = proto_bytes_field(1, &cpace_host_pub);
        tag_msg.extend_from_slice(&proto_bytes_field(2, &tag));
        self.app_send(crypto, SID, msgtype::THP_CODE_ENTRY_CPACE_HOST_TAG, &tag_msg)?;

        // HP5 - the device only reveals its secret once our tag proved we knew the code.
        let secret_body =
            self.app_expect(crypto, SID, msgtype::THP_CODE_ENTRY_SECRET, USER_INTERACTION_TIMEOUT)?;
        let secret =
            proto_first_bytes(&secret_body, 1).ok_or("ThpCodeEntrySecret without a secret field")?;

        // The commitment check is what makes the earlier commitment meaningful.
        if sha256(&[secret.as_slice()]) != commitment.as_slice() {
            return Err("the device's secret does not match the commitment it made - aborting".into());
        }

        // Cross-check that the code we were shown is the one the device's secret actually derives.
        // Confirmed against a Safe 7: the pairing method is a single byte in this hash.
        let expected = code_from_hash(&sha256(&[
            &[pairing_method::CODE_ENTRY as u8][..],
            &handshake_hash[..],
            secret.as_slice(),
            &challenge[..],
        ]));
        if format!("{expected:06}") != code {
            return Err(format!(
                "the code derived from the device's secret ({expected:06}) does not match the code \
                 displayed ({code}) - aborting"
            ));
        }

        // Credential phase (HC0/HC1): ask for a credential so future connections skip pairing.
        //
        // Note this asks for an ordinary credential, not an autoconnect one. The firmware rejects
        // `autoconnect` here outright ("Cannot ask for autoconnect credential after pairing"):
        // upgrading to autoconnect is a separate request made on a later connection, once the
        // device already recognises us. See `request_autoconnect_credential`.
        let cred_req = proto_bytes_field(1, host_static_pub);
        self.app_send(crypto, SID, msgtype::THP_CREDENTIAL_REQUEST, &cred_req)?;
        let cred_body =
            self.app_expect(crypto, SID, msgtype::THP_CREDENTIAL_RESPONSE, USER_INTERACTION_TIMEOUT)?;
        let trezor_static_pubkey = proto_first_bytes(&cred_body, 1)
            .ok_or("ThpCredentialResponse without the device's static public key")?;
        let credential = proto_first_bytes(&cred_body, 2)
            .ok_or("ThpCredentialResponse without a credential")?;

        // HC2 - leave the credential phase and enter encrypted transport.
        self.app_send(crypto, SID, msgtype::THP_END_REQUEST, &[])?;
        self.app_expect(crypto, SID, msgtype::THP_END_RESPONSE, USER_INTERACTION_TIMEOUT)?;

        Ok(PairingOutcome { credential, trezor_static_pubkey })
    }

    /// Create a session, which is what a passphrase wallet corresponds to in THP. Passing no
    /// passphrase gives the standard wallet; `on_device` asks the user to type it on the Trezor
    /// instead of sending it over the wire.
    ///
    /// Session ids are chosen by the *host*. The specification does not say so, but it was
    /// established on a Safe 7: the device honours whichever id the create request is sent on, and
    /// answers "Invalid session" for any id that was never created - it does not silently fall back
    /// to a default wallet, which is what makes host-chosen ids safe here. Id 0 is left for the
    /// pairing/management traffic, so wallets are numbered from 1.
    pub fn create_session(
        &mut self,
        crypto: &mut EncryptedChannel,
        passphrase: Option<&str>,
        on_device: bool,
    ) -> Result<u8, String> {
        if self.next_session_id == 0 {
            return Err("ran out of THP session ids on this channel".into());
        }
        let id = self.next_session_id;
        let body = Self::create_session_body(passphrase, on_device);
        let got = self.create_session_on(crypto, id, &body)?;
        if got != id {
            return Err(format!(
                "asked the device for session {id} but it answered on session {got}"
            ));
        }
        self.next_session_id += 1;
        Ok(id)
    }

    /// As `create_session`, but sends the request on a caller-chosen session id. The specification
    /// does not state whether the host or the device picks that byte, so this exists to let the
    /// diagnostic distinguish the two: the returned id is whatever the device replied on.
    pub fn create_session_on(
        &mut self,
        crypto: &mut EncryptedChannel,
        requested_id: u8,
        body: &[u8],
    ) -> Result<u8, String> {
        self.app_send(crypto, requested_id, msgtype::THP_CREATE_NEW_SESSION, body)?;
        let (session_id, _) = self.app_expect_with_session(
            crypto,
            requested_id,
            msgtype::SUCCESS,
            USER_INTERACTION_TIMEOUT,
        )?;
        Ok(session_id)
    }

    /// Encode a `ThpCreateNewSession` body.
    pub fn create_session_body(passphrase: Option<&str>, on_device: bool) -> Vec<u8> {
        let mut body = Vec::new();
        if let Some(p) = passphrase {
            body.extend_from_slice(&proto_string_field(1, p));
        }
        if on_device {
            body.extend_from_slice(&proto_varint_field(2, 1));
        }
        body
    }

    /// Ask the device for the Ethereum address at `path`, without displaying it on screen.
    pub fn ethereum_address(
        &mut self,
        crypto: &mut EncryptedChannel,
        session_id: u8,
        path: &[u32],
    ) -> Result<String, String> {
        let body = ethereum_get_address(path);
        self.app_send(crypto, session_id, msgtype::ETHEREUM_GET_ADDRESS, &body)?;
        let reply =
            self.app_expect(crypto, session_id, msgtype::ETHEREUM_ADDRESS, USER_INTERACTION_TIMEOUT)?;
        parse_ethereum_address(&reply).ok_or_else(|| "could not parse the Ethereum address".into())
    }

    /// Ask the device to sign an EIP-1559 transaction. The user must approve it on screen.
    ///
    /// Returns the signature as `(v, r, s)`, where `v` is the recovery parameter the device
    /// reports. Transaction payloads longer than the first chunk are streamed back in response to
    /// the device's requests, which is why this is a loop rather than a single exchange.
    pub fn ethereum_sign_eip1559(
        &mut self,
        crypto: &mut EncryptedChannel,
        session_id: u8,
        path: &[u32],
        tx: &Eip1559Tx,
    ) -> Result<(u64, [u8; 32], [u8; 32]), String> {
        const MAX_CHUNK: usize = 1024;

        let mut body = Vec::new();
        for &p in path {
            body.extend_from_slice(&proto_varint_field(1, p as u64));
        }
        body.extend_from_slice(&proto_bytes_field(2, &be_minimal(tx.nonce as u128)));
        body.extend_from_slice(&proto_bytes_field(3, &be_minimal(tx.max_fee_per_gas)));
        body.extend_from_slice(&proto_bytes_field(4, &be_minimal(tx.max_priority_fee_per_gas)));
        body.extend_from_slice(&proto_bytes_field(5, &be_minimal(tx.gas_limit as u128)));
        body.extend_from_slice(&proto_string_field(6, tx.to));
        body.extend_from_slice(&proto_bytes_field(7, &be_minimal(tx.value)));
        let first_chunk = tx.data.len().min(MAX_CHUNK);
        if first_chunk > 0 {
            body.extend_from_slice(&proto_bytes_field(8, &tx.data[..first_chunk]));
        }
        // data_length and chain_id are `required`, so they go on the wire even when zero.
        body.extend_from_slice(&proto_varint_field(9, tx.data.len() as u64));
        body.extend_from_slice(&proto_varint_field(10, tx.chain_id));

        self.app_send(crypto, session_id, msgtype::ETHEREUM_SIGN_TX_EIP1559, &body)?;
        self.collect_signature(crypto, session_id, tx.data, first_chunk)
    }

    /// Ask the device to sign a pre-EIP-1559 (legacy) transaction, for chains without a fee market.
    ///
    /// Note the field numbering differs from the EIP-1559 message in a way that is easy to get
    /// wrong: `to` is field 11, not 6.
    pub fn ethereum_sign_legacy(
        &mut self,
        crypto: &mut EncryptedChannel,
        session_id: u8,
        path: &[u32],
        tx: &LegacyTx,
    ) -> Result<(u64, [u8; 32], [u8; 32]), String> {
        const MAX_CHUNK: usize = 1024;

        let mut body = Vec::new();
        for &p in path {
            body.extend_from_slice(&proto_varint_field(1, p as u64));
        }
        body.extend_from_slice(&proto_bytes_field(2, &be_minimal(tx.nonce as u128)));
        body.extend_from_slice(&proto_bytes_field(3, &be_minimal(tx.gas_price)));
        body.extend_from_slice(&proto_bytes_field(4, &be_minimal(tx.gas_limit as u128)));
        body.extend_from_slice(&proto_bytes_field(6, &be_minimal(tx.value)));
        let first_chunk = tx.data.len().min(MAX_CHUNK);
        if first_chunk > 0 {
            body.extend_from_slice(&proto_bytes_field(7, &tx.data[..first_chunk]));
        }
        body.extend_from_slice(&proto_varint_field(8, tx.data.len() as u64));
        body.extend_from_slice(&proto_varint_field(9, tx.chain_id));
        body.extend_from_slice(&proto_string_field(11, tx.to));

        self.app_send(crypto, session_id, msgtype::ETHEREUM_SIGN_TX, &body)?;
        self.collect_signature(crypto, session_id, tx.data, first_chunk)
    }

    /// Shared tail of both signing flows: stream any remaining payload the device asks for, then
    /// return the signature.
    fn collect_signature(
        &mut self,
        crypto: &mut EncryptedChannel,
        session_id: u8,
        data: &[u8],
        already_sent: usize,
    ) -> Result<(u64, [u8; 32], [u8; 32]), String> {
        let mut sent = already_sent;
        loop {
            let reply = self.app_expect(
                crypto,
                session_id,
                msgtype::ETHEREUM_TX_REQUEST,
                USER_INTERACTION_TIMEOUT,
            )?;

            let (mut want, mut v, mut r, mut s) = (None, None, None, None);
            for (field, val) in proto_decode(&reply) {
                match (field, val) {
                    (1, WireVal::Varint(x)) => want = Some(x as usize),
                    (2, WireVal::Varint(x)) => v = Some(x),
                    (3, WireVal::Bytes(b)) => r = Some(b),
                    (4, WireVal::Bytes(b)) => s = Some(b),
                    _ => {}
                }
            }

            if let (Some(v), Some(r), Some(s)) = (v, r, s) {
                return Ok((v, pad32(&r)?, pad32(&s)?));
            }

            match want {
                Some(n) if n > 0 => {
                    let end = data.len().min(sent.saturating_add(n));
                    if end <= sent {
                        return Err("the device asked for transaction data we do not have".into());
                    }
                    let ack = proto_bytes_field(1, &data[sent..end]);
                    sent = end;
                    self.app_send(crypto, session_id, msgtype::ETHEREUM_TX_ACK, &ack)?;
                }
                _ => return Err("EthereumTxRequest had neither a signature nor a data request".into()),
            }
        }
    }

    /// Trade an existing pairing credential for one that allows connecting without a confirmation
    /// tap, returning the new credential.
    ///
    /// This is only valid once the device already recognises us - that is, on a connection whose
    /// handshake reported PAIRED. Asking during pairing itself is refused by the firmware with
    /// "Cannot ask for autoconnect credential after pairing". The user is asked to approve the
    /// upgrade on the device.
    ///
    /// Call before `finish_without_pairing`, while the channel is still in the pairing phase.
    pub fn request_autoconnect_credential(
        &mut self,
        crypto: &mut EncryptedChannel,
        host_static_pub: &[u8; 32],
        previous: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut req = proto_bytes_field(1, host_static_pub);
        req.extend_from_slice(&proto_varint_field(2, 1)); // autoconnect
        req.extend_from_slice(&proto_bytes_field(3, previous));
        self.app_send(crypto, 0, msgtype::THP_CREDENTIAL_REQUEST, &req)?;
        let body =
            self.app_expect(crypto, 0, msgtype::THP_CREDENTIAL_RESPONSE, USER_INTERACTION_TIMEOUT)?;
        proto_first_bytes(&body, 2)
            .ok_or_else(|| "ThpCredentialResponse without a credential".to_string())
    }

    /// Leave the credential phase without asking for a credential - used when the device already
    /// recognised us and pairing was skipped.
    pub fn finish_without_pairing(&mut self, crypto: &mut EncryptedChannel) -> Result<(), String> {
        self.app_send(crypto, 0, msgtype::THP_END_REQUEST, &[])?;
        self.app_expect(crypto, 0, msgtype::THP_END_RESPONSE, USER_INTERACTION_TIMEOUT)?;
        Ok(())
    }

    /// Send an application-layer message over the encrypted transport.
    pub fn app_send(
        &mut self,
        crypto: &mut EncryptedChannel,
        session_id: u8,
        msg_type: u16,
        protobuf: &[u8],
    ) -> Result<(), String> {
        let plaintext = app_frame(session_id, msg_type, protobuf);
        let ciphertext = crypto.encrypt_request(&plaintext);
        self.send(control::ENCRYPTED_TRANSPORT, &ciphertext)
    }

    /// Receive and decrypt one application-layer message.
    pub fn app_recv(
        &mut self,
        crypto: &mut EncryptedChannel,
        timeout: Duration,
    ) -> Result<(u8, u16, Vec<u8>), String> {
        let msg = self.recv(timeout)?;
        let base = msg.control_byte & !control::SYNC_MASK;
        if base != control::ENCRYPTED_TRANSPORT {
            return Err(format!(
                "expected an encrypted transport message, got control byte 0x{base:02x}"
            ));
        }
        let plaintext = crypto
            .decrypt_response(&msg.payload)
            .ok_or("could not decrypt an application message (traffic keys or nonce out of step)")?;
        let (session_id, msg_type, body) = parse_app_frame(&plaintext)?;
        Ok((session_id, msg_type, body.to_vec()))
    }

    /// Receive the message we expect, transparently answering the device's ButtonRequest prompts
    /// and turning a Failure reply into an error.
    ///
    /// The device asks for a button press whenever it needs the user to confirm something on
    /// screen; the protocol requires the host to acknowledge that request before the device will
    /// wait for the user.
    pub fn app_expect(
        &mut self,
        crypto: &mut EncryptedChannel,
        session_id: u8,
        want: u16,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        self.app_expect_with_session(crypto, session_id, want, timeout).map(|(_, body)| body)
    }

    /// As `app_expect`, but also reports the session id the reply arrived on - which is how the
    /// device tells us the id it allocated for a newly created session.
    pub fn app_expect_with_session(
        &mut self,
        crypto: &mut EncryptedChannel,
        session_id: u8,
        want: u16,
        timeout: Duration,
    ) -> Result<(u8, Vec<u8>), String> {
        loop {
            let (sid, msg_type, body) = self.app_recv(crypto, timeout)?;
            match msg_type {
                t if t == want => return Ok((sid, body)),
                msgtype::BUTTON_REQUEST => {
                    self.app_send(crypto, session_id, msgtype::BUTTON_ACK, &[])?;
                }
                msgtype::FAILURE => return Err(describe_failure(&body)),
                other => {
                    return Err(format!(
                        "unexpected message type {other} from the device (expected {want})"
                    ))
                }
            }
        }
    }

    fn send_ack(&self, seq: bool) -> Result<(), String> {
        self.link.send_message(control::ack_for(seq), self.cid, &[])
    }

    /// Run one inbound message through the sync layer.
    fn handle(&mut self, msg: TransportMessage, awaiting_ack: bool) -> Result<Handled, String> {
        // Packets for other channels are none of our business.
        if msg.cid != self.cid {
            return Ok(Handled::Other);
        }
        let cb = msg.control_byte;

        if cb == control::TRANSPORT_ERROR {
            let code = msg.payload.first().copied().unwrap_or(0);
            if code == 1 {
                // TRANSPORT_BUSY: the device is reassembling on another channel. Back off and retry.
                let jitter = rand::random::<u64>() % (MAX_BUSY_BACKOFF_MS + 1);
                return Ok(Handled::Busy(Duration::from_millis(jitter)));
            }
            let hint = if transport_error_is_fatal(code) {
                " - the channel is gone, a new one must be allocated"
            } else {
                ""
            };
            return Err(format!("transport error {code} ({}){hint}", transport_error_name(code)));
        }

        if cb == control::PING {
            // Keep-alive from the device; echo the nonce back so it doesn't drop the channel.
            self.link.send_message(control::PONG, self.cid, &msg.payload)?;
            return Ok(Handled::Other);
        }
        if cb == control::PONG {
            return Ok(Handled::Other);
        }

        if control::is_ack(cb) {
            if awaiting_ack && control::ack_of(cb) == self.send_seq {
                self.send_seq = !self.send_seq;
                return Ok(Handled::Acked);
            }
            // An ACK for the other sequence number acknowledges an older message; ignore it.
            return Ok(Handled::Other);
        }

        if control::is_data(cb) {
            let seq = control::seq_of(cb);
            // Acknowledge every data message, including duplicates - a duplicate means our previous
            // ACK was the thing that got lost, so staying silent would wedge the device.
            self.send_ack(seq)?;
            if seq != self.expect_seq {
                return Ok(Handled::Other); // duplicate, already delivered
            }
            self.expect_seq = !self.expect_seq;
            self.inbox.push_back(msg);
            // A fresh message from the device proves our request arrived, whether or not a
            // standalone ACK follows. This covers ACK piggybacking without having to rely on the
            // piggyback bit, which is an optional feature we have not negotiated.
            if awaiting_ack {
                self.send_seq = !self.send_seq;
                return Ok(Handled::Acked);
            }
            return Ok(Handled::Other);
        }

        Ok(Handled::Other)
    }
}

/// STAGE 2 HARDWARE MILESTONE: allocate a channel and run the full Noise_XX handshake, reporting
/// whether the device considers us paired. This is the first exchange that exercises the
/// Alternating Bit Protocol, since channel allocation deliberately bypasses it.
///
/// A fresh random host static key is generated on every run, so the device will always report
/// UNPAIRED here. That is the expected result for this milestone: it confirms the handshake
/// completed and was authenticated, which is what we are testing.
pub fn handshake_probe() -> Result<String, String> {
    let link = usb::UsbLink::open()?;
    let (mut channel, props) = Channel::allocate(link)?;
    let host_static_priv: [u8; 32] = rand::random();
    let result = channel.handshake(host_static_priv, None, true)?;
    Ok(format!(
        "channel 0x{:04x} allocated to {} (protocol v{}.{})\n\
         handshake OK - Noise_XX completed and authenticated\n\
         trezor_state=0x{:02x} {}\n\
         handshake_hash={}\n\
         host_static_pubkey={}",
        channel.cid(),
        props.internal_model,
        props.protocol_version_major,
        props.protocol_version_minor,
        result.trezor_state,
        device_state::name(result.trezor_state),
        hex_of(&result.handshake_hash),
        hex_of(&result.host_static_pub),
    ))
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// STAGE 3 HARDWARE MILESTONE: pair with the device using CodeEntry, store the resulting
/// credential, and on subsequent runs use that credential to skip pairing entirely.
///
/// `state_path` holds the host static key and credential between runs. In the wallet these live in
/// the encrypted metadata; here they are a plain file purely so the two paths can be tested. The
/// host static key is only a pairing identity - it is not a wallet key and controls no funds.
pub fn pair_probe(state_path: &std::path::Path) -> Result<String, String> {
    // Reuse a previously stored identity if there is one, so the device can recognise us.
    let stored = std::fs::read_to_string(state_path).ok();
    let (host_static_priv, credential) = match stored.as_deref().and_then(parse_pairing_state) {
        Some(v) => v,
        None => (rand::random::<[u8; 32]>(), None),
    };
    let reused = credential.is_some();

    let link = usb::UsbLink::open()?;
    let (mut channel, props) = Channel::allocate(link)?;
    let mut session = channel.handshake(host_static_priv, credential.as_deref(), true)?;

    let mut out = format!(
        "channel 0x{:04x} allocated to {} (protocol v{}.{})\n\
         handshake OK - trezor_state=0x{:02x} {}\n\
         stored credential: {}\n",
        channel.cid(),
        props.internal_model,
        props.protocol_version_major,
        props.protocol_version_minor,
        session.trezor_state,
        device_state::name(session.trezor_state),
        if reused { "present, offered during handshake" } else { "none, this is a first pairing" },
    );

    if session.is_paired() {
        channel.finish_without_pairing(&mut session.crypto)?;
        out.push_str("PAIRING SKIPPED - the device recognised the stored credential.\n");
        out.push_str("Encrypted transport is ready.\n");
        return Ok(out);
    }

    out.push_str("Pairing required. Confirm on the device, then type the 6-digit code it shows.\n");
    println!("{out}");

    let handshake_hash = session.handshake_hash;
    let host_static_pub = session.host_static_pub;
    let outcome = channel.pair_code_entry(
        &handshake_hash,
        &host_static_pub,
        &mut session.crypto,
        "Aero",
        "Aero Wallet",
        || {
        print!("6-digit code shown on the Trezor: ");
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| format!("could not read the code: {e}"))?;
            Ok(line)
        },
    )?;

    let state = format!(
        "host_static_priv={}\ncredential={}\n",
        hex_of(&host_static_priv),
        hex_of(&outcome.credential)
    );
    std::fs::write(state_path, state).map_err(|e| format!("could not save the credential: {e}"))?;

    let mut result = String::from("PAIRED - credential issued and saved.\n");
    result.push_str(&format!("trezor_static_pubkey={}\n", hex_of(&outcome.trezor_static_pubkey)));
    result.push_str(&format!("credential={} bytes\n", outcome.credential.len()));
    result.push_str("Run this command again - it should now report PAIRING SKIPPED.\n");
    Ok(result)
}

/// STAGE 4 HARDWARE MILESTONE: connect with the stored credential, open sessions, and derive
/// Ethereum addresses. This is the first time the device is asked to do anything with the seed.
///
/// It doubles as the experiment that settles session-id ownership. The specification does not say
/// whether the host or the device chooses the one-byte session id, and a run without a passphrase
/// cannot tell the difference because every session then derives the same address. So this creates
/// a standard session and a passphrase session on *different* requested ids and derives an address
/// on each id, including the ones we did not ask for. Reading which ids produce which wallet
/// answers the question outright.
///
/// Requires `thp-pair` to have been run first.
pub fn address_probe(state_path: &std::path::Path, passphrase: Option<&str>) -> Result<String, String> {
    let stored = std::fs::read_to_string(state_path)
        .map_err(|_| "no stored pairing - run `aero thp-pair` first".to_string())?;
    let (host_static_priv, credential) =
        parse_pairing_state(&stored).ok_or("could not read the stored pairing")?;
    let credential = credential.ok_or("the stored pairing has no credential - re-run `thp-pair`")?;

    let link = usb::UsbLink::open()?;
    let (mut channel, _props) = Channel::allocate(link)?;
    let mut session = channel.handshake(host_static_priv, Some(&credential), true)?;
    if !session.is_paired() {
        return Err("the device did not accept the stored credential - re-run `thp-pair`".into());
    }
    channel.finish_without_pairing(&mut session.crypto)?;

    // m/44'/60'/0'/0/0 - the first Ethereum account, same path the wallet uses.
    const H: u32 = 0x8000_0000;
    let path = [44 | H, 60 | H, H, 0, 0];
    let crypto = &mut session.crypto;

    let mut out = format!(
        "connected with the stored credential (trezor_state=0x{:02x})\n",
        session.trezor_state
    );

    // Standard wallet, requested on session 0.
    let body = Channel::create_session_body(None, false);
    let standard_id = channel.create_session_on(crypto, 0, &body)?;
    out.push_str(&format!("standard session: requested id 0, device replied on id {standard_id}\n"));

    // Passphrase wallet, deliberately requested on a different id so an echo is distinguishable
    // from a real allocation.
    let mut passphrase_id = None;
    if let Some(p) = passphrase {
        let body = Channel::create_session_body(Some(p), false);
        match channel.create_session_on(crypto, 2, &body) {
            Ok(id) => {
                out.push_str(&format!(
                    "passphrase session: requested id 2, device replied on id {id}\n"
                ));
                passphrase_id = Some(id);
            }
            Err(e) => out.push_str(&format!("passphrase session: creating it failed: {e}\n")),
        }
    } else {
        out.push_str("passphrase session: skipped, no passphrase given\n");
    }

    // Derive on every id in play. Whichever ids answer, and with which wallet, is the result.
    out.push_str("\nm/44'/60'/0'/0/0 by session id:\n");
    let mut ids: Vec<u8> = vec![0, 1, 2];
    if let Some(id) = passphrase_id {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    for id in ids {
        match channel.ethereum_address(crypto, id, &path) {
            Ok(addr) => out.push_str(&format!("  session {id}: {addr}\n")),
            Err(e) => out.push_str(&format!("  session {id}: {e}\n")),
        }
    }

    out.push_str(match passphrase {
        None => "\nNo passphrase was given, so every session should show the same address.\n",
        Some("") => "\nThe passphrase was empty, which is the same wallet as no passphrase.\n",
        Some(_) => {
            "\nThe passphrase session must show a DIFFERENT address from the standard session.\n\
             If every id shows the same address, the passphrase did not take effect.\n"
        }
    });

    Ok(out)
}

/// STAGE 5 HARDWARE MILESTONE: sign an EIP-1559 transaction and verify the signature locally.
///
/// The transaction is a fixed dummy and is **never broadcast** - the probe makes no network
/// connection at all. Its purpose is twofold: the device's confirmation screen shows whether we
/// encoded the amount, recipient and fees correctly, and recovering the signer address from the
/// returned signature proves the signature is valid for exactly the transaction we think we signed.
/// If the recovered address matches the address derived from the same path, signing is correct.
pub fn sign_probe(state_path: &std::path::Path, passphrase: Option<&str>) -> Result<String, String> {
    use alloy::consensus::{SignableTransaction, TxEip1559};
    use alloy::primitives::{Address, Bytes, Signature, TxKind, U256};

    // A deliberately recognisable, unspendable recipient.
    const TO: &str = "0x000000000000000000000000000000000000dEaD";
    const CHAIN_ID: u64 = 1;
    const NONCE: u64 = 0;
    const GAS_LIMIT: u64 = 21_000;
    const MAX_FEE: u128 = 30_000_000_000; // 30 gwei
    const MAX_PRIORITY: u128 = 1_000_000_000; // 1 gwei
    const VALUE: u128 = 1_000_000_000_000_000; // 0.001 ETH

    let stored = std::fs::read_to_string(state_path)
        .map_err(|_| "no stored pairing - run `aero thp-pair` first".to_string())?;
    let (host_static_priv, credential) =
        parse_pairing_state(&stored).ok_or("could not read the stored pairing")?;
    let credential = credential.ok_or("the stored pairing has no credential - re-run `thp-pair`")?;

    let link = usb::UsbLink::open()?;
    let (mut channel, _props) = Channel::allocate(link)?;
    let mut session = channel.handshake(host_static_priv, Some(&credential), true)?;
    if !session.is_paired() {
        return Err("the device did not accept the stored credential - re-run `thp-pair`".into());
    }
    channel.finish_without_pairing(&mut session.crypto)?;
    let crypto = &mut session.crypto;

    const H: u32 = 0x8000_0000;
    let path = [44 | H, 60 | H, H, 0, 0];
    let session_id = channel.create_session(crypto, passphrase, false)?;
    let address = channel.ethereum_address(crypto, session_id, &path)?;

    let mut out = format!("session {session_id}, signing from {address}\n");
    out.push_str(&format!(
        "\nThe device should be asking you to confirm:\n  \
         send 0.001 ETH\n  to {TO}\n  on Ethereum mainnet (chain id {CHAIN_ID})\n  \
         max fee 30 gwei, priority fee 1 gwei, gas limit {GAS_LIMIT}\n\n"
    ));

    let tx_fields = Eip1559Tx {
        nonce: NONCE,
        max_fee_per_gas: MAX_FEE,
        max_priority_fee_per_gas: MAX_PRIORITY,
        gas_limit: GAS_LIMIT,
        to: TO,
        value: VALUE,
        data: &[],
        chain_id: CHAIN_ID,
    };
    let (v, r, s) = channel.ethereum_sign_eip1559(crypto, session_id, &path, &tx_fields)?;

    // Rebuild the same transaction locally and check the signature recovers to the signing address.
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: NONCE,
        gas_limit: GAS_LIMIT,
        max_fee_per_gas: MAX_FEE,
        max_priority_fee_per_gas: MAX_PRIORITY,
        to: TxKind::Call(TO.parse::<Address>().map_err(|e| e.to_string())?),
        value: U256::from(VALUE),
        access_list: Default::default(),
        input: Bytes::new(),
    };
    let sighash = tx.signature_hash();

    let parity = match v {
        0 | 27 => false,
        1 | 28 => true,
        other => return Err(format!("device returned an unexpected recovery parameter {other}")),
    };
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(&r);
    rs[32..].copy_from_slice(&s);
    let sig = Signature::from_bytes_and_parity(&rs, parity);
    let recovered = sig
        .recover_address_from_prehash(&sighash)
        .map_err(|e| format!("could not recover the signer: {e}"))?;
    let recovered = format!("{recovered}");

    out.push_str(&format!("signature v={v}\n  r=0x{}\n  s=0x{}\n", hex::encode(r), hex::encode(s)));
    out.push_str(&format!("signing hash = 0x{}\n", hex::encode(sighash)));
    out.push_str(&format!("recovered signer = {recovered}\n"));
    if recovered.eq_ignore_ascii_case(&address) {
        out.push_str("\nSIGNATURE VERIFIED - it recovers to the device's own address.\n");
    } else {
        out.push_str(&format!(
            "\nMISMATCH - the signature recovers to {recovered} but the device's address is \
             {address}. The transaction fields we sent do not match what the device signed.\n"
        ));
    }
    out.push_str("Nothing was broadcast; this probe makes no network connection.\n");

    Ok(out)
}

fn parse_pairing_state(text: &str) -> Option<([u8; 32], Option<Vec<u8>>)> {
    let mut priv_key = None;
    let mut cred = None;
    for line in text.lines() {
        let (k, v) = line.split_once('=')?;
        match k.trim() {
            "host_static_priv" => priv_key = hex_to_bytes(v.trim())?.try_into().ok(),
            "credential" => cred = hex_to_bytes(v.trim()),
            _ => {}
        }
    }
    priv_key.map(|p| (p, cred))
}

/// STAGE 1-2 HARDWARE MILESTONE: open the device, allocate a channel, and report the device
/// properties. This exercises the USB transport + 64-byte framing + CRC + channel-allocation parse
/// against the real device WITHOUT any crypto or the ABP layer, so it's the safest first thing to
/// verify on a plugged-in 2025+ Trezor. Returns a human/JSON summary.
pub fn probe() -> Result<String, String> {
    // Report what is attached before touching it, so that a claim/permission failure still tells us
    // the product id and interface layout of the device rather than just "it didn't work".
    let found = usb::list()?;
    let mut report = String::new();
    if found.is_empty() {
        report.push_str("USB: no Trezor found\n");
    } else {
        for d in &found {
            report.push_str(&format!("USB: {}\n", d.describe()));
        }
    }
    let link = usb::UsbLink::open().map_err(|e| format!("{report}{e}"))?;
    allocate_and_describe(link).map(|s| format!("{report}{s}")).map_err(|e| format!("{report}{e}"))
}

fn allocate_and_describe(link: usb::UsbLink) -> Result<String, String> {
    let (channel, dp) = Channel::allocate(link)?;
    let cid = channel.cid();
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

    // --- synchronization layer (ABP) -------------------------------------------------------------

    #[test]
    fn control_byte_patterns_match_the_spec_table() {
        // ack: 0010X000, mask 0xF7, value 0x20 - the X is the ACK bit, not a sequence number.
        assert!(control::is_ack(0x20));
        assert!(control::is_ack(0x28));
        assert_eq!(control::ack_for(false), 0x20);
        assert_eq!(control::ack_for(true), 0x28);
        assert!(!control::ack_of(control::ack_for(false)));
        assert!(control::ack_of(control::ack_for(true)));
        // An ACK never carries a sequence bit, so 0x30 must not parse as one.
        assert!(!control::is_ack(0x30));

        // encrypted_transport: 000XX100, mask 0xE7, value 0x04.
        for seq in [false, true] {
            let cb = control::data_with_seq(control::ENCRYPTED_TRANSPORT, seq);
            assert!(control::is_data(cb));
            assert_eq!(control::seq_of(cb), seq);
            assert_eq!(cb & !control::SYNC_MASK, control::ENCRYPTED_TRANSPORT);
        }
        assert_eq!(control::data_with_seq(control::ENCRYPTED_TRANSPORT, false), 0x04);
        assert_eq!(control::data_with_seq(control::ENCRYPTED_TRANSPORT, true), 0x14);
        assert_eq!(control::data_with_seq(control::HANDSHAKE_INIT_REQUEST, true), 0x10);

        // Continuation packets and channel-management bytes are not data messages.
        assert!(!control::is_data(control::CONTINUATION));
        assert!(!control::is_data(control::CHANNEL_ALLOCATION_REQUEST));
        assert!(!control::is_data(control::PING));
        assert!(!control::is_data(control::ACK));
    }

    #[test]
    fn ack_message_is_a_single_packet_with_only_a_crc() {
        let pkts = segment(control::ack_for(true), 0x1234, &[]);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0][0], 0x28);
        assert_eq!(u16::from_be_bytes([pkts[0][3], pkts[0][4]]), 4); // CRC only
        let msg = reassemble(&pkts).unwrap();
        assert!(msg.payload.is_empty());
        assert!(control::is_ack(msg.control_byte));
    }

    #[test]
    fn cpace_host_and_device_derive_the_same_secret() {
        // Both sides run the same construction, so this catches any mix-up in what gets multiplied
        // by what - the sort of mistake the type system cannot see when every value is [u8; 32].
        let handshake_hash = [7u8; 32];
        let generator = cpace_generator("740902", &handshake_hash).unwrap();

        // Device side: private scalar, public key over the shared generator.
        let trezor_priv = [3u8; 32];
        let trezor_pub = x25519(trezor_priv, generator);

        // Host side, exactly as `pair_code_entry` calls it.
        let host_priv = [5u8; 32];
        let (host_pub, tag) = cpace_host(generator, trezor_pub, host_priv);

        // The device recomputes the shared secret from the host's public key and checks the tag.
        let device_shared = x25519(trezor_priv, host_pub);
        assert_eq!(tag, sha256(&[&device_shared[..]]), "CPace tag must match the device's view");
    }

    /// Known answers from `scripts/cpace_reference.py`, an implementation written independently
    /// from the THP spec and RFC 9380 G.2.1 rather than from this code. Agreement is what tells us
    /// the Elligator2 mapping matches the one Trezor's firmware uses; nothing else here can.
    #[test]
    fn cpace_generator_matches_the_reference_implementation() {
        let cases: [(&str, [u8; 32], &str); 3] = [
            ("740902", [7u8; 32], "4263aaa42b54c42daef296ced908225bc186fa252b02a722cde8b6bd25f70911"),
            ("000000", [0u8; 32], "e1cc15339fb0fcbe825a85644a088d133f1b140ad43b6879708232659b18dc2e"),
            ("123456", {
                let mut h = [0u8; 32];
                let mut i = 0;
                while i < 32 {
                    h[i] = i as u8;
                    i += 1;
                }
                h
            }, "4e1da1dfe958d2243b655fd45da026889142bcc3aa96c7eb58f10242cd8af52a"),
        ];
        for (code, handshake_hash, expected) in cases {
            let got = cpace_generator(code, &handshake_hash).unwrap();
            assert_eq!(hex_of(&got), expected, "generator mismatch for code {code}");
        }
    }

    #[test]
    fn cpace_generator_binds_to_the_code_and_handshake() {
        let h = [7u8; 32];
        assert_ne!(
            cpace_generator("000000", &h).unwrap(),
            cpace_generator("000001", &h).unwrap(),
            "a different code must give a different generator"
        );
        assert_ne!(
            cpace_generator("123456", &h).unwrap(),
            cpace_generator("123456", &[8u8; 32]).unwrap(),
            "a different handshake must give a different generator"
        );
    }

    #[test]
    fn transport_error_classification() {
        assert!(transport_error_is_fatal(2)); // UNALLOCATED_CHANNEL
        assert!(transport_error_is_fatal(3)); // DECRYPTION_FAILED
        assert!(!transport_error_is_fatal(1)); // TRANSPORT_BUSY is retryable
        assert!(!transport_error_is_fatal(5)); // DEVICE_LOCKED - unlock and retry
        assert_eq!(transport_error_name(2), "UNALLOCATED_CHANNEL");
    }

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
    fn eip1559_amounts_use_minimal_big_endian() {
        assert_eq!(be_minimal(0), Vec::<u8>::new(), "zero is the empty default");
        assert_eq!(be_minimal(1), vec![0x01]);
        assert_eq!(be_minimal(255), vec![0xff]);
        assert_eq!(be_minimal(256), vec![0x01, 0x00]);
        assert_eq!(be_minimal(21_000), vec![0x52, 0x08]);
        assert_eq!(be_minimal(u128::MAX), vec![0xff; 16]);
        // Signature components come back with leading zeros stripped and must be re-padded.
        assert_eq!(pad32(&[0x01]).unwrap()[31], 0x01);
        assert_eq!(pad32(&[0x01]).unwrap()[..31], [0u8; 31]);
        assert!(pad32(&[0u8; 33]).is_err());
    }

    /// Guards the field numbering of `EthereumSignTxEIP1559`, where a silent mistake would produce
    /// a perfectly valid signature over the wrong transaction.
    #[test]
    fn eip1559_request_field_numbers_and_values() {
        let path = [44 | 0x8000_0000u32, 60 | 0x8000_0000, 0x8000_0000, 0, 0];
        let mut body = Vec::new();
        for &p in &path {
            body.extend_from_slice(&proto_varint_field(1, p as u64));
        }
        body.extend_from_slice(&proto_bytes_field(2, &be_minimal(7)));         // nonce
        body.extend_from_slice(&proto_bytes_field(3, &be_minimal(30_000_000_000)));
        body.extend_from_slice(&proto_bytes_field(4, &be_minimal(1_000_000_000)));
        body.extend_from_slice(&proto_bytes_field(5, &be_minimal(21_000)));
        body.extend_from_slice(&proto_string_field(6, "0xdead"));
        body.extend_from_slice(&proto_bytes_field(7, &be_minimal(1_000_000_000_000_000)));
        body.extend_from_slice(&proto_varint_field(9, 0));
        body.extend_from_slice(&proto_varint_field(10, 1));

        let decoded = proto_decode(&body);
        let paths: Vec<u64> = decoded
            .iter()
            .filter_map(|(f, v)| match v {
                WireVal::Varint(x) if *f == 1 => Some(*x),
                _ => None,
            })
            .collect();
        assert_eq!(paths, path.iter().map(|&p| p as u64).collect::<Vec<_>>());

        let bytes_field = |n: u32| {
            decoded.iter().find_map(|(f, v)| match v {
                WireVal::Bytes(b) if *f == n => Some(b.clone()),
                _ => None,
            })
        };
        assert_eq!(bytes_field(2).unwrap(), vec![7]);
        assert_eq!(bytes_field(5).unwrap(), vec![0x52, 0x08]);
        assert_eq!(bytes_field(6).unwrap(), b"0xdead".to_vec());
        // data_length and chain_id are `required`, so both must be present even when zero.
        let varint_field = |n: u32| {
            decoded.iter().find_map(|(f, v)| match v {
                WireVal::Varint(x) if *f == n => Some(*x),
                _ => None,
            })
        };
        assert_eq!(varint_field(9), Some(0), "data_length must be on the wire even at zero");
        assert_eq!(varint_field(10), Some(1), "chain_id");
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
