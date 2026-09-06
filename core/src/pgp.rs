// SPDX-License-Identifier: BSD-3-Clause
//! Just enough OpenPGP to decide whether an update is genuine.
//!
//! This is not an OpenPGP library and must never grow into one. It reads exactly one thing: a
//! version-4 detached binary signature made by one pinned Ed25519 key. Every other shape of
//! OpenPGP - encryption, compression, other algorithms, other key types, keyring lookup, web of
//! trust - is out of scope and is rejected rather than handled.
//!
//! That narrowness is deliberate. This code decides which binary the user runs next, so it is the
//! one place in Aero where "we accepted something we did not fully understand" is fatal. A general
//! parser has to be liberal in what it accepts; this one gets to be hostile.
//!
//! What is checked, in order, before a signature is called good:
//!   1. The armor decodes, and its CRC-24 matches.
//!   2. There is exactly one signature packet and nothing else.
//!   3. It is v4, type 0x00 (binary document), algorithm 22 (EdDSA), hash SHA-256/384/512.
//!   4. It was issued by the pinned key - compared on the full 20-byte fingerprint where the
//!      signature carries one, never on the 8-byte key id alone.
//!   5. It was created inside the pinned key's validity window.
//!   6. The digest matches the document, and Ed25519 verifies it against the pinned key.
//!
//! References: RFC 4880 (section 5.2.3, section 5.2.4, section 6.2) and RFC 8032 for Ed25519.

use crate::error::{CoreError, Result};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The Aero release signing key, as raw Ed25519 public key bytes.
///
/// Pinned, not looked up. There is no keyring, no key server and no way for a downloaded file to
/// nominate the key that verifies it - the only key that can ever authorise an update to this build
/// is the one compiled into it. Replacing the key therefore requires replacing Aero, which is the
/// property we want: an attacker who can serve you a manifest still cannot serve you a key.
///
/// Primary key of:
///     pub   ed25519 2026-09-05 [SC] [expires: 2029-09-05]
///           FD06 516B 6C76 2BB8 B016  16DE 80D5 05C2 5B02 54B3
///     uid   Aero
pub const RELEASE_KEY: [u8; 32] = [
    0x83, 0x32, 0xd4, 0x82, 0x06, 0x8a, 0x3e, 0x41, 0x21, 0xf2, 0x25, 0x7a, 0x17, 0x5e, 0xfc, 0x9e,
    0x59, 0x50, 0x15, 0x09, 0xfb, 0xe8, 0xd6, 0x46, 0x63, 0xd5, 0x00, 0x85, 0x29, 0x44, 0x48, 0xb1,
];

/// V4 fingerprint of [`RELEASE_KEY`]: SHA-1 over the public-key packet body, per RFC 4880 section 12.2.
/// Shown to the user so the key in the app can be compared against the one published elsewhere.
pub const RELEASE_FINGERPRINT: [u8; 20] = [
    0xFD, 0x06, 0x51, 0x6B, 0x6C, 0x76, 0x2B, 0xB8, 0xB0, 0x16, 0x16, 0xDE, 0x80, 0xD5, 0x05, 0xC2,
    0x5B, 0x02, 0x54, 0xB3,
];

/// When the release key was created, and when it expires (unix seconds), read from the key itself.
///
/// A signature dated outside this window is refused. Without the lower bound a signature could claim
/// to predate the key; without the upper bound the key would keep authorising updates forever, which
/// is the one thing an expiry date is for.
const KEY_CREATED: u64 = 1_788_638_245; // 2026-09-05
const KEY_EXPIRES: u64 = 1_883_457_664; // 2029-09-05

/// Grace allowed on the "not created in the future" check, for ordinary clock skew between the
/// machine that signed and the machine that is checking.
const FUTURE_SKEW_SECS: u64 = 24 * 60 * 60;

/// `RELEASE_FINGERPRINT` in the spaced, upper-case form GnuPG prints, for showing to a human.
pub fn release_fingerprint_display() -> String {
    let hex: Vec<String> = RELEASE_FINGERPRINT
        .chunks(2)
        .map(|p| format!("{:02X}{:02X}", p[0], p[1]))
        .collect();
    // GnuPG splits the ten groups into two halves with a wider gap in the middle.
    format!("{} {}", hex[..5].join(" "), hex[5..].join(" "))
}

/// Verify a detached OpenPGP signature over `data`, made by the pinned release key.
///
/// `armored_sig` is the contents of a `.asc` file (`-----BEGIN PGP SIGNATURE-----` â€¦ ). Returns the
/// signature's creation time on success. Any deviation at all is an error: this function has no
/// "probably fine" answer.
pub fn verify_detached(data: &[u8], armored_sig: &str) -> Result<u64> {
    Verifier::release().verify(data, armored_sig)
}

/// A pinned signing key and the window it is allowed to have signed in.
///
/// The shipping app only ever uses [`Verifier::release`]. It exists as a type so the tests can point
/// the exact same code at a throwaway key, rather than testing a near-copy of it.
pub struct Verifier {
    key: [u8; 32],
    fingerprint: Option<[u8; 20]>,
    created: u64,
    expires: u64,
}

/// Build a verifier for an arbitrary Ed25519 key. Test-only: the application must never verify an
/// update against anything but the pinned key, and making that hard to do by accident is the point
/// of keeping this behind `cfg(test)`.
#[cfg(test)]
pub fn verifier_for_tests(key: [u8; 32]) -> Verifier {
    Verifier {
        key,
        fingerprint: None,
        created: 0,
        expires: u64::MAX,
    }
}

/// Pull the raw Ed25519 point out of an armored public key block, using this module's own reader.
#[cfg(test)]
pub fn ed25519_from_armored_key(armored: &str) -> [u8; 32] {
    let raw = dearmor(armored, "PGP PUBLIC KEY BLOCK").expect("decode public key");
    let (tag, body, _) = read_packet(&raw).expect("public key packet");
    assert_eq!(tag, 6, "expected a public-key packet");
    // version(1) created(4) algo(1) oid-len(1) oid(9) mpi-header(2) native-point marker(1).
    let mut key = [0u8; 32];
    key.copy_from_slice(&body[19..51]);
    key
}

impl Verifier {
    /// The one verifier the application uses: the pinned Aero release key.
    pub fn release() -> Self {
        Self {
            key: RELEASE_KEY,
            fingerprint: Some(RELEASE_FINGERPRINT),
            created: KEY_CREATED,
            expires: KEY_EXPIRES,
        }
    }

    pub fn verify(&self, data: &[u8], armored_sig: &str) -> Result<u64> {
        let packet = dearmor(armored_sig, "PGP SIGNATURE")?;
        let sig = parse_signature(&packet)?;
        self.check(data, &sig)
    }

    fn check(&self, data: &[u8], sig: &SigPacket) -> Result<u64> {

    // Whose signature is this? Prefer the fingerprint, which names one key. A key id is the last
    // eight bytes of a fingerprint and can be made to collide by anyone who wants to, so it is only
    // ever a hint about which key to try - never, on its own, an answer to "is this our key".
        match (sig.issuer_fingerprint, self.fingerprint) {
            (Some(fpr), Some(want)) => {
                if fpr != want {
                    return Err(CoreError::other(format!(
                        "update signed by the wrong key ({}), not the Aero release key",
                        hex::encode_upper(fpr)
                    )));
                }
            }
            (None, Some(want)) => {
                // No fingerprint subpacket. The key id still has to match, but on its own it proves
                // nothing - the Ed25519 check below is what actually decides.
                if let Some(id) = sig.issuer_key_id {
                    if id != want[12..20] {
                        return Err(CoreError::other(
                            "update signed by the wrong key, not the Aero release key".to_string(),
                        ));
                    }
                }
            }
            _ => {}
        }

        if sig.created < self.created {
            return Err(CoreError::other(
                "update signature is dated before the Aero release key existed".to_string(),
            ));
        }
        if sig.created > self.expires {
            return Err(CoreError::other(
                "update signature was made after the Aero release key expired".to_string(),
            ));
        }
        if sig.created > now_secs().saturating_add(FUTURE_SKEW_SECS) {
            return Err(CoreError::other(
                "update signature is dated in the future - check this machine's clock".to_string(),
            ));
        }

    // RFC 4880 section 5.2.4: a v4 signature hashes the document, then the signature packet's own metadata,
    // then a six-byte trailer covering that metadata. Hashing the document alone would let anyone
    // move a signature onto a different kind of object.
        let digest = match sig.hash_algo {
            8 => sig.digest_with::<Sha256>(data),
            9 => sig.digest_with::<Sha384>(data),
            10 => sig.digest_with::<Sha512>(data),
            other => {
                return Err(CoreError::other(format!(
                    "update signature uses hash algorithm {other}; Aero accepts only SHA-256, \
                     SHA-384 or SHA-512"
                )))
            }
        };

        // The two-byte quick check is not security, just an early and much clearer error than a
        // failed curve operation when the file simply does not match.
        if digest[0] != sig.digest_prefix[0] || digest[1] != sig.digest_prefix[1] {
            return Err(CoreError::other(
                "update signature does not match the file it is supposed to cover".to_string(),
            ));
        }

        let key = VerifyingKey::from_bytes(&self.key)
            .map_err(|e| CoreError::other(format!("bad pinned release key: {e}")))?;
        // Ed25519Legacy (algorithm 22) signs the OpenPGP digest itself, so the digest is the
        // message.
        let signature = Signature::from_bytes(&sig.ed25519);
        key.verify_strict(&digest, &signature).map_err(|_| {
            CoreError::other("update signature is not valid for the Aero release key".to_string())
        })?;

        Ok(sig.created)
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- ASCII armor -------------------------------------------------------------------------------

/// Strip OpenPGP ASCII armor and return the binary inside it.
///
/// The CRC-24 line is checked when present. It is not a security control - anyone editing the body
/// can recompute it - but a mismatch means the file was mangled in transit, and saying so is much
/// more useful than a signature error that looks like an attack.
fn dearmor(text: &str, want: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {want}-----");
    let end = format!("-----END {want}-----");
    let start = text
        .find(&begin)
        .ok_or_else(|| CoreError::other(format!("not an armored {want} (no BEGIN line)")))?;
    let rest = &text[start + begin.len()..];
    let stop = rest
        .find(&end)
        .ok_or_else(|| CoreError::other(format!("not an armored {want} (no END line)")))?;
    // Drop the line break that ends the BEGIN line itself, so the first thing the loop sees is a
    // real armor header (or the data). Without this the loop reads that break as the blank line
    // that terminates the header block, and then tries to base64-decode "Comment: ..." lines.
    let body = rest[..stop].trim_start_matches(['\r', '\n']);

    let mut b64 = String::new();
    let mut crc: Option<u32> = None;
    let mut in_headers = true;
    for raw in body.lines() {
        let line = raw.trim_end_matches('\r').trim();
        if in_headers {
            // Armor headers run until the first blank line. Base64 has no colon in its alphabet, so
            // a colon is an unambiguous way to tell a header apart from the data.
            if line.is_empty() {
                in_headers = false;
                continue;
            }
            if line.contains(':') {
                continue;
            }
            in_headers = false;
        }
        if line.is_empty() {
            continue;
        }
        if let Some(sum) = line.strip_prefix('=') {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(sum)
                .map_err(|_| CoreError::other("armor checksum is not valid base64".to_string()))?;
            if bytes.len() == 3 {
                crc = Some(
                    (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]),
                );
            }
            continue;
        }
        b64.push_str(line);
    }

    let data = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| CoreError::other(format!("{want} armor is not valid base64")))?;
    if let Some(expected) = crc {
        if crc24(&data) != expected {
            return Err(CoreError::other(format!(
                "{want} armor checksum does not match - the file is corrupt or truncated"
            )));
        }
    }
    if data.is_empty() {
        return Err(CoreError::other(format!("{want} armor is empty")));
    }
    Ok(data)
}

/// CRC-24 as specified in RFC 4880 section 6.1.
fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00B7_04CE;
    for &b in data {
        crc ^= u32::from(b) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    crc & 0x00FF_FFFF
}

// ---- Signature packet --------------------------------------------------------------------------

struct SigPacket {
    hash_algo: u8,
    created: u64,
    issuer_key_id: Option<[u8; 8]>,
    issuer_fingerprint: Option<[u8; 20]>,
    digest_prefix: [u8; 2],
    ed25519: [u8; 64],
    /// The bytes this signature commits to besides the document: version, type, algorithms and the
    /// whole hashed-subpacket area. Kept verbatim, because that is what was hashed.
    hashed_meta: Vec<u8>,
}

impl SigPacket {
    fn digest_with<H: Digest>(&self, data: &[u8]) -> Vec<u8> {
        let mut h = H::new();
        h.update(data);
        h.update(&self.hashed_meta);
        // RFC 4880 section 5.2.4 trailer: version 0x04, 0xFF, then the length of the hashed metadata.
        h.update([0x04, 0xFF]);
        h.update((self.hashed_meta.len() as u32).to_be_bytes());
        h.finalize().to_vec()
    }
}

/// Read the one signature packet a detached `.asc` should contain.
///
/// Anything else in the stream is refused. A file that carries a signature *and* something else is
/// not a detached signature, and guessing which part was meant is how a checker ends up verifying
/// one thing while the caller uses another.
fn parse_signature(bytes: &[u8]) -> Result<SigPacket> {
    let (tag, body, consumed) = read_packet(bytes)?;
    if tag != 2 {
        return Err(CoreError::other(format!(
            "expected an OpenPGP signature packet, found packet type {tag}"
        )));
    }
    if consumed != bytes.len() {
        return Err(CoreError::other(
            "detached signature file contains more than one packet".to_string(),
        ));
    }

    let take = |from: usize, n: usize| -> Result<&[u8]> {
        body.get(from..from + n)
            .ok_or_else(|| CoreError::other("truncated OpenPGP signature".to_string()))
    };

    if *body.first().ok_or_else(|| CoreError::other("empty signature packet".to_string()))? != 4 {
        return Err(CoreError::other(
            "unsupported OpenPGP signature version; Aero accepts only version 4".to_string(),
        ));
    }
    let sig_type = body[1];
    let pubkey_algo = body[2];
    let hash_algo = body[3];

    // 0x00 is a signature over a binary document. Aero signs files, so anything else - a text
    // signature, a key certification, a revocation - is a signature over something that is not the
    // file in front of us, however genuine it may be.
    if sig_type != 0x00 {
        return Err(CoreError::other(format!(
            "signature type 0x{sig_type:02x} is not a binary-document signature"
        )));
    }
    // 22 is EdDSA (Ed25519). The pinned key is Ed25519, so no other algorithm can be a match, and
    // saying so here means the rest of the parser never has to consider one.
    if pubkey_algo != 22 {
        return Err(CoreError::other(format!(
            "signature algorithm {pubkey_algo} is not Ed25519"
        )));
    }

    let hashed_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let hashed = take(6, hashed_len)?.to_vec();
    let mut at = 6 + hashed_len;

    let unhashed_len = u16::from_be_bytes([
        *body.get(at).ok_or_else(|| CoreError::other("truncated signature".to_string()))?,
        *body.get(at + 1).ok_or_else(|| CoreError::other("truncated signature".to_string()))?,
    ]) as usize;
    let unhashed = take(at + 2, unhashed_len)?.to_vec();
    at += 2 + unhashed_len;

    let prefix = take(at, 2)?;
    let digest_prefix = [prefix[0], prefix[1]];
    at += 2;

    // EdDSA carries two MPIs, r and s, each a 32-byte scalar once left-padded. OpenPGP MPIs drop
    // leading zero bytes, so a short r or s is normal and has to be padded back out, not rejected.
    let (r, next) = read_mpi(body, at)?;
    let (s, next) = read_mpi(body, next)?;
    if next != body.len() {
        return Err(CoreError::other("trailing bytes after the signature".to_string()));
    }
    let mut ed25519 = [0u8; 64];
    place_scalar(&mut ed25519[..32], &r)?;
    place_scalar(&mut ed25519[32..], &s)?;

    // Creation time is a hashed subpacket, so it is covered by the signature and cannot be edited
    // after the fact. The issuer fingerprint is normally hashed too; the older key-id subpacket
    // usually is not, which is exactly why it is treated as a hint and not as proof.
    let mut created: Option<u64> = None;
    let mut issuer_key_id: Option<[u8; 8]> = None;
    let mut issuer_fingerprint: Option<[u8; 20]> = None;
    for (kind, data) in subpackets(&hashed)? {
        match kind {
            2 if data.len() == 4 => {
                created = Some(u64::from(u32::from_be_bytes([
                    data[0], data[1], data[2], data[3],
                ])));
            }
            16 if data.len() == 8 => issuer_key_id = Some(data.try_into().unwrap()),
            33 if data.len() == 21 && data[0] == 4 => {
                issuer_fingerprint = Some(data[1..21].try_into().unwrap());
            }
            _ => {}
        }
    }
    for (kind, data) in subpackets(&unhashed)? {
        match kind {
            16 if data.len() == 8 && issuer_key_id.is_none() => {
                issuer_key_id = Some(data.try_into().unwrap());
            }
            33 if data.len() == 21 && data[0] == 4 && issuer_fingerprint.is_none() => {
                issuer_fingerprint = Some(data[1..21].try_into().unwrap());
            }
            _ => {}
        }
    }

    let created = created.ok_or_else(|| {
        CoreError::other("signature has no creation time, so it cannot be dated".to_string())
    })?;

    let mut hashed_meta = Vec::with_capacity(6 + hashed.len());
    hashed_meta.extend_from_slice(&[4, sig_type, pubkey_algo, hash_algo]);
    hashed_meta.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
    hashed_meta.extend_from_slice(&hashed);

    Ok(SigPacket {
        hash_algo,
        created,
        issuer_key_id,
        issuer_fingerprint,
        digest_prefix,
        ed25519,
        hashed_meta,
    })
}

/// Right-align an MPI into a fixed-width scalar slot.
fn place_scalar(slot: &mut [u8], mpi: &[u8]) -> Result<()> {
    if mpi.len() > slot.len() {
        return Err(CoreError::other(
            "signature scalar is too large for Ed25519".to_string(),
        ));
    }
    let at = slot.len() - mpi.len();
    slot[at..].copy_from_slice(mpi);
    Ok(())
}

/// Read one multiprecision integer (RFC 4880 section 3.2): a bit count, then that many bits of big-endian
/// value. Returns the value bytes and the offset just past them.
fn read_mpi(body: &[u8], at: usize) -> Result<(Vec<u8>, usize)> {
    let hi = *body
        .get(at)
        .ok_or_else(|| CoreError::other("truncated MPI".to_string()))?;
    let lo = *body
        .get(at + 1)
        .ok_or_else(|| CoreError::other("truncated MPI".to_string()))?;
    let bits = u16::from_be_bytes([hi, lo]) as usize;
    let len = (bits + 7) / 8;
    if len > 64 {
        return Err(CoreError::other("MPI is too large for a signature".to_string()));
    }
    let end = at + 2 + len;
    let val = body
        .get(at + 2..end)
        .ok_or_else(|| CoreError::other("truncated MPI".to_string()))?
        .to_vec();

    // RFC 4880 section 3.2 requires the length to be counted from the most significant non-zero
    // bit, so for any given value there is exactly one correct encoding. Accepting a bit count that
    // merely rounds to the same number of bytes would leave the signature file malleable: the same
    // signature could be written several ways, each a different sequence of bytes. Nothing is
    // forgeable through that, but "the file that verified is not the only file that would have"
    // is not a property worth keeping when rejecting it costs three lines.
    let declared_bits = val
        .iter()
        .position(|&b| b != 0)
        .map(|i| (val.len() - i) * 8 - val[i].leading_zeros() as usize)
        .unwrap_or(0);
    if declared_bits != bits {
        return Err(CoreError::other(format!(
            "signature MPI claims {bits} bits but holds {declared_bits}"
        )));
    }
    Ok((val, end))
}

/// Split a subpacket area into `(type, data)` pairs (RFC 4880 section 5.2.3.1).
fn subpackets(area: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < area.len() {
        let first = area[i];
        let (len, header) = if first < 192 {
            (first as usize, 1usize)
        } else if first < 255 {
            let second = *area
                .get(i + 1)
                .ok_or_else(|| CoreError::other("truncated subpacket length".to_string()))?;
            (((first as usize - 192) << 8) + second as usize + 192, 2)
        } else {
            let b = area
                .get(i + 1..i + 5)
                .ok_or_else(|| CoreError::other("truncated subpacket length".to_string()))?;
            (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize, 5)
        };
        if len == 0 {
            return Err(CoreError::other("zero-length subpacket".to_string()));
        }
        let kind_at = i + header;
        let kind = *area
            .get(kind_at)
            .ok_or_else(|| CoreError::other("truncated subpacket".to_string()))?;
        // The length counts the type byte, so the payload is one shorter.
        let data = area
            .get(kind_at + 1..kind_at + len)
            .ok_or_else(|| CoreError::other("truncated subpacket".to_string()))?;
        // Bit 7 of the type marks "critical"; the type itself is the low seven bits.
        out.push((kind & 0x7F, data));
        i = kind_at + len;
    }
    Ok(out)
}

/// Read one packet header and body (RFC 4880 section 4.2), returning `(tag, body, bytes_consumed)`.
fn read_packet(bytes: &[u8]) -> Result<(u8, &[u8], usize)> {
    let first = *bytes
        .first()
        .ok_or_else(|| CoreError::other("empty OpenPGP data".to_string()))?;
    if first & 0x80 == 0 {
        return Err(CoreError::other("not an OpenPGP packet".to_string()));
    }
    let (tag, len, header) = if first & 0x40 != 0 {
        // New format: tag in the low six bits, then a variable-length length.
        let tag = first & 0x3F;
        let b1 = *bytes
            .get(1)
            .ok_or_else(|| CoreError::other("truncated packet length".to_string()))?;
        if b1 < 192 {
            (tag, b1 as usize, 2usize)
        } else if b1 < 224 {
            let b2 = *bytes
                .get(2)
                .ok_or_else(|| CoreError::other("truncated packet length".to_string()))?;
            (tag, ((b1 as usize - 192) << 8) + b2 as usize + 192, 3)
        } else if b1 == 255 {
            let b = bytes
                .get(2..6)
                .ok_or_else(|| CoreError::other("truncated packet length".to_string()))?;
            (tag, u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize, 6)
        } else {
            // Partial body lengths only ever appear on streamed literal data, never on a signature.
            return Err(CoreError::other(
                "partial-length packets are not accepted here".to_string(),
            ));
        }
    } else {
        // Old format: tag in bits 5..2, length type in the low two bits.
        let tag = (first >> 2) & 0x0F;
        match first & 0x03 {
            0 => (
                tag,
                *bytes
                    .get(1)
                    .ok_or_else(|| CoreError::other("truncated packet length".to_string()))?
                    as usize,
                2usize,
            ),
            1 => {
                let b = bytes
                    .get(1..3)
                    .ok_or_else(|| CoreError::other("truncated packet length".to_string()))?;
                (tag, u16::from_be_bytes([b[0], b[1]]) as usize, 3)
            }
            2 => {
                let b = bytes
                    .get(1..5)
                    .ok_or_else(|| CoreError::other("truncated packet length".to_string()))?;
                (tag, u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize, 5)
            }
            _ => {
                return Err(CoreError::other(
                    "indeterminate-length packets are not accepted here".to_string(),
                ))
            }
        }
    };
    let body = bytes
        .get(header..header + len)
        .ok_or_else(|| CoreError::other("truncated OpenPGP packet".to_string()))?;
    Ok((tag, body, header + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key compiled into Aero has to be the key whose fingerprint we print. If these ever drift,
    /// the app would be telling the user to compare against a fingerprint it does not actually use.
    #[test]
    fn the_pinned_key_matches_its_published_fingerprint() {
        // A v4 fingerprint is SHA-1 over the public-key packet body, prefixed with 0x99 and the
        // body's two-byte length (RFC 4880 section 12.2). Rebuild that body from the pinned key.
        let mut body = Vec::new();
        body.push(4); // version
        body.extend_from_slice(&(KEY_CREATED as u32).to_be_bytes());
        body.push(22); // EdDSA
        body.push(9); // OID length
        body.extend_from_slice(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]); // Ed25519
        body.extend_from_slice(&[0x01, 0x07]); // MPI: 263 bits
        body.push(0x40); // native-point prefix
        body.extend_from_slice(&RELEASE_KEY);

        let mut input = vec![0x99, (body.len() >> 8) as u8, body.len() as u8];
        input.extend_from_slice(&body);

        use sha1_for_test::sha1;
        assert_eq!(
            sha1(&input),
            RELEASE_FINGERPRINT,
            "the pinned Ed25519 key does not hash to the published fingerprint"
        );
        assert_eq!(
            release_fingerprint_display(),
            "FD06 516B 6C76 2BB8 B016 16DE 80D5 05C2 5B02 54B3"
        );
    }

    /// The published Aero release key, exactly as it is handed out.
    const PUBLIC_KEY_BLOCK: &str = "\
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: User ID:\tAero
Comment: Fingerprint:\tFD06 516B 6C76 2BB8 B016  16DE 80D5 05C2 5B02 54B3

mDMEapx0JRYJKwYBBAHaRw8BAQdAgzLUggaKPkEh8iV6F178nllQFQn76NZGY9UA
hSlESLG0BEFlcm+ItQQTFgoAXRYhBP0GUWtsdiu4sBYW3oDVBcJbAlSzBQJqnHQl
GxSAAAAAAAQADm1hbnUyLDIuNSsxLjEyLDIsMQIbAwUJBaS0WwULCQgHAgIiAgYV
CgkICwIEFgIDAQIeBwIXgAAKCRCA1QXCWwJUs4vLAQDYQtkcNLq7MUu/T7PD5zCk
j0bUrKEuLICdUiL3ZeIJYAEAwhZDhafAzBJOMHqZjp+8by7uXU+MVWRg7Xy723AO
9Qa4OARqnHQlEgorBgEEAZdVAQUBAQdAGbgpqgAC4YSlZIrosW4AVRi5zPGpClU4
8MDekwj3/TYDAQgHiJoEGBYKAEIWIQT9BlFrbHYruLAWFt6A1QXCWwJUswUCapx0
JRsUgAAAAAAEAA5tYW51MiwyLjUrMS4xMiwyLDECGwwFCQWktFsACgkQgNUFwlsC
VLPxAwD/Rr0/ctizeBixYl+qvnevcu1hpLCYfZoSdtuVZKadddwA/35RQ3k91liI
SVwaWLSpiQwTPq+jvg3TpJMkEY4tH0wM
=PrgU
-----END PGP PUBLIC KEY BLOCK-----";

    /// The armor reader, the CRC-24 and the packet reader, exercised on the real published key
    /// rather than on input this file made up for itself. The `=PrgU` trailer is that key's own
    /// checksum, so a CRC that disagreed with the rest of the world would fail right here.
    #[test]
    fn the_published_key_block_reads_back_as_the_pinned_key() {
        let raw = dearmor(PUBLIC_KEY_BLOCK, "PGP PUBLIC KEY BLOCK").expect("armor should decode");
        let (tag, body, _) = read_packet(&raw).expect("first packet");
        assert_eq!(tag, 6, "the block should start with a public-key packet");
        assert_eq!(body[0], 4, "version 4 key");
        assert_eq!(body[5], 22, "EdDSA");
        // Skip version(1) + created(4) + algo(1) + oid-len(1) + oid(9) + mpi-header(2) + 0x40(1).
        assert_eq!(
            &body[19..51],
            &RELEASE_KEY,
            "the key Aero pins is not the key that was published"
        );
        assert_eq!(
            u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as u64,
            KEY_CREATED,
            "pinned creation time does not match the key"
        );
    }

    /// The key Aero ships to users, on disk, is the key Aero pins in its own binary.
    ///
    /// `keys/aero-release.asc` is what a user is told to compare a signature against. If it ever
    /// drifted from the constant compiled into the wallet - a re-generated key committed to one and
    /// not the other - the published instructions would verify a release the wallet then refuses,
    /// and the disagreement would surface as a mysterious update failure rather than as a mistake.
    #[test]
    fn the_key_file_we_publish_is_the_key_we_pin() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../keys/aero-release.asc");
        let armored = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} should be readable: {e}", path.display()));
        assert_eq!(
            ed25519_from_armored_key(&armored),
            RELEASE_KEY,
            "keys/aero-release.asc is not the key Aero pins"
        );
    }

    // ---- Cross-implementation tests --------------------------------------------------------
    //
    // Everything below signs with rpgp, an OpenPGP implementation Aero shares no code with, and
    // verifies with pgp.rs. Testing this parser against signatures produced by the same author's
    // understanding of the spec would mostly prove the understanding was self-consistent. Making a
    // separate implementation produce them is what turns these into real tests.

    use pgp::composed::{Deserializable, KeyType, SecretKeyParamsBuilder, SignedSecretKey, StandaloneSignature};
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::crypto::public_key::PublicKeyAlgorithm;
    use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
    use pgp::types::PublicKeyTrait;

    /// A throwaway Ed25519 signing key, plus a verifier pinned to it.
    fn test_key() -> (SignedSecretKey, Verifier) {
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::EdDSALegacy)
            .can_sign(true)
            .primary_user_id("Aero Test <test@example.invalid>".into())
            .build()
            .expect("key params");
        let secret = params
            .generate(rand::thread_rng())
            .expect("generate")
            .sign(rand::thread_rng(), String::new)
            .expect("self-sign");

        // Read the public half back out through Aero's own armor and packet reader. That keeps this
        // to rpgp's public API, and means the reader is exercised on a second, independently
        // generated key rather than only on the one published key checked above.
        let armored = pgp::composed::SignedPublicKey::from(secret.clone())
            .to_armored_string(Default::default())
            .expect("armor public key");
        let key = ed25519_from_armored_key(&armored);

        let verifier = Verifier {
            key,
            // A fresh key has a fresh fingerprint. Leaving it unpinned here keeps these tests about
            // the signature mathematics; `a_signature_from_another_key_is_refused` covers identity.
            fingerprint: None,
            created: 0,
            expires: u64::MAX,
        };
        (secret, verifier)
    }

    /// The published key block is a real, internally consistent OpenPGP signing key.
    ///
    /// The secret half lives on the release machine, so no test here can produce a signature by the
    /// pinned key. What the block itself carries is the next best thing: self-signatures made by
    /// that key, over its own user ID and subkey. Having rpgp check them proves the pinned bytes are
    /// a working Ed25519 verification key that has demonstrably signed something, that the
    /// fingerprint Aero shows users is the one that key computes, and that the block is not a
    /// truncated or mistyped paste. Everything else about the accept path is covered by the
    /// signatures rpgp generates below; this is what ties those to *this* key.
    #[test]
    fn the_published_key_verifies_its_own_signatures() {
        let (key, _) =
            pgp::composed::SignedPublicKey::from_string(PUBLIC_KEY_BLOCK).expect("published block");
        key.verify()
            .expect("the published key block should carry valid self-signatures");

        assert_eq!(
            hex::encode(key.fingerprint().as_bytes()),
            hex::encode(RELEASE_FINGERPRINT),
            "the fingerprint Aero shows is not the one this key computes"
        );
        assert!(
            !key.details.users.is_empty(),
            "the key should carry the Aero user ID"
        );
    }

    /// Detached-sign `data` with rpgp and return the armored `.asc`.
    fn sign(secret: &SignedSecretKey, data: &[u8], hash: HashAlgorithm) -> String {
        let mut config = SignatureConfig::v4(
            SignatureType::Binary,
            PublicKeyAlgorithm::EdDSALegacy,
            hash,
        );
        config.hashed_subpackets = vec![Subpacket::regular(SubpacketData::SignatureCreationTime(
            chrono::Utc::now(),
        ))];
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(
            secret.primary_key.key_id(),
        ))];
        let sig = config
            .sign(&secret.primary_key, String::new, data)
            .expect("sign");
        StandaloneSignature::new(sig)
            .to_armored_string(Default::default())
            .expect("armor")
    }

    /// The whole point of the module: a signature made by the pinned key over exactly these bytes
    /// is accepted, and the same signature over any other bytes is not.
    #[test]
    fn a_genuine_signature_verifies_and_only_over_its_own_bytes() {
        let (secret, verifier) = test_key();
        let manifest = br#"{"version":"0.1.28","file":"Aero-0.1.28.zip"}"#;
        let asc = sign(&secret, manifest, HashAlgorithm::SHA2_256);

        verifier
            .verify(manifest, &asc)
            .expect("a genuine signature must verify");

        // One byte of the covered document changed - the version the user would be sent to.
        let tampered = br#"{"version":"0.1.29","file":"Aero-0.1.28.zip"}"#;
        assert!(
            verifier.verify(tampered, &asc).is_err(),
            "a signature must not carry over to different content"
        );
    }

    /// SHA-384 and SHA-512 signatures are equally valid OpenPGP and have to work, since which one
    /// gets used is the signer's choice, not ours.
    #[test]
    fn the_accepted_hashes_all_work() {
        let (secret, verifier) = test_key();
        let data = b"aero release manifest";
        for hash in [
            HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_512,
        ] {
            let asc = sign(&secret, data, hash);
            verifier
                .verify(data, &asc)
                .unwrap_or_else(|e| panic!("{hash:?} should verify: {e}"));
        }
    }

    /// A signature from a perfectly valid key that is simply not ours must be refused. This is the
    /// case that matters most: an attacker can always sign their own build with their own key.
    #[test]
    fn a_signature_from_another_key_is_refused() {
        let (_ours, verifier) = test_key();
        let (theirs, _) = test_key();
        let data = b"aero release manifest";
        let asc = sign(&theirs, data, HashAlgorithm::SHA2_256);
        assert!(
            verifier.verify(data, &asc).is_err(),
            "a signature from a key we do not pin must never be accepted"
        );
    }

    /// Flip every byte of a genuine signature in turn. Everything the signature actually commits to
    /// must be refused.
    ///
    /// The exception is real and worth stating: an OpenPGP signature does not cover its own unhashed
    /// subpacket area, so edits there are not forgeries and are not supposed to fail here. That area
    /// is where the issuer key id lives, which is precisely why this module treats the key id as a
    /// hint about which key to try and never as evidence of who signed. The test asserts the
    /// boundary rather than papering over it: anything accepted has to lie inside that region.
    #[test]
    fn tampering_is_refused_everywhere_the_signature_actually_covers() {
        let (secret, verifier) = test_key();
        let data = b"aero release manifest";
        let asc = sign(&secret, data, HashAlgorithm::SHA2_256);
        let raw = dearmor(&asc, "PGP SIGNATURE").expect("decode");

        // Locate the unhashed area inside the packet body, mirroring the layout in parse_signature.
        let (_, body, _) = read_packet(&raw).expect("packet");
        let body_at = raw.len() - body.len();
        let hashed_len = u16::from_be_bytes([body[4], body[5]]) as usize;
        let unhashed_at = 6 + hashed_len;
        let unhashed_len =
            u16::from_be_bytes([body[unhashed_at], body[unhashed_at + 1]]) as usize;
        // Include the two length bytes: changing them re-slices the same untrusted region.
        let untrusted = (body_at + unhashed_at)..(body_at + unhashed_at + 2 + unhashed_len);

        let mut covered = 0;
        for i in 0..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 0x01;
            // Re-armor without a checksum line, so it is the signature machinery doing the
            // rejecting here and not the CRC.
            let armored = format!(
                "-----BEGIN PGP SIGNATURE-----\n\n{}\n-----END PGP SIGNATURE-----\n",
                base64::engine::general_purpose::STANDARD.encode(&bad)
            );
            if verifier.verify(data, &armored).is_ok() {
                assert!(
                    untrusted.contains(&i),
                    "byte {i} is covered by the signature but tampering with it was accepted"
                );
            } else {
                covered += 1;
            }
        }
        assert!(
            covered > 60,
            "expected most of the signature to be covered, only {covered} bytes were"
        );
    }

    /// The attack the key-id-as-a-hint reasoning exists for: an attacker signs their own build with
    /// their own key, then rewrites the unhashed issuer field to name Aero's key. The file now
    /// claims to be from us, and nothing in the signature's own integrity contradicts that - only
    /// checking the signature against the pinned key does.
    #[test]
    fn a_forged_issuer_does_not_make_a_foreign_signature_ours() {
        let (ours, _) = test_key();
        let (theirs, _) = test_key();
        let data = b"aero release manifest";

        // A verifier pinned to our key, as the shipping one is.
        let our_key = ed25519_from_armored_key(
            &pgp::composed::SignedPublicKey::from(ours.clone())
                .to_armored_string(Default::default())
                .expect("armor"),
        );

        // Their signature, with the issuer subpacket rewritten to claim our key id.
        let asc = sign(&theirs, data, HashAlgorithm::SHA2_256);
        let raw = dearmor(&asc, "PGP SIGNATURE").expect("decode");
        let (_, body, _) = read_packet(&raw).expect("packet");
        let their_id = {
            let hashed_len = u16::from_be_bytes([body[4], body[5]]) as usize;
            let unhashed = &body[6 + hashed_len + 2..];
            // Issuer subpacket: length byte, type 16, then the eight-byte id.
            unhashed[2..10].to_vec()
        };
        let mut forged = raw.clone();
        let start = raw
            .windows(8)
            .position(|w| w == their_id.as_slice())
            .expect("issuer id in the signature");
        // Any eight bytes will do; the point is that the claim is now false.
        forged[start..start + 8].copy_from_slice(&[0xAB; 8]);

        let verifier = Verifier {
            key: our_key,
            fingerprint: None,
            created: 0,
            expires: u64::MAX,
        };
        let armored = format!(
            "-----BEGIN PGP SIGNATURE-----\n\n{}\n-----END PGP SIGNATURE-----\n",
            base64::engine::general_purpose::STANDARD.encode(&forged)
        );
        assert!(
            verifier.verify(data, &armored).is_err(),
            "a signature from another key must not become ours by relabelling it"
        );
    }

    /// The signature must cover the release archive itself, not merely parse. Truncating the file
    /// is the cheapest tampering there is.
    #[test]
    fn a_truncated_document_is_refused() {
        let (secret, verifier) = test_key();
        let data = b"aero release manifest, in full";
        let asc = sign(&secret, data, HashAlgorithm::SHA2_256);
        assert!(verifier.verify(&data[..data.len() - 1], &asc).is_err());
        assert!(verifier.verify(b"", &asc).is_err());
    }

    /// Corrupting one character of armor has to be caught by the checksum, not passed through to
    /// come out as a confusing signature failure later.
    #[test]
    fn mangled_armor_is_rejected() {
        let broken = PUBLIC_KEY_BLOCK.replace("mDMEapx0JRYJKwYBBAHaRw8BAQdAgzLUggaKPkEh8iV6F178", "mDMEapx0JRYJKwYBBAHaRw8BAQdAgzLUggaKPkEh8iV6F179");
        assert!(dearmor(&broken, "PGP PUBLIC KEY BLOCK").is_err(), "a flipped character must not decode cleanly");
    }

    /// A tiny SHA-1, for the fingerprint test only. SHA-1 is not used anywhere in the verification
    /// path - it appears here because that is what an OpenPGP v4 fingerprint is defined as.
    mod sha1_for_test {
        pub fn sha1(data: &[u8]) -> [u8; 20] {
            let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
            let mut msg = data.to_vec();
            let bits = (data.len() as u64) * 8;
            msg.push(0x80);
            while msg.len() % 64 != 56 {
                msg.push(0);
            }
            msg.extend_from_slice(&bits.to_be_bytes());
            for block in msg.chunks(64) {
                let mut w = [0u32; 80];
                for i in 0..16 {
                    w[i] = u32::from_be_bytes([
                        block[i * 4],
                        block[i * 4 + 1],
                        block[i * 4 + 2],
                        block[i * 4 + 3],
                    ]);
                }
                for i in 16..80 {
                    w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
                }
                let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
                for (i, &wi) in w.iter().enumerate() {
                    let (f, k) = match i {
                        0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                        20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                        40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                        _ => (b ^ c ^ d, 0xCA62C1D6),
                    };
                    let t = a
                        .rotate_left(5)
                        .wrapping_add(f)
                        .wrapping_add(e)
                        .wrapping_add(k)
                        .wrapping_add(wi);
                    e = d;
                    d = c;
                    c = b.rotate_left(30);
                    b = a;
                    a = t;
                }
                h[0] = h[0].wrapping_add(a);
                h[1] = h[1].wrapping_add(b);
                h[2] = h[2].wrapping_add(c);
                h[3] = h[3].wrapping_add(d);
                h[4] = h[4].wrapping_add(e);
            }
            let mut out = [0u8; 20];
            for (i, v) in h.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
            }
            out
        }
    }
}
