"""Independent reference for the THP CodeEntry CPace generator.

Deliberately written from the specifications rather than from the Rust code, so that agreement
between the two is evidence of correctness rather than a shared mistake:

  * the generator string layout from the THP spec ("Pairing phase"), which is the CPace255
    suite of draft-irtf-cfrg-cpace-10 in the symmetric setting, and
  * map_to_curve_elligator2_curve25519 from RFC 9380 Appendix G.2.1, matching what Trezor's
    crypto/elligator2.c implements.

Only the Montgomery u-coordinate is produced; the y-coordinate is not needed.
"""

import hashlib

P = 2**255 - 19
J = 486662


def elligator2_u_coordinate(input32: bytes) -> bytes:
    """RFC 9380 G.2.1 map_to_curve_elligator2_curve25519, u-coordinate only (K = 1, Z = 2)."""
    # Trezor decodes the input with curve25519_expand: little-endian, high bit masked off.
    u = int.from_bytes(input32, "little") & ((1 << 255) - 1)
    u %= P

    tv1 = (2 * u * u) % P          # Z * u^2
    xd = (tv1 + 1) % P             # 1 + Z * u^2
    if xd == 0:                    # inv0(0) = 0, so x1 collapses to -J
        x1 = (-J) % P
    else:
        x1 = (-J * pow(xd, P - 2, P)) % P

    gx1 = (pow(x1, 3, P) + J * pow(x1, 2, P) + x1) % P

    if pow(gx1, (P - 1) // 2, P) in (0, 1):   # gx1 is a square
        x = x1
    else:
        x = (-x1 - J) % P

    return x.to_bytes(32, "little")


def cpace_generator(code: str, handshake_hash: bytes) -> bytes:
    """generator_string per the THP spec, hashed with SHA-512, then mapped to the curve."""
    prefix = bytes([0x08]) + b"CPace255" + bytes([0x06])   # len||DSI, then len(PRS)
    padding = bytes([0x6F]) + bytes(111) + bytes([0x20])   # len||zpad, then len(CI)
    gen_str = prefix + code.encode("ascii") + padding + handshake_hash + bytes([0x00])
    # The zero padding exists to push the first SHA-512 block boundary to exactly 128 bytes.
    assert len(prefix) + len(code) + 1 + 111 == 128, "zero padding must align the first block"
    assert len(gen_str) == 162, f"unexpected generator string length {len(gen_str)}"
    pregenerator = hashlib.sha512(gen_str).digest()[:32]
    return elligator2_u_coordinate(pregenerator)


if __name__ == "__main__":
    # Fixed inputs so the result can be pinned as a known-answer test in the Rust suite.
    for code, hh in (("740902", bytes([7] * 32)), ("000000", bytes(32)), ("123456", bytes(range(32)))):
        print(f'code={code} handshake_hash={hh.hex()[:16]}... -> {cpace_generator(code, hh).hex()}')
