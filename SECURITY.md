# Security policy

## Reporting a vulnerability

Please report security issues **privately** — open a GitHub Security Advisory
(`Security → Report a vulnerability`) on this repository rather than a public issue. Include steps
to reproduce and the affected version/commit. Do not disclose publicly until a fix is available.

## Supported versions

Only the latest release receives security fixes. This is pre-1.0 software.

## Threat model

**What Aero is designed to protect against**
- **Local key theft from the wallet file.** Keys/seed are encrypted at rest (see below); the file
  alone is useless without the password.
- **Network-level surveillance / IP correlation.** All traffic (RPC, explorer, price, liquidity,
  images) goes through the bundled Tor with `socks5h` (DNS resolved through Tor). There is **no
  clearnet fallback** — if Tor is unreachable the wallet stays offline rather than leaking your IP.
- **Telemetry / phone-home.** There is none. No analytics, no update pings, no third-party services
  beyond the keyless public data sources listed below.
- **Address-poisoning / spam.** History hides zero-value/poisoning transfers, homoglyph-symbol
  tokens, and untrusted ERC-20s below a configurable dust threshold; the send dialog highlights the
  address head/tail so a poisoned look-alike is visible.
- **Silent data loss.** Wallet saves are atomic (temp + fsync + rename) and imported keys — the only
  funds not recoverable from the seed — fail loudly if they can't be persisted.

**What Aero does NOT (and cannot) protect against**
- A compromised operating system (keyloggers, memory scrapers, malicious clipboard readers).
- A weak wallet password — the KDF raises the cost but can't save a trivial password.
- **Data-correctness trust in the RPC/explorer.** A light wallet trusts its RPC endpoint for
  balances/nonces/gas and the block explorer for history. Aero rotates across multiple keyless
  endpoints so no single one sees all requests, and it can point at your **own node** (Settings →
  Node) to remove that trust. On-chain values that can be verified (ETH price via Chainlink) are.
- Privacy from the explorer/RPC operators themselves: they still see the queried addresses (over
  Tor, unlinked from your IP, but the address set is visible to whoever answers the query).
- Phishing / a user approving a malicious transaction.

## Key handling

- **Custody:** fully local and non-custodial. Private keys never leave the machine (hardware-wallet
  keys never leave the device).
- **Derivation:** BIP39 (12/24 words) + optional BIP39 passphrase, BIP44 `m/44'/60'/0'/0/x`.
- **Keystore encryption:** Argon2id (64 MiB, 3 iterations) → AES-256-GCM. Fresh random 16-byte salt
  and 96-bit nonce **per save**. The v3 envelope binds version/KDF-params/salt/nonce as AES-GCM
  associated data, so downgrading the KDF or tampering with the header fails authentication.
- **At rest:** wallet files are written atomically with `0600` permissions (on Unix); the seed,
  passphrase, imported keys and decrypted metadata are zeroized from memory on drop.
- **Clipboard:** copying a seed or private key auto-clears the clipboard after a configurable
  timeout.
- **Watch-only / hardware:** watch-only wallets hold no keys and refuse to sign; hardware wallets
  require the device present to open and sign, and refuse to load if the device/passphrase doesn't
  re-derive the stored address.

## Known limitations (please read before storing significant funds)

- **Not independently audited.** The cryptography uses well-reviewed libraries (RustCrypto AES-GCM,
  Argon2; alloy for signing) and the design is documented above, but there has been **no external
  security audit**. Treat accordingly and test with small amounts.
- **Release signing:** releases currently ship SHA-256 checksums; signed releases (minisign/GPG) are
  documented in `RELEASING.md` but not yet part of every release.
- **Reproducible builds** are supported via `cargo --locked` + pinned Qt, but not yet verified by a
  third party.
- Native-coin transaction history depends on a keyless block explorer and is unavailable on chains
  that lack one (BNB Smart Chain, Avalanche).

## Reproducing / verifying a build

See `RELEASING.md` for the deterministic build steps and how to verify a download's checksum (and
signature, when present).
