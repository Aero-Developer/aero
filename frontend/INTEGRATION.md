# Aero frontend integration guide

This document explains how to turn a checkout of **Feather** into **Aero** by swapping the Monero
backend for the `ethwallet` module (the Rust `aero_core` + the Qt shim in `src/ethwallet/`).

The shim intentionally mirrors Feather's `libwalletqt` shape (a `WalletManager` that hands out
`Wallet*`, a `Wallet` with `address()`, `getSeed()`, `store()`, `createTransaction()`,
`commitTransaction()`, and `updated()`/`refreshed()`/`balanceUpdated()`/`transactionCommitted()`
signals), so most widgets bind to it with small edits rather than rewrites.

## 0. Vendor Feather

`git` is not required to build; you can vendor a source snapshot:

```
# with git:
git clone https://github.com/feather-wallet/feather.git aero
cd aero && git submodule update --init --recursive   # pulls the Monero submodule (removed below)

# without git:
#   download https://github.com/feather-wallet/feather/archive/refs/heads/master.zip and extract.
```

Copy this repo's `core/` next to the Feather tree and drop `frontend/src/ethwallet/` into
`aero/src/ethwallet/`.

## 1. Cut the Monero backend

Remove the Monero dependency and its Qt wrapper:

- Delete the `monero` submodule (`.gitmodules` entry + `monero/` dir) and the
  `add_subdirectory(monero ...)` / `get_directory_property(... monero ...)` lines from the root
  `CMakeLists.txt`.
- Delete `src/libwalletqt/`, `src/monero_seed/`, `src/polyseed/`, and Monero-only widgets you
  will not port (e.g. proofs, key-image sync).
- In `src/CMakeLists.txt`, replace the `libwalletqt`/`monero` link targets with `ethwallet`
  (see `src/ethwallet/CMakeLists.txt`) and `add_subdirectory(ethwallet)`.

The Rust static library is built and linked automatically via Corrosion (declared in
`src/ethwallet/CMakeLists.txt`); no separate build step is needed.

## 2. Concept mapping (Monero -> Ethereum)

| Feather / Monero            | Aero / Ethereum                                             |
|-----------------------------|--------------------------------------------------------------|
| 25-word Monero seed         | BIP39 12/24-word mnemonic (`Wallet::getSeed`)                |
| Subaddress (major/minor)    | HD account index `m/44'/60'/0'/0/index` (`Wallet::address`) |
| `balance()` (atomic units)  | `BalanceInfo` (ETH wei / token base units)                   |
| Outputs / coin control      | Tokens/Assets panel (`TokensModel`)                          |
| `TransactionHistory`        | `HistoryModel` (ERC20 logs + local sends)                    |
| `createTransaction` fee lvl | EIP-1559 `FeeInfo` (base fee + tip)                          |
| Remote node                 | RPC endpoint(s) over Tor / local Helios                      |

## 3. Wizard: create / restore (todo: wizard-balance)

In the wizard pages under `src/wizard/`:

- **Create:** call `WalletManager::instance()->createWallet(12 /*or 24*/)`, then display
  `wallet->getSeed()` on the "write down your seed" page. On the password page call
  `wallet->store(path, password)`.
- **Restore:** feed the entered phrase to `WalletManager::instance()->recoveryWallet(phrase)`;
  a `nullptr` return means invalid mnemonic (`WalletManager::errorString()`).
- **Open:** `WalletManager::instance()->openWallet(path, password)`; `nullptr` = bad password.

Reword the seed pages from Monero's 25 words to BIP39 12/24; the widget layout is unchanged.

## 4. Balances + Receive (todo: wizard-balance)

After opening/creating, configure networking once from `networks.json`:

```cpp
wallet->setProvider(1, {"https://rpc.ankr.com/eth", "https://eth.llamarpc.com"},
                    "socks5h://127.0.0.1:9050");
connect(wallet, &Wallet::balanceUpdated, tokensModel, &TokensModel::onBalancesUpdated);
wallet->refresh(currentAccountIndex);   // async; updates the balance label + Assets panel
```

**ReceiveWidget:** show `wallet->address(index)` and render it as a QR code with Feather's existing
`qrcode/` helper (an Ethereum address is a plain `0x...` string; no payment-id concept).

## 5. Send: ETH + ERC20 (todo: send)

`SendWidget` collects recipient + amount (+ optional token selector populated from
`wallet->tokens()`), then:

```cpp
// 1) build (async) -> fee suggestion comes back on transactionCreated
connect(wallet, &Wallet::transactionCreated, this, &SendWidget::showConfirmDialog);
wallet->createTransaction(fromIndex, toAddress, amountText, /*token=*/tokenAddressOrEmpty);

// 2) user confirms in the dialog (shows PendingEthTx::fee) -> commit
connect(wallet, &Wallet::transactionCommitted, this, &SendWidget::onCommitted);
wallet->commitTransaction(pendingTx);
```

`createTransaction` fetches an EIP-1559 fee suggestion and converts the human amount to base units
using the correct decimals (18 for ETH, token decimals for ERC20). `commitTransaction` signs
locally and broadcasts `eth_sendRawTransaction` over Tor; `transactionCommitted` carries the tx
hash. Wire `onCommitted` to `HistoryModel::addLocalSend` for an immediate pending row.

**CoinsWidget -> Assets:** repoint `CoinsWidget` at `TokensModel`. "Add token" calls
`wallet->addToken({address, symbol, decimals})` (metadata can be auto-filled by a background
`erc20_metadata` lookup). Coin-control/freeze actions are removed (no UTXOs in the account model).

## 6. History + Tor (todo: history-tor)

- **History:** connect `wallet->historyRefreshed` to `HistoryModel::onHistoryRefreshed` and call
  `wallet->refreshHistory(index)`. This reconstructs ERC20 transfers from `eth_getLogs`
  (in + out). Native-ETH history has no lightweight trustless source; we show local sends and,
  optionally, an explicitly opt-in indexer (see README caveat).
- **Tor:** keep Feather's bundled-Tor manager (`-DTOR_DIR=...`). It already launches `tor` as a
  subprocess exposing a SOCKS port; pass that as the `socksProxy` to `setProvider`. `socks5h://`
  resolves DNS through Tor too. Requests to `127.0.0.1`/localhost (your node or Helios) bypass the
  proxy automatically (enforced in `aero_core`).

## 7. Settings: RPC config + rotation (todo: history-tor)

In `SettingsDialog`, replace the Monero "Node" tab with an "Endpoints" tab that edits the endpoint
list and SOCKS proxy from `networks.json`, then re-calls `wallet->setProvider(...)`. Multiple
endpoints are rotated per-request by the core so no single server sees all traffic. Offer a
"Trustless (Helios)" toggle that points the endpoint at `http://127.0.0.1:8545` (see README).

## 8. Debrand (todo: debrand)

- Rename the app/target `feather` -> `aero`, update `CMakeLists.txt` `project()`, window titles,
  `constants.h`, desktop/metadata files, and `assets/` icons.
- Remove donation prompts (`-DDONATE_BEG=OFF` and any donation UI), the update checker
  (`CHECK_UPDATES` stays `OFF`), and any remote "feather" service endpoints (price API, reddit/rss
  feeds, CCS/reddit widgets) — these are third-party calls the project's privacy stance rejects.
- Keep BSD-3-Clause headers and add attribution to Feather and the Monero Project in `LICENSE`/
  `README` (both are BSD-3-Clause; attribution is required).

## 9. Build

```
cmake -S . -B build -DTOR_DIR=/path/to/tor -DCHECK_UPDATES=OFF -DDONATE_BEG=OFF
cmake --build build -j
```

Corrosion invokes `cargo build --release` for `aero_core` and links the static library into the
`ethwallet` target, which the GUI links against.
