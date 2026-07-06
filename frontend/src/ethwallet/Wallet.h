// SPDX-License-Identifier: BSD-3-Clause
// Aero — Ethereum wallet wrapper. Replaces Feather's Monero libwalletqt/Wallet.
//
// This QObject keeps the same *shape* as Feather's Wallet (status, address, seed, store,
// create/commit transaction, and updated()/refreshed()/balanceUpdated()/transactionCommitted()
// signals) so the existing widgets bind to it with minimal churn, but it is backed by the Rust
// `aero_core` C ABI instead of Monero. Ethereum is account-based, so Monero concepts like key
// images, subaddress proofs and coin control are dropped; "subaddress index" maps to the HD
// account index (m/44'/60'/0'/0/index).

#ifndef AERO_WALLET_H
#define AERO_WALLET_H

#include <QObject>
#include <QReadWriteLock>
#include <QString>
#include <QVector>

#include "aero_core.h"

struct TokenInfo {
    QString address;
    QString symbol;
    quint8 decimals = 18;
};

struct BalanceInfo {
    QString raw;        // integer, base units (wei / token units)
    QString formatted;  // human readable, e.g. "1.2345"
    quint8 decimals = 18;
    QString symbol;
};

struct FeeInfo {
    QString baseFee;
    QString maxPriorityFee;
    QString maxFee;
};

struct PendingEthTx {
    QString to;
    QString amountWei;   // for ETH sends
    QString token;       // empty for ETH; contract address for ERC20
    QString amountUnits; // for ERC20 sends
    quint32 fromIndex = 0;
    FeeInfo fee;
};

struct HistoryItem {
    QString direction;    // "in" | "out"
    QString counterparty;
    QString amount;
    QString formatted;
    QString txHash;
    quint64 block = 0;
    QString token;
    QString symbol;
    quint64 timestamp = 0; // unix seconds (0 if unknown)
    QString fee;           // gas fee in wei (empty if unknown)
    bool failed = false;   // reverted / errored transaction
};

struct NftCollection {
    QString name;
    QString symbol;
    QString address;
    QString type;       // "ERC-721" | "ERC-1155"
    QString reputation; // "ok" | "scam" | ...
    quint64 count = 0;  // items held in this collection
    QString imageUrl;   // representative item image (data:/https/ipfs)
};

class Wallet : public QObject
{
    Q_OBJECT

public:
    enum Status {
        Status_Ok = 0,
        Status_Error = 1,
        Status_Critical = 2,
        Status_BadPassword = 3,
    };
    Q_ENUM(Status)

    // Takes ownership of the raw core handle.
    explicit Wallet(AeroWallet *core, QObject *parent = nullptr);
    ~Wallet() override;

    Status status() const { return m_status; }
    QString errorString() const { return m_errorString; }

    // ##### Accounts / keys #####
    QString address(quint32 index) const;
    quint32 numAccounts() const;
    quint32 addAccount();
    // Import a raw hex private key as a new account; returns its index (or 0xFFFFFFFF on error).
    quint32 importPrivateKey(const QString &hexKey);

    // ##### Hardware wallets #####
    bool isHardware() const;      // keys live on a Ledger/Trezor
    QString hwKind() const;       // "ledger" | "trezor" | "" (software)
    // Derive+append one more account from the device (blocks on the device); index or 0xFFFFFFFF.
    quint32 addHardwareAccount();
    // Export the 0x-prefixed private key for an account index (empty on error). Sensitive.
    QString exportPrivateKey(quint32 index) const;
    QString getSeed() const;

    // ##### Persistence #####
    bool store(const QString &path, const QString &password);
    void setWalletPath(const QString &path) { m_path = path; }
    QString walletPath() const { return m_path; }
    // Retain the password so the wallet can be re-encrypted/saved after in-memory changes.
    void setPassword(const QString &password) { m_password = password; }
    bool hasPassword() const { return !m_password.isEmpty(); }
    bool passwordMatches(const QString &pw) const { return pw == m_password; }
    // Re-save the wallet to its known path with its retained password. No-op if no path is set.
    bool save();

    // ##### Networking #####
    // endpoints: list of RPC URLs; socksProxy e.g. "socks5h://127.0.0.1:9050" ("" disables Tor).
    bool setProvider(quint64 chainId, const QStringList &endpoints, const QString &socksProxy);

    // Async connect: try Tor first (if socksProxy set), probe connectivity, and fall back to a
    // direct connection if Tor is unreachable. Emits providerConnected(mode, message) where
    // mode is 2=Tor, 1=Direct, 0=Offline.
    void connectProvider(quint64 chainId, const QStringList &endpoints, const QString &socksProxy);

    // Async: fetch the balance of `index` for `token` ("" = ETH); emits availableBalance().
    void fetchAvailable(quint32 index, const QString &token);

    // Async: fetch native + tracked-token balances for accounts [0, numAccounts) in ONE batched
    // RPC request. Emits accountBalanceUpdated() + availableBalance() per account/token (reusing
    // the same handlers as the single-balance path) and allBalancesRefreshed() when done. This
    // replaces per-account/per-token fan-out so everything loads together in one Tor round-trip.
    void refreshAllBalances(quint32 numAccounts);

    // Async: emits balanceUpdated() / refreshed() when done.
    void refresh(quint32 accountIndex);

    // Async: reconstruct ERC20 transfer history from logs; emits historyRefreshed().
    void refreshHistory(quint32 accountIndex, const QString &fromBlock = QStringLiteral("earliest"));

    // Async: merged history across accounts [0, numAccounts); emits historyRefreshed() once.
    void refreshHistoryAll(quint32 numAccounts);

    // Async: gap-limit scan of HD addresses; emits fundedScanned() with the funded indices.
    void scanFunded(quint32 gapLimit = 20);

    // Async: query a token's deepest DEX pool liquidity (USD) via DexScreener over Tor; emits
    // tokenLiquidity(). Used to auto-trust unknown-but-liquid tokens in History.
    void checkTokenLiquidity(const QString &tokenAddress);

    // Async: owned NFT collections for an account (Blockscout over Tor); emits nftsRefreshed().
    void refreshNfts(quint32 accountIndex);
    // Async: fetch an image (NFT thumbnail) over Tor; emits imageReady(url, bytes).
    void fetchImage(const QString &url);

    // Async: resolve an arbitrary ERC-20's symbol/decimals over Tor; emits tokenMetaResolved().
    void resolveTokenMeta(const QString &address);
    // Async: USD -> fiat rate over Tor; emits fiatRate().
    void refreshFiatRate(const QString &currency);

    // Async: fetch a single account's ETH balance; emits accountBalanceUpdated() with the index.
    void refreshAccountBalance(quint32 accountIndex);

    // Async: fetch the ETH/USD price from the on-chain Chainlink feed; emits ethUsdPriceUpdated().
    void refreshEthUsdPrice();

    // Async: fetch XMR + ETH market prices (over Tor) for the Home tickers; emits
    // marketPricesUpdated(). Uses a public price API since XMR has no usable on-chain feed.
    void refreshMarketPrices();

    // Async: poll the chain head; emits blockNumberUpdated() so the UI can refresh on new blocks.
    void refreshBlockNumber();

    // ##### Per-wallet metadata (labels/contacts/notes/funded) — encrypted inside the wallet file #####
    // Opaque JSON blob owned by the UI. Read once on open; setMetadata()+save() persists it.
    QString metadata() const;
    void setMetadata(const QString &json);

    // ##### Tokens (Assets panel) #####
    void addToken(const TokenInfo &t);
    void removeToken(const QString &address);
    QVector<TokenInfo> tokens() const;

    // ##### Transactions #####
    // Suggests fees, then emits transactionCreated() with a fully-prepared PendingEthTx.
    // maxFeeWei/maxPriorityWei (decimal wei) override the fee; empty = automatic.
    // decimals: base-unit exponent for `token`; 0xFF = unknown (resolve from tracked metadata/18).
    void createTransaction(quint32 fromIndex, const QString &to, const QString &amount,
                           const QString &token = QString(), const QString &maxFeeWei = QString(),
                           const QString &maxPriorityWei = QString(), quint8 decimals = 0xFF);

    // Async: fetch a fresh fee suggestion (base fee + priority tip, decimal wei); emits feesUpdated().
    void refreshFees();
    // Signs + broadcasts; emits transactionCommitted().
    void commitTransaction(const PendingEthTx &tx);

    // Utility: convert human amount -> base units for `decimals`.
    static QString parseUnits(const QString &amount, quint8 decimals);

signals:
    void updated();
    void refreshed(bool success, const QString &message);
    void balanceUpdated(const BalanceInfo &eth, const QVector<BalanceInfo> &tokens);
    void transactionCreated(const PendingEthTx &tx);
    // Emitted (for hardware wallets) right before a signature is requested from the device, so the
    // UI can prompt "confirm on your device". Cleared by transactionCommitted.
    void signingOnDevice();
    void transactionCommitted(bool success, const QString &txHash, const QString &error);
    void historyRefreshed(const QVector<HistoryItem> &items);
    void fundedScanned(const QList<quint32> &indices);
    void tokenLiquidity(const QString &tokenAddress, double usd);
    void nftsRefreshed(const QVector<NftCollection> &items);
    void imageReady(const QString &url, const QByteArray &data);
    void tokenMetaResolved(const QString &address, const QString &symbol, quint8 decimals);
    void fiatRate(const QString &currency, double rate);
    void accountBalanceUpdated(quint32 accountIndex, const QString &formatted, const QString &symbol);
    void ethUsdPriceUpdated(double usdPerEth);
    void marketPricesUpdated(double xmrUsd, double xmrChangePct, double ethUsd, double ethChangePct);
    void blockNumberUpdated(quint64 block);
    void feesUpdated(const QString &baseFeeWei, const QString &tipWei);
    void connectionStatusChanged(int status);
    void providerConnected(int mode, const QString &message); // 2=Tor, 1=Direct, 0=Offline
    void availableBalance(quint32 index, const QString &token, const QString &formatted,
                          const QString &symbol);
    // Emitted once after a batched refreshAllBalances() has dispatched all per-account signals.
    void allBalancesRefreshed();

private:
    QString takeLastError() const;

    AeroWallet *m_core = nullptr;
    Status m_status = Status_Ok;
    QString m_errorString;
    QString m_path;
    QString m_password;
    quint64 m_chainId = 1;

    // The Rust `Wallet` behind `m_core` is not internally synchronized: read methods borrow it as
    // `&self`, mutations (set_provider / add_account / import_private_key / add_token) as `&mut`.
    // Wallet operations run on QtConcurrent pool threads, so calling a mutation while a read is in
    // flight (e.g. switching chains mid-refresh) is a data race / UB. This lock serializes access:
    // concurrent reads (shared) are allowed and safe; every mutation takes it exclusively (write).
    // Recursive so a read op that calls another read op (e.g. refresh() -> tokens()) won't deadlock.
    mutable QReadWriteLock m_coreLock{QReadWriteLock::Recursive};
};

Q_DECLARE_METATYPE(BalanceInfo)
Q_DECLARE_METATYPE(FeeInfo)
Q_DECLARE_METATYPE(PendingEthTx)
Q_DECLARE_METATYPE(HistoryItem)
Q_DECLARE_METATYPE(NftCollection)

#endif // AERO_WALLET_H
