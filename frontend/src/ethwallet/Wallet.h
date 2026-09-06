// SPDX-License-Identifier: BSD-3-Clause
// Aero - Ethereum wallet wrapper. Replaces Feather's Monero libwalletqt/Wallet.
//
// This QObject keeps the same *shape* as Feather's Wallet (status, address, seed, store,
// create/commit transaction, and updated()/refreshed()/balanceUpdated()/transactionCommitted()
// signals) so the existing widgets bind to it with minimal churn, but it is backed by the Rust
// `aero_core` C ABI instead of Monero. Ethereum is account-based, so Monero concepts like key
// images, subaddress proofs and coin control are dropped; "subaddress index" maps to the HD
// account index (m/44'/60'/0'/0/index).

#ifndef AERO_WALLET_H
#define AERO_WALLET_H

#include <QAtomicInt>
#include <QHash>
#include <QMutex>
#include <QObject>
#include <QReadWriteLock>
#include <QString>
#include <QThreadPool>
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
    // Nonce to broadcast at. ~0 (default) = automatic; set to an existing pending tx's nonce to
    // replace it (speed-up: same tx + higher fee).
    quint64 nonce = ~Q_UINT64_C(0);
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
    // Swap rows (kind == "swap"): sell side reuses symbol/formatted/token above.
    QString kind;          // "" for a normal transfer, "swap" for a swap
    QString buySymbol;     // asset received
    QString buyFormatted;  // human amount received
    QString status;        // "pending" | "done" | "failed"
    quint64 expiry = 0;    // swap order validTo (unix secs); 0 = unknown. A pending swap isn't marked
                           // failed before this - CoW orders can legitimately stay open for minutes.
    // Which account this row was fetched for. An off-chain order can only be asked about through the
    // address that placed it, so a swap made from an account other than the one on screen is
    // unreachable without this. `unknownAccount` means an older cache that predates the field.
    static constexpr quint32 unknownAccount = 0xFFFFFFFFu;
    quint32 account = unknownAccount;
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
    // True only if addresses [0, count) are ALL already in the derived-address cache, so a caller can
    // decide whether reading them (e.g. rebuilding the account combos) would derive HD keys on the
    // calling thread. Cheap (a single mutexed hash lookup per index); no derivation.
    bool addressesCached(quint32 count) const;
    quint32 numAccounts() const;
    quint32 addAccount();
    // Async variant: derives the next HD account off the UI thread and emits accountAdded(index).
    // Used by "Create new address" so it can't freeze the UI while the funded scan holds the core
    // lock exclusively (the write would otherwise block on the UI thread for the whole scan).
    void addAccountAsync();
    // Import a raw hex private key as a new account; returns its index (or 0xFFFFFFFF on error).
    quint32 importPrivateKey(const QString &hexKey);

    // Address-only watch wallet: tracks addresses with no keys (can't sign or send).
    bool isWatchOnly() const;

    // Ask the core's background network loops (funded scan, per-account history) to stop ASAP so they
    // release the core lock - call this before a blocking close-time save so the UI can't hang waiting
    // on an in-flight multi-minute scan/history load. Process-global; safe to call from the UI thread.
    static void requestShutdown();

    // ##### Hardware wallets #####
    bool isHardware() const;      // keys live on a Ledger/Trezor
    // The 0-based imported-key ordinal for `index`, or -1 when the account is seed-derived. Lets the
    // UI name imported accounts ("Imported #n") distinctly from HD ("Account #n") accounts.
    int accountImportedOrdinal(quint32 index) const;
    QString hwKind() const;       // "ledger" | "trezor" | "" (software)
    // Derive+append one more account from the device (blocks on the device); index or 0xFFFFFFFF.
    quint32 addHardwareAccount();
    // Export the 0x-prefixed private key for an account index (empty on error). Sensitive.
    QString exportPrivateKey(quint32 index) const;
    QString getSeed() const;

    // ##### Message signing (EIP-191 personal_sign) #####
    // Sign a UTF-8 message with account `index`; returns 0x 65-byte sig, or "" on error.
    QString signMessage(quint32 index, const QString &message);
    // Recover the signer address from a personal_sign signature; returns checksummed address, or ""
    // on error (bad signature). Pure function - no keys involved.
    QString verifyMessage(const QString &message, const QString &signature);

    // Resolve an ENS name ("alice.eth") to a checksummed 0x address (Ethereum mainnet only); ""
    // on failure. Blocking (network) - call from a worker (runBusy).
    QString resolveEns(const QString &name);

    // ##### Persistence #####
    bool store(const QString &path, const QString &password);
    void setWalletPath(const QString &path) { m_path = path; }
    QString walletPath() const { return m_path; }
    // Retain the password so the wallet can be re-encrypted/saved after in-memory changes.
    void setPassword(const QString &password) {
        if (!m_password.isEmpty())
            m_password.fill(QChar(u'\0')); // scrub the previous password before replacing it
        m_password = password;
    }
    bool hasPassword() const { return !m_password.isEmpty(); }
    bool passwordMatches(const QString &pw) const { return pw == m_password; }
    // Re-save the wallet to its known path with its retained password. No-op if no path is set.
    // Synchronous (blocks the caller with the full Argon2id encrypt + fsync). Prefer saveAsync()
    // on the UI thread; use this only where blocking is acceptable (e.g. flush on app close).
    bool save();
    // Apply `metaJson` to the core, then synchronously encrypt+write. Use for a GUARANTEED, prompt
    // persist of critical state (e.g. right after a funded scan discovers hundreds of accounts) where
    // the debounced saveAsync() could be lost if the app is killed before the timer fires. Blocks the
    // caller (run it on a worker / behind a busy dialog).
    bool saveWithMetadata(const QString &metaJson);
    // Non-blocking save: runs the (slow) encrypt + atomic write on the bounded net pool and emits
    // saved(ok) on the UI thread. Saves are serialized so two encrypt/atomic-writes never overlap;
    // a request made while one is in flight coalesces into a single follow-up save.
    void saveAsync();

    // ##### Networking #####
    // endpoints: list of RPC URLs; socksProxy e.g. "socks5h://127.0.0.1:9050" ("" disables Tor).
    bool setProvider(quint64 chainId, const QStringList &endpoints, const QString &socksProxy);

    // Point transaction history for `chainId` at explorer APIs of the user's choosing (comma
    // separated), tried ahead of the built-in ones; blank restores the built-ins. Applies to the
    // whole process rather than one wallet, hence static.
    static void setHistoryApis(quint64 chainId, const QString &csv);

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
    // `extraTokensJson` (optional) is a JSON array [{address,symbol,decimals}] of tokens to include
    // in the read (e.g. the current chain's curated tokens) so pickers show balances immediately.
    void refreshAllBalances(quint32 numAccounts, const QString &extraTokensJson = QString());

    // Async: emits balanceUpdated() / refreshed() when done.
    void refresh(quint32 accountIndex);

    // Async: reconstruct ERC20 transfer history from logs; emits historyRefreshed().
    void refreshHistory(quint32 accountIndex, const QString &fromBlock = QStringLiteral("earliest"));

    // Async: history across accounts [0, numAccounts), fetched with bounded parallelism. Emits one
    // historyBatch(items, done, total) per account as it completes. `priorityIndex` (the currently
    // selected account) is fetched first so its rows appear near-instantly.
    void refreshHistoryAll(quint32 numAccounts, quint32 priorityIndex = 0);

    // Async: full history (native + tokens + CoW swaps) for a SINGLE account. Emits
    // accountHistoryReady(index, items) - the caller appends it to the model (no clear), enabling
    // Electrum-style lazy/on-demand and status-gated refresh instead of an all-account fan-out.
    void refreshAccountHistory(quint32 accountIndex);

    // Async: gap-limit scan of HD addresses (current chain); emits fundedScanned().
    void scanFunded(quint32 gapLimit = 20);
    // Async: gap-limit scan across MULTIPLE chains. `configsJson` is a JSON array of
    // {"chain_id","endpoints":[...],"socks"}. Finds addresses funded on any chain. Emits fundedScanned().
    void scanFundedMulti(const QString &configsJson, quint32 gapLimit = 20);
    // Live progress of an in-flight scan (lock-free reads of core atomics): addresses checked / found.
    quint64 scanProgress() const;
    quint64 scanFound() const;
    // Derive addresses 0..count-1 off the UI thread to warm the address cache, then emit
    // addressesWarmed(). Lets a big post-scan rebuildAccountCombos read from a hot cache instead of
    // doing hundreds of synchronous key derivations on the UI thread.
    void warmAddresses(quint32 count);

    // Async: query a token's deepest DEX pool liquidity (USD) via DexScreener over Tor; emits
    // tokenLiquidity(). Used to auto-trust unknown-but-liquid tokens in History.
    void checkTokenLiquidity(const QString &tokenAddress);

    // Async: historical USD price of `symbol` on `date` (YYYY-MM-DD); emits historicalPriceReady().
    void historicalPrice(const QString &symbol, const QString &date);

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

    // Async: fetch the receipt for a just-broadcast tx; emits txReceiptReady(txHash, mined, success).
    // `mined` = the tx is in a block; `success` = it didn't revert. The UI polls this after a send so
    // the balance/history confirm the instant the tx lands (not on a fixed timer).
    void txReceipt(const QString &txHash);

    // ##### Per-wallet metadata (labels/contacts/notes/funded) - encrypted inside the wallet file #####
    // Opaque JSON blob owned by the UI. Read once on open; setMetadata()+save() persists it.
    QString metadata() const;
    void setMetadata(const QString &json);
    // Queue metadata to be applied to the core off the UI thread (by the next saveAsync). This never
    // takes the core lock on the UI thread, so editing a label can't freeze the UI while the funded
    // scan holds the core lock exclusively. flushPendingMetadata() applies it synchronously (used by
    // the blocking save on close).
    void queueMetadata(const QString &json);
    void flushPendingMetadata();

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
    // Signs + broadcasts; emits transactionCommitted() (and transactionSent() on success).
    // To speed up a stuck tx, re-call this with the same PendingEthTx but tx.nonce set to the
    // pending nonce and a higher fee - it replaces the original.
    void commitTransaction(const PendingEthTx &tx);

    // Cancel a pending tx: broadcast a 0-value self-send at `nonce` with a bumped fee (wei strings).
    // Emits transactionCommitted().
    void cancelTransaction(quint32 fromIndex, quint64 nonce, const QString &maxFeeWei,
                           const QString &maxPriorityWei);

    // Replace-by-fee an ARBITRARY still-pending tx of `fromIndex`, found by hash: cancel=true does a
    // 0-value self-send at its nonce; else rebroadcasts the same tx at the higher fee (speed-up).
    // Emits transactionCommitted(). Used by the History right-click "Speed up / Cancel".
    void replaceTx(quint32 fromIndex, const QString &txHash, const QString &maxFeeWei,
                   const QString &maxPriorityWei, bool cancel);

    // Broadcast an already-signed raw tx (0x RLP hex) over Tor; emits transactionCommitted().
    void broadcastRaw(const QString &rawHex);

    // "Pay to many": one tx per recipient (sequential nonces). `recipients` is (to, humanAmount);
    // amounts are converted to base units with `decimals` (18 for native, token decimals for ERC-20).
    // `token` empty = native. Emits manySent(resultJson).
    void sendMany(quint32 fromIndex, const QVector<QPair<QString, QString>> &recipients,
                  const QString &token, quint8 decimals, const QString &maxFeeWei,
                  const QString &maxPriorityWei);

    // Air-gapped signing. buildUnsigned resolves nonce/gas/fees over the network and emits
    // unsignedTxReady(json). signUnsigned signs that JSON locally (offline) and returns 0x raw hex.
    void buildUnsigned(const PendingEthTx &tx);
    QString signUnsigned(const QString &json);

    // ##### CoW Protocol swaps (all async over Tor) #####
    // Fetch a swap quote. sellIsNative sells the chain's wrapped-native token; pass BUY_ETH sentinel
    // as buyToken to receive native ETH. Emits swapQuoteReady(quoteJson, error).
    void swapQuote(quint32 fromIndex, const QString &sellToken, const QString &buyToken,
                   const QString &sellAmountWei, bool sellIsNative);
    // Current allowance of `token` to the CoW Vault Relayer (decimal-wei); emits swapAllowanceReady().
    void swapAllowance(quint32 fromIndex, const QString &token);
    // Approve the CoW Vault Relayer for `token`. `amountWei` is the decimal-wei cap; "max" (or empty)
    // approves unlimited. Emits swapApproved(txHash, error).
    void swapApprove(quint32 fromIndex, const QString &token, const QString &amountWei);
    // Sign (EIP-712) + submit the order from a quote JSON; slippageBps lowers the order's minimum
    // buy so it can fill. Emits swapSubmitted(orderUid, error).
    void swapSubmit(quint32 fromIndex, const QString &quoteJson, quint32 slippageBps);
    // Sell native ETH via eth-flow (on-chain tx); emits swapEthFlowSent(txHash, error).
    void swapEthFlow(quint32 fromIndex, const QString &quoteJson, const QString &buyToken,
                     quint32 slippageBps);
    // Batched allowance scan over (tokens x spenders); emits tokenAllowancesReady(json, error).
    void tokenAllowances(quint32 fromIndex, const QString &tokensJson, const QString &spendersJson);
    // Revoke an approval (approve(spender,0)); emits approvalRevoked(token, spender, txHash, error).
    void revokeApproval(quint32 fromIndex, const QString &token, const QString &spender);
    // DefiLlama current prices for a comma-separated coin-key list; emits defillamaPricesReady().
    void defillamaPrices(const QString &coinsCsv);

    // ##### Multi-router swap aggregator #####
    // Fetch quotes from every keyless router on the current chain; emits swapQuotesReady(json,err).
    void swapQuotes(quint32 fromIndex, const QString &sell, const QString &buy,
                    const QString &sellAmountWei, bool sellIsNative, quint8 sellDecimals,
                    quint8 buyDecimals, quint32 slippageBps);
    // Build the executable tx for a chosen on-chain router; emits routerBuilt(json,err) with
    // {to,data,value,spender,buy_amount,min_buy_amount}.
    void routerBuild(const QString &routerId, quint32 fromIndex, const QString &sell,
                     const QString &buy, const QString &sellAmountWei, bool sellIsNative,
                     quint8 sellDecimals, quint8 buyDecimals, quint32 slippageBps);
    // Current allowance of `token` to `spender` (decimal-wei); emits routerAllowanceReady().
    void routerAllowance(quint32 fromIndex, const QString &token, const QString &spender);
    // Approve `spender` for `token` (amountWei cap; "max"/empty = unlimited); emits routerApproved().
    void routerApprove(quint32 fromIndex, const QString &token, const QString &spender,
                       const QString &amountWei);
    // Send an arbitrary-calldata swap tx; emits routerSwapSent(txHash,err).
    void routerSwap(quint32 fromIndex, const QString &to, const QString &valueWei,
                    const QString &dataHex);

    // --- Across cross-chain bridge ---
    // What Across will bridge out of the connected chain right now; emits acrossAssetsReady(json,err)
    // with {origin_chain, assets:[{symbol,display,decimals,native,destinations:[id]}]}. Asked rather
    // than assumed, because Across retires routes (it has dropped DAI entirely).
    void acrossAssets();
    // Fee quote for bridging `symbol` from the connected chain to `destChainId`; emits
    // acrossQuoteReady(json,err).
    void acrossQuote(quint32 fromIndex, const QString &symbol, quint64 destChainId,
                     const QString &amountWei);
    // Build the SpokePool depositV3 tx (fresh quote); emits acrossBuilt(json,err) with
    // {to,spender,data,value,native,output_amount,...}.
    void acrossBuild(quint32 fromIndex, const QString &symbol, quint64 destChainId,
                     const QString &amountWei);
    // Bridge send legs (reuse the generic router FFI but emit bridge-specific signals so they never
    // collide with the Swap tab's state): allowance -> approve -> send the depositV3 calldata.
    // --- Hyperliquid (XMR1) ---
    // The book, balances, resting orders and recent fills in one shot; emits hlOverviewReady().
    // Fetched together because they are read together - a book from one moment beside balances from
    // another would be quietly misleading.
    void hlOverview(quint32 index);
    // Whether this account has authorised Aero's trading key; emits hlAgentReady(ready,err).
    void hlAgentReady(quint32 index);
    // Authorise it (one signature with the account key); emits hlAgentApproved(err).
    void hlApproveAgent(quint32 index);
    // Place an order; emits hlOrderPlaced(json,err) with {state,size,price,oid}.
    void hlPlaceOrder(quint32 index, bool isBuy, double price, double size, bool marketOrder);
    // Cancel a resting order; emits hlOrderCancelled(err).
    void hlCancelOrder(quint32 index, quint64 oid);
    // Move USDC from Arbitrum onto the exchange; emits hlDeposited(txHash,err).
    void hlDeposit(quint32 index, const QString &amountUsdc);
    // Withdraw USDC back to Arbitrum; emits hlWithdrawn(err).
    void hlWithdraw(quint32 index, const QString &amountUsdc);
    // Move USDC between the perp and spot wallets on the exchange; emits hlClassTransferred(err).
    // toPerp false is perp -> spot, which makes a fresh deposit spendable on the XMR1 book.
    void hlClassTransfer(quint32 index, const QString &amountUsdc, bool toPerp);

    // What redeeming XMR1 for real Monero would cost; emits xmrRedeemQuoted(quote,err).
    void xmrRedeemQuote(quint32 index, const QString &amountXmr1);
    // Redeem XMR1 for Monero paid to moneroAddress; emits xmrRedeemed(order,err).
    void xmrRedeem(quint32 index, const QString &moneroAddress, const QString &amountXmr1);
    // Progress of a redemption; emits xmrRedeemStatusReady(status,err).
    void xmrRedeemStatus(const QString &orderId, const QString &sessionId);

    void bridgeAllowance(quint32 fromIndex, const QString &token, const QString &spender);
    void bridgeApprove(quint32 fromIndex, const QString &token, const QString &spender,
                       const QString &amountWei);
    void bridgeSend(quint32 fromIndex, const QString &to, const QString &valueWei,
                    const QString &dataHex);

    // The CoW BUY_ETH sentinel (used as buyToken to receive native ETH).
    static QString buyEthSentinel() { return QStringLiteral("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"); }
    // The CoW Vault Relayer (approval target) - same on every supported chain.
    static QString cowVaultRelayer() { return QStringLiteral("0xC92E8bdf79f0507f65a392b0ab4667716BFE0110"); }
    // The GPv2 Settlement contract (EIP-712 verifying contract) - shown in the confirm dialog.
    static QString cowSettlement() { return QStringLiteral("0x9008D19f58AAbD9eD0D60971565AA8510560ab41"); }
    // CoW's production EthFlow contract, which receives the coin on a native sell. Must stay equal to
    // ETH_FLOW_PROD in core/src/chains.rs: this is the address the confirm dialog shows the user, and
    // showing one address while sending to another defeats the point of showing it.
    static QString cowEthFlow() { return QStringLiteral("0xbA3cB449bD2B4ADddBc894D8697F5170800EAdeC"); }

    // Utility: convert human amount -> base units for `decimals`.
    static QString parseUnits(const QString &amount, quint8 decimals);

signals:
    void updated();
    void saved(bool ok); // emitted on the UI thread after an async save completes
    void refreshed(bool success, const QString &message);
    void balanceUpdated(const BalanceInfo &eth, const QVector<BalanceInfo> &tokens);
    void transactionCreated(const PendingEthTx &tx);
    // Emitted (for hardware wallets) right before a signature is requested from the device, so the
    // UI can prompt "confirm on your device". Cleared by transactionCommitted.
    void signingOnDevice();
    void transactionCommitted(bool success, const QString &txHash, const QString &error);
    // Emitted after a successful broadcast with the sent tx (including the nonce it used), so the UI
    // can offer speed-up/cancel on it.
    void transactionSent(const PendingEthTx &tx, const QString &txHash);
    // Emitted when buildUnsigned() finishes: `json` is the unsigned tx (empty on error).
    void unsignedTxReady(const QString &json, const QString &error);
    // Emitted when sendMany() finishes: `resultJson` is an array of {to, tx_hash|error}.
    void manySent(const QString &resultJson, const QString &error);
    // `chainId` = the chain this history was fetched for, so the UI can drop a late batch that
    // arrives after a network switch (otherwise a previous chain's rows leak into the new chain).
    void historyRefreshed(const QVector<HistoryItem> &items, quint64 chainId);
    // Emitted (synchronously, on the caller/UI thread) at the very start of an all-account refresh,
    // before any batch is dispatched - the UI clears the model + resets dedup here. This must NOT be
    // driven off "done==1", because with parallel per-account fetches batches complete out of order
    // and a later batch could be delivered first.
    void historyRefreshStarted();
    // Incremental all-account history: one batch per account (delivered as each completes, so in
    // arbitrary order). `done`/`total` drive the progress indicator; done==total is the end.
    void historyBatch(const QVector<HistoryItem> &items, quint32 done, quint32 total, quint64 chainId);
    // Targeted single-account history (refreshAccountHistory): appended to the model, not cleared.
    void accountHistoryReady(quint32 accountIndex, const QVector<HistoryItem> &items, quint64 chainId);
    void addressesWarmed(); // emitted after warmAddresses() finishes populating the address cache
    void fundedScanned(const QList<quint32> &indices);
    void accountAdded(quint32 index); // a new HD account was derived (addAccountAsync)
    void tokenLiquidity(const QString &tokenAddress, double usd);
    void historicalPriceReady(const QString &symbol, const QString &date, double usd);
    void nftsRefreshed(const QVector<NftCollection> &items);
    void imageReady(const QString &url, const QByteArray &data);
    void tokenMetaResolved(const QString &address, const QString &symbol, quint8 decimals);
    void fiatRate(const QString &currency, double rate);
    void accountBalanceUpdated(quint32 accountIndex, const QString &formatted, const QString &symbol);
    void ethUsdPriceUpdated(double usdPerEth);
    void marketPricesUpdated(double xmrUsd, double xmrChangePct, double ethUsd, double ethChangePct);
    void blockNumberUpdated(quint64 block);
    void txReceiptReady(const QString &txHash, bool mined, bool success);
    void feesUpdated(const QString &baseFeeWei, const QString &tipWei);
    void connectionStatusChanged(int status);
    void providerConnected(int mode, const QString &message); // 2=Tor, 1=Direct, 0=Offline
    void availableBalance(quint32 index, const QString &token, const QString &formatted,
                          const QString &symbol);
    // Emitted once after a batched refreshAllBalances() has dispatched all per-account signals.
    void allBalancesRefreshed();

    // ##### CoW swap signals #####
    void swapQuoteReady(const QString &quoteJson, const QString &error);
    void swapAllowanceReady(const QString &token, const QString &allowanceWei, const QString &error);
    void swapApproved(const QString &txHash, const QString &error);
    void swapSubmitted(const QString &orderUid, const QString &error);
    void swapEthFlowSent(const QString &txHash, const QString &error);
    void tokenAllowancesReady(const QString &json, const QString &error);
    void approvalRevoked(const QString &token, const QString &spender, const QString &txHash,
                         const QString &error);
    void defillamaPricesReady(const QString &json, const QString &error);
    // Multi-router aggregator.
    void swapQuotesReady(const QString &json, const QString &error);
    void routerBuilt(const QString &json, const QString &error);
    void routerAllowanceReady(const QString &token, const QString &spender,
                              const QString &allowanceWei, const QString &error);
    void routerApproved(const QString &txHash, const QString &error);
    void routerSwapSent(const QString &txHash, const QString &error);
    // Across bridge signals (kept separate from the Swap tab's router signals).
    void acrossAssetsReady(const QString &json, const QString &error);
    void acrossQuoteReady(const QString &json, const QString &error);
    void acrossBuilt(const QString &json, const QString &error);
    void bridgeAllowanceReady(const QString &token, const QString &spender, const QString &weiOrErr,
                              const QString &error);
    void bridgeApproved(const QString &txHash, const QString &error);
    void bridgeSent(const QString &txHash, const QString &error);
    // Hyperliquid (XMR1) signals.
    // Carries the account it was fetched for. Switching accounts leaves the previous account's
    // request in flight, and a reply that does not say whose it is cannot be told apart from the new
    // one: balances and resting orders would be shown against the wrong address.
    void hlOverviewReady(quint32 account, const QString &json, const QString &error);
    void hlAgentReadyResult(bool ready, const QString &error);
    void hlAgentApproved(const QString &error);
    void hlOrderPlaced(const QString &json, const QString &error);
    void hlOrderCancelled(const QString &error);
    void hlDeposited(const QString &txHash, const QString &error);
    void hlWithdrawn(const QString &error);
    void hlClassTransferred(const QString &error);
    void xmrRedeemQuoted(const QJsonObject &quote, const QString &error);
    void xmrRedeemed(const QJsonObject &order, const QString &error);
    void xmrRedeemStatusReady(const QJsonObject &status, const QString &error);

private:
    QString takeLastError() const;
    // Append CoW Protocol swap rows for `accountIndex` to `items` (deduped). Call with m_coreLock held.
    void mergeCowOrders(quint32 accountIndex, QVector<HistoryItem> &items);
    // Writer preference: block briefly if an account mutation (add/import/scan-commit) is pending, so a
    // long read task about to take the core read lock yields the wallet to it first. A no-op unless a
    // writer is currently holding m_writeGate. Call BEFORE taking a QReadLocker in a long network task.
    void yieldToWriter() { QMutexLocker g(&m_writeGate); }

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

    // Writer-preference gate over m_coreLock. QReadWriteLock favours neither side, so a steady stream
    // of long read locks (a history fan-out over Tor, or the funded scan) can starve a waiting writer
    // for minutes - which is why "create a new address" (a write) could hang behind a big scan. A
    // pending mutation grabs this gate first; long read tasks pass THROUGH it (lock+unlock) before
    // taking their read lock, so once a writer is waiting, no new long read starts and the writer gets
    // in after the current one drains. Used via coreReadGate()/coreWriteGate() below.
    QMutex m_writeGate;

    // Dedicated pool for network (Tor) tasks. All refresh/fetch methods run here instead of the
    // global QThreadPool, so (a) they never contend with Qt's own worker threads, and (b) the bound
    // caps how many Tor circuits open at once - flooding one SOCKS proxy with dozens of simultaneous
    // requests (balances + history + prices + fees + NFTs + liquidity + images) is what made data
    // arrive in stuttering waves. A modest bound lets the essentials run together and queues the
    // rest right behind them.
    QThreadPool m_netPool;
    // A SEPARATE, smaller pool for the all-account history fan-out. History fans out one task per
    // account; on a shared pool that starved the single-task balance/price/fee/block refreshes
    // (balances took minutes to update after a send). Its own bounded lane keeps history off the
    // essentials' threads; the core RPC semaphore still caps total Tor concurrency.
    QThreadPool m_historyPool;
    // And a third for anything the user has pressed a button to send: orders, cancels, exchange
    // deposits and withdrawals. These share nothing with a refresh - they are one small request each,
    // and the person who pressed the button is watching. On the shared pool an order could be queued
    // behind eight in-flight Tor fetches of prices and images and simply not go out for a while,
    // which is exactly how a payment came to be sent twice here once before.
    QThreadPool m_tradePool;

    // Serialize async saves: only one encrypt/atomic-write runs at a time; a request arriving while
    // one is in flight sets m_saveQueued so exactly one follow-up save runs afterwards (coalescing a
    // burst of edits into a single write).
    QAtomicInt m_saveRunning{0};
    QAtomicInt m_saveQueued{0};

    // Derived-address cache (index -> checksummed address). Deriving an address re-runs BIP32 HD
    // derivation under the core lock; with ~230 accounts, rebuildAccountCombos would derive hundreds
    // of times on the UI thread and stutter. Cache them (addresses are chain-independent). Cleared
    // whenever the account set/order changes (add account, import key, funded scan).
    mutable QHash<quint32, QString> m_addrCache;
    mutable QMutex m_addrCacheMutex;
    void invalidateAddressCache();

    // Caches for the two other hot, UI-thread getters (account count + tracked tokens). The funded
    // scan holds an EXCLUSIVE core lock for its whole (multi-minute, Tor-bound) run; without these,
    // any tokens()/numAccounts() call on the UI thread during the scan would block on that lock and
    // freeze the app ("not responding"). Populated before the scan, invalidated on mutation.
    mutable QMutex m_metaCacheMutex;
    mutable int m_numAccountsCache = -1;         // -1 = unknown (must re-read)
    mutable int m_numAccountsLast = 1;           // last successfully read count; non-blocking fallback
    mutable QVector<TokenInfo> m_tokensCache;
    mutable bool m_tokensCacheValid = false;
    mutable int m_watchOnlyCache = -1;           // -1 = unknown (immutable once computed)
    mutable int m_hardwareCache = -1;            // -1 = unknown (immutable once computed)
    mutable QString m_hwKindCache;               // immutable once computed
    mutable bool m_hwKindCached = false;
    // Bumped on every invalidation. A getter reads it before the (unlocked) core read and only stores
    // the result if it hasn't changed since - so a mutation that races an in-flight read can never
    // poison the cache with a stale value (the read simply isn't cached and re-runs next call).
    mutable quint64 m_metaGen = 0;
    void invalidateMetaCache();   // clears the account-count cache (NOT tokens - see .cpp)
    void invalidateTokensCache(); // clears the tracked-tokens cache (addToken/removeToken only)

    // Metadata queued from the UI thread (lock-free); applied to the core off-thread by saveAsync.
    QMutex m_pendingMetaMutex;
    QString m_pendingMetadata;
    bool m_hasPendingMetadata = false;
};

Q_DECLARE_METATYPE(BalanceInfo)
Q_DECLARE_METATYPE(FeeInfo)
Q_DECLARE_METATYPE(PendingEthTx)
Q_DECLARE_METATYPE(HistoryItem)
Q_DECLARE_METATYPE(NftCollection)

#endif // AERO_WALLET_H
