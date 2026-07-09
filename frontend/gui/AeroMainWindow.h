// SPDX-License-Identifier: BSD-3-Clause
// The Aero main window: assembles Feather's actual MainWindow.ui + tab widget .ui forms and
// wires them to the Ethereum backend (ethwallet Wallet/WalletManager + models).
#ifndef AERO_MAINWINDOW_H
#define AERO_MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QPixmap>
#include <QHash>
#include <QJsonObject>
#include <QSet>
#include <QList>

#include <functional>

#include "ui_MainWindow.h"
#include "ui_SendWidget.h"
#include "ui_ReceiveWidget.h"
#include "ui_HistoryWidget.h"

#include "ethwallet/Wallet.h"
#include "ethwallet/HistoryModel.h"
#include "ethwallet/AddressModel.h"
#include "TorManager.h"

class QComboBox;
class QGroupBox;
class QMessageBox;
class QButtonGroup;
class QToolButton;
class QHBoxLayout;
class QLineEdit;
class QDoubleSpinBox;
class QTimer;
class QSystemTrayIcon;
class QAction;
class QSortFilterProxyModel;
class QListWidget;
class QTableWidget;
class QTreeWidget;
class QScrollArea;

class AeroMainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit AeroMainWindow(QWidget *parent = nullptr);
    ~AeroMainWindow() override;

    // Takes ownership of the wallet and brings the window online.
    void setWallet(Wallet *wallet);

protected:
    void closeEvent(QCloseEvent *event) override; // flush wallet state to disk on exit
    void changeEvent(QEvent *event) override;      // lock on minimize
    bool eventFilter(QObject *obj, QEvent *event) override; // reset idle timer on activity

private slots:
    void onSettings();
    void onChangePassword();
    void onShowSeed();
    void onSignVerifyMessage(); // Tools -> Sign / Verify Message (EIP-191 personal_sign)
    void onBroadcastRaw();      // Tools -> Broadcast Raw Transaction (push a signed raw tx)
    void onSignUnsigned();      // Tools -> Sign Unsigned Transaction (offline signing)
    void onSendMany();          // Tools -> Send to Many (one tx per recipient)
    void onManySent(const QString &resultJson, const QString &error); // pay-to-many summary
    void onUnsignedTxReady(const QString &json, const QString &error); // export-unsigned result
    void onTransactionSent(const PendingEthTx &tx, const QString &txHash); // remember for speed/cancel
    void onSpeedUpLast(); // rebroadcast the last tx at the same nonce with a higher fee
    void onCancelLast();  // replace the last pending tx with a 0-value self-send (higher fee)
    void onFundedScanned(const QList<quint32> &indices);
    void onTokenLiquidity(const QString &tokenAddress, double usd);
    void onHistoricalPrice(const QString &symbol, const QString &date, double usd);
    void onFiatRate(const QString &currency, double rate);
    void onTokenMetaResolved(const QString &address, const QString &symbol, quint8 decimals);
    void onNftsRefreshed(const QVector<NftCollection> &items);
    void onImageReady(const QString &url, const QByteArray &data);
    void onRefresh();
    void onAccountChanged(int index);
    void onCreateAddress();
    void onAccountAdded(quint32 index); // completes onCreateAddress once derivation finishes
    void onImportKey();
    void onAddressContextMenu(const QPoint &pos);
    void onSendClicked();
    void onTransactionCreated(const PendingEthTx &tx);
    void onTransactionCommitted(bool ok, const QString &txHash, const QString &error);
    void onBalanceUpdated(const BalanceInfo &eth, const QVector<BalanceInfo> &tokens);
    void onAccountBalance(quint32 index, const QString &formatted, const QString &symbol);
    void onEthUsdPrice(double usdPerEth);
    void onMarketPrices(double xmrUsd, double xmrChangePct, double ethUsd, double ethChangePct);
    void onAmountConversion();
    void onProviderConnected(int mode, const QString &message);
    void onAvailableBalance(quint32 index, const QString &token, const QString &formatted,
                            const QString &symbol);
    void onBlockNumber(quint64 block);
    void onFeesUpdated(const QString &baseFeeWei, const QString &tipWei);
    void onFeeModeChanged();
    void updateFeeEstimate();
    void updateAvailable();
    // Swap (multi-router) tab.
    void onSwapConfirm();
    void onSwapQuoteReady(const QString &quoteJson, const QString &error);
    void onSwapQuotesReady(const QString &json, const QString &error);      // comparison list
    void onRouterBuilt(const QString &json, const QString &error);          // chosen on-chain router
    void onRouterAllowanceReady(const QString &token, const QString &spender,
                                const QString &allowanceWei, const QString &error);
    void onRouterApproved(const QString &txHash, const QString &error);
    void onRouterSwapSent(const QString &txHash, const QString &error);
    void onDefillamaPricesReady(const QString &json, const QString &error);
    void onSwapAllowanceReady(const QString &token, const QString &allowanceWei, const QString &error);
    void onSwapApproved(const QString &txHash, const QString &error);
    void onSwapSubmitted(const QString &orderUid, const QString &error);
    void onSwapEthFlowSent(const QString &txHash, const QString &error);

private:
    void setupTabs();
    void setupHomeTab();
    void setupStatusBar();
    void autoConnect();
    void switchChain(quint64 chainId); // reconnect + relabel native coin + refresh for a new chain
    void relabelNative();              // update native-coin labels (Home ticker, status) after switch
    void rebuildAccountCombos();
    void refreshAllBalances();
    void recomputeHomeTotal();
    void scheduleHomeRecompute();     // debounced recompute (coalesces bulk balance updates)
    void refreshUsedFlags();          // recompute all rows' red/used flags in one pass
    void startScanProgress();         // poll live funded-scan progress into the status bar
    void notify(const QString &title, const QString &body);
    void loadLabels();                // restore persisted address labels for the open wallet
    // Per-wallet metadata (labels/contacts/notes/funded) lives encrypted inside the wallet file.
    void loadMetadata();              // parse m_wallet->metadata() (+ migrate legacy) and apply to UI
    void saveMetadata();              // serialize m_meta into the wallet, then persist (debounced)
    void saveBalanceCache();          // stash the current chain's balances in metadata (for instant reopen)
    void loadBalanceCache();          // show last-known balances instantly, before the Tor refresh
    void saveHistoryCache();          // persist the current chain's fetched history (debounced)
    void foldHistoryCacheIntoMeta();  // build history snapshot into m_meta without saving (close path)
    void loadHistoryCache();          // restore the current chain's history instantly (0 requests)
    void loadHistoricalPrices();      // restore cached per-date prices (immutable) — no re-fetch ever
    void scheduleHistorySave();       // debounce persisting history after targeted batches arrive
    void primeZeroBalances();         // show 0 immediately for accounts with no known balance yet
    // Run a blocking wallet op (Argon2 save/store, or a core-locked read that may wait behind a
    // running funded scan) OFF the UI thread behind a modal busy dialog, so the UI never freezes.
    // The work lambda may write results into caller-owned variables (safe: read after this returns).
    void runBusy(const QString &message, const std::function<void()> &work);
    void applyOptimisticSend(const QString &amount, const QString &tokenAddr); // instant balance drop
    void scheduleSave();              // debounced, off-thread wallet save (never blocks the UI)
    void migrateLegacyMetadata();     // one-time import from the old plaintext QSettings
    void showCachedBalance(quint32 index); // instant status-bar balance from cache
    void showTransactionDialog(const HistoryItem &tx); // Feather-style tx details (txid + copy)
    void refreshHistoryView();             // full (re)load: clear + fetch viewed + funded accounts
    void ensureAccountHistory(quint32 index, bool force = false); // targeted fetch (lazy/on-demand)
    void refreshDirtyHistory();            // refetch only accounts whose balance changed (per block)
    void onAccountHistoryReady(quint32 index, const QVector<HistoryItem> &items,
                               quint64 chainId); // append targeted
    void updatePollCadence();          // fast block poll when focused/sending, slow when idle
    void startReceiptWatch(const QString &txHash); // fast-poll the tx receipt to confirm a send
    void onTxReceiptReady(const QString &txHash, bool mined, bool success);
    void rebuildHistoryCombo();            // (re)populate the History account selector
    void updateHistoryPricing();           // push per-symbol USD prices into the History dust filter
    QString fiatStr(double usd) const;     // format a USD value in the user's chosen fiat
    QString explorerTxUrl(const QString &hash) const;   // preferred explorer tx link
    void lockWallet();                     // auto-lock: require the password to regain access
    // Copy a secret (seed / private key) to the clipboard and auto-clear it after the configured
    // timeout, so it doesn't linger in the OS clipboard (Feather-style).
    void copySensitive(const QString &text);
    QSet<QString> verifiedTokenAddresses() const; // trusted-token allow-list (lower-case) for spam
    void applyVerifiedTokens();            // push the allow-list into the History model
    void checkUntrackedTokenLiquidity();   // query DexScreener for unknown tokens seen in history
    void loadLiquidityCache();             // restore persisted liquidity decisions
    void setupNftTab();                    // build the NFTs tab (hidden unless enabled)
    void setNftTabEnabled(bool on);        // show/hide the NFTs tab (Settings toggle)
    void setupSwapTab();                   // build the Swap (CoW Protocol) tab
    void openSwapPicker(bool sell);        // asset picker for the sell (true) / buy (false) slot
    void setSwapAsset(bool sell, const QString &symbol, const QString &address, quint8 decimals);
    void refreshSwapQuote();               // (re)fetch a CoW quote for the current sell/buy/amount
    void resetSwapFlow();                  // clear "swap in flight" state (unblocks the re-quote guard)
    void updateSwapTabEnabled();           // show/hide + enable Swap per chain (CoW) + watch-only
    void updateSwapAvailable();            // Swap: refresh the "Available: X" line for the sell asset
    double swapAvailable() const;          // cached balance of the selected sell asset (From account)
    void updateSwapPayUsd();               // Swap: refresh the "≈ $X" USD value under "You pay"
    void showRevokeApprovals();            // Tools -> Revoke Token Approvals dialog
    // MetaMask-style detailed confirmation for a swap. Returns true if the user confirms.
    // `cowVerified` reflects CoW's own `verified` quote flag (surfaced as a security badge).
    // For on-chain routers, `routerId`/`routerLabel`/`routerTo`/`routerSpender` describe the router
    // contract + approval target; for CoW pass routerId "cow" and empty to/spender.
    bool swapConfirmDialog(bool sellIsNative, bool buyIsNative, double sellH, double buyH,
                           double feeH, double sellUsd, double buyUsd, double feeUsd, double refOut,
                           double diffPct, qint64 validTo, quint32 fromIndex, bool cowVerified,
                           const QString &routerId, const QString &routerLabel,
                           const QString &routerTo, const QString &routerSpender);
    // True if `addr` is a known aggregator router/proxy (for the verified badge).
    bool isKnownRouter(const QString &addr) const;
    // Inline swap result on the Swap tab (no popup) + History refresh; optional explorer/CoW link.
    void swapInlineDone(const QString &summary, const QString &url = QString(),
                        const QString &linkText = QString());
    void addPendingSwap(const QString &id); // optimistic "pending" swap row in History (any network)
    void startCowPoll();                    // poll swap status while any swap is pending
    quint32 swapSlippageBps() const; // parse the Swap slippage selector
    // MetaMask-style spending-cap approval prompt with an editable cap (exact vs unlimited). Returns
    // the chosen cap as decimal-wei, "max" for unlimited, or an empty string if the user rejects.
    QString spendingApprovalDialog(const QString &tokenSymbol, const QString &tokenAddr,
                                   const QString &spenderName, const QString &spenderAddr,
                                   const QString &exactHuman, const QString &exactWei);
    // True if `addr` is on the local verified/known-token allow-list (used for security badges).
    bool isKnownToken(const QString &addr) const;
    void refreshNfts();                    // fetch owned NFT collections for the current account
    void displayNfts();                    // (re)render m_nftCache honoring the spam toggle
    void setupMenu();                      // wire the menu bar actions; hide dead ones
    void setupContactsTab();               // build the Contacts address book
    void exportHistoryCsv();               // Wallet -> Export CSV
    void showTokenSettings();              // manage verified / imported tokens
    void applyFundedFilter();              // push the funded-only filter into the Receive list
    void loadFundedSet();                  // restore persisted funded indices for this wallet
    void saveFundedSet();                  // persist funded indices + a "scanned" marker
    QPair<QString, QString> chosenFeeWei() const; // (maxFee, priority) wei; empty = automatic
    QPair<QString, QString> bumpedFeeWei() const; // generous fee (wei) to replace a stuck tx
    QString accountLabel(quint32 index) const;
    void updateReceive();
    void ensureMinAddresses(quint32 count);
    void selectAddressRow(quint32 index);
    void applyReceiveSearch(); // re-hide Receive rows per the search box (survives model resets)
    void populateSendCurrencies();     // reset the Send asset selector to ETH
    void openTokenPicker();            // searchable token picker (held + verified + paste)
    void setSendAsset(const QString &symbol, const QString &address, quint8 decimals);
    quint8 currentDecimals() const;    // decimals of the selected Send asset
    void updateAmountUnit();            // show/hide the ETH/USD unit for the selected asset
    QString currentSymbol() const;
    QString currentTokenAddr() const;   // "" == ETH
    double unitPriceUsd(const QString &symbol) const;
    QPixmap renderQr(const QString &text) const;
    // Air-gapped QR transfer: show a payload as a scannable QR (warns if too big for one code), and
    // decode a QR from an image file the user picks. Used by the offline sign/broadcast flow.
    void showQrPopup(const QString &title, const QString &text);
    QString scanQrFromFile();
    QIcon tokenIcon(const QString &symbol) const; // native coins fall back to the chain icon

    Ui::MainWindow ui;
    Ui::SendWidget sendUi;
    Ui::ReceiveWidget recvUi;
    Ui::HistoryWidget histUi;

    Wallet *m_wallet = nullptr;
    quint32 m_account = 0;

    void setConnectionState(int mode, const QString &tip); // 2=Tor, 1=Direct, 0=Offline
    void showConnectionMenu();          // click the status area: status + Reconnect + New circuit
    void reconnectTor(const QString &reason); // re-establish the connection (restart Tor if it died)
    void newTorCircuit();               // fresh Tor circuit (restart bundled Tor)

    // Custom-node support: return the RPC endpoints / SOCKS proxy to use for `chainId`. If the user
    // saved a custom node for that chain (Settings -> Node) it wins; otherwise the bundled defaults
    // (registry RPCs over the running Tor proxy) are used. socksFor("") == direct/own-node.
    QStringList endpointsFor(quint64 chainId) const;
    QString socksFor(quint64 chainId) const;
    // If the user opted to share an external Tor (Feather / Tor Browser / system Tor) instead of the
    // bundled one, returns its SOCKS URL (socks5h://host:port); empty when using the bundled Tor.
    QString externalSocks() const;
    QString allChainsScanConfig() const; // JSON of every chain's endpoints+socks, for cross-chain scan
    void connectCurrentChain(); // (re)connect the active chain using the resolved node settings

    QLabel *m_balanceLabel = nullptr;
    QLabel *m_availLabel = nullptr;    // Send: "Available: X SYM" for the selected From + currency
    QString m_availAmount;             // Send: cached available amount (for the Max button)
    QLabel *m_connLabel = nullptr;
    QLabel *m_connIcon = nullptr;  // green/gray connection indicator (bottom-right)
    QLabel *m_recvBalanceLabel = nullptr; // Receive: address + balance shown under the QR
    QLabel *m_recvTotalLabel = nullptr;   // Receive: combined total across accounts (like Home)
    QComboBox *m_fromCombo = nullptr;     // Send: which account to send from
    QToolButton *m_assetButton = nullptr;    // Send: opens the searchable token picker
    QString m_sendSymbol = QStringLiteral("ETH"); // selected Send asset
    QString m_sendTokenAddr;                 // "" == ETH
    quint8 m_sendDecimals = 18;
    QString m_pendingSendAsset;              // contract being resolved on-chain for the picker
    QComboBox *m_amountUnit = nullptr;       // Send: ETH/USD entry unit (ETH & WETH only)
    QLabel *m_feeEstimateLabel = nullptr;    // Send: "≈ X ETH ($Y) · ETA ~Z"
    QLineEdit *m_customMaxFee = nullptr;     // Send: custom max fee per gas (gwei)
    QLineEdit *m_customPriority = nullptr;   // Send: custom priority fee per gas (gwei)
    QWidget *m_customFeeWidget = nullptr;    // Send: container for the custom-fee inputs
    double m_feeBaseWei = 0.0;               // cached base fee per gas (wei)
    double m_feeTipWei = 0.0;                // cached priority tip per gas (wei)
    double m_nativeUsd = 0.0;             // cached native-coin/USD price (chain-aware, for valuation)
    double m_xmrUsd = 0.0;                // cached XMR/USD price (market API over Tor)
    // Active chain (multichain). Defaults to Ethereum mainnet on every launch.
    quint64 m_chainId = 1;
    QString m_nativeSymbol = QStringLiteral("ETH");
    QToolButton *m_networkButton = nullptr; // status-bar network selector
    QMessageBox *m_deviceDialog = nullptr;  // "confirm on your device" prompt during hardware signing
    bool m_parsingUri = false; // guard against re-entrancy while rewriting the Pay-to field
    void requestHistoricalPrices(const QVector<HistoryItem> &items); // fetch per-date native prices
    QSet<QString> m_histPriceRequested; // "SYMBOL|date" already requested (dedupe historical lookups)
    // Set when a batched balance refresh sees an actual change vs the cached value; drives an
    // event-driven history refresh (so we don't re-pull the full history on every block).
    bool m_balancesChanged = false;
    // Last broadcast tx this session, for Tools -> Speed Up / Cancel (replacement reuses its nonce).
    PendingEthTx m_lastSent;
    bool m_hasPending = false;
    QAction *m_speedUpAction = nullptr;
    QAction *m_cancelTxAction = nullptr;
    bool m_hideBalances = false;          // Appearance: mask balances for privacy
    QString m_fiatCurrency = QStringLiteral("USD"); // display fiat (Settings)
    QString m_fiatSymbol = QStringLiteral("$");
    double m_fiatRate = 1.0;              // USD -> m_fiatCurrency multiplier
    bool m_notifications = true;          // desktop notifications on/off
    bool m_confirmSend = false;           // require password before broadcasting
    int m_autoLockMinutes = 0;            // 0 = disabled
    bool m_lockOnMinimize = false;
    bool m_locked = false;                // guard against re-entrant lock dialog
    QTimer *m_idleTimer = nullptr;        // inactivity -> auto-lock

    // Home tab tickers (Feather-style).
    QWidget *m_homeTab = nullptr;
    QGroupBox *m_homeNativeBox = nullptr; // native-coin ticker box (relabeled on chain switch)
    QLabel *m_homeTotalValue = nullptr;
    QLabel *m_homeXmrValue = nullptr;
    QLabel *m_homeXmrPct = nullptr;
    QLabel *m_homeEthValue = nullptr;
    QLabel *m_homeEthPct = nullptr;
    QHash<quint32, double> m_ethRawByAccount;  // raw ETH balance per account (for combined total)
    QHash<QString, double> m_tokenRawByKey;    // "account|tokenAddr" -> raw token balance
    // Details of the tx being committed, captured at confirm time so the post-send UI (optimistic
    // balance drop, history row, notification) uses the ACTUAL token amount — not the raw Amount
    // field, which may be entered in USD. m_committedIsReplacement suppresses the optimistic drop +
    // duplicate history row for a speed-up/cancel (a replacement of an already-shown tx).
    QString m_committedAmount;                 // human token amount (asset units)
    QString m_committedSymbol;                 // its symbol
    QString m_committedTokenAddr;              // token contract ("" = native)
    QString m_committedTo;                     // recipient address
    quint32 m_committedFrom = 0xFFFFFFFFu;      // account the tx was actually sent FROM (not the live combo)
    bool m_committedIsReplacement = false;
    quint32 m_lastSendFrom = 0xFFFFFFFFu;      // account we last sent from (for the optimistic drop)
    qint64 m_lastSendMs = 0;                   // when we last sent — suppress false "received" while
                                               // a pre-mine refresh reads the still-higher balance

    QTimer *m_refreshTimer = nullptr;
    QTimer *m_blockTimer = nullptr;            // polls the chain head for new blocks
    QTimer *m_receiptTimer = nullptr;          // fast-polls a just-sent tx's receipt to confirm it
    QString m_pendingReceiptHash;              // the tx we're watching for confirmation ("" = none)
    int m_receiptPolls = 0;                    // safety cap on receipt polls
    QTimer *m_saveTimer = nullptr;             // debounces wallet saves (coalesces rapid edits)
    QTimer *m_histSaveTimer = nullptr;         // debounces persisting the per-chain history cache
    qint64 m_lastBalCacheSaveMs = 0;           // throttles persisting the balance cache (Argon2 cost)
    bool m_balancesFromCache = false;          // suppress "payment received" on the 1st refresh after
                                               // loading stale cached balances (not a live change)
    QTimer *m_homeTotalTimer = nullptr;        // debounces home-total + used-flag recompute
    QTimer *m_scanProgressTimer = nullptr;     // polls live funded-scan progress into the status bar
    QTimer *m_cowPollTimer = nullptr;          // re-checks CoW/swap status while any swap is pending
    quint64 m_lastBlock = 0;                   // last seen block height
    QSystemTrayIcon *m_tray = nullptr;         // desktop notifications (received / sent)
    TorManager *m_tor = nullptr;               // bundled Tor process supervisor
    HistoryModel *m_historyModel = nullptr;
    QComboBox *m_historyCombo = nullptr;       // History filter: All / a specific account
    int m_historyFilter = -1;                  // -1 = All accounts, else account index
    // Electrum/Feather-style lazy, status-gated history so we never fan out a fetch over every
    // (mostly empty) account, and never refetch everything each block.
    QSet<quint32> m_histFetched;               // accounts whose history is already loaded this session
    QSet<quint32> m_dirtyHistory;              // accounts whose balance changed -> need a targeted refetch
    QHash<quint32, double> m_histStatus;       // account balance when its history was last fetched (status gate)
    quint64 m_historyLoadedChain = ~Q_UINT64_C(0); // chain the history view was (re)loaded for
    QToolButton *m_historyPrev = nullptr;      // pagination: previous 500-row page
    QToolButton *m_historyNext = nullptr;      // pagination: next 500-row page
    QLabel *m_historyPageLabel = nullptr;      // "Page X of Y (N transactions)"
    QAction *m_hideSpamAction = nullptr;       // History menu toggle (kept in sync with Settings)
    AddressModel *m_addressModel = nullptr;    // Receive: the address list
    QWidget *m_nftTab = nullptr;               // NFTs tab
    QListWidget *m_nftList = nullptr;          // NFT collection grid

    // ##### Swap (multi-router) tab #####
    QWidget *m_swapTab = nullptr;              // scrollable content (widgets parented here)
    QScrollArea *m_swapScroll = nullptr;       // scroll viewport for the content
    QWidget *m_swapPage = nullptr;             // tab page: scroll on top + pinned Confirm bar below
    QComboBox *m_swapFrom = nullptr;           // account the swap sells from
    QToolButton *m_swapSellButton = nullptr;   // sell-asset picker
    QToolButton *m_swapBuyButton = nullptr;    // buy-asset picker
    QLineEdit *m_swapAmount = nullptr;         // sell amount (human units)
    QLabel *m_swapReceive = nullptr;           // (unused legacy single-line receive)
    QLabel *m_swapRate = nullptr;              // rate line + DefiLlama cross-check
    QLabel *m_swapStatus = nullptr;            // quote/error status
    QPushButton *m_swapConfirmBtn = nullptr;
    QTimer *m_swapQuoteTimer = nullptr;        // debounce + live-refresh the quote
    QTreeWidget *m_swapList = nullptr;         // router comparison table (best-first, columns)
    QComboBox *m_swapSlippage = nullptr;       // slippage mode: Auto / preset / Custom
    QDoubleSpinBox *m_swapSlipCustom = nullptr; // manual slippage % (shown when Custom)
    QLabel *m_swapSlipNote = nullptr;          // shows the effective slippage for the trade
    QLabel *m_swapAvailLabel = nullptr;        // "Available: X SYM" for the selected sell asset
    QLabel *m_swapPayUsd = nullptr;            // "≈ $X" USD value of the pay amount
    // Selected router (from the comparison list).
    QString m_swapSelRouter;                   // "cow" | "kyberswap" | ...
    QString m_swapSelKind;                     // "signed-order" | "onchain"
    QString m_swapSelLabel;
    QString m_swapSelBuyAmount;                // expected out (wei) for the selected router
    double m_swapSelGasUsd = 0.0;              // selected router's estimated gas cost (USD)
    bool m_swapCowExecuting = false;           // onSwapQuoteReady should proceed to CoW confirm+exec
    bool m_swapAwaitingApprove = false;        // CoW: waiting for the approve tx to confirm on-chain
    int m_swapApprovePolls = 0;                // CoW: allowance re-check attempts after approving
    bool m_swapAwaitingRouterApprove = false;  // on-chain router: waiting for approve to mine
    int m_swapRouterApprovePolls = 0;          // on-chain router: allowance re-check attempts
    bool m_swapRouterExecuteAfterBuild = false;// on-chain router: routerBuilt should swap immediately
    // Built on-chain tx (from routerBuild), used across confirm -> allowance -> approve -> swap.
    QString m_swapBuiltTo, m_swapBuiltData, m_swapBuiltValue, m_swapBuiltSpender, m_swapBuiltMinBuy;
    QString m_swapConfirmedMinBuy;             // min-out the user confirmed, to detect a post-approval drop
    QString m_swapSellSymbol = QStringLiteral("ETH");
    QString m_swapSellAddr;                    // "" == native
    quint8 m_swapSellDecimals = 18;
    QString m_swapBuySymbol;
    QString m_swapBuyAddr;                     // "" == native (BUY_ETH sentinel when quoting)
    quint8 m_swapBuyDecimals = 18;
    QString m_swapQuoteJson;                   // last successful quote (drives Confirm)
    bool m_swapPickerSell = true;              // which slot the open picker writes to
    bool m_swapUserPickedRouter = false;       // user manually chose a route (don't snap to best on refresh)
    double m_swapLlamaSellUsd = 0.0;           // DefiLlama sell-token USD (cross-check)
    double m_swapLlamaBuyUsd = 0.0;            // DefiLlama buy-token USD (cross-check)
    // Pending execution context captured at Confirm time (used across the approve->submit chain).
    quint32 m_swapExecFrom = 0;
    QString m_swapExecQuote;
    QString m_swapExecSellAddr;                // token being sold (for allowance/approve)
    QString m_swapExecBuyAddr;                 // token being bought (eth-flow buyToken)
    QString m_swapExecSellAmountWei;           // needed allowance
    bool m_swapExecNative = false;             // native-ETH sell -> eth-flow
    quint32 m_swapExecSlippageBps = 50;        // slippage captured at Confirm (applied to CoW min-buy)
    QTableWidget *m_contactsTable = nullptr;   // Contacts address book
    QJsonObject m_meta;                        // in-memory per-wallet metadata mirror (persisted encrypted)
    bool m_metaLoading = false;                // guard so applying metadata to the UI doesn't re-persist
    QLabel *m_nftStatus = nullptr;             // NFT tab status line
    bool m_nftShowSpam = false;                // include reputation!=ok collections
    bool m_nftEnabled = false;                 // whether the NFTs tab is shown (Settings toggle)
    QVector<NftCollection> m_nftCache;         // last-fetched collections (for re-filtering)
    QHash<quint32, QString> m_accountBalances; // index -> "1.23 ETH"
    QSet<QString> m_liquidityVerified;         // token addresses auto-trusted via DEX liquidity
    QSet<QString> m_liquidityChecked;          // token addresses already checked (pass or fail)
    QSet<QString> m_liquidityInFlight;         // checks currently running (avoid duplicates)
    double m_liquidityThresholdUsd = 1000000.0;// auto-trust tokens with pool liquidity above this
    QSet<quint32> m_fundedAccounts;            // HD indices discovered to hold a balance
    bool m_showFundedOnly = false;             // Receive: show only funded addresses (default off)
    bool m_fundedScanned = false;              // a gap-limit scan has completed/was persisted
    int m_connMode = 0;                        // last connection mode (0 off, 1 direct, 2 Tor)
    QString m_connText;                        // last connected status text (to restore after Scanning)
    int m_connHealthFails = 0;                 // consecutive failed block polls while "connected"
    bool m_reconnecting = false;               // a self-healing reconnect is in progress
    bool m_everConnected = false;              // connected at least once (enables drop auto-recovery)
    bool m_fundedScanTried = false;            // guard so auto-scan runs at most once per session
};

#endif // AERO_MAINWINDOW_H
