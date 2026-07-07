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
class QTimer;
class QSystemTrayIcon;
class QAction;
class QSortFilterProxyModel;
class QListWidget;
class QTableWidget;

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
    void notify(const QString &title, const QString &body);
    void updateUsed(quint32 index);   // mark an address red if it holds funds / has transacted
    void loadLabels();                // restore persisted address labels for the open wallet
    // Per-wallet metadata (labels/contacts/notes/funded) lives encrypted inside the wallet file.
    void loadMetadata();              // parse m_wallet->metadata() (+ migrate legacy) and apply to UI
    void saveMetadata();              // serialize m_meta into the wallet and persist (encrypted)
    void migrateLegacyMetadata();     // one-time import from the old plaintext QSettings
    void showCachedBalance(quint32 index); // instant status-bar balance from cache
    void showTransactionDialog(const HistoryItem &tx); // Feather-style tx details (txid + copy)
    void refreshHistoryView();             // fetch history per the History filter (All / account)
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
    void populateSendCurrencies();     // reset the Send asset selector to ETH
    void openTokenPicker();            // searchable token picker (held + verified + paste)
    void setSendAsset(const QString &symbol, const QString &address, quint8 decimals);
    quint8 currentDecimals() const;    // decimals of the selected Send asset
    void updateAmountUnit();            // show/hide the ETH/USD unit for the selected asset
    QString currentSymbol() const;
    QString currentTokenAddr() const;   // "" == ETH
    double unitPriceUsd(const QString &symbol) const;
    QPixmap renderQr(const QString &text) const;
    QIcon tokenIcon(const QString &symbol) const; // native coins fall back to the chain icon

    Ui::MainWindow ui;
    Ui::SendWidget sendUi;
    Ui::ReceiveWidget recvUi;
    Ui::HistoryWidget histUi;

    Wallet *m_wallet = nullptr;
    quint32 m_account = 0;

    void setConnectionState(int mode, const QString &tip); // 2=Tor, 1=Direct, 0=Offline

    // Custom-node support: return the RPC endpoints / SOCKS proxy to use for `chainId`. If the user
    // saved a custom node for that chain (Settings -> Node) it wins; otherwise the bundled defaults
    // (registry RPCs over the running Tor proxy) are used. socksFor("") == direct/own-node.
    QStringList endpointsFor(quint64 chainId) const;
    QString socksFor(quint64 chainId) const;
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

    QTimer *m_refreshTimer = nullptr;
    QTimer *m_blockTimer = nullptr;            // polls the chain head for new blocks
    quint64 m_lastBlock = 0;                   // last seen block height
    QSystemTrayIcon *m_tray = nullptr;         // desktop notifications (received / sent)
    TorManager *m_tor = nullptr;               // bundled Tor process supervisor
    HistoryModel *m_historyModel = nullptr;
    QSortFilterProxyModel *m_historyProxy = nullptr; // enables header-click sort (date / amount)
    QComboBox *m_historyCombo = nullptr;       // History filter: All / a specific account
    int m_historyFilter = -1;                  // -1 = All accounts, else account index
    QAction *m_hideSpamAction = nullptr;       // History menu toggle (kept in sync with Settings)
    AddressModel *m_addressModel = nullptr;    // Receive: the address list
    QWidget *m_nftTab = nullptr;               // NFTs tab
    QListWidget *m_nftList = nullptr;          // NFT collection grid
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
    bool m_showFundedOnly = true;              // Receive: show only funded addresses
    bool m_fundedScanned = false;              // a gap-limit scan has completed/was persisted
    bool m_fundedScanTried = false;            // guard so auto-scan runs at most once per session
};

#endif // AERO_MAINWINDOW_H
