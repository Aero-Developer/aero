// SPDX-License-Identifier: BSD-3-Clause
#include "AeroMainWindow.h"

#include <cmath>

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QButtonGroup>
#include <QCheckBox>
#include <QColor>
#include <QIcon>
#include <QBoxLayout>
#include <QListView>
#include <QPixmap>
#include <QPointer>
#include <QPlainTextEdit>
#include <QSpinBox>
#include <QTableWidget>
#include <QHeaderView>
#include <QTextStream>
#include <QFile>
#include <QFileDialog>
#include <QDoubleSpinBox>
#include <QListWidget>
#include <QListWidgetItem>
#include <QSortFilterProxyModel>
#include <QTabWidget>
#include <QToolButton>
#include <QClipboard>
#include <QCloseEvent>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFont>
#include <QFormLayout>
#include <QFrame>
#include <QGroupBox>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QImage>
#include <QInputDialog>
#include <QItemSelectionModel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QDesktopServices>
#include <QPainter>
#include <QPushButton>
#include <QSettings>
#include <QSystemTrayIcon>
#include <QUrl>
#include <QTimer>
#include <QVBoxLayout>

#include "qrcodegen.hpp"

namespace {
const quint64 kChainId = 1;
const QStringList kDefaultEndpoints = {
    QStringLiteral("https://eth.llamarpc.com"),
    QStringLiteral("https://ethereum-rpc.publicnode.com"),
    QStringLiteral("https://eth.drpc.org"),
    QStringLiteral("https://rpc.mevblocker.io"),
};
const QString kDefaultSocks = QStringLiteral("socks5h://127.0.0.1:9055");

// ---- Multichain registry -------------------------------------------------------------------
// Same keys/addresses on every EVM chain; switching a network reconnects the RPC with a new chain
// id + endpoints, relabels the native coin, and repoints history/price/explorer lookups. Keyless
// public RPCs only (publicnode / official) so nothing identifies the user. Mirrors the core-side
// `chains::chain_info` table (native symbol / explorer availability must stay in sync).
struct ChainDef {
    quint64 id;
    QString name;
    QString nativeSymbol;
    QString icon;        // bundled qrc icon
    QStringList rpcs;    // keyless endpoints, rotated
    QString explorer;    // block-explorer base for tx links
};

const QList<ChainDef> &chainDefs() {
    static const QList<ChainDef> defs = {
        {1, QStringLiteral("Ethereum"), QStringLiteral("ETH"),
         QStringLiteral(":/assets/images/chains/ethereum.png"),
         {QStringLiteral("https://eth.llamarpc.com"),
          QStringLiteral("https://ethereum-rpc.publicnode.com"),
          QStringLiteral("https://eth.drpc.org"),
          QStringLiteral("https://rpc.mevblocker.io")},
         QStringLiteral("https://etherscan.io")},
        {42161, QStringLiteral("Arbitrum One"), QStringLiteral("ETH"),
         QStringLiteral(":/assets/images/chains/arbitrum.png"),
         {QStringLiteral("https://arbitrum-one-rpc.publicnode.com"),
          QStringLiteral("https://arb1.arbitrum.io/rpc"),
          QStringLiteral("https://arbitrum.drpc.org")},
         QStringLiteral("https://arbiscan.io")},
        {8453, QStringLiteral("Base"), QStringLiteral("ETH"),
         QStringLiteral(":/assets/images/chains/base.png"),
         {QStringLiteral("https://base-rpc.publicnode.com"),
          QStringLiteral("https://mainnet.base.org"),
          QStringLiteral("https://base.drpc.org")},
         QStringLiteral("https://basescan.org")},
        {10, QStringLiteral("Optimism"), QStringLiteral("ETH"),
         QStringLiteral(":/assets/images/chains/optimism.png"),
         {QStringLiteral("https://optimism-rpc.publicnode.com"),
          QStringLiteral("https://mainnet.optimism.io"),
          QStringLiteral("https://optimism.drpc.org")},
         QStringLiteral("https://optimistic.etherscan.io")},
        {137, QStringLiteral("Polygon"), QStringLiteral("POL"),
         QStringLiteral(":/assets/images/chains/polygon.png"),
         {QStringLiteral("https://polygon-bor-rpc.publicnode.com"),
          QStringLiteral("https://polygon-rpc.com"),
          QStringLiteral("https://polygon.drpc.org")},
         QStringLiteral("https://polygonscan.com")},
        {56, QStringLiteral("BNB Smart Chain"), QStringLiteral("BNB"),
         QStringLiteral(":/assets/images/chains/bsc.png"),
         {QStringLiteral("https://bsc-rpc.publicnode.com"),
          QStringLiteral("https://bsc-dataseed.bnbchain.org"),
          QStringLiteral("https://bsc.drpc.org")},
         QStringLiteral("https://bscscan.com")},
        {100, QStringLiteral("Gnosis"), QStringLiteral("XDAI"),
         QStringLiteral(":/assets/images/chains/gnosis.png"),
         {QStringLiteral("https://gnosis-rpc.publicnode.com"),
          QStringLiteral("https://rpc.gnosischain.com"),
          QStringLiteral("https://gnosis.drpc.org")},
         QStringLiteral("https://gnosisscan.io")},
        {43114, QStringLiteral("Avalanche"), QStringLiteral("AVAX"),
         QStringLiteral(":/assets/images/chains/avalanche.png"),
         {QStringLiteral("https://avalanche-c-chain-rpc.publicnode.com"),
          QStringLiteral("https://api.avax.network/ext/bc/C/rpc"),
          QStringLiteral("https://avalanche.drpc.org")},
         QStringLiteral("https://snowtrace.io")},
    };
    return defs;
}

const ChainDef &chainDefFor(quint64 id) {
    for (const auto &c : chainDefs())
        if (c.id == id)
            return c;
    return chainDefs().first(); // default to Ethereum
}

// Curated list of well-known mainnet ERC-20s that are auto-trusted in History (so legitimate
// transfers of these aren't hidden by the spam filter). This is an allow-list only: these are not
// balance-tracked unless the user explicitly adds them. Matched case-insensitively by address.
QVector<TokenInfo> curatedTopTokens() {
    return {
        {QStringLiteral("0xdAC17F958D2ee523a2206206994597C13D831ec7"), QStringLiteral("USDT"), 6},
        {QStringLiteral("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), QStringLiteral("USDC"), 6},
        {QStringLiteral("0x6B175474E89094C44Da98b954EedeAC495271d0F"), QStringLiteral("DAI"), 18},
        {QStringLiteral("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"), QStringLiteral("WETH"), 18},
        {QStringLiteral("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"), QStringLiteral("WBTC"), 8},
        {QStringLiteral("0x514910771AF9Ca656af840dff83E8264EcF986CA"), QStringLiteral("LINK"), 18},
        {QStringLiteral("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984"), QStringLiteral("UNI"), 18},
        {QStringLiteral("0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE"), QStringLiteral("SHIB"), 18},
        {QStringLiteral("0x6982508145454Ce325dDbE47a25d4ec3d2311933"), QStringLiteral("PEPE"), 18},
        {QStringLiteral("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84"), QStringLiteral("stETH"), 18},
        {QStringLiteral("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"), QStringLiteral("wstETH"), 18},
        {QStringLiteral("0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9"), QStringLiteral("AAVE"), 18},
        {QStringLiteral("0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2"), QStringLiteral("MKR"), 18},
        {QStringLiteral("0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32"), QStringLiteral("LDO"), 18},
        {QStringLiteral("0xD533a949740bb3306d119CC777fa900bA034cd52"), QStringLiteral("CRV"), 18},
        {QStringLiteral("0x4d224452801ACEd8B2F0aebE155379bb5D594381"), QStringLiteral("APE"), 18},
        {QStringLiteral("0x3845badAde8e6dFF049820680d1F14bD3903a5d0"), QStringLiteral("SAND"), 18},
        {QStringLiteral("0x0F5D2fB29fb7d3CFeE444a200298f468908cC942"), QStringLiteral("MANA"), 18},
        {QStringLiteral("0xc944E90C64B2c07662A292be6244BDf05Cda44a7"), QStringLiteral("GRT"), 18},
        {QStringLiteral("0x111111111117dC0aa78b770fA6A738034120C302"), QStringLiteral("1INCH"), 18},
        {QStringLiteral("0xc00e94Cb662C3520282E6f5717214004A7f26888"), QStringLiteral("COMP"), 18},
        {QStringLiteral("0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F"), QStringLiteral("SNX"), 18},
        {QStringLiteral("0x0000000000085d4780B73119b644AE5ecd22b376"), QStringLiteral("TUSD"), 18},
        {QStringLiteral("0x853d955aCEf822Db058eb8505911ED77F175b99e"), QStringLiteral("FRAX"), 18},
    };
}

QString shortAddr(const QString &a) {
    if (a.size() < 12) return a;
    return a.left(8) + QStringLiteral("…") + a.right(6);
}

// Insert thousands separators into the integer part of a decimal string ("1234.56" -> "1,234.56").
QString grouped(const QString &number) {
    QString s = number.trimmed();
    if (s.isEmpty()) return s;
    QString sign;
    if (s.startsWith(QLatin1Char('-')) || s.startsWith(QLatin1Char('+'))) {
        sign = s.left(1);
        s = s.mid(1);
    }
    const int dot = s.indexOf(QLatin1Char('.'));
    const QString intPart = dot < 0 ? s : s.left(dot);
    const QString frac = dot < 0 ? QString() : s.mid(dot);
    for (const QChar &c : intPart)
        if (!c.isDigit())
            return number; // not a plain number — leave it untouched
    QString out;
    int count = 0;
    for (int i = intPart.size() - 1; i >= 0; --i) {
        out.prepend(intPart.at(i));
        if (++count % 3 == 0 && i > 0)
            out.prepend(QLatin1Char(','));
    }
    return sign + out + frac;
}

// Currency code -> display symbol (falls back to a spaced code, e.g. "AUD ").
QString fiatSymbolFor(const QString &code) {
    static const QHash<QString, QString> syms = {
        {QStringLiteral("USD"), QStringLiteral("$")},      {QStringLiteral("EUR"), QStringLiteral("\u20ac")},
        {QStringLiteral("GBP"), QStringLiteral("\u00a3")}, {QStringLiteral("JPY"), QStringLiteral("\u00a5")},
        {QStringLiteral("CNY"), QStringLiteral("\u00a5")}, {QStringLiteral("CAD"), QStringLiteral("$")},
        {QStringLiteral("AUD"), QStringLiteral("$")},      {QStringLiteral("CHF"), QStringLiteral("CHF ")},
        {QStringLiteral("INR"), QStringLiteral("\u20b9")}, {QStringLiteral("KRW"), QStringLiteral("\u20a9")},
        {QStringLiteral("RUB"), QStringLiteral("\u20bd")}, {QStringLiteral("BRL"), QStringLiteral("R$")},
    };
    return syms.value(code.toUpper(), code.toUpper() + QLatin1Char(' '));
}

// Stable (cross-run) settings key for a wallet's labels. qHash is per-process randomized, so we
// use a fixed digest of the wallet path instead.
QString labelsGroup(const QString &walletPath) {
    const QByteArray h = QCryptographicHash::hash(walletPath.toUtf8(), QCryptographicHash::Md5);
    return QStringLiteral("labels/%1").arg(QString::fromLatin1(h.toHex()));
}

// Drop trailing zeros from a fixed-decimal string ("1.230000" -> "1.23", "5.000000" -> "5").
QString trimZeros(QString s) {
    if (s.contains(QLatin1Char('.'))) {
        while (s.endsWith(QLatin1Char('0')))
            s.chop(1);
        if (s.endsWith(QLatin1Char('.')))
            s.chop(1);
    }
    return s;
}

// Display an ETH/token balance without stretching the UI: cap at 4 decimals
// ("0.0398234892389..." -> "0.0398"), but keep more places for dust so tiny non-zero balances
// don't collapse to "0". Thousands separators are added to the integer part.
QString formatBalance(double v) {
    int decimals = 4;
    const double a = qAbs(v);
    if (a != 0.0 && a < 0.0001)
        decimals = 8;
    return grouped(trimZeros(QString::number(v, 'f', decimals)));
}
QString formatBalance(const QString &raw) {
    bool ok = false;
    const double v = raw.toDouble(&ok);
    return ok ? formatBalance(v) : raw;
}
}

AeroMainWindow::AeroMainWindow(QWidget *parent) : QMainWindow(parent) {
    ui.setupUi(this);
    ui.stackedWidget->setCurrentWidget(ui.page_wallet);

    setupTabs();
    setupStatusBar();

    // Settings menu -> RPC/Tor editor (no Connect/Refresh toolbar anymore).
    connect(ui.actionSettings, &QAction::triggered, this, &AeroMainWindow::onSettings);

    // Dev hook: open a specific tab on startup (0=History,1=Send,2=Receive,...).
    const QByteArray tabEnv = qgetenv("AERO_TAB");
    if (!tabEnv.isEmpty())
        ui.tabWidget->setCurrentIndex(tabEnv.toInt());

    setWindowTitle(QStringLiteral("Aero"));
}

AeroMainWindow::~AeroMainWindow() {
    delete m_wallet;
}

void AeroMainWindow::closeEvent(QCloseEvent *event) {
    // Flush any in-memory changes (created addresses, imported keys, tokens) to the wallet file.
    // If this final save fails, changes made since the last successful save (notably imported keys,
    // which aren't recoverable from the seed) would be lost — so let the user cancel the close and
    // fix the problem rather than silently dropping them.
    if (m_wallet && !m_wallet->walletPath().isEmpty() && !m_wallet->save()) {
        const auto choice = QMessageBox::warning(
            this, tr("Could not save wallet"),
            tr("Your wallet could not be saved:\n\n%1\n\nAny recently imported keys or new addresses "
               "may be lost if you close now. Close anyway?")
                .arg(m_wallet->errorString()),
            QMessageBox::Close | QMessageBox::Cancel, QMessageBox::Cancel);
        if (choice != QMessageBox::Close) {
            event->ignore();
            return;
        }
    }
    QMainWindow::closeEvent(event);
}

// Host a .ui form inside a tab page: the tab pages already carry a layout (from MainWindow.ui),
// so we add the form widget into that layout instead of calling setupUi() on the page directly
// (which would leave the form's widgets unmanaged and piled at the top-left).
static QWidget *hostForm(QWidget *tab) {
    auto *page = new QWidget(tab);
    if (!tab->layout()) {
        auto *l = new QVBoxLayout(tab);
        l->setContentsMargins(0, 0, 0, 0);
    }
    tab->layout()->addWidget(page);
    return page;
}

void AeroMainWindow::setupTabs() {
    // The Send tab has a dedicated placeholder layout (sendWidgetLayout) above a stretch spacer;
    // put the form there so it sits at the top (not below the spacer).
    {
        auto *sendPage = new QWidget(ui.tabSend);
        sendUi.setupUi(sendPage);
        ui.sendWidgetLayout->addWidget(sendPage);
    }
    recvUi.setupUi(hostForm(ui.tabReceive));
    histUi.setupUi(hostForm(ui.tabHistory));

    // Coin control does not apply to account-based Ethereum: drop the Coins tab and hide the
    // "Coin control active" bar entirely.
    ui.tabWidget->removeTab(ui.tabWidget->indexOf(ui.tabCoins));
    ui.frame_coinControl->hide();

    m_historyModel = new HistoryModel(this);
    // Sort proxy: click the Date or Amount header to sort (chronological / by value, not text).
    m_historyProxy = new QSortFilterProxyModel(this);
    m_historyProxy->setSourceModel(m_historyModel);
    m_historyProxy->setSortRole(HistoryModel::SortRole);
    m_historyProxy->setFilterKeyColumn(-1); // search across all columns
    m_historyProxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    histUi.history->setModel(m_historyProxy);
    histUi.history->setSelectionBehavior(QAbstractItemView::SelectRows);
    histUi.history->setSortingEnabled(true);
    histUi.history->sortByColumn(HistoryModel::Column_Date, Qt::DescendingOrder); // newest first
    // Wire the (previously dead) history search box, and drop the Monero sync-notice banner.
    connect(histUi.search, &QLineEdit::textChanged, this,
            [this](const QString &t) { m_historyProxy->setFilterFixedString(t.trimmed()); });
    histUi.syncNotice->hide();
    // Double-click a transaction to open the Feather-style details dialog (map proxy -> source row).
    connect(histUi.history, &QTreeView::doubleClicked, this, [this](const QModelIndex &idx) {
        if (idx.isValid())
            showTransactionDialog(m_historyModel->itemAt(m_historyProxy->mapToSource(idx).row()));
    });

    // History account filter: "All accounts" or a single account, placed at the left of the
    // search bar (Feather shows a similar account filter above the history view).
    m_historyCombo = new QComboBox(histUi.frame_search);
    m_historyCombo->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    m_historyCombo->setMinimumWidth(200);
    histUi.horizontalLayout_2->insertWidget(0, m_historyCombo);
    connect(m_historyCombo, &QComboBox::currentIndexChanged, this, [this](int idx) {
        m_historyFilter = idx <= 0 ? -1 : (idx - 1); // item 0 = All; items 1..N = account idx-1
        refreshHistoryView();
    });

    // History "..." options: toggle hiding of spam / address-poisoning transactions (persisted).
    {
        QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
        const bool hideSpam = s.value(QStringLiteral("history/hideSpam"), true).toBool();
        m_historyModel->setHideSpam(hideSpam);
        // Dust threshold: hide incoming transfers worth less than this many USD (default $0.005).
        m_historyModel->setDustThreshold(s.value(QStringLiteral("history/dustUsd"), 0.005).toDouble());
        auto *menu = new QMenu(this);
        m_hideSpamAction = menu->addAction(tr("Hide spam && address-poisoning transactions"));
        m_hideSpamAction->setCheckable(true);
        m_hideSpamAction->setChecked(hideSpam);
        connect(m_hideSpamAction, &QAction::toggled, this, [this](bool on) {
            m_historyModel->setHideSpam(on);
            QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                .setValue(QStringLiteral("history/hideSpam"), on);
        });
        menu->addAction(tr("Spam filter settings\u2026"), this, &AeroMainWindow::onSettings);
        histUi.btn_options->setMenu(menu);
        histUi.btn_options->setPopupMode(QToolButton::InstantPopup);
    }

    // Feather-style Receive tab: the address list is on the LEFT, the QR code + buttons on the
    // RIGHT (this is exactly the stock ReceiveWidget.ui layout — addresses | verticalLayout_2).
    m_addressModel = new AddressModel(this);
    recvUi.addresses->setModel(m_addressModel);
    // When an address label is edited on Receive: persist it (so it survives restarts, like
    // Feather) and mirror it into the Send "From" selector.
    connect(m_addressModel, &QAbstractItemModel::dataChanged, this,
            [this](const QModelIndex &tl, const QModelIndex &br, const QList<int> &roles) {
                const bool labelTouched = tl.column() <= AddressModel::Column_Label &&
                                          br.column() >= AddressModel::Column_Label;
                const bool isEdit = roles.isEmpty() || roles.contains(Qt::EditRole);
                if (!labelTouched || !isEdit)
                    return; // ignore balance / "used" (background) updates
                if (!m_metaLoading) {
                    // Persist labels inside the encrypted wallet (not plaintext settings).
                    QJsonObject labels = m_meta.value(QStringLiteral("labels")).toObject();
                    for (int r = tl.row(); r <= br.row(); ++r) {
                        const quint32 acct = m_addressModel->accountAt(r);
                        labels[QString::number(acct)] = m_addressModel->labelAt(acct);
                    }
                    m_meta[QStringLiteral("labels")] = labels;
                    saveMetadata();
                }
                if (m_fromCombo) {
                    QSignalBlocker block(m_fromCombo);
                    for (int i = 0; i < m_fromCombo->count(); ++i)
                        m_fromCombo->setItemText(i, accountLabel(static_cast<quint32>(i)));
                }
            });
    recvUi.addresses->setSelectionBehavior(QAbstractItemView::SelectRows);
    recvUi.addresses->setSelectionMode(QAbstractItemView::SingleSelection);
    recvUi.addresses->setEditTriggers(QAbstractItemView::DoubleClicked |
                                      QAbstractItemView::SelectedClicked);
    recvUi.addresses->setRootIsDecorated(false);
    if (auto *hdr = recvUi.addresses->header()) {
        hdr->setSectionResizeMode(AddressModel::Column_Index, QHeaderView::ResizeToContents);
        hdr->setSectionResizeMode(AddressModel::Column_Address, QHeaderView::Stretch);
        hdr->setSectionResizeMode(AddressModel::Column_Label, QHeaderView::Interactive);
        hdr->setSectionResizeMode(AddressModel::Column_Balance, QHeaderView::ResizeToContents);
    }

    recvUi.qrCode->setScaledContents(false);

    // Address + per-asset balance for the currently selected row, shown under the QR (on the right).
    m_recvBalanceLabel = new QLabel(ui.tabReceive);
    m_recvBalanceLabel->setAlignment(Qt::AlignHCenter);
    m_recvBalanceLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_recvBalanceLabel->setWordWrap(true);
    m_recvBalanceLabel->setFixedWidth(240);
    recvUi.verticalLayout_2->insertWidget(1, m_recvBalanceLabel); // just below the QR

    // Combined total across all accounts (like Home), pinned at the very bottom of the Receive tab.
    m_recvTotalLabel = new QLabel(tr("Total balance: —"), ui.tabReceive);
    m_recvTotalLabel->setAlignment(Qt::AlignHCenter);
    m_recvTotalLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_recvTotalLabel->setStyleSheet(QStringLiteral("font-weight:bold; padding:4px;"));
    if (auto *tabLayout = qobject_cast<QBoxLayout *>(ui.tabReceive->layout()))
        tabLayout->addWidget(m_recvTotalLabel);
    else
        recvUi.verticalLayout_2->addWidget(m_recvTotalLabel);

    // Right-hand buttons: "Create new address" (stock) and the repurposed "Import private key".
    recvUi.btn_generateSubaddress->setText(tr("Create new address"));
    recvUi.btn_createPaymentRequest->setText(tr("Import private key"));
    connect(recvUi.btn_generateSubaddress, &QPushButton::clicked, this,
            &AeroMainWindow::onCreateAddress);
    connect(recvUi.btn_createPaymentRequest, &QPushButton::clicked, this,
            &AeroMainWindow::onImportKey);

    // Selecting an address updates the QR + its balance.
    connect(recvUi.addresses->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](const QModelIndex &current, const QModelIndex &) {
                if (current.isValid())
                    onAccountChanged(static_cast<int>(m_addressModel->accountAt(current.row())));
            });

    // Double-click an address row -> jump to Send with that account selected as "From". Double-
    // clicking the Label column still edits the label (it's the editable one).
    connect(recvUi.addresses, &QTreeView::doubleClicked, this, [this](const QModelIndex &idx) {
        if (!idx.isValid() || idx.column() == AddressModel::Column_Label)
            return;
        const quint32 acct = m_addressModel->accountAt(idx.row());
        if (m_fromCombo && static_cast<int>(acct) < m_fromCombo->count())
            m_fromCombo->setCurrentIndex(static_cast<int>(acct)); // sets From + refreshes available
        ui.tabWidget->setCurrentWidget(ui.tabSend);
    });

    // Right-click an address for copy / export private key.
    recvUi.addresses->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(recvUi.addresses, &QWidget::customContextMenuRequested, this,
            &AeroMainWindow::onAddressContextMenu);

    // Receive "..." options: toggle showing only funded addresses + rescan the seed.
    {
        m_showFundedOnly = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                               .value(QStringLiteral("receive/fundedOnly"), true).toBool();
        auto *menu = new QMenu(this);
        auto *fundedAct = menu->addAction(tr("Show only addresses with a balance"));
        fundedAct->setCheckable(true);
        fundedAct->setChecked(m_showFundedOnly);
        connect(fundedAct, &QAction::toggled, this, [this](bool on) {
            m_showFundedOnly = on;
            QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                .setValue(QStringLiteral("receive/fundedOnly"), on);
            applyFundedFilter();
            if (m_addressModel->rowCount() > 0)
                selectAddressRow(m_addressModel->accountAt(0));
        });
        connect(menu->addAction(tr("Rescan for funded addresses")), &QAction::triggered, this,
                [this]() {
                    if (!m_wallet) return;
                    setConnectionState(2, tr("Scanning for funded addresses\u2026"));
                    m_wallet->scanFunded(20);
                });
        recvUi.toolBtn_options->setMenu(menu);
        recvUi.toolBtn_options->setPopupMode(QToolButton::InstantPopup);
    }

    // Click the QR to copy the selected address; live search filters the list.
    connect(recvUi.qrCode, &ClickableLabel::clicked, this, [this]() {
        if (m_wallet)
            QApplication::clipboard()->setText(m_wallet->address(m_account));
    });
    connect(recvUi.search, &QLineEdit::textChanged, this, [this](const QString &text) {
        if (!m_wallet)
            return;
        const QString needle = text.trimmed();
        const int rows = m_addressModel->rowCount();
        for (int r = 0; r < rows; ++r) {
            const quint32 acct = m_addressModel->accountAt(r);
            const bool match = needle.isEmpty() ||
                               m_wallet->address(acct).contains(needle, Qt::CaseInsensitive) ||
                               m_addressModel->labelAt(acct).contains(needle, Qt::CaseInsensitive);
            recvUi.addresses->setRowHidden(r, QModelIndex(), !match);
        }
    });

    // "From" account selector at the top of the Send form (which account funds the send).
    m_fromCombo = new QComboBox(ui.tabSend);
    sendUi.formLayout->insertRow(0, tr("From"), m_fromCombo);

    // The stock .ui uses two dropdowns (a currency combo + an ETH/USD unit toggle). Replace them
    // with a single row of clickable asset buttons (ETH / DAI / USDC / USDT / …): pick one, then
    // just type the amount in that asset.
    sendUi.comboCurrencySelection->hide();
    // Hide Monero/OpenAlias leftovers that were never wired for Ethereum.
    sendUi.btnScan->hide();                    // QR scanner (not implemented)
    sendUi.btn_openAlias->hide();              // OpenAlias resolver (Monero)
    sendUi.check_subtractFeeFromAmount->hide();// unused
    sendUi.label_Description->hide();          // local-only description isn't stored anywhere
    sendUi.lineDescription->hide();
    // Asset selector: a single button that opens a searchable token picker (ETH + held + verified +
    // paste any contract), replacing the old fixed 4-token button row.
    m_assetButton = new QToolButton(ui.tabSend);
    m_assetButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_assetButton->setPopupMode(QToolButton::InstantPopup);
    m_assetButton->setCursor(Qt::PointingHandCursor);
    m_assetButton->setToolTip(tr("Choose the asset to send"));
    connect(m_assetButton, &QToolButton::clicked, this, &AeroMainWindow::openTokenPicker);
    int curRow = -1;
    QFormLayout::ItemRole curRole;
    sendUi.formLayout->getWidgetPosition(sendUi.label_Amount, &curRow, &curRole);
    sendUi.formLayout->insertRow(curRow >= 0 ? curRow : 2, tr("Asset"), m_assetButton);

    // Amount unit selector: lets you type the amount in the token or in USD. Only ETH/WETH have a
    // USD option; for stablecoins (already ~USD) the whole selector is hidden.
    m_amountUnit = new QComboBox(ui.tabSend);
    sendUi.horizontalLayout_2->addWidget(m_amountUnit);
    connect(m_amountUnit, &QComboBox::currentIndexChanged, this, &AeroMainWindow::onAmountConversion);

    // "Available" row (right under Amount) shows the spendable balance for the selected From
    // account + asset, and the Max button fills the amount with it.
    m_availLabel = new QLabel(tr("—"), ui.tabSend);
    int amtRow = -1;
    QFormLayout::ItemRole amtRole;
    sendUi.formLayout->getWidgetPosition(sendUi.label_Amount, &amtRow, &amtRole);
    sendUi.formLayout->insertRow(amtRow >= 0 ? amtRow + 1 : 3, tr("Available"), m_availLabel);

    // "Pay to" is a PayToEdit (QPlainTextEdit); constrain it to a single line so it reads like a
    // normal address field instead of a tall box.
    sendUi.lineAddress->setFixedHeight(sendUi.lineAddress->fontMetrics().height() + 12);
    sendUi.lineAddress->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    sendUi.lineAddress->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    sendUi.lineAddress->setLineWrapMode(QPlainTextEdit::NoWrap);
    sendUi.lineAddress->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    connect(sendUi.btnSend, &QPushButton::clicked, this, &AeroMainWindow::onSendClicked);
    connect(sendUi.btnClear, &QPushButton::clicked, this, [this]() {
        sendUi.lineAddress->clear();
        sendUi.lineAmount->clear();
    });
    connect(sendUi.lineAmount, &QLineEdit::textChanged, this, &AeroMainWindow::onAmountConversion);
    connect(m_fromCombo, &QComboBox::currentIndexChanged, this, &AeroMainWindow::updateAvailable);
    // Accept pasted EIP-681 payment URIs in Pay-to: "ethereum:0xADDR@chainId?value=<wei>" fills the
    // recipient (and, for the simple value form, the amount). Other wallets/QR codes emit these.
    connect(sendUi.lineAddress, &QPlainTextEdit::textChanged, this, [this]() {
        if (m_parsingUri) return;
        const QString raw = sendUi.lineAddress->toPlainText().trimmed();
        if (!raw.startsWith(QLatin1String("ethereum:"), Qt::CaseInsensitive))
            return;
        QString rest = raw.mid(9); // drop "ethereum:"
        if (rest.startsWith(QLatin1String("pay-"), Qt::CaseInsensitive))
            rest = rest.mid(4);
        QString query;
        const int q = rest.indexOf(QLatin1Char('?'));
        if (q >= 0) {
            query = rest.mid(q + 1);
            rest = rest.left(q);
        }
        QString addr = rest;
        const int at = addr.indexOf(QLatin1Char('@')); // strip "@chainId"
        if (at >= 0)
            addr = addr.left(at);
        QString fnPath;
        const int slash = addr.indexOf(QLatin1Char('/')); // token "/transfer" form
        if (slash >= 0) {
            fnPath = addr.mid(slash + 1);
            addr = addr.left(slash);
        }
        QString valueWei, toParam;
        for (const QString &kv : query.split(QLatin1Char('&'), Qt::SkipEmptyParts)) {
            const int eq = kv.indexOf(QLatin1Char('='));
            if (eq < 0) continue;
            const QString k = kv.left(eq);
            const QString v = QUrl::fromPercentEncoding(kv.mid(eq + 1).toUtf8());
            if (k == QLatin1String("value")) valueWei = v;
            else if (k == QLatin1String("address")) toParam = v;
        }
        m_parsingUri = true;
        if (fnPath.compare(QLatin1String("transfer"), Qt::CaseInsensitive) == 0 && !toParam.isEmpty()) {
            sendUi.lineAddress->setPlainText(toParam); // ERC20 transfer: recipient is in ?address=
        } else {
            sendUi.lineAddress->setPlainText(addr);
            bool ok = false;
            const double wei = valueWei.toDouble(&ok); // may be scientific, e.g. 2.5e18
            if (ok && wei > 0) {
                if (m_amountUnit && m_amountUnit->isVisible())
                    m_amountUnit->setCurrentIndex(0); // amount is the native coin, not USD
                sendUi.lineAmount->setText(trimZeros(QString::number(wei / 1e18, 'f', 9)));
            }
        }
        m_parsingUri = false;
    });
    // Max fills the amount field with the full available balance (in the selected asset). For the
    // native coin we must reserve the gas cost (value + gasLimit*maxFee must fit the balance), or
    // the send fails; ERC-20 sends pay gas separately, so their Max is the full token balance.
    connect(sendUi.btnMax, &QPushButton::clicked, this, [this]() {
        if (m_availAmount.isEmpty())
            return;
        if (m_amountUnit && m_amountUnit->isVisible())
            m_amountUnit->setCurrentIndex(0); // switch to the token unit, not USD
        QString amount = m_availAmount;
        if (currentTokenAddr().isEmpty()) {
            const double avail = m_availAmount.toDouble();
            const QPair<QString, QString> fee = chosenFeeWei(); // wei; empty == automatic
            double maxFeeWei = !fee.first.isEmpty() ? fee.first.toDouble()
                                                    : (m_feeBaseWei * 2.0 + m_feeTipWei);
            if (maxFeeWei <= 0.0)
                maxFeeWei = 2e9; // fees not loaded yet — assume a safe 2 gwei floor
            // 21000 (plain transfer) + the core's 25% gas-limit headroom, plus a 5% cushion so
            // rounding never pushes the send over the balance.
            const double reserveEth = 21000.0 * 1.25 * maxFeeWei / 1e18 * 1.05;
            double sendEth = avail - reserveEth;
            if (sendEth < 0.0)
                sendEth = 0.0;
            amount = trimZeros(QString::number(sendEth, 'f', 9));
        }
        sendUi.lineAmount->setText(amount);
    });

    // Fee section: priority tiers + Custom, with a live estimate (fee + ETA) below.
    sendUi.combo_feePriority->clear();
    sendUi.combo_feePriority->addItems({tr("Automatic"), tr("Fast"), tr("Normal"), tr("Slow"),
                                        tr("Custom")});
    m_feeEstimateLabel = new QLabel(tr("—"), ui.tabSend);
    int feeRow = -1;
    QFormLayout::ItemRole feeRole;
    sendUi.formLayout->getWidgetPosition(sendUi.label_feeTarget, &feeRow, &feeRole);
    sendUi.formLayout->insertRow(feeRow >= 0 ? feeRow + 1 : 6, tr("Estimated fee"), m_feeEstimateLabel);

    // Custom max-fee / priority inputs (gwei), shown only when "Custom" is selected.
    m_customFeeWidget = new QWidget(ui.tabSend);
    auto *customRow = new QHBoxLayout(m_customFeeWidget);
    customRow->setContentsMargins(0, 0, 0, 0);
    m_customMaxFee = new QLineEdit(m_customFeeWidget);
    m_customMaxFee->setPlaceholderText(tr("max fee"));
    m_customPriority = new QLineEdit(m_customFeeWidget);
    m_customPriority->setPlaceholderText(tr("priority"));
    customRow->addWidget(m_customMaxFee);
    customRow->addWidget(new QLabel(tr("gwei  ·  tip"), m_customFeeWidget));
    customRow->addWidget(m_customPriority);
    customRow->addWidget(new QLabel(tr("gwei"), m_customFeeWidget));
    sendUi.formLayout->insertRow(feeRow >= 0 ? feeRow + 2 : 7, tr("Custom fee"), m_customFeeWidget);
    sendUi.formLayout->setRowVisible(m_customFeeWidget, false);

    connect(sendUi.combo_feePriority, &QComboBox::currentIndexChanged, this,
            &AeroMainWindow::onFeeModeChanged);
    connect(m_customMaxFee, &QLineEdit::textChanged, this, &AeroMainWindow::updateFeeEstimate);
    connect(m_customPriority, &QLineEdit::textChanged, this, &AeroMainWindow::updateFeeEstimate);

    setupHomeTab();
    setupNftTab();
    setupMenu();

    // Notes tab: a per-wallet scratch pad, stored encrypted inside the wallet (loaded in
    // loadMetadata()). Persist edits into the wallet metadata.
    connect(ui.notes, &QPlainTextEdit::textChanged, this, [this]() {
        if (m_metaLoading) return;
        m_meta[QStringLiteral("notes")] = ui.notes->toPlainText();
        saveMetadata();
    });

    setupContactsTab();
}

void AeroMainWindow::onFeeModeChanged() {
    const bool custom = sendUi.combo_feePriority->currentText().compare(tr("Custom"),
                                                                        Qt::CaseInsensitive) == 0;
    if (m_customFeeWidget)
        sendUi.formLayout->setRowVisible(m_customFeeWidget, custom);
    // Prefill the custom inputs with the current suggested gwei so the user sees what to adjust.
    if (custom && m_feeBaseWei > 0) {
        if (m_customMaxFee && m_customMaxFee->text().trimmed().isEmpty())
            m_customMaxFee->setText(trimZeros(QString::number((m_feeBaseWei * 2 + m_feeTipWei) / 1e9, 'f', 3)));
        if (m_customPriority && m_customPriority->text().trimmed().isEmpty())
            m_customPriority->setText(trimZeros(QString::number(m_feeTipWei / 1e9, 'f', 3)));
    }
    updateFeeEstimate();
}

void AeroMainWindow::onFeesUpdated(const QString &baseFeeWei, const QString &tipWei) {
    m_feeBaseWei = baseFeeWei.toDouble();
    m_feeTipWei = tipWei.toDouble();
    // Hint the custom fields with the current suggested gwei ("what to customize it as").
    if (m_customMaxFee && m_feeBaseWei > 0)
        m_customMaxFee->setPlaceholderText(
            tr("e.g. %1").arg(trimZeros(QString::number((m_feeBaseWei * 2 + m_feeTipWei) / 1e9, 'f', 3))));
    if (m_customPriority && m_feeTipWei > 0)
        m_customPriority->setPlaceholderText(
            tr("e.g. %1").arg(trimZeros(QString::number(m_feeTipWei / 1e9, 'f', 3))));
    updateFeeEstimate();
}

// Chosen (maxFee, priority) per gas in wei for the selected fee mode. Empty pair => automatic.
QPair<QString, QString> AeroMainWindow::chosenFeeWei() const {
    const QString mode = sendUi.combo_feePriority->currentText();
    const double gwei = 1e9;
    if (mode.compare(tr("Custom"), Qt::CaseInsensitive) == 0) {
        const double mf = m_customMaxFee->text().trimmed().toDouble() * gwei;
        const double mp = m_customPriority->text().trimmed().toDouble() * gwei;
        if (mf <= 0)
            return {};
        return {QString::number(mf, 'f', 0), QString::number(mp, 'f', 0)};
    }
    if (mode.compare(tr("Automatic"), Qt::CaseInsensitive) == 0 || m_feeBaseWei <= 0)
        return {}; // let the core use its node suggestion

    double tipMul = 1.0, baseMul = 2.0;
    if (mode.compare(tr("Fast"), Qt::CaseInsensitive) == 0) tipMul = 2.0;
    else if (mode.compare(tr("Slow"), Qt::CaseInsensitive) == 0) { tipMul = 0.5; baseMul = 1.5; }
    double tip = qMax(m_feeTipWei * tipMul, 1e9); // floor at 1 gwei
    double maxFee = m_feeBaseWei * baseMul + tip;
    return {QString::number(maxFee, 'f', 0), QString::number(tip, 'f', 0)};
}

void AeroMainWindow::updateFeeEstimate() {
    if (!m_feeEstimateLabel) return;
    // Effective max fee per gas for the selected mode (fall back to the node suggestion for Auto).
    const QPair<QString, QString> chosen = chosenFeeWei();
    double maxFeeWei = chosen.first.toDouble();
    if (maxFeeWei <= 0)
        maxFeeWei = m_feeBaseWei > 0 ? m_feeBaseWei * 2.0 + m_feeTipWei : 0.0;
    if (maxFeeWei <= 0) {
        m_feeEstimateLabel->setText(tr("—"));
        return;
    }
    // Gas price (gwei) is a market rate — the same for any tx — but an ERC20 transfer needs far
    // more gas units than a 21k native ETH send, so its total fee is proportionally higher.
    const double gasLimit = currentTokenAddr().isEmpty() ? 21000.0 : 65000.0;
    const double feeEth = maxFeeWei * gasLimit / 1e18;
    QString text = tr("Gas: %1 Gwei \u00d7 %2 units")
                       .arg(trimZeros(QString::number(maxFeeWei / 1e9, 'f', 2)),
                            grouped(QString::number(gasLimit, 'f', 0)));
    text += tr("  ·  \u2248 %1 ETH").arg(grouped(trimZeros(QString::number(feeEth, 'f', 8))));
    if (m_nativeUsd > 0)
        text += tr(" (%1)").arg(fiatStr(feeEth * m_nativeUsd));

    const QString mode = sendUi.combo_feePriority->currentText();
    QString eta = tr("~30 sec");
    if (mode.compare(tr("Fast"), Qt::CaseInsensitive) == 0) eta = tr("~15 sec");
    else if (mode.compare(tr("Normal"), Qt::CaseInsensitive) == 0) eta = tr("~45 sec");
    else if (mode.compare(tr("Slow"), Qt::CaseInsensitive) == 0) eta = tr("~3 min");
    else if (mode.compare(tr("Custom"), Qt::CaseInsensitive) == 0) eta = tr("varies");
    text += tr("  ·  ETA %1").arg(eta);
    m_feeEstimateLabel->setText(text);
}

void AeroMainWindow::setupHomeTab() {
    // Feather's Home: a row of ticker boxes (Total balance + price tickers) above a divider.
    m_homeTab = new QWidget();
    auto *outer = new QVBoxLayout(m_homeTab);
    outer->setContentsMargins(10, 10, 10, 10);

    // Match Feather's TickerWidget fonts exactly: the value uses the base application font
    // (relativeFont(0)) and the percentage uses base-1pt (relativeFont(-1)) — no bold/enlarging.
    auto relativeFont = [](int delta) {
        QFont f = QApplication::font();
        f.setPointSize(f.pointSize() + delta);
        return f;
    };
    auto makeTicker = [this, &relativeFont](const QString &title, QLabel *&valueOut, QLabel *&pctOut,
                                            bool withPct) {
        auto *box = new QGroupBox(title, m_homeTab);
        auto *v = new QVBoxLayout(box);
        v->setContentsMargins(6, 6, 6, 4);
        v->setSpacing(2);
        auto *value = new QLabel(QStringLiteral("…"), box);
        value->setFont(relativeFont(0));
        value->setTextInteractionFlags(Qt::LinksAccessibleByMouse | Qt::TextSelectableByMouse);
        v->addWidget(value);
        valueOut = value;
        if (withPct) {
            auto *pct = new QLabel(box);
            pct->setFont(relativeFont(-1));
            v->addWidget(pct);
            pctOut = pct;
        }
        return box;
    };

    auto *row = new QHBoxLayout();
    QLabel *unused = nullptr;
    // Feather-style: price tickers on the left, total balance pinned to the right.
    row->addWidget(makeTicker(QStringLiteral("XMR"), m_homeXmrValue, m_homeXmrPct, true));
    m_homeNativeBox = makeTicker(m_nativeSymbol, m_homeEthValue, m_homeEthPct, true);
    row->addWidget(m_homeNativeBox);
    row->addStretch();
    row->addWidget(makeTicker(tr("Total balance"), m_homeTotalValue, unused, false));
    outer->addLayout(row);

    auto *line = new QFrame(m_homeTab);
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    outer->addWidget(line);
    outer->addStretch();

    // Home is the first tab and the default landing page (like Feather).
    ui.tabWidget->insertTab(0, m_homeTab, QIcon(QStringLiteral(":/assets/images/tab_home.png")),
                            tr("Home"));
    ui.tabWidget->setCurrentIndex(0);
}

void AeroMainWindow::setupNftTab() {
    m_nftShowSpam = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                        .value(QStringLiteral("nft/showSpam"), false).toBool();
    m_nftTab = new QWidget();
    auto *outer = new QVBoxLayout(m_nftTab);

    auto *topRow = new QHBoxLayout();
    m_nftStatus = new QLabel(tr("No wallet open."), m_nftTab);
    m_nftStatus->setStyleSheet(QStringLiteral("color:#8a8a8a;"));
    topRow->addWidget(m_nftStatus, 1);
    auto *showSpam = new QCheckBox(tr("Show unverified / spam collections"), m_nftTab);
    showSpam->setChecked(m_nftShowSpam);
    connect(showSpam, &QCheckBox::toggled, this, [this](bool on) {
        m_nftShowSpam = on;
        QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
            .setValue(QStringLiteral("nft/showSpam"), on);
        displayNfts();
    });
    topRow->addWidget(showSpam);
    outer->addLayout(topRow);

    m_nftList = new QListWidget(m_nftTab);
    m_nftList->setViewMode(QListView::IconMode);
    m_nftList->setIconSize(QSize(112, 112));
    m_nftList->setGridSize(QSize(150, 168));
    m_nftList->setResizeMode(QListView::Adjust);
    m_nftList->setMovement(QListView::Static);
    m_nftList->setWordWrap(true);
    m_nftList->setSpacing(8);
    m_nftList->setUniformItemSizes(true);
    m_nftList->setSelectionMode(QAbstractItemView::NoSelection);
    outer->addWidget(m_nftList, 1);

    // The NFTs tab is opt-in (off by default) — enable it in Settings -> Appearance.
    m_nftEnabled = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                       .value(QStringLiteral("nft/enabled"), false).toBool();
    if (m_nftEnabled) {
        const int idx = qMin(4, ui.tabWidget->count());
        ui.tabWidget->insertTab(idx, m_nftTab, tr("NFTs"));
    }
}

void AeroMainWindow::setNftTabEnabled(bool on) {
    m_nftEnabled = on;
    QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
        .setValue(QStringLiteral("nft/enabled"), on);
    const int cur = ui.tabWidget->indexOf(m_nftTab);
    if (on && cur < 0) {
        ui.tabWidget->insertTab(qMin(4, ui.tabWidget->count()), m_nftTab, tr("NFTs"));
        refreshNfts();
    } else if (!on && cur >= 0) {
        ui.tabWidget->removeTab(cur); // widget is retained (owned via m_nftTab)
    }
}

// Load a QPixmap from raw image bytes; returns a null pixmap if the format isn't supported.
static QPixmap pixmapFromBytes(const QByteArray &data) {
    QPixmap pm;
    pm.loadFromData(data);
    return pm;
}

void AeroMainWindow::refreshNfts() {
    if (m_wallet && m_nftEnabled) // skip the Blockscout call entirely when the tab is off
        m_wallet->refreshNfts(m_account);
}

void AeroMainWindow::onNftsRefreshed(const QVector<NftCollection> &items) {
    m_nftCache = items;
    displayNfts();
}

void AeroMainWindow::displayNfts() {
    if (!m_nftList) return;
    m_nftList->clear();

    // Fallback icon for collections whose image is missing/unsupported.
    QPixmap placeholder(112, 112);
    placeholder.fill(QColor(0x2a, 0x2e, 0x33));

    int shown = 0, hidden = 0;
    for (const NftCollection &c : m_nftCache) {
        const bool verified = c.reputation.compare(QLatin1String("ok"), Qt::CaseInsensitive) == 0 ||
                              c.reputation.isEmpty();
        if (!verified && !m_nftShowSpam) {
            ++hidden;
            continue;
        }
        ++shown;
        const QString title = c.name.isEmpty() ? c.symbol : c.name;
        auto *item = new QListWidgetItem(
            QStringLiteral("%1\n\u00d7%2").arg(title).arg(c.count), m_nftList);
        item->setToolTip(tr("%1 (%2)\n%3\nItems: %4")
                             .arg(title, c.type, c.address, QString::number(c.count)));
        item->setTextAlignment(Qt::AlignHCenter | Qt::AlignTop);
        item->setData(Qt::UserRole, c.imageUrl); // matched when the async image arrives
        item->setIcon(QIcon(placeholder));
        if (!verified)
            item->setForeground(QBrush(QColor(0x80, 0x80, 0x80)));

        // Resolve the thumbnail: decode data: URIs locally; fetch http/ipfs over Tor.
        const QString url = c.imageUrl;
        if (url.startsWith(QStringLiteral("data:"), Qt::CaseInsensitive)) {
            const int comma = url.indexOf(QLatin1Char(','));
            if (comma > 0 && url.left(comma).contains(QStringLiteral("base64"))) {
                const QPixmap pm = pixmapFromBytes(
                    QByteArray::fromBase64(url.mid(comma + 1).toLatin1()));
                if (!pm.isNull())
                    item->setIcon(QIcon(pm));
            }
        } else if (url.startsWith(QStringLiteral("http"), Qt::CaseInsensitive) ||
                   url.startsWith(QStringLiteral("ipfs://"), Qt::CaseInsensitive)) {
            QString fetch = url;
            if (fetch.startsWith(QStringLiteral("ipfs://"), Qt::CaseInsensitive))
                fetch = QStringLiteral("https://ipfs.io/ipfs/") + fetch.mid(7);
            item->setData(Qt::UserRole, fetch); // key we match in onImageReady
            m_wallet->fetchImage(fetch);        // over Tor
        }
    }

    if (!m_wallet)
        m_nftStatus->setText(tr("No wallet open."));
    else if (shown == 0)
        m_nftStatus->setText(hidden > 0
                                 ? tr("No verified collections (%1 hidden as spam).").arg(hidden)
                                 : tr("No NFTs found for this account."));
    else
        m_nftStatus->setText(tr("%1 collection(s)%2").arg(shown).arg(
            hidden > 0 ? tr("  \u00b7  %1 spam hidden").arg(hidden) : QString()));
}

void AeroMainWindow::onImageReady(const QString &url, const QByteArray &data) {
    if (!m_nftList || data.isEmpty()) return;
    const QPixmap pm = pixmapFromBytes(data);
    if (pm.isNull()) return;
    const QIcon icon(pm);
    for (int i = 0; i < m_nftList->count(); ++i) {
        QListWidgetItem *it = m_nftList->item(i);
        if (it->data(Qt::UserRole).toString() == url)
            it->setIcon(icon);
    }
}

void AeroMainWindow::setupContactsTab() {
    m_contactsTable = new QTableWidget(0, 2, ui.tabContacts);
    m_contactsTable->setHorizontalHeaderLabels({tr("Name"), tr("Address")});
    m_contactsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_contactsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_contactsTable->verticalHeader()->hide();
    m_contactsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_contactsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui.contactsWidgetLayout->addWidget(m_contactsTable, 1);

    auto *row = new QHBoxLayout();
    auto *addBtn = new QPushButton(tr("Add"), ui.tabContacts);
    auto *removeBtn = new QPushButton(tr("Remove"), ui.tabContacts);
    auto *copyBtn = new QPushButton(tr("Copy address"), ui.tabContacts);
    auto *sendBtn = new QPushButton(tr("Send to"), ui.tabContacts);
    row->addWidget(addBtn);
    row->addWidget(removeBtn);
    row->addWidget(copyBtn);
    row->addWidget(sendBtn);
    row->addStretch();
    ui.contactsWidgetLayout->addLayout(row);

    // Persist contacts inside the encrypted wallet (per-wallet, like Feather) rather than in
    // plaintext settings. Contents are (re)loaded per wallet in loadMetadata().
    auto persist = [this]() {
        if (m_metaLoading) return;
        QJsonArray arr;
        for (int r = 0; r < m_contactsTable->rowCount(); ++r) {
            const QString name = m_contactsTable->item(r, 0) ? m_contactsTable->item(r, 0)->text() : QString();
            const QString addr = m_contactsTable->item(r, 1) ? m_contactsTable->item(r, 1)->text() : QString();
            if (!addr.isEmpty()) {
                QJsonObject c;
                c[QStringLiteral("name")] = name;
                c[QStringLiteral("address")] = addr;
                arr.append(c);
            }
        }
        m_meta[QStringLiteral("contacts")] = arr;
        saveMetadata();
    };

    connect(addBtn, &QPushButton::clicked, this, [this, persist]() {
        QDialog dlg(this);
        dlg.setWindowTitle(tr("Add contact"));
        auto *f = new QFormLayout(&dlg);
        auto *nameE = new QLineEdit(&dlg);
        auto *addrE = new QLineEdit(&dlg);
        addrE->setPlaceholderText(tr("0x address"));
        f->addRow(tr("Name"), nameE);
        f->addRow(tr("Address"), addrE);
        auto *bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
        connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
        connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
        f->addRow(bb);
        if (dlg.exec() != QDialog::Accepted) return;
        const QString addr = addrE->text().trimmed();
        if (!addr.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) || addr.size() != 42) {
            QMessageBox::warning(this, tr("Add contact"), tr("Enter a valid 0x address."));
            return;
        }
        const int r = m_contactsTable->rowCount();
        m_contactsTable->insertRow(r);
        m_contactsTable->setItem(r, 0, new QTableWidgetItem(nameE->text().trimmed()));
        m_contactsTable->setItem(r, 1, new QTableWidgetItem(addr));
        persist();
    });
    connect(removeBtn, &QPushButton::clicked, this, [this, persist]() {
        const int r = m_contactsTable->currentRow();
        if (r >= 0) {
            m_contactsTable->removeRow(r);
            persist();
        }
    });
    connect(copyBtn, &QPushButton::clicked, this, [this]() {
        const int r = m_contactsTable->currentRow();
        if (r >= 0 && m_contactsTable->item(r, 1))
            QApplication::clipboard()->setText(m_contactsTable->item(r, 1)->text());
    });
    connect(sendBtn, &QPushButton::clicked, this, [this]() {
        const int r = m_contactsTable->currentRow();
        if (r < 0 || !m_contactsTable->item(r, 1)) return;
        sendUi.lineAddress->setPlainText(m_contactsTable->item(r, 1)->text());
        ui.tabWidget->setCurrentWidget(ui.tabSend);
    });
}

void AeroMainWindow::exportHistoryCsv() {
    if (!m_historyModel || m_historyModel->rowCount() == 0) {
        QMessageBox::information(this, tr("Export CSV"), tr("No transactions to export."));
        return;
    }
    const QString path = QFileDialog::getSaveFileName(this, tr("Export history"),
                                                      QStringLiteral("aero-history.csv"),
                                                      tr("CSV (*.csv)"));
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Export CSV"), tr("Could not write the file."));
        return;
    }
    QTextStream out(&f);
    out << "date,direction,amount,symbol,counterparty,txhash\n";
    for (int r = 0; r < m_historyModel->rowCount(); ++r) {
        const HistoryItem h = m_historyModel->itemAt(r);
        const QString date = h.timestamp
                                 ? QDateTime::fromSecsSinceEpoch(static_cast<qint64>(h.timestamp))
                                       .toString(Qt::ISODate)
                                 : QString::number(h.block);
        out << date << ',' << (h.failed ? "failed" : h.direction) << ',' << h.formatted << ','
            << h.symbol << ',' << h.counterparty << ',' << h.txHash << '\n';
    }
    f.close();
    QMessageBox::information(this, tr("Export CSV"), tr("History exported to:\n%1").arg(path));
}

void AeroMainWindow::setupMenu() {
    auto hide = [](QAction *a) { if (a) a->setVisible(false); };

    // --- File: keep Quit + Settings; wallet-lifecycle items aren't wired mid-session yet. ---
    connect(ui.actionQuit, &QAction::triggered, this, &QWidget::close);
    ui.menuRecently_open->menuAction()->setVisible(false);
    hide(ui.actionOpen);
    hide(ui.actionNew_Restore);
    hide(ui.actionLock);
    hide(ui.actionClose);

    // --- Wallet ---
    connect(ui.actionInformation, &QAction::triggered, this, [this]() {
        if (!m_wallet) return;
        QMessageBox::information(
            this, tr("Wallet information"),
            tr("File: %1\nAddresses: %2\nActive account: #%3\n%4\nNetwork: %5 (chain %6)")
                .arg(m_wallet->walletPath().isEmpty() ? tr("(unsaved)") : m_wallet->walletPath())
                .arg(m_wallet->numAccounts())
                .arg(m_account)
                .arg(m_wallet->address(m_account))
                .arg(chainDefFor(m_chainId).name)
                .arg(m_chainId));
    });
    connect(ui.actionStore_wallet, &QAction::triggered, this, [this]() {
        if (m_wallet) m_wallet->save();
    });
    connect(ui.actionUpdate_balance, &QAction::triggered, this, &AeroMainWindow::onRefresh);
    connect(ui.actionRefresh_tabs, &QAction::triggered, this, &AeroMainWindow::onRefresh);
    connect(ui.actionPassword, &QAction::triggered, this, &AeroMainWindow::onChangePassword);
    connect(ui.actionSeed, &QAction::triggered, this, &AeroMainWindow::onShowSeed);
    connect(ui.actionExport_CSV, &QAction::triggered, this, &AeroMainWindow::exportHistoryCsv);
    hide(ui.actionRescan_spent);
    hide(ui.actionWallet_cache_debug);
    hide(ui.actionAccount);
    hide(ui.actionKeys);
    hide(ui.actionViewOnly);
    hide(ui.actionImportHistoryCSV);

    // --- View: Contacts / Notes visibility toggles; drop Monero-only entries. ---
    ui.actionShow_Contacts->setCheckable(true);
    ui.actionShow_Contacts->setChecked(true);
    connect(ui.actionShow_Contacts, &QAction::toggled, this, [this](bool on) {
        const int idx = ui.tabWidget->indexOf(ui.tabContacts);
        if (on && idx < 0)
            ui.tabWidget->addTab(ui.tabContacts, QIcon(QStringLiteral(":/assets/images/tab_contacts.png")), tr("Contacts"));
        else if (!on && idx >= 0)
            ui.tabWidget->removeTab(idx);
    });
    ui.actionShow_Notes->setCheckable(true);
    ui.actionShow_Notes->setChecked(true);
    connect(ui.actionShow_Notes, &QAction::toggled, this, [this](bool on) {
        const int idx = ui.tabWidget->indexOf(ui.tabNotes);
        if (on && idx < 0)
            ui.tabWidget->addTab(ui.tabNotes, QIcon(QStringLiteral(":/assets/images/tab_notes.png")), tr("Notes"));
        else if (!on && idx >= 0)
            ui.tabWidget->removeTab(idx);
    });
    hide(ui.actionPlaceholderBegin);
    hide(ui.actionShow_Coins);
    hide(ui.actionPlaceholderEnd);
    hide(ui.actionShow_Searchbar);

    // --- Tools: drop the Monero-specific actions and expose Aero tools. ---
    ui.menuTools->clear();
    connect(ui.menuTools->addAction(tr("Sign / Verify Message…")), &QAction::triggered, this,
            &AeroMainWindow::onSignVerifyMessage);
    connect(ui.menuTools->addAction(tr("Broadcast Raw Transaction…")), &QAction::triggered, this,
            &AeroMainWindow::onBroadcastRaw);
    connect(ui.menuTools->addAction(tr("Sign Unsigned Transaction…")), &QAction::triggered, this,
            &AeroMainWindow::onSignUnsigned);
    ui.menuTools->addSeparator();
    m_speedUpAction = ui.menuTools->addAction(tr("Speed Up Last Transaction"));
    m_cancelTxAction = ui.menuTools->addAction(tr("Cancel Last Transaction"));
    m_speedUpAction->setEnabled(false); // enabled once a tx is sent this session
    m_cancelTxAction->setEnabled(false);
    connect(m_speedUpAction, &QAction::triggered, this, &AeroMainWindow::onSpeedUpLast);
    connect(m_cancelTxAction, &QAction::triggered, this, &AeroMainWindow::onCancelLast);

    // --- Help: keep About; the rest have no Aero targets. ---
    connect(ui.actionAbout, &QAction::triggered, this, [this]() {
        QMessageBox::about(this, tr("About Aero"),
                           tr("<b>Aero</b> — a lightweight, Tor-routed Ethereum wallet.<br><br>"
                              "Local key custody, trustless RPC over Tor, no telemetry."));
    });
    hide(ui.actionCheckForUpdates);
    hide(ui.actionOfficialWebsite);
    hide(ui.actionDocumentation);
    hide(ui.actionReport_bug);
    hide(ui.actionShow_debug_info);
}

void AeroMainWindow::setupStatusBar() {
    {
        QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
        m_hideBalances = s.value(QStringLiteral("appearance/hideBalances"), false).toBool();
        m_fiatCurrency = s.value(QStringLiteral("appearance/fiat"), QStringLiteral("USD")).toString().toUpper();
        m_fiatSymbol = fiatSymbolFor(m_fiatCurrency);
        m_notifications = s.value(QStringLiteral("notifications/enabled"), true).toBool();
        m_confirmSend = s.value(QStringLiteral("security/confirmSend"), false).toBool();
        m_autoLockMinutes = s.value(QStringLiteral("security/autoLockMinutes"), 0).toInt();
        m_lockOnMinimize = s.value(QStringLiteral("security/lockOnMinimize"), false).toBool();
    }
    // Inactivity auto-lock: watch app-wide input to reset the timer; fire -> lockWallet().
    m_idleTimer = new QTimer(this);
    m_idleTimer->setSingleShot(true);
    connect(m_idleTimer, &QTimer::timeout, this, &AeroMainWindow::lockWallet);
    qApp->installEventFilter(this);
    if (m_autoLockMinutes > 0)
        m_idleTimer->start(m_autoLockMinutes * 60000);

    m_balanceLabel = new QLabel(tr("Balance: —"), this);
    m_balanceLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_connLabel = new QLabel(tr("Offline"), this);
    m_connIcon = new QLabel(this);
    m_connIcon->setFixedSize(18, 18);
    m_connIcon->setScaledContents(true);

    statusBar()->setStyleSheet(QStringLiteral("QStatusBar::item { border: none; }"));

    // Feather layout: connection status on the LEFT; balance + status icons on the RIGHT.
    statusBar()->addWidget(m_connIcon);
    statusBar()->addWidget(m_connLabel, 1);

    // Network selector: pick the active EVM chain. Same keys on every chain; switching reconnects.
    m_networkButton = new QToolButton(this);
    m_networkButton->setAutoRaise(true);
    m_networkButton->setCursor(Qt::PointingHandCursor);
    m_networkButton->setIconSize(QSize(18, 18));
    m_networkButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_networkButton->setPopupMode(QToolButton::InstantPopup);
    {
        auto *menu = new QMenu(m_networkButton);
        for (const ChainDef &c : chainDefs()) {
            QAction *a = menu->addAction(QIcon(c.icon), c.name);
            const quint64 id = c.id;
            connect(a, &QAction::triggered, this, [this, id]() {
                if (id != m_chainId) switchChain(id);
            });
        }
        m_networkButton->setMenu(menu);
    }
    {
        const ChainDef &c = chainDefFor(m_chainId);
        m_networkButton->setIcon(QIcon(c.icon));
        m_networkButton->setText(c.name);
        m_networkButton->setToolTip(tr("Network: %1").arg(c.name));
    }
    statusBar()->addPermanentWidget(m_networkButton);

    statusBar()->addPermanentWidget(m_balanceLabel);

    auto statusButton = [this](const QString &icon, const QString &tip) {
        auto *b = new QToolButton(this);
        b->setAutoRaise(true);
        b->setCursor(Qt::PointingHandCursor);
        b->setIcon(QIcon(icon));
        b->setIconSize(QSize(18, 18));
        b->setToolTip(tip);
        statusBar()->addPermanentWidget(b);
        return b;
    };
    connect(statusButton(QStringLiteral(":/assets/images/seed.png"), tr("Show seed")),
            &QToolButton::clicked, this, &AeroMainWindow::onShowSeed);
    connect(statusButton(QStringLiteral(":/assets/images/lock.svg"), tr("Change password")),
            &QToolButton::clicked, this, &AeroMainWindow::onChangePassword);
    connect(statusButton(QStringLiteral(":/assets/images/preferences.svg"), tr("Settings")),
            &QToolButton::clicked, this, &AeroMainWindow::onSettings);

    setConnectionState(0, tr("Disconnected"));

    // System-tray icon for received/sent transaction notifications.
    QIcon trayIcon = windowIcon();
    if (trayIcon.isNull())
        trayIcon = QIcon(QStringLiteral(":/assets/images/tokens/ETH.png"));
    m_tray = new QSystemTrayIcon(trayIcon, this);
    m_tray->setToolTip(QStringLiteral("Aero"));
    m_tray->show();
}

void AeroMainWindow::notify(const QString &title, const QString &body) {
    if (m_notifications && m_tray && QSystemTrayIcon::supportsMessages())
        m_tray->showMessage(title, body, QSystemTrayIcon::Information, 6000);
}

QString AeroMainWindow::explorerTxUrl(const QString &hash) const {
    // Default to the active chain's explorer. A user-set explorer override applies only on
    // Ethereum mainnet (chain 1); other chains always use their registry explorer so links resolve.
    QString base = chainDefFor(m_chainId).explorer;
    if (m_chainId == 1) {
        base = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                   .value(QStringLiteral("explorer/base"), base).toString();
    }
    return QStringLiteral("%1/tx/%2").arg(base, hash);
}

void AeroMainWindow::lockWallet() {
    if (m_locked || !m_wallet || !m_wallet->hasPassword())
        return; // nothing to lock behind if the wallet has no password
    m_locked = true;
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Wallet locked"));
    dlg.setModal(true);
    dlg.setWindowFlag(Qt::WindowCloseButtonHint, false);
    auto *v = new QVBoxLayout(&dlg);
    v->addWidget(new QLabel(tr("Enter your password to unlock."), &dlg));
    auto *pw = new QLineEdit(&dlg);
    pw->setEchoMode(QLineEdit::Password);
    v->addWidget(pw);
    auto *err = new QLabel(&dlg);
    err->setStyleSheet(QStringLiteral("color:#e06c75;"));
    v->addWidget(err);
    auto *unlock = new QPushButton(tr("Unlock"), &dlg);
    v->addWidget(unlock);
    connect(unlock, &QPushButton::clicked, &dlg, [&]() {
        if (m_wallet->passwordMatches(pw->text()))
            dlg.accept();
        else {
            err->setText(tr("Incorrect password."));
            pw->clear();
        }
    });
    connect(pw, &QLineEdit::returnPressed, unlock, &QPushButton::click);
    dlg.exec();
    m_locked = false;
    if (m_autoLockMinutes > 0)
        m_idleTimer->start(m_autoLockMinutes * 60000); // restart the countdown
}

bool AeroMainWindow::eventFilter(QObject *obj, QEvent *event) {
    switch (event->type()) {
    case QEvent::MouseMove:
    case QEvent::MouseButtonPress:
    case QEvent::KeyPress:
    case QEvent::Wheel:
        if (m_autoLockMinutes > 0 && m_idleTimer && !m_locked)
            m_idleTimer->start(m_autoLockMinutes * 60000);
        break;
    default:
        break;
    }
    return QMainWindow::eventFilter(obj, event);
}

void AeroMainWindow::changeEvent(QEvent *event) {
    if (event->type() == QEvent::WindowStateChange && m_lockOnMinimize && isMinimized())
        QTimer::singleShot(0, this, &AeroMainWindow::lockWallet);
    QMainWindow::changeEvent(event);
}

void AeroMainWindow::setConnectionState(int mode, const QString &tip) {
    QString icon;
    switch (mode) {
    case 2:  icon = QStringLiteral(":/assets/images/status_connected_proxy.svg"); break; // Tor
    case 1:  icon = QStringLiteral(":/assets/images/status_connected.svg"); break;       // Direct
    default: icon = QStringLiteral(":/assets/images/status_disconnected.svg"); break;    // Offline
    }
    if (m_connIcon) {
        m_connIcon->setPixmap(QIcon(icon).pixmap(18, 18));
        m_connIcon->setToolTip(tip);
    }
    if (m_connLabel)
        m_connLabel->setText(tip);
}

void AeroMainWindow::setWallet(Wallet *wallet) {
    m_wallet = wallet;
    connect(m_wallet, &Wallet::balanceUpdated, this, &AeroMainWindow::onBalanceUpdated);
    connect(m_wallet, &Wallet::historyRefreshed, this, [this](const QVector<HistoryItem> &items) {
        // Keep the allow-list current (curated top tokens + tracked tokens) so legit transfers are
        // shown while unsolicited/fake ERC-20s stay hidden.
        m_historyModel->setKnownTokens(verifiedTokenAddresses());
        m_historyModel->onHistoryRefreshed(items);
        checkUntrackedTokenLiquidity(); // auto-trust unknown-but-liquid tokens (DexScreener/Tor)
    });
    connect(m_wallet, &Wallet::accountBalanceUpdated, this, &AeroMainWindow::onAccountBalance);
    connect(m_wallet, &Wallet::ethUsdPriceUpdated, this, &AeroMainWindow::onEthUsdPrice);
    connect(m_wallet, &Wallet::marketPricesUpdated, this, &AeroMainWindow::onMarketPrices);
    connect(m_wallet, &Wallet::providerConnected, this, &AeroMainWindow::onProviderConnected);
    connect(m_wallet, &Wallet::availableBalance, this, &AeroMainWindow::onAvailableBalance);
    connect(m_wallet, &Wallet::blockNumberUpdated, this, &AeroMainWindow::onBlockNumber);
    connect(m_wallet, &Wallet::feesUpdated, this, &AeroMainWindow::onFeesUpdated);
    connect(m_wallet, &Wallet::transactionCreated, this, &AeroMainWindow::onTransactionCreated);
    connect(m_wallet, &Wallet::transactionCommitted, this, &AeroMainWindow::onTransactionCommitted);
    connect(m_wallet, &Wallet::transactionSent, this, &AeroMainWindow::onTransactionSent);
    connect(m_wallet, &Wallet::fundedScanned, this, &AeroMainWindow::onFundedScanned);
    connect(m_wallet, &Wallet::tokenLiquidity, this, &AeroMainWindow::onTokenLiquidity);
    connect(m_wallet, &Wallet::nftsRefreshed, this, &AeroMainWindow::onNftsRefreshed);
    connect(m_wallet, &Wallet::imageReady, this, &AeroMainWindow::onImageReady);
    connect(m_wallet, &Wallet::fiatRate, this, &AeroMainWindow::onFiatRate);
    connect(m_wallet, &Wallet::tokenMetaResolved, this, &AeroMainWindow::onTokenMetaResolved);

    // Hardware wallets: reflect the device in the title, and prompt "confirm on device" while it
    // signs (cleared when the broadcast result arrives).
    if (m_wallet->isHardware()) {
        const QString dev = m_wallet->hwKind() == QLatin1String("ledger") ? tr("Ledger") : tr("Trezor");
        setWindowTitle(tr("Aero — %1 hardware wallet").arg(dev));
        connect(m_wallet, &Wallet::signingOnDevice, this, [this, dev]() {
            if (!m_deviceDialog) {
                m_deviceDialog = new QMessageBox(QMessageBox::Information, tr("Confirm on device"),
                                                 tr("Review and approve the transaction on your %1.").arg(dev),
                                                 QMessageBox::NoButton, this);
                m_deviceDialog->setStandardButtons(QMessageBox::NoButton);
            }
            m_deviceDialog->show();
            m_deviceDialog->raise();
        });
    }

    // Watch-only wallets hold no keys: they can't sign, but they CAN build an unsigned transaction
    // for air-gapped signing, so the Send button becomes "Export Unsigned Tx".
    if (m_wallet->isWatchOnly()) {
        setWindowTitle(tr("Aero — watch-only wallet"));
        if (sendUi.btnSend) {
            sendUi.btnSend->setText(tr("Export Unsigned Tx"));
            sendUi.btnSend->setToolTip(
                tr("Watch-only: builds an unsigned transaction to sign on an offline wallet"));
        }
    }
    connect(m_wallet, &Wallet::unsignedTxReady, this, &AeroMainWindow::onUnsignedTxReady);

    // Track the common mainnet tokens by default so their balances and logos show up.
    if (m_wallet->tokens().isEmpty()) {
        m_wallet->addToken({QStringLiteral("0xdAC17F958D2ee523a2206206994597C13D831ec7"), QStringLiteral("USDT"), 6});
        m_wallet->addToken({QStringLiteral("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), QStringLiteral("USDC"), 6});
        m_wallet->addToken({QStringLiteral("0x6B175474E89094C44Da98b954EedeAC495271d0F"), QStringLiteral("DAI"), 18});
        m_wallet->addToken({QStringLiteral("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"), QStringLiteral("WETH"), 18});
    }

    // Show 5 receive addresses by default; "Create new address" derives more on demand.
    ensureMinAddresses(5);
    m_addressModel->setWallet(m_wallet);
    // Load per-wallet metadata (labels/funded/contacts/notes) from the encrypted wallet file
    // (migrating any legacy plaintext settings on first open). Applies labels + funded set too.
    loadMetadata();

    // Restore the "show funded only" preference; the funded set itself came from loadMetadata().
    m_showFundedOnly = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                           .value(QStringLiteral("receive/fundedOnly"), true).toBool();
    applyFundedFilter();
    updateHistoryPricing(); // seed the History dust filter with the tracked-token symbols
    loadLiquidityCache();   // restore auto-trust (DEX liquidity) decisions
    applyVerifiedTokens();  // seed the History spam allow-list (curated top tokens + tracked)

    // Dev hook: mark rows used (red) for screenshots, e.g. AERO_USED=0,2
    if (!qEnvironmentVariableIsEmpty("AERO_USED"))
        for (const QString &s : qEnvironmentVariable("AERO_USED").split(QLatin1Char(',')))
            m_addressModel->setUsed(s.toUInt(), true);

    rebuildAccountCombos();
    populateSendCurrencies();
    selectAddressRow(0);
    updateReceive();

    // Dev hook: preselect a send asset (e.g. AERO_SENDCUR=USDT) for screenshots/testing.
    if (!qEnvironmentVariableIsEmpty("AERO_SENDCUR")) {
        const QString want = qEnvironmentVariable("AERO_SENDCUR");
        for (const TokenInfo &t : m_wallet->tokens())
            if (t.symbol.compare(want, Qt::CaseInsensitive) == 0)
                setSendAsset(t.symbol, t.address, t.decimals);
    }
    // Dev hooks for testing the Receive tab without pixel-clicking:
    //   AERO_RECV_CREATE=N  -> click "Create new address" N times
    //   AERO_RECV_ROW=k     -> select address row k
    for (int i = 0, n = qEnvironmentVariable("AERO_RECV_CREATE").toInt(); i < n; ++i)
        onCreateAddress();
    if (!qEnvironmentVariableIsEmpty("AERO_RECV_ROW"))
        selectAddressRow(qEnvironmentVariable("AERO_RECV_ROW").toUInt());
    if (!qEnvironmentVariableIsEmpty("AERO_SENDAMT"))
        sendUi.lineAmount->setText(qEnvironmentVariable("AERO_SENDAMT"));
    if (!qEnvironmentVariableIsEmpty("AERO_FEEMODE")) {
        const int i = sendUi.combo_feePriority->findText(qEnvironmentVariable("AERO_FEEMODE"));
        if (i >= 0) sendUi.combo_feePriority->setCurrentIndex(i);
    }
    // Dev hook: show the confirm-transaction dialog with a sample tx for testing.
    if (!qEnvironmentVariableIsEmpty("AERO_TEST_CONFIRM")) {
        QTimer::singleShot(1200, this, [this] {
            m_nativeUsd = 1800.0;
            PendingEthTx t;
            t.fromIndex = 0;
            t.to = QStringLiteral("0x742d35Cc6634C0532925a3b844Bc454e4438f44e");
            t.amountWei = QStringLiteral("250000000000000000"); // 0.25 ETH
            t.fee.maxFee = QStringLiteral("150000000");         // 0.15 gwei
            onTransactionCreated(t);
        });
    }
    // Dev hook: inject sample history (incl. a poisoning + failed tx) for testing the History tab.
    if (!qEnvironmentVariableIsEmpty("AERO_TEST_HISTORY")) {
        m_nativeUsd = 1800.0;
        QTimer::singleShot(2000, this, [this] {
            m_nativeUsd = 1800.0; // demo has no provider; keep a price so the dust filter can value ETH
            const quint64 now = static_cast<quint64>(QDateTime::currentSecsSinceEpoch());
            auto mk = [](const QString &dir, const QString &cp, const QString &amt, const QString &sym,
                         const QString &token, const QString &hash, quint64 block, quint64 ts,
                         const QString &fee, bool failed) {
                HistoryItem h;
                h.direction = dir; h.counterparty = cp; h.formatted = amt;
                h.amount = amt == QLatin1String("0") ? QStringLiteral("0") : QStringLiteral("1");
                h.symbol = sym; h.token = token; h.txHash = hash; h.block = block; h.timestamp = ts;
                h.fee = fee; h.failed = failed;
                return h;
            };
            const QString USDT = QStringLiteral("0xdAC17F958D2ee523a2206206994597C13D831ec7");
            QVector<HistoryItem> items;
            items << mk("in", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "1.5", "ETH", QString(),
                        "0xaaa1111111111111111111111111111111111111111111111111111111111111", 25000000, now - 3600, "", false);
            items << mk("out", "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", "0.25", "ETH", QString(),
                        "0xbbb2222222222222222222222222222222222222222222222222222222222222", 24999000, now - 7200, "315000000000000", false);
            items << mk("in", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "100", "USDT", USDT,
                        "0xccc3333333333333333333333333333333333333333333333333333333333333", 24990000, now - 86400, "", false);
            // A top ERC-20 (MANA) — auto-trusted and should show its logo in History.
            items << mk("in", "0x1111111111111111111111111111111111111111", "1500", "MANA",
                        QStringLiteral("0x0F5D2fB29fb7d3CFeE444a200298f468908cC942"),
                        "0x1112223334445556667778889990001112223334445556667778889990001112", 24985000, now - 90000, "", false);
            // Scam ERC-20 impersonating native ETH: must show NO logo and be greyed out.
            items << mk("in", "0x742d35Cc6634C0532925a3b844Bc454e0000f44e", "0.01", "ETH",
                        "0x00000000000000000000000000000000deadbeef",
                        "0xddd4444444444444444444444444444444444444444444444444444444444444", 24980000, now - 90000, "", false);
            items << mk("out", "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", "0", "ETH", QString(),
                        "0xeee5555555555555555555555555555555555555555555555555555555555555", 24970000, now - 100000, "120000000000000", true);
            // Sub-threshold dust: 0.000002 ETH ~= $0.0036 (< $0.005 default) -> hidden by dust filter.
            items << mk("in", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "0.000002", "ETH", QString(),
                        "0xfff6666666666666666666666666666666666666666666666666666666666666", 24960000, now - 110000, "", false);
            // Address-poisoning spoof: a fake *outgoing* ERC-20 Transfer with a Cyrillic "ЕТН" symbol
            // (homoglyph) from an untracked contract — the user never signed it. Must be hidden.
            const QString cyrillicEth = QString(QChar(0x0415)) + QChar(0x0422) + QChar(0x041D); // ЕТН
            items << mk("out", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "2.5", cyrillicEth,
                        "0x000000000000000000000000000000000000dEaD",
                        "0x9999999999999999999999999999999999999999999999999999999999999999", 25000001, now - 1800, "", false);
            applyVerifiedTokens(); // real allow-list (curated top tokens + tracked) incl. MANA
            updateHistoryPricing(); // push ETH=$1800 so the dust filter can value the tiny receive
            m_historyModel->onHistoryRefreshed(items);
        });
    }
    // Dev hook: exercise the real received/sent notification code paths for testing.
    if (!qEnvironmentVariableIsEmpty("AERO_TEST_NOTIFY")) {
        qDebug() << "NOTIFYTEST trayAvailable=" << QSystemTrayIcon::isSystemTrayAvailable()
                 << "supportsMessages=" << QSystemTrayIcon::supportsMessages();
        const QString usdt = QStringLiteral("0xdAC17F958D2ee523a2206206994597C13D831ec7");
        QTimer::singleShot(2000, this, [this] { m_ethRawByAccount.insert(0, 0.0); });
        QTimer::singleShot(3000, this, [this] {
            qDebug() << "NOTIFYTEST native-eth-received";
            onAccountBalance(0, QStringLiteral("0.5"), QStringLiteral("ETH")); // simulated +0.5 ETH
        });
        QTimer::singleShot(5000, this, [this, usdt] {
            m_tokenRawByKey.insert(QStringLiteral("0|%1").arg(usdt), 0.0);
        });
        QTimer::singleShot(6000, this, [this, usdt] {
            qDebug() << "NOTIFYTEST erc20-received";
            onAvailableBalance(0, usdt, QStringLiteral("100"), QStringLiteral("USDT")); // simulated +100 USDT
        });
        QTimer::singleShot(9000, this, [this] {
            qDebug() << "NOTIFYTEST sent-confirmation";
            notify(tr("Payment sent"), tr("0.25 ETH to 0x1234…abcd")); // simulated send confirmation
        });
    }

    autoConnect();

    // Fast new-block watcher: poll the (cheap) chain head every few seconds and refresh balances
    // the instant a new block lands, so incoming transactions are detected immediately rather than
    // on a fixed 30s tick.
    m_blockTimer = new QTimer(this);
    m_blockTimer->setInterval(6000);
    connect(m_blockTimer, &QTimer::timeout, this, [this]() {
        if (m_wallet) m_wallet->refreshBlockNumber();
    });
    m_blockTimer->start();

    // Slow timer just keeps the market prices fresh (balances are block-driven above).
    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(60000);
    connect(m_refreshTimer, &QTimer::timeout, this, [this]() {
        if (!m_wallet) return;
        m_wallet->refreshEthUsdPrice();
        m_wallet->refreshMarketPrices();
    });
    m_refreshTimer->start();
}

void AeroMainWindow::onBlockNumber(quint64 block) {
    if (block == 0 || block <= m_lastBlock)
        return;
    const bool firstSeen = (m_lastBlock == 0);
    m_lastBlock = block;
    if (firstSeen)
        return; // baseline; the connect handler already did the initial refresh
    // A new block landed — refresh balances + history so incoming/outgoing txs surface at once,
    // and refresh the fee suggestion (base fee changes each block). Balances are one batched call.
    refreshAllBalances();
    refreshHistoryView();
    m_wallet->refreshFees();
}

// RPC endpoints for `chainId`: a user-saved custom node (Settings -> Node) wins over the bundled
// registry defaults.
QStringList AeroMainWindow::endpointsFor(quint64 chainId) const {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    const QString csv = s.value(QStringLiteral("node/%1/rpc").arg(chainId)).toString().trimmed();
    if (!csv.isEmpty()) {
        QStringList out;
        for (const QString &e : csv.split(QLatin1Char(','), Qt::SkipEmptyParts))
            out << e.trimmed();
        if (!out.isEmpty()) return out;
    }
    return chainDefFor(chainId).rpcs;
}

// SOCKS proxy for `chainId`: if the user saved a custom node they may also have set (or blanked, to
// go direct) a proxy for it. Otherwise everything routes over the running Tor proxy.
QString AeroMainWindow::socksFor(quint64 chainId) const {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    const QString key = QStringLiteral("node/%1/socks").arg(chainId);
    if (s.contains(key)) return s.value(key).toString(); // may be "" => direct (own node)
    return m_tor ? m_tor->socksProxy() : kDefaultSocks;
}

// (Re)connect the active chain using the resolved node settings. A custom node with a blank proxy
// connects directly (for a local/own node); otherwise we go over Tor.
void AeroMainWindow::connectCurrentChain() {
    if (!m_wallet) return;
    m_wallet->connectProvider(m_chainId, endpointsFor(m_chainId), socksFor(m_chainId));
}

void AeroMainWindow::autoConnect() {
    if (!m_wallet) return;

    // If the user configured a custom node for this chain with Tor disabled (blank proxy), connect
    // directly to their own node without waiting on/booting Tor.
    {
        QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
        const QString key = QStringLiteral("node/%1/socks").arg(m_chainId);
        if (s.contains(key) && s.value(key).toString().trimmed().isEmpty()) {
            setConnectionState(0, tr("Connecting to your node…"));
            connectCurrentChain();
            return;
        }
    }

    setConnectionState(0, tr("Starting Tor…"));

    // Otherwise always route through Tor — start (or reuse) Tor first, then connect only once it has
    // bootstrapped. There is no clearnet fallback, so the wallet never leaks the user's IP.
    if (!m_tor) {
        m_tor = new TorManager(this);
        connect(m_tor, &TorManager::statusChanged, this,
                [this](const QString &msg) { setConnectionState(0, msg); });
        connect(m_tor, &TorManager::ready, this, [this]() {
            setConnectionState(0, tr("Connecting via Tor…"));
            connectCurrentChain();
        });
        connect(m_tor, &TorManager::failed, this, [this](const QString &err) {
            setConnectionState(0, tr("Tor unavailable — %1").arg(err));
        });
    }
    if (m_tor->isReady()) {
        connectCurrentChain();
    } else {
        m_tor->start();
    }
}

// Switch the active network: relabel the native coin, clear cached balances/history (addresses are
// identical across chains but balances are not), reconnect the RPC to the new chain, and reset the
// Send asset to the new chain's native coin. Everything still routes over the already-running Tor.
void AeroMainWindow::switchChain(quint64 chainId) {
    if (!m_wallet) return;
    const ChainDef &c = chainDefFor(chainId);
    m_chainId = chainId;
    m_nativeSymbol = c.nativeSymbol;

    // Reset cached, chain-specific state so stale numbers from the previous chain don't linger.
    m_nativeUsd = 0.0;
    m_accountBalances.clear();
    m_ethRawByAccount.clear();
    m_tokenRawByKey.clear();
    if (m_historyModel) m_historyModel->onHistoryRefreshed({}); // drop previous chain's history

    // Reflect the new chain in the selector button.
    if (m_networkButton) {
        m_networkButton->setIcon(QIcon(c.icon));
        m_networkButton->setText(c.name);
        m_networkButton->setToolTip(tr("Network: %1").arg(c.name));
    }
    // Reset the Send asset to the new chain's native coin.
    setSendAsset(m_nativeSymbol, QString(), 18);
    updateAmountUnit();

    // Update the Home native ticker label + any native-symbol labels.
    relabelNative();

    // Reconnect to the new chain's endpoints (custom node if configured for it, else registry
    // defaults over the existing Tor transport).
    setConnectionState(0, tr("Switching to %1…").arg(c.name));
    {
        QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
        const QString key = QStringLiteral("node/%1/socks").arg(chainId);
        const bool directNode = s.contains(key) && s.value(key).toString().trimmed().isEmpty();
        if (directNode || (m_tor && m_tor->isReady()))
            connectCurrentChain();
        else
            autoConnect();
    }
}

// Update UI labels that name the native coin after a chain switch.
void AeroMainWindow::relabelNative() {
    if (m_homeNativeBox) m_homeNativeBox->setTitle(m_nativeSymbol);
    // Refresh the Receive multi-asset breakdown + totals, which label the native coin.
    if (m_addressModel) showCachedBalance(m_account);
}

void AeroMainWindow::onProviderConnected(int mode, const QString &message) {
    setConnectionState(mode, mode > 0 ? tr("%1 · %2").arg(message, chainDefFor(m_chainId).name) : message);
    if (mode > 0) {
        // Only now that we can actually reach an RPC do we pull balances + prices. Each of these is
        // a single (or batched) request — no per-account fan-out and no duplicate refreshes.
        refreshAllBalances();               // batched: native + tokens for every account
        refreshHistoryView();               // full history (Blockscout over Tor)
        m_wallet->refreshEthUsdPrice();     // native/USD (Chainlink or fallback)
        m_wallet->refreshMarketPrices();    // XMR + native market prices for Home
        m_wallet->refreshFees();            // gas suggestion
        if (m_fiatCurrency.compare(QStringLiteral("USD"), Qt::CaseInsensitive) != 0)
            m_wallet->refreshFiatRate(m_fiatCurrency); // USD->fiat rate for display
        refreshNfts();
        // First time we can reach the chain: if we've never scanned this wallet for funded
        // addresses, do it now (finds addresses with a balance across the seed).
        if (!m_fundedScanned && !m_fundedScanTried) {
            m_fundedScanTried = true;
            setConnectionState(mode, tr("Scanning for funded addresses\u2026"));
            m_wallet->scanFunded(20);
        }
    }
}

void AeroMainWindow::applyFundedFilter() {
    if (m_addressModel)
        m_addressModel->setFundedFilter(m_showFundedOnly, m_fundedAccounts);
}

void AeroMainWindow::loadFundedSet() {
    // The funded set now lives in the encrypted wallet metadata (loaded in loadMetadata()); this
    // just reflects the already-parsed m_meta into m_fundedAccounts.
    m_fundedAccounts.clear();
    m_fundedScanned = m_meta.value(QStringLiteral("funded_done")).toBool(false);
    for (const QJsonValue &v : m_meta.value(QStringLiteral("funded")).toArray())
        m_fundedAccounts.insert(static_cast<quint32>(v.toDouble()));
}

void AeroMainWindow::saveFundedSet() {
    QJsonArray arr;
    for (quint32 i : m_fundedAccounts)
        arr.append(static_cast<double>(i));
    m_meta[QStringLiteral("funded")] = arr;
    m_meta[QStringLiteral("funded_done")] = true;
    saveMetadata();
}

void AeroMainWindow::onFundedScanned(const QList<quint32> &indices) {
    m_fundedScanned = true;
    m_fundedAccounts.clear();
    // The core scan (across all derivation schemes) already registered each funded address as an
    // account and returns their unified indices; we just mark them funded and refresh.
    for (quint32 i : indices)
        m_fundedAccounts.insert(i);
    if (!m_fundedAccounts.isEmpty()) {
        m_wallet->save(); // persist the discovered accounts (incl. non-standard-path ones)
        m_addressModel->refresh();
        rebuildAccountCombos();
        refreshAllBalances();
    }
    saveFundedSet();
    applyFundedFilter();
    if (m_addressModel->rowCount() > 0)
        selectAddressRow(m_addressModel->accountAt(0)); // first visible (funded) address
    setConnectionState(2, tr("Connected via Tor"));
    notify(tr("Scan complete"),
           tr("Found %1 funded address(es).").arg(m_fundedAccounts.size()));
}

void AeroMainWindow::refreshAllBalances() {
    if (!m_wallet) return;
    // ONE batched request fetches native + all tracked-token balances for every account, instead of
    // firing numAccounts × (1 + numTokens) independent Tor calls (which trickled in one-by-one and
    // could overwhelm Tor so nothing loaded). Results arrive via the usual per-account signals.
    m_wallet->refreshAllBalances(m_wallet->numAccounts());
}

void AeroMainWindow::updateUsed(quint32 index) {
    if (!m_addressModel) return;
    bool used = m_ethRawByAccount.value(index, 0.0) > 0.0;
    if (!used && m_wallet) {
        for (const TokenInfo &t : m_wallet->tokens())
            if (m_tokenRawByKey.value(QStringLiteral("%1|%2").arg(index).arg(t.address), 0.0) > 0.0) {
                used = true;
                break;
            }
    }
    m_addressModel->setUsed(index, used);
}

void AeroMainWindow::loadLabels() {
    // Apply address labels from the (already-parsed) encrypted wallet metadata.
    if (!m_wallet || !m_addressModel) return;
    const QJsonObject labels = m_meta.value(QStringLiteral("labels")).toObject();
    const quint32 n = m_wallet->numAccounts();
    for (quint32 i = 0; i < n; ++i) {
        const QString v = labels.value(QString::number(i)).toString();
        if (!v.isEmpty())
            m_addressModel->setLabel(i, v);
    }
    if (m_fromCombo) {
        QSignalBlocker block(m_fromCombo);
        for (int i = 0; i < m_fromCombo->count(); ++i)
            m_fromCombo->setItemText(i, accountLabel(static_cast<quint32>(i)));
    }
}

void AeroMainWindow::copySensitive(const QString &text) {
    QApplication::clipboard()->setText(text);
    const int secs = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                         .value(QStringLiteral("security/clipboardClearSecs"), 30).toInt();
    if (secs <= 0)
        return; // 0 = never auto-clear
    // Only clear if the clipboard still holds this secret (don't clobber later copies).
    QTimer::singleShot(secs * 1000, this, [text]() {
        QClipboard *cb = QApplication::clipboard();
        if (cb->text() == text)
            cb->clear();
    });
}

void AeroMainWindow::saveMetadata() {
    if (!m_wallet) return;
    m_wallet->setMetadata(QString::fromUtf8(QJsonDocument(m_meta).toJson(QJsonDocument::Compact)));
    m_wallet->save(); // re-encrypt with the retained password (atomic write)
}

void AeroMainWindow::loadMetadata() {
    if (!m_wallet) return;
    const QString json = m_wallet->metadata();
    m_meta = json.isEmpty() ? QJsonObject()
                            : QJsonDocument::fromJson(json.toUtf8()).object();
    if (m_meta.isEmpty())
        migrateLegacyMetadata(); // one-time import from the old plaintext QSettings (persists)

    // Apply to the UI without re-persisting (guard re-entrant writes).
    m_metaLoading = true;
    loadLabels();
    loadFundedSet();
    if (m_contactsTable) {
        m_contactsTable->setRowCount(0);
        for (const QJsonValue &v : m_meta.value(QStringLiteral("contacts")).toArray()) {
            const QJsonObject c = v.toObject();
            const int r = m_contactsTable->rowCount();
            m_contactsTable->insertRow(r);
            m_contactsTable->setItem(r, 0, new QTableWidgetItem(c.value(QStringLiteral("name")).toString()));
            m_contactsTable->setItem(r, 1, new QTableWidgetItem(c.value(QStringLiteral("address")).toString()));
        }
    }
    ui.notes->setPlainText(m_meta.value(QStringLiteral("notes")).toString());
    m_metaLoading = false;
}

void AeroMainWindow::migrateLegacyMetadata() {
    // Import metadata that older builds stored in plaintext QSettings, fold it into the encrypted
    // wallet, and remove the plaintext copies. Runs once (when a wallet has no embedded metadata).
    if (!m_wallet) return;
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    const QString grp = labelsGroup(m_wallet->walletPath());
    bool migrated = false;

    QJsonObject labels;
    const quint32 n = m_wallet->numAccounts();
    for (quint32 i = 0; i < n; ++i) {
        const QString v = s.value(QStringLiteral("%1/%2").arg(grp).arg(i)).toString();
        if (!v.isEmpty()) labels[QString::number(i)] = v;
    }
    if (!labels.isEmpty()) { m_meta[QStringLiteral("labels")] = labels; migrated = true; }

    if (s.contains(QStringLiteral("%1/funded").arg(grp))) {
        QJsonArray funded;
        for (const QString &part : s.value(QStringLiteral("%1/funded").arg(grp)).toString()
                                       .split(QLatin1Char(','), Qt::SkipEmptyParts)) {
            bool ok = false; const quint32 i = part.toUInt(&ok);
            if (ok) funded.append(static_cast<double>(i));
        }
        m_meta[QStringLiteral("funded")] = funded;
        m_meta[QStringLiteral("funded_done")] =
            s.value(QStringLiteral("%1/funded_done").arg(grp), false).toBool();
        migrated = true;
    }

    const QStringList legacyContacts =
        s.value(QStringLiteral("contacts")).toStringList(); // was global in old builds
    if (!legacyContacts.isEmpty()) {
        QJsonArray arr;
        for (const QString &e : legacyContacts) {
            const int sep = e.indexOf(QLatin1Char('|'));
            if (sep < 0) continue;
            QJsonObject c;
            c[QStringLiteral("name")] = e.left(sep);
            c[QStringLiteral("address")] = e.mid(sep + 1);
            arr.append(c);
        }
        m_meta[QStringLiteral("contacts")] = arr;
        migrated = true;
    }
    const QString legacyNotes = s.value(QStringLiteral("notes/text")).toString();
    if (!legacyNotes.isEmpty()) { m_meta[QStringLiteral("notes")] = legacyNotes; migrated = true; }

    if (migrated) {
        saveMetadata(); // persist into the encrypted wallet
        // Scrub the migrated plaintext copies.
        s.remove(grp);                        // per-wallet labels/funded group
        s.remove(QStringLiteral("contacts")); // formerly-global contacts
        s.remove(QStringLiteral("notes/text"));
    }
}

QString AeroMainWindow::currentTokenAddr() const { return m_sendTokenAddr; }

QString AeroMainWindow::currentSymbol() const {
    return m_sendSymbol.isEmpty() ? m_nativeSymbol : m_sendSymbol;
}

quint8 AeroMainWindow::currentDecimals() const { return m_sendTokenAddr.isEmpty() ? 18 : m_sendDecimals; }

void AeroMainWindow::setSendAsset(const QString &symbol, const QString &address, quint8 decimals) {
    m_sendSymbol = symbol.isEmpty() ? m_nativeSymbol : symbol;
    m_sendTokenAddr = address;
    m_sendDecimals = address.isEmpty() ? 18 : decimals;
    if (m_assetButton) {
        m_assetButton->setText(QStringLiteral("%1  \u25be").arg(m_sendSymbol));
        m_assetButton->setIcon(tokenIcon(m_sendSymbol));
    }
    updateAmountUnit();
    updateAvailable();
    onAmountConversion();
    updateFeeEstimate(); // gas differs for ETH vs ERC20
}

void AeroMainWindow::updateAvailable() {
    if (!m_wallet || !m_fromCombo || !m_availLabel) return;
    const int fromIndex = qMax(0, m_fromCombo->currentIndex());
    m_availAmount.clear();
    m_availLabel->setText(tr("Fetching…"));
    m_wallet->fetchAvailable(static_cast<quint32>(fromIndex), currentTokenAddr());
}

void AeroMainWindow::onAvailableBalance(quint32 index, const QString &token,
                                         const QString &formatted, const QString &symbol) {
    // Accumulate per-account token balances for the combined Home total (token != "" == ERC20).
    if (!token.isEmpty()) {
        const QString key = QStringLiteral("%1|%2").arg(index).arg(token);
        const double newBal = formatted.toDouble();
        const double oldBal = m_tokenRawByKey.value(key, -1.0);
        m_tokenRawByKey.insert(key, newBal);
        recomputeHomeTotal();
        updateUsed(index);
        if (oldBal >= 0.0 && newBal > oldBal + 1e-9)
            notify(tr("Payment received"),
                   tr("+%1 %2 to Account #%3")
                       .arg(grouped(QString::number(newBal - oldBal, 'f', 6)), symbol)
                       .arg(index));
        if (index == m_account) {
            showCachedBalance(m_account); // token totals changed -> update the status balance too
            updateReceive();              // refresh the token breakdown for the shown address
        }
    }

    // Ignore results that no longer match the current From account + asset selection.
    const int fromIndex = m_fromCombo ? qMax(0, m_fromCombo->currentIndex()) : 0;
    if (static_cast<int>(index) != fromIndex || token != currentTokenAddr())
        return;
    m_availAmount = formatted; // raw (no separators) so Max can fill the amount field
    if (m_availLabel)
        m_availLabel->setText(formatted.isEmpty() ? tr("—")
                                                  : tr("%1 %2").arg(formatBalance(formatted), symbol));
}

QString AeroMainWindow::accountLabel(quint32 index) const {
    // Use the address's Receive label if the user has set one; otherwise "Account #i".
    QString name = tr("Account #%1").arg(index);
    if (m_addressModel) {
        const QString custom = m_addressModel->labelAt(index);
        if (!custom.isEmpty())
            name = custom;
    }
    QString label = tr("%1  ·  %2").arg(name, shortAddr(m_wallet->address(index)));
    if (m_accountBalances.contains(index))
        label += QStringLiteral("  ·  %1").arg(m_accountBalances.value(index));
    return label;
}

void AeroMainWindow::rebuildAccountCombos() {
    if (!m_wallet) return;
    const quint32 n = m_wallet->numAccounts();
    // Send's "From" selector lists every address.
    if (m_fromCombo) {
        QSignalBlocker block(m_fromCombo);
        const int prev = m_fromCombo->currentIndex();
        m_fromCombo->clear();
        for (quint32 i = 0; i < n; ++i)
            m_fromCombo->addItem(tokenIcon(m_nativeSymbol), accountLabel(i));
        m_fromCombo->setCurrentIndex(prev >= 0 && prev < static_cast<int>(n) ? prev : 0);
    }
    if (m_addressModel)
        m_addressModel->refresh();
    rebuildHistoryCombo();
}

void AeroMainWindow::rebuildHistoryCombo() {
    if (!m_historyCombo || !m_wallet)
        return;
    QSignalBlocker block(m_historyCombo);
    m_historyCombo->clear();
    m_historyCombo->addItem(tr("All accounts"));
    const quint32 n = m_wallet->numAccounts();
    for (quint32 i = 0; i < n; ++i)
        m_historyCombo->addItem(tokenIcon(m_nativeSymbol), accountLabel(i));
    int want = (m_historyFilter < 0) ? 0 : (m_historyFilter + 1);
    if (want >= m_historyCombo->count())
        want = 0;
    m_historyCombo->setCurrentIndex(want);
}

void AeroMainWindow::refreshHistoryView() {
    if (!m_wallet)
        return;
    if (m_historyFilter < 0)
        m_wallet->refreshHistoryAll(m_wallet->numAccounts());
    else
        m_wallet->refreshHistory(static_cast<quint32>(m_historyFilter));
}

void AeroMainWindow::onAccountBalance(quint32 index, const QString &formatted, const QString &symbol) {
    if (formatted.isEmpty()) return; // offline / no balance yet — don't append an empty suffix
    const double newBal = formatted.toDouble();
    const double oldBal = m_ethRawByAccount.value(index, -1.0);
    m_ethRawByAccount.insert(index, newBal); // raw, for the combined total
    recomputeHomeTotal();
    updateUsed(index);
    // A balance increase means an incoming payment (our own sends decrease it).
    if (oldBal >= 0.0 && newBal > oldBal + 1e-12)
        notify(tr("Payment received"),
               tr("+%1 ETH to Account #%2")
                   .arg(grouped(QString::number(newBal - oldBal, 'f', 6)))
                   .arg(index));
    const QString display = tr("%1 %2").arg(formatBalance(formatted), symbol);
    m_accountBalances.insert(index, display);
    if (m_addressModel)
        m_addressModel->setBalance(index, display);
    if (m_fromCombo && static_cast<int>(index) < m_fromCombo->count()) {
        QSignalBlocker block(m_fromCombo);
        m_fromCombo->setItemText(static_cast<int>(index), accountLabel(index));
    }
    if (index == m_account) {
        showCachedBalance(m_account); // bottom-left status balance (native + tokens), from the batch
        updateReceive();              // refresh the balance shown under the QR
    }
}

void AeroMainWindow::updateReceive() {
    if (!m_wallet) return;
    const QString addr = m_wallet->address(m_account);
    const QPixmap qr = renderQr(addr);
    recvUi.qrCode->setPixmap(qr);
    recvUi.qrCode->setFixedSize(qr.size());
    recvUi.qrCode->setToolTip(tr("Click to copy"));

    // Full per-address balance: native coin + every tracked token, each with its logo.
    auto row = [](const QString &iconPath, const QString &symbol, double balance) {
        return QStringLiteral(
                   "<tr><td><img src='%3' width='16' height='16'></td>"
                   "<td>&nbsp;%2 %1</td></tr>")
            .arg(symbol, formatBalance(balance), iconPath);
    };
    QString html = QStringLiteral("<div align='center'>%1<br><br><table align='center' cellspacing='2'>")
                       .arg(addr.toHtmlEscaped());
    // Always show the native coin; only show a token if this address actually holds some of it, so
    // the breakdown stays clean (ETH by default, other assets appear as they arrive).
    html += row(chainDefFor(m_chainId).icon, m_nativeSymbol,
                m_ethRawByAccount.value(m_account, 0.0));
    for (const TokenInfo &t : m_wallet->tokens()) {
        const double bal =
            m_tokenRawByKey.value(QStringLiteral("%1|%2").arg(m_account).arg(t.address), 0.0);
        if (bal > 0.0)
            html += row(QStringLiteral(":/assets/images/tokens/%1.png").arg(t.symbol), t.symbol, bal);
    }
    html += QStringLiteral("</table></div>");

    m_recvBalanceLabel->setTextFormat(Qt::RichText);
    m_recvBalanceLabel->setText(html);
}

void AeroMainWindow::onAccountChanged(int index) {
    if (index < 0 || !m_wallet) return;
    m_account = static_cast<quint32>(index);
    showCachedBalance(m_account); // instant bottom-left balance from cache (Feather-style)
    updateReceive();
    onRefresh();
    refreshNfts();
}

// Populate the bottom-left balance label from already-fetched data so switching addresses is
// instant; the async refresh in onRefresh() then updates it with fresh numbers.
void AeroMainWindow::showCachedBalance(quint32 index) {
    if (!m_balanceLabel || !m_accountBalances.contains(index))
        return; // nothing cached yet — leave the current text until the refresh arrives
    if (m_hideBalances) {
        m_balanceLabel->setText(tr("Balance: hidden"));
        return;
    }
    QString status = tr("Balance: %1").arg(m_accountBalances.value(index));
    double totalUsd = m_ethRawByAccount.value(index, 0.0) * unitPriceUsd(m_nativeSymbol);
    if (m_wallet) {
        for (const TokenInfo &t : m_wallet->tokens())
            totalUsd += m_tokenRawByKey.value(QStringLiteral("%1|%2").arg(index).arg(t.address), 0.0) *
                        unitPriceUsd(t.symbol);
    }
    if (totalUsd > 0)
        status += tr("   \u2248 %1").arg(fiatStr(totalUsd));
    m_balanceLabel->setText(status);
}

void AeroMainWindow::ensureMinAddresses(quint32 count) {
    if (!m_wallet) return;
    // Hardware wallets derive their accounts up front (via the device at create time), and
    // watch-only wallets have no keys to derive from — never fabricate extra HD entries for either.
    if (m_wallet->isHardware() || m_wallet->isWatchOnly()) return;
    while (m_wallet->numAccounts() < count)
        m_wallet->addAccount();
}

void AeroMainWindow::selectAddressRow(quint32 index) {
    if (!m_addressModel)
        return;
    const int row = m_addressModel->rowForAccount(index);
    if (row < 0)
        return; // the account isn't currently visible (e.g. filtered out as unfunded)
    const QModelIndex idx = m_addressModel->index(row, 0);
    recvUi.addresses->setCurrentIndex(idx);
    recvUi.addresses->scrollTo(idx);
}

void AeroMainWindow::onCreateAddress() {
    if (!m_wallet) return;
    if (m_wallet->isWatchOnly()) {
        QMessageBox::information(this, tr("Watch-only wallet"),
                                 tr("A watch-only wallet can't derive new addresses — it only "
                                    "tracks the addresses you added."));
        return;
    }
    quint32 idx;
    if (m_wallet->isHardware()) {
        // Derive the next address from the device (needs it connected; may take a moment).
        QApplication::setOverrideCursor(Qt::WaitCursor);
        idx = m_wallet->addHardwareAccount();
        QApplication::restoreOverrideCursor();
        if (idx == 0xFFFFFFFFu) {
            QMessageBox::warning(this, tr("Create address"),
                                 tr("Couldn't derive an address from the device:\n%1")
                                     .arg(m_wallet->errorString()));
            return;
        }
    } else {
        idx = m_wallet->addAccount();
    }
    m_account = idx;
    m_wallet->save(); // persist the new account count / cached address
    rebuildAccountCombos();
    selectAddressRow(idx);
    updateReceive();
    onRefresh();
}

void AeroMainWindow::onImportKey() {
    if (!m_wallet) return;
    if (m_wallet->isWatchOnly()) {
        QMessageBox::information(this, tr("Watch-only wallet"),
                                 tr("This is a watch-only wallet. Create or restore a normal wallet "
                                    "to import a spending key."));
        return;
    }
    bool ok = false;
    const QString key = QInputDialog::getText(
        this, tr("Import private key"),
        tr("Paste a raw private key (0x-prefixed, 64 hex chars):"),
        QLineEdit::Password, QString(), &ok);
    if (!ok || key.trimmed().isEmpty()) return;

    const quint32 idx = m_wallet->importPrivateKey(key.trimmed());
    if (idx == 0xFFFFFFFFu) {
        QMessageBox::warning(this, tr("Import failed"), m_wallet->errorString());
        return;
    }
    // Imported keys are the ONLY funds not recoverable from the seed, so persistence must succeed.
    // If the save fails, tell the user loudly (and keep the key on screen so they can retry/back it
    // up) instead of silently losing it on the next close.
    if (m_wallet->walletPath().isEmpty()) {
        QMessageBox::warning(
            this, tr("Not saved"),
            tr("The key was imported but this wallet isn't saved to a file, so it will be lost when "
               "you close. Save the wallet first, then re-import."));
    } else if (!m_wallet->save()) {
        QMessageBox::critical(
            this, tr("Import not saved"),
            tr("The private key was imported but could NOT be written to your wallet file:\n\n%1\n\n"
               "This key is NOT recoverable from your seed. Do not close the wallet — back up the "
               "key you just pasted, fix the problem (disk space / permissions), then try again.")
                .arg(m_wallet->errorString()));
    }
    m_account = idx;
    // A key you explicitly imported should always be visible in Receive, even with the
    // "show only funded" filter on (the funded scan only covers HD-derived addresses).
    m_fundedAccounts.insert(idx);
    saveFundedSet();
    rebuildAccountCombos();
    applyFundedFilter();
    selectAddressRow(idx);
    updateReceive();
    onRefresh();
    QMessageBox::information(this, tr("Imported"),
                            tr("Imported address #%1:\n%2").arg(idx).arg(m_wallet->address(idx)));
}

void AeroMainWindow::onAddressContextMenu(const QPoint &pos) {
    if (!m_wallet) return;
    const QModelIndex idx = recvUi.addresses->indexAt(pos);
    if (!idx.isValid()) return;
    const quint32 row = m_addressModel->accountAt(idx.row());

    QMenu menu(this);
    QAction *copyAddr = menu.addAction(tr("Copy address"));
    // Hardware wallets have no exportable key (it never leaves the device).
    QAction *exportKey = m_wallet->isHardware() ? nullptr : menu.addAction(tr("Export private key"));
    QAction *chosen = menu.exec(recvUi.addresses->viewport()->mapToGlobal(pos));
    if (!chosen) return;

    if (chosen == copyAddr) {
        QApplication::clipboard()->setText(m_wallet->address(row));
        return;
    }
    if (chosen != exportKey) return; // (exportKey is null for hardware wallets)

    // Export private key — warn before revealing.
    if (QMessageBox::warning(
            this, tr("Export private key"),
            tr("Anyone with this private key can spend everything at address #%1.\n"
               "Never share it. Reveal it now?").arg(row),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;

    const QString key = m_wallet->exportPrivateKey(row);
    if (key.isEmpty()) {
        QMessageBox::warning(this, tr("Export failed"), m_wallet->errorString());
        return;
    }

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Private key — address #%1").arg(row));
    auto *lay = new QVBoxLayout(&dlg);
    auto *addrLabel = new QLabel(m_wallet->address(row), &dlg);
    addrLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lay->addWidget(addrLabel);
    auto *keyEdit = new QLineEdit(key, &dlg);
    keyEdit->setReadOnly(true);
    keyEdit->setCursorPosition(0);
    lay->addWidget(keyEdit);
    auto *copyBtn = new QPushButton(tr("Copy to clipboard"), &dlg);
    connect(copyBtn, &QPushButton::clicked, &dlg,
            [this, key]() { copySensitive(key); });
    lay->addWidget(copyBtn);
    auto *box = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    lay->addWidget(box);
    dlg.exec();
}

void AeroMainWindow::onSettings() {
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Settings"));
    dlg.setMinimumWidth(460);
    auto *outer = new QVBoxLayout(&dlg);
    auto *tabs = new QTabWidget(&dlg);

    // --- Node tab (RPC / Tor) ---
    auto *nodeTab = new QWidget(&dlg);
    auto *nodeForm = new QFormLayout(nodeTab);
    auto *chainEdit = new QLineEdit(QString::number(m_chainId), nodeTab);
    // Pre-fill with the node actually in use for this chain: a saved custom node if there is one,
    // otherwise the bundled defaults over Tor. This is what makes "use your own node" stick.
    auto *rpcEdit = new QLineEdit(endpointsFor(m_chainId).join(QStringLiteral(", ")), nodeTab);
    auto *socksEdit = new QLineEdit(socksFor(m_chainId), nodeTab);
    rpcEdit->setToolTip(tr("Leave equal to defaults to keep the bundled endpoints; enter your own\n"
                           "node (e.g. http://127.0.0.1:8545) to use it for this network."));
    socksEdit->setToolTip(tr("socks5h://127.0.0.1:9055 routes over Tor. Blank = connect directly\n"
                             "(use this for a local/own node)."));
    nodeForm->addRow(tr("Chain ID"), chainEdit);
    nodeForm->addRow(tr("RPC endpoint(s), comma-separated"), rpcEdit);
    nodeForm->addRow(tr("SOCKS proxy (blank to disable Tor)"), socksEdit);
    // Preferred block explorer for transaction/address links.
    auto *explorerEdit = new QLineEdit(nodeTab);
    explorerEdit->setText(QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                              .value(QStringLiteral("explorer/base"),
                                     QStringLiteral("https://eth.blockscout.com")).toString());
    explorerEdit->setToolTip(tr("e.g. https://eth.blockscout.com or https://etherscan.io"));
    nodeForm->addRow(tr("Block explorer base URL"), explorerEdit);
    tabs->addTab(nodeTab, tr("Node"));

    // --- Security / General tab ---
    auto *secTab = new QWidget(&dlg);
    auto *secForm = new QFormLayout(secTab);
    auto *notifChk = new QCheckBox(tr("Show transaction notifications"), secTab);
    notifChk->setChecked(m_notifications);
    secForm->addRow(notifChk);
    auto *confirmChk = new QCheckBox(tr("Require password before sending"), secTab);
    confirmChk->setChecked(m_confirmSend);
    secForm->addRow(confirmChk);
    auto *lockMinSpin = new QSpinBox(secTab);
    lockMinSpin->setRange(0, 240);
    lockMinSpin->setSuffix(tr(" min"));
    lockMinSpin->setSpecialValueText(tr("Off"));
    lockMinSpin->setValue(m_autoLockMinutes);
    secForm->addRow(tr("Auto-lock after inactivity"), lockMinSpin);
    auto *lockMinChk = new QCheckBox(tr("Lock when minimized"), secTab);
    lockMinChk->setChecked(m_lockOnMinimize);
    secForm->addRow(lockMinChk);
    auto *clipSpin = new QSpinBox(secTab);
    clipSpin->setRange(0, 600);
    clipSpin->setSuffix(tr(" sec"));
    clipSpin->setSpecialValueText(tr("Never"));
    clipSpin->setValue(QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                           .value(QStringLiteral("security/clipboardClearSecs"), 30).toInt());
    secForm->addRow(tr("Clear clipboard after copying a seed/key"), clipSpin);
    tabs->addTab(secTab, tr("Security"));

    // --- Appearance tab ---
    auto *appTab = new QWidget(&dlg);
    auto *appForm = new QFormLayout(appTab);
    auto *hideBalances = new QCheckBox(tr("Hide balances"), appTab);
    hideBalances->setChecked(m_hideBalances);
    appForm->addRow(hideBalances);
    auto *hint = new QLabel(tr("Balances are replaced with dots in the status bar and Home."), appTab);
    hint->setStyleSheet(QStringLiteral("color:#8a8a8a; font-size:11px;"));
    appForm->addRow(hint);

    auto *nftTabChk = new QCheckBox(tr("Show NFTs tab"), appTab);
    nftTabChk->setChecked(m_nftEnabled);
    appForm->addRow(nftTabChk);
    auto *nftHint = new QLabel(
        tr("Adds a tab listing your ERC-721 / ERC-1155 collections (fetched over Tor). Off by "
           "default."),
        appTab);
    nftHint->setWordWrap(true);
    nftHint->setStyleSheet(QStringLiteral("color:#8a8a8a; font-size:11px;"));
    appForm->addRow(nftHint);

    auto *fiatCombo = new QComboBox(appTab);
    fiatCombo->addItems({QStringLiteral("USD"), QStringLiteral("EUR"), QStringLiteral("GBP"),
                         QStringLiteral("JPY"), QStringLiteral("CNY"), QStringLiteral("CAD"),
                         QStringLiteral("AUD"), QStringLiteral("CHF"), QStringLiteral("INR"),
                         QStringLiteral("KRW"), QStringLiteral("RUB"), QStringLiteral("BRL")});
    fiatCombo->setCurrentText(m_fiatCurrency);
    appForm->addRow(tr("Display currency"), fiatCombo);
    tabs->addTab(appTab, tr("Appearance"));

    // --- Spam filter tab ---
    auto *spamTab = new QWidget(&dlg);
    auto *spamForm = new QFormLayout(spamTab);
    auto *hideSpamChk = new QCheckBox(tr("Hide spam && address-poisoning transactions"), spamTab);
    hideSpamChk->setChecked(m_historyModel && m_historyModel->hideSpam());
    spamForm->addRow(hideSpamChk);
    auto *dustSpin = new QDoubleSpinBox(spamTab);
    dustSpin->setDecimals(3);
    dustSpin->setRange(0.0, 1000.0);
    dustSpin->setSingleStep(0.01); // arrows step by a cent; type 0.05 / 0.10 / 1 etc. directly
    dustSpin->setPrefix(QStringLiteral("$"));
    dustSpin->setValue(QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                           .value(QStringLiteral("history/dustUsd"), 0.005).toDouble());
    spamForm->addRow(tr("Hide transfers below"), dustSpin);
    auto *dustHint = new QLabel(
        tr("Transfers worth less than this (in USD) are treated as spam / address-poisoning and "
           "hidden from History \u2014 e.g. set $0.05 or $0.10 to hide low-value junk. Set $0.000 to "
           "disable the value threshold. Fake tokens and impersonation transfers are always hidden "
           "while the spam filter above is on, regardless of value."),
        spamTab);
    dustHint->setWordWrap(true);
    dustHint->setStyleSheet(QStringLiteral("color:#8a8a8a; font-size:11px;"));
    spamForm->addRow(dustHint);

    // Auto-trust threshold: unknown tokens with a DEX pool above this are shown (not hidden).
    auto *liqSpin = new QDoubleSpinBox(spamTab);
    liqSpin->setDecimals(0);
    liqSpin->setRange(0.0, 1'000'000'000.0);
    liqSpin->setSingleStep(100000.0);
    liqSpin->setGroupSeparatorShown(true);
    liqSpin->setPrefix(QStringLiteral("$"));
    liqSpin->setValue(QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                          .value(QStringLiteral("tokens/liquidityUsd"), 1000000.0).toDouble());
    spamForm->addRow(tr("Auto-trust tokens with liquidity above"), liqSpin);
    auto *liqHint = new QLabel(
        tr("An unknown ERC-20 seen in History is automatically trusted (and shown) if its deepest "
           "DEX pool holds at least this much USD liquidity (checked via DexScreener over Tor). "
           "Set $0 to disable auto-trust."),
        spamTab);
    liqHint->setWordWrap(true);
    liqHint->setStyleSheet(QStringLiteral("color:#8a8a8a; font-size:11px;"));
    spamForm->addRow(liqHint);

    auto *manageTokensBtn = new QPushButton(tr("Manage verified tokens\u2026"), spamTab);
    connect(manageTokensBtn, &QPushButton::clicked, this, &AeroMainWindow::showTokenSettings);
    spamForm->addRow(manageTokensBtn);
    tabs->addTab(spamTab, tr("Spam filter"));

    outer->addWidget(tabs);
    auto *box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    outer->addWidget(box);

    if (dlg.exec() != QDialog::Accepted) return;

    // Appearance.
    if (hideBalances->isChecked() != m_hideBalances) {
        m_hideBalances = hideBalances->isChecked();
        QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
            .setValue(QStringLiteral("appearance/hideBalances"), m_hideBalances);
        showCachedBalance(m_account);
        recomputeHomeTotal();
    }
    if (nftTabChk->isChecked() != m_nftEnabled)
        setNftTabEnabled(nftTabChk->isChecked());
    if (fiatCombo->currentText().toUpper() != m_fiatCurrency) {
        m_fiatCurrency = fiatCombo->currentText().toUpper();
        m_fiatSymbol = fiatSymbolFor(m_fiatCurrency);
        QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
            .setValue(QStringLiteral("appearance/fiat"), m_fiatCurrency);
        if (m_fiatCurrency == QLatin1String("USD"))
            onFiatRate(QStringLiteral("USD"), 1.0); // reset immediately
        else if (m_wallet)
            m_wallet->refreshFiatRate(m_fiatCurrency); // fetch rate; onFiatRate refreshes displays
    }
    {
        QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
        const double dust = dustSpin->value();
        s.setValue(QStringLiteral("history/dustUsd"), dust);
        const bool hideSpam = hideSpamChk->isChecked();
        s.setValue(QStringLiteral("history/hideSpam"), hideSpam);
        m_liquidityThresholdUsd = liqSpin->value();
        s.setValue(QStringLiteral("tokens/liquidityUsd"), m_liquidityThresholdUsd);
        if (m_historyModel) {
            m_historyModel->setDustThreshold(dust);
            m_historyModel->setHideSpam(hideSpam);
        }
        if (m_hideSpamAction) { // keep the History "..." menu toggle in sync
            QSignalBlocker block(m_hideSpamAction);
            m_hideSpamAction->setChecked(hideSpam);
        }
    }

    // Security / general + explorer.
    {
        QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
        m_notifications = notifChk->isChecked();
        m_confirmSend = confirmChk->isChecked();
        m_lockOnMinimize = lockMinChk->isChecked();
        m_autoLockMinutes = lockMinSpin->value();
        s.setValue(QStringLiteral("notifications/enabled"), m_notifications);
        s.setValue(QStringLiteral("security/confirmSend"), m_confirmSend);
        s.setValue(QStringLiteral("security/lockOnMinimize"), m_lockOnMinimize);
        s.setValue(QStringLiteral("security/autoLockMinutes"), m_autoLockMinutes);
        s.setValue(QStringLiteral("security/clipboardClearSecs"), clipSpin->value());
        QString base = explorerEdit->text().trimmed();
        while (base.endsWith(QLatin1Char('/'))) base.chop(1);
        if (!base.isEmpty())
            s.setValue(QStringLiteral("explorer/base"), base);
        if (m_idleTimer) {
            if (m_autoLockMinutes > 0)
                m_idleTimer->start(m_autoLockMinutes * 60000);
            else
                m_idleTimer->stop();
        }
    }

    // Node / network. Persist the custom node PER CHAIN so it survives reconnects/restarts, then
    // reconnect using it. Leaving the RPC field equal to the defaults clears the override.
    if (m_wallet) {
        const quint64 chainId = chainEdit->text().toULongLong();
        QStringList endpoints;
        for (const QString &e : rpcEdit->text().split(QLatin1Char(','), Qt::SkipEmptyParts))
            endpoints << e.trimmed();
        QString socks = socksEdit->text().trimmed();
        if (socks.compare(QStringLiteral("none"), Qt::CaseInsensitive) == 0) socks.clear();

        QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
        const QString rpcKey = QStringLiteral("node/%1/rpc").arg(chainId);
        const QString socksKey = QStringLiteral("node/%1/socks").arg(chainId);
        // If the entered endpoints match the bundled defaults, treat it as "no custom node".
        if (endpoints.isEmpty() || endpoints == chainDefFor(chainId).rpcs) {
            s.remove(rpcKey);
            s.remove(socksKey);
        } else {
            s.setValue(rpcKey, endpoints.join(QStringLiteral(", ")));
            s.setValue(socksKey, socks); // may be "" => direct/own node
        }
        s.sync();

        // Reflect the possibly-changed chain so downstream labels/explorer stay consistent.
        if (chainId != m_chainId && chainDefFor(chainId).id == chainId) {
            switchChain(chainId);
        } else {
            m_chainId = chainId;
            setConnectionState(0, tr("Connecting…"));
            m_wallet->connectProvider(chainId, endpoints, socks); // result via onProviderConnected()
        }
    }
}

void AeroMainWindow::showTokenSettings() {
    if (!m_wallet) return;

    // Kind stored per row so we know how to apply changes on OK.
    enum Kind { Curated = 0, Tracked = 1, New = 2 };
    const int RoleAddr = Qt::UserRole, RoleSym = Qt::UserRole + 1, RoleDec = Qt::UserRole + 2,
              RoleKind = Qt::UserRole + 3;

    QSettings settings(QStringLiteral("Aero"), QStringLiteral("Aero"));
    QSet<QString> disabled;
    for (const QString &a : settings.value(QStringLiteral("tokens/disabled")).toStringList())
        disabled.insert(a.toLower());

    QSet<QString> trackedAddrs;
    for (const TokenInfo &t : m_wallet->tokens())
        trackedAddrs.insert(t.address.toLower());

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Verified tokens"));
    dlg.setMinimumSize(480, 460);
    auto *v = new QVBoxLayout(&dlg);
    auto *info = new QLabel(
        tr("Checked tokens are trusted in History (never hidden as spam). Uncheck to distrust. "
           "Tokens you add are also tracked for balances. Unknown tokens are treated as spam."),
        &dlg);
    info->setWordWrap(true);
    v->addWidget(info);

    auto *list = new QListWidget(&dlg);
    v->addWidget(list, 1);

    auto addRow = [&](const QString &addr, const QString &sym, quint8 dec, int kind, bool checked) {
        auto *it = new QListWidgetItem(QStringLiteral("%1    %2").arg(sym, shortAddr(addr)), list);
        it->setFlags(it->flags() | Qt::ItemIsUserCheckable);
        it->setCheckState(checked ? Qt::Checked : Qt::Unchecked);
        it->setData(RoleAddr, addr);
        it->setData(RoleSym, sym);
        it->setData(RoleDec, dec);
        it->setData(RoleKind, kind);
    };

    // Curated top tokens that aren't already tracked by the wallet.
    for (const TokenInfo &t : curatedTopTokens())
        if (!trackedAddrs.contains(t.address.toLower()))
            addRow(t.address, t.symbol, t.decimals, Curated, !disabled.contains(t.address.toLower()));
    // Wallet-tracked tokens (the defaults + anything imported) — always shown, checked.
    for (const TokenInfo &t : m_wallet->tokens())
        addRow(t.address, t.symbol, t.decimals, Tracked, true);

    // Import form.
    auto *addRowLayout = new QHBoxLayout();
    auto *addrEdit = new QLineEdit(&dlg);
    addrEdit->setPlaceholderText(tr("0x contract address"));
    auto *symEdit = new QLineEdit(&dlg);
    symEdit->setPlaceholderText(tr("symbol"));
    symEdit->setMaximumWidth(80);
    auto *decEdit = new QLineEdit(QStringLiteral("18"), &dlg);
    decEdit->setPlaceholderText(tr("dec"));
    decEdit->setMaximumWidth(50);
    auto *addBtn = new QPushButton(tr("Add"), &dlg);
    addRowLayout->addWidget(addrEdit, 1);
    addRowLayout->addWidget(symEdit);
    addRowLayout->addWidget(decEdit);
    addRowLayout->addWidget(addBtn);
    v->addLayout(addRowLayout);

    connect(addBtn, &QPushButton::clicked, &dlg, [&]() {
        const QString addr = addrEdit->text().trimmed();
        if (!addr.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) || addr.size() != 42) {
            QMessageBox::warning(&dlg, tr("Add token"), tr("Enter a valid 0x contract address."));
            return;
        }
        const QString sym = symEdit->text().trimmed().isEmpty() ? tr("TOKEN") : symEdit->text().trimmed();
        addRow(addr, sym, static_cast<quint8>(decEdit->text().toUInt()), New, true);
        addrEdit->clear();
        symEdit->clear();
        decEdit->setText(QStringLiteral("18"));
    });

    auto *box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    v->addWidget(box);

    if (dlg.exec() != QDialog::Accepted) return;

    // Apply: rebuild the disabled set and reconcile tracked tokens.
    QStringList newDisabled;
    bool walletChanged = false;
    for (int i = 0; i < list->count(); ++i) {
        QListWidgetItem *it = list->item(i);
        const QString addr = it->data(RoleAddr).toString();
        const bool checked = it->checkState() == Qt::Checked;
        const int kind = it->data(RoleKind).toInt();
        if (kind == Curated) {
            if (!checked) newDisabled << addr;
        } else if (kind == Tracked) {
            if (!checked) { m_wallet->removeToken(addr); walletChanged = true; newDisabled << addr; }
        } else { // New
            if (checked) {
                m_wallet->addToken({addr, it->data(RoleSym).toString(),
                                    static_cast<quint8>(it->data(RoleDec).toUInt())});
                walletChanged = true;
            }
        }
    }
    settings.setValue(QStringLiteral("tokens/disabled"), newDisabled);
    if (walletChanged)
        m_wallet->save();

    applyVerifiedTokens();
    rebuildAccountCombos();
    populateSendCurrencies();
    updateHistoryPricing();
    refreshAllBalances();
    updateReceive();
}

void AeroMainWindow::onChangePassword() {
    if (!m_wallet) return;
    if (m_wallet->walletPath().isEmpty()) {
        QMessageBox::information(this, tr("Change password"),
                                 tr("This wallet isn't saved to a file, so it has no password."));
        return;
    }
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Change password"));
    auto *form = new QFormLayout(&dlg);
    auto *p1 = new QLineEdit(&dlg);
    p1->setEchoMode(QLineEdit::Password);
    auto *p2 = new QLineEdit(&dlg);
    p2->setEchoMode(QLineEdit::Password);
    form->addRow(tr("New password"), p1);
    form->addRow(tr("Confirm password"), p2);
    auto *box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(box);
    if (dlg.exec() != QDialog::Accepted) return;

    if (p1->text() != p2->text()) {
        QMessageBox::warning(this, tr("Change password"), tr("Passwords do not match."));
        return;
    }
    // An empty password still encrypts the file, but with a trivially-derivable key — warn before
    // effectively removing the passphrase protection.
    if (p1->text().isEmpty() &&
        QMessageBox::warning(
            this, tr("Change password"),
            tr("An empty password offers no protection — anyone with the wallet file could open "
               "it.\n\nContinue without a password?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;
    // store() re-encrypts (fresh salt + nonce) with the new password and retains it for future
    // saves. The write is atomic, so a crash mid-change can't corrupt or lose the wallet.
    if (m_wallet->store(m_wallet->walletPath(), p1->text()))
        QMessageBox::information(this, tr("Change password"), tr("Password updated."));
    else
        QMessageBox::warning(this, tr("Change password"), m_wallet->errorString());
}

void AeroMainWindow::onSignVerifyMessage() {
    if (!m_wallet) return;
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Sign / Verify Message"));
    dlg.setMinimumWidth(540);
    auto *v = new QVBoxLayout(&dlg);

    auto *form = new QFormLayout();
    auto *accountCombo = new QComboBox(&dlg);
    const quint32 n = m_wallet->numAccounts();
    for (quint32 i = 0; i < n; ++i)
        accountCombo->addItem(accountLabel(i));
    if (static_cast<int>(m_account) < accountCombo->count())
        accountCombo->setCurrentIndex(static_cast<int>(m_account));
    form->addRow(tr("Account (for signing)"), accountCombo);
    v->addLayout(form);

    v->addWidget(new QLabel(tr("Message"), &dlg));
    auto *msg = new QPlainTextEdit(&dlg);
    msg->setMinimumHeight(90);
    v->addWidget(msg);

    v->addWidget(new QLabel(tr("Signature"), &dlg));
    auto *sig = new QLineEdit(&dlg);
    sig->setPlaceholderText(tr("0x… — produced by Sign, or paste a signature to Verify"));
    v->addWidget(sig);

    auto *result = new QLabel(&dlg);
    result->setWordWrap(true);
    result->setTextInteractionFlags(Qt::TextSelectableByMouse);
    v->addWidget(result);

    auto *row = new QHBoxLayout();
    auto *signBtn = new QPushButton(tr("Sign"), &dlg);
    auto *verifyBtn = new QPushButton(tr("Verify"), &dlg);
    auto *copyBtn = new QPushButton(tr("Copy signature"), &dlg);
    auto *closeBtn = new QPushButton(tr("Close"), &dlg);
    row->addWidget(signBtn);
    row->addWidget(verifyBtn);
    row->addWidget(copyBtn);
    row->addStretch();
    row->addWidget(closeBtn);
    v->addLayout(row);

    connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    connect(copyBtn, &QPushButton::clicked, &dlg, [sig]() {
        const QString s = sig->text().trimmed();
        if (!s.isEmpty())
            QApplication::clipboard()->setText(s);
    });
    connect(signBtn, &QPushButton::clicked, &dlg, [this, accountCombo, msg, sig, result]() {
        if (m_wallet->isHardware()) {
            result->setText(tr("<span style='color:#e0b040;'>Message signing on the device isn't "
                               "supported here yet.</span>"));
            return;
        }
        const quint32 idx = static_cast<quint32>(qMax(0, accountCombo->currentIndex()));
        const QString s = m_wallet->signMessage(idx, msg->toPlainText());
        if (s.isEmpty()) {
            result->setText(tr("<span style='color:#e74c3c;'>Sign failed: %1</span>")
                                .arg(m_wallet->errorString().toHtmlEscaped()));
            return;
        }
        sig->setText(s);
        result->setText(tr("<span style='color:#27ae60;'>Signed with %1</span>")
                            .arg(m_wallet->address(idx)));
    });
    connect(verifyBtn, &QPushButton::clicked, &dlg, [this, msg, sig, result]() {
        const QString recovered = m_wallet->verifyMessage(msg->toPlainText(), sig->text().trimmed());
        if (recovered.isEmpty()) {
            result->setText(tr("<span style='color:#e74c3c;'>Invalid signature — could not "
                               "recover a signer.</span>"));
            return;
        }
        bool mine = false;
        const quint32 n2 = m_wallet->numAccounts();
        for (quint32 i = 0; i < n2; ++i)
            if (m_wallet->address(i).compare(recovered, Qt::CaseInsensitive) == 0) {
                mine = true;
                break;
            }
        result->setText(tr("<span style='color:#27ae60;'>Signed by %1%2</span>")
                            .arg(recovered, mine ? tr("  (one of your accounts)") : QString()));
    });

    dlg.exec();
}

void AeroMainWindow::onBroadcastRaw() {
    if (!m_wallet) return;
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Broadcast Raw Transaction"));
    dlg.setMinimumWidth(540);
    auto *v = new QVBoxLayout(&dlg);
    v->addWidget(new QLabel(
        tr("Paste a signed raw transaction (0x…). It will be broadcast over Tor. Use this to relay "
           "a transaction signed on an offline machine."),
        &dlg));
    auto *edit = new QPlainTextEdit(&dlg);
    edit->setMinimumHeight(120);
    edit->setPlaceholderText(QStringLiteral("0x02f8…"));
    v->addWidget(edit);
    auto *box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    box->button(QDialogButtonBox::Ok)->setText(tr("Broadcast"));
    v->addWidget(box);
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    if (dlg.exec() != QDialog::Accepted)
        return;
    const QString raw = edit->toPlainText().trimmed();
    if (raw.isEmpty())
        return;
    m_wallet->broadcastRaw(raw); // result surfaces via onTransactionCommitted
}

void AeroMainWindow::onUnsignedTxReady(const QString &json, const QString &error) {
    if (!error.isEmpty() || json.isEmpty()) {
        QMessageBox::warning(this, tr("Export unsigned transaction"),
                             error.isEmpty() ? tr("Could not build the transaction.") : error);
        return;
    }
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Unsigned transaction"));
    dlg.setMinimumWidth(560);
    auto *v = new QVBoxLayout(&dlg);
    v->addWidget(new QLabel(
        tr("Move this to your offline wallet and sign it there (Tools → Sign Unsigned "
           "Transaction), then broadcast the signed result here (Tools → Broadcast Raw "
           "Transaction)."),
        &dlg));
    auto *edit = new QPlainTextEdit(&dlg);
    edit->setReadOnly(true);
    edit->setPlainText(json);
    edit->setMinimumHeight(150);
    v->addWidget(edit);
    auto *row = new QHBoxLayout();
    auto *copyBtn = new QPushButton(tr("Copy"), &dlg);
    auto *saveBtn = new QPushButton(tr("Save to file…"), &dlg);
    auto *closeBtn = new QPushButton(tr("Close"), &dlg);
    row->addWidget(copyBtn);
    row->addWidget(saveBtn);
    row->addStretch();
    row->addWidget(closeBtn);
    v->addLayout(row);
    connect(copyBtn, &QPushButton::clicked, &dlg, [json]() { QApplication::clipboard()->setText(json); });
    connect(saveBtn, &QPushButton::clicked, &dlg, [this, json]() {
        const QString f = QFileDialog::getSaveFileName(this, tr("Save unsigned transaction"),
                                                       QStringLiteral("unsigned-tx.json"),
                                                       tr("JSON (*.json)"));
        if (f.isEmpty()) return;
        QFile out(f);
        if (out.open(QIODevice::WriteOnly | QIODevice::Text))
            out.write(json.toUtf8());
    });
    connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    dlg.exec();
}

void AeroMainWindow::onSignUnsigned() {
    if (!m_wallet) return;
    if (m_wallet->isWatchOnly()) {
        QMessageBox::information(this, tr("Sign unsigned transaction"),
                                 tr("This wallet is watch-only (no keys). Open the wallet that owns "
                                    "the address on an offline machine to sign."));
        return;
    }
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Sign Unsigned Transaction"));
    dlg.setMinimumWidth(560);
    auto *v = new QVBoxLayout(&dlg);
    v->addWidget(new QLabel(tr("Paste an unsigned transaction (JSON exported from a watch-only "
                               "wallet). It is signed locally — no network is used."),
                            &dlg));
    auto *in = new QPlainTextEdit(&dlg);
    in->setMinimumHeight(120);
    v->addWidget(in);
    auto *signBtn = new QPushButton(tr("Sign"), &dlg);
    v->addWidget(signBtn);
    v->addWidget(new QLabel(tr("Signed raw transaction (broadcast this on an online wallet):"), &dlg));
    auto *out = new QPlainTextEdit(&dlg);
    out->setReadOnly(true);
    out->setMinimumHeight(90);
    v->addWidget(out);
    auto *row = new QHBoxLayout();
    auto *copyBtn = new QPushButton(tr("Copy raw tx"), &dlg);
    auto *closeBtn = new QPushButton(tr("Close"), &dlg);
    row->addWidget(copyBtn);
    row->addStretch();
    row->addWidget(closeBtn);
    v->addLayout(row);
    connect(signBtn, &QPushButton::clicked, &dlg, [this, in, out]() {
        const QString raw = m_wallet->signUnsigned(in->toPlainText().trimmed());
        if (raw.isEmpty())
            out->setPlainText(tr("Sign failed: %1").arg(m_wallet->errorString()));
        else
            out->setPlainText(raw);
    });
    connect(copyBtn, &QPushButton::clicked, &dlg, [out]() {
        const QString s = out->toPlainText().trimmed();
        if (s.startsWith(QLatin1String("0x")))
            QApplication::clipboard()->setText(s);
    });
    connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    dlg.exec();
}

void AeroMainWindow::onTransactionSent(const PendingEthTx &tx, const QString &txHash) {
    Q_UNUSED(txHash);
    m_lastSent = tx; // carries the nonce it was broadcast at
    m_hasPending = true;
    if (m_speedUpAction) m_speedUpAction->setEnabled(true);
    if (m_cancelTxAction) m_cancelTxAction->setEnabled(true);
}

// A generous replacement fee (wei) computed from current market fees, so it reliably out-bids a
// stuck low-fee transaction (nodes require a replacement to pay meaningfully more gas).
QPair<QString, QString> AeroMainWindow::bumpedFeeWei() const {
    const double base = m_feeBaseWei > 0 ? m_feeBaseWei : 2e9;
    const double tip = m_feeTipWei > 0 ? m_feeTipWei : 1e9;
    const double priority = qMax(tip * 2.0, 2e9);   // at least ~2 gwei tip
    const double maxFee = base * 3.0 + priority;     // generous cap to ensure the replacement wins
    return {QString::number(maxFee, 'f', 0), QString::number(priority, 'f', 0)};
}

void AeroMainWindow::onSpeedUpLast() {
    if (!m_wallet || !m_hasPending) return;
    if (QMessageBox::question(
            this, tr("Speed up transaction"),
            tr("Rebroadcast the last transaction at the same nonce with a higher fee so it confirms "
               "faster?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes) != QMessageBox::Yes)
        return;
    PendingEthTx tx = m_lastSent; // same recipient/value/token and (crucially) the same nonce
    const QPair<QString, QString> fee = bumpedFeeWei();
    tx.fee.maxFee = fee.first;
    tx.fee.maxPriorityFee = fee.second;
    m_wallet->commitTransaction(tx); // result surfaces via onTransactionCommitted
}

void AeroMainWindow::onCancelLast() {
    if (!m_wallet || !m_hasPending) return;
    if (QMessageBox::question(
            this, tr("Cancel transaction"),
            tr("Attempt to cancel the last pending transaction by replacing it with a 0-value "
               "transfer to yourself (at a higher fee)? This only works if it hasn't confirmed yet."),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;
    const QPair<QString, QString> fee = bumpedFeeWei();
    m_wallet->cancelTransaction(m_lastSent.fromIndex, m_lastSent.nonce, fee.first, fee.second);
}

void AeroMainWindow::onShowSeed() {
    if (!m_wallet) return;
    if (m_wallet->isHardware()) {
        QMessageBox::information(this, tr("Show seed"),
                                 tr("This is a hardware wallet — the seed stays on your device and "
                                    "is never shown here."));
        return;
    }
    if (QMessageBox::warning(
            this, tr("Show seed"),
            tr("Your seed phrase controls all your funds. Never share it, and make sure no one is "
               "watching your screen.\n\nReveal it now?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;

    const QString seed = m_wallet->getSeed();
    if (seed.isEmpty()) {
        QMessageBox::warning(this, tr("Show seed"), tr("No seed available for this wallet."));
        return;
    }

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Seed phrase"));
    dlg.setMinimumWidth(460);
    auto *v = new QVBoxLayout(&dlg);
    auto *warn = new QLabel(tr("Write these words down and keep them offline and secret."), &dlg);
    warn->setWordWrap(true);
    v->addWidget(warn);
    QFont mono;
    mono.setFamily(QStringLiteral("monospace"));
    mono.setStyleHint(QFont::TypeWriter);
    auto *seedLabel = new QLabel(seed, &dlg);
    seedLabel->setWordWrap(true);
    seedLabel->setFont(mono);
    seedLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    seedLabel->setStyleSheet(QStringLiteral("padding:8px; border:1px solid #555;"));
    v->addWidget(seedLabel);
    auto *copyBtn = new QPushButton(tr("Copy to clipboard"), &dlg);
    connect(copyBtn, &QPushButton::clicked, &dlg,
            [this, seed]() { copySensitive(seed); });
    v->addWidget(copyBtn);
    auto *box = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    v->addWidget(box);
    dlg.exec();
}

void AeroMainWindow::onRefresh() {
    if (!m_wallet) return;
    // Manual refresh: batched balances + history + prices + fees. No per-account fan-out.
    refreshAllBalances();
    refreshHistoryView();
    m_wallet->refreshEthUsdPrice();
    m_wallet->refreshMarketPrices();
    m_wallet->refreshFees();
}

static bool isStablecoin(const QString &symbol) {
    const QString s = symbol.toUpper();
    return s == "USDT" || s == "USDC" || s == "DAI";
}

double AeroMainWindow::unitPriceUsd(const QString &symbol) const {
    const QString s = symbol.toUpper();
    if (s == m_nativeSymbol.toUpper()) return m_nativeUsd;
    // WETH tracks ETH — only equal to the native price on ETH-native chains (not e.g. Polygon/POL).
    if (s == "WETH" && m_nativeSymbol.compare(QStringLiteral("ETH"), Qt::CaseInsensitive) == 0)
        return m_nativeUsd;
    if (isStablecoin(s)) return 1.0; // stablecoins ~ $1
    return 0.0; // unknown -> no conversion
}

void AeroMainWindow::onEthUsdPrice(double usdPerEth) {
    m_nativeUsd = usdPerEth;
    // On non-ETH chains the Home native ticker is driven by this chain-aware price.
    if (m_homeEthValue && m_nativeSymbol.compare(QStringLiteral("ETH"), Qt::CaseInsensitive) != 0) {
        m_homeEthValue->setText(m_nativeUsd > 0 ? fiatStr(m_nativeUsd) : QStringLiteral("—"));
        if (m_homeEthPct) m_homeEthPct->clear();
    }
    onAmountConversion();
    recomputeHomeTotal(); // native valuation uses the chain-aware price
    updateFeeEstimate();  // fee is also shown in USD
    updateHistoryPricing(); // dust filter values incoming transfers in USD
}

QString AeroMainWindow::fiatStr(double usd) const {
    return QStringLiteral("%1%2").arg(m_fiatSymbol, grouped(QString::number(usd * m_fiatRate, 'f', 2)));
}

void AeroMainWindow::onFiatRate(const QString &currency, double rate) {
    if (currency.compare(m_fiatCurrency, Qt::CaseInsensitive) != 0)
        return; // stale (user changed currency again)
    m_fiatRate = rate > 0.0 ? rate : 1.0;
    // Refresh every surface that shows a fiat value.
    recomputeHomeTotal();
    showCachedBalance(m_account);
    updateHistoryPricing();
    if (m_historyModel)
        m_historyModel->setFiat(m_fiatRate, m_fiatSymbol);
}

void AeroMainWindow::updateHistoryPricing() {
    if (!m_historyModel) return;
    QHash<QString, double> prices;
    prices.insert(m_nativeSymbol.toUpper(), unitPriceUsd(m_nativeSymbol));
    if (m_wallet)
        for (const TokenInfo &t : m_wallet->tokens())
            prices.insert(t.symbol.toUpper(), unitPriceUsd(t.symbol));
    m_historyModel->setPrices(prices);
}

QSet<QString> AeroMainWindow::verifiedTokenAddresses() const {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    QSet<QString> disabled;
    for (const QString &a : s.value(QStringLiteral("tokens/disabled")).toStringList())
        disabled.insert(a.toLower());
    QSet<QString> out;
    for (const TokenInfo &t : curatedTopTokens())
        if (!disabled.contains(t.address.toLower()))
            out.insert(t.address.toLower());
    if (m_wallet) // balance-tracked tokens (the defaults + anything the user imported) are trusted
        for (const TokenInfo &t : m_wallet->tokens())
            out.insert(t.address.toLower());
    out.unite(m_liquidityVerified); // tokens auto-trusted by having a deep DEX pool
    return out;
}

void AeroMainWindow::applyVerifiedTokens() {
    if (m_historyModel)
        m_historyModel->setKnownTokens(verifiedTokenAddresses());
}

void AeroMainWindow::loadLiquidityCache() {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    m_liquidityThresholdUsd = s.value(QStringLiteral("tokens/liquidityUsd"), 1000000.0).toDouble();
    m_liquidityVerified.clear();
    for (const QString &a : s.value(QStringLiteral("tokens/liquidityVerified")).toStringList())
        m_liquidityVerified.insert(a.toLower());
    m_liquidityChecked.clear();
    for (const QString &a : s.value(QStringLiteral("tokens/liquidityChecked")).toStringList())
        m_liquidityChecked.insert(a.toLower());
}

void AeroMainWindow::checkUntrackedTokenLiquidity() {
    if (!m_wallet || !m_historyModel)
        return;
    int budget = 15; // cap DexScreener calls per refresh so spam-heavy wallets don't hammer it
    for (const QString &addr : m_historyModel->untrackedTokenAddresses()) {
        if (budget <= 0)
            break;
        const QString a = addr.toLower();
        if (m_liquidityVerified.contains(a) || m_liquidityChecked.contains(a) ||
            m_liquidityInFlight.contains(a))
            continue; // already decided or in progress
        m_liquidityInFlight.insert(a);
        m_wallet->checkTokenLiquidity(a);
        --budget;
    }
}

void AeroMainWindow::onTokenLiquidity(const QString &tokenAddress, double usd) {
    const QString a = tokenAddress.toLower();
    m_liquidityInFlight.remove(a);
    m_liquidityChecked.insert(a);
    const bool trusted = usd >= m_liquidityThresholdUsd;
    if (trusted)
        m_liquidityVerified.insert(a);

    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    s.setValue(QStringLiteral("tokens/liquidityChecked"),
               QStringList(m_liquidityChecked.values()));
    if (trusted) {
        s.setValue(QStringLiteral("tokens/liquidityVerified"),
                   QStringList(m_liquidityVerified.values()));
        applyVerifiedTokens(); // token is now trusted -> its history rows become visible
    }
}

void AeroMainWindow::onMarketPrices(double xmrUsd, double xmrChangePct, double ethUsd,
                                     double ethChangePct) {
    m_xmrUsd = xmrUsd;
    auto setTicker = [this](QLabel *value, QLabel *pct, double price, double chg) {
        if (value)
            value->setText(price > 0 ? fiatStr(price) : QStringLiteral("—"));
        if (pct) {
            const bool up = chg >= 0.0;
            pct->setText(QStringLiteral("<span style=\"color:%1;\">%2%3%</span>")
                             .arg(up ? QStringLiteral("#27ae60") : QStringLiteral("#e74c3c"),
                                  up ? QStringLiteral("+") : QString(),
                                  QString::number(chg, 'f', 1)));
        }
    };
    setTicker(m_homeXmrValue, m_homeXmrPct, xmrUsd, xmrChangePct);
    // The market feed only carries ETH; on ETH-native chains use it (with 24h change). On other
    // chains the native ticker is driven by the chain-aware native price (no 24h change available).
    if (m_nativeSymbol.compare(QStringLiteral("ETH"), Qt::CaseInsensitive) == 0)
        setTicker(m_homeEthValue, m_homeEthPct, ethUsd, ethChangePct);
    else {
        if (m_homeEthValue)
            m_homeEthValue->setText(m_nativeUsd > 0 ? fiatStr(m_nativeUsd) : QStringLiteral("—"));
        if (m_homeEthPct)
            m_homeEthPct->clear();
    }
}

void AeroMainWindow::recomputeHomeTotal() {
    if (!m_homeTotalValue) return;
    double total = 0.0;
    for (auto it = m_ethRawByAccount.constBegin(); it != m_ethRawByAccount.constEnd(); ++it)
        total += it.value() * m_nativeUsd;
    const QVector<TokenInfo> toks = m_wallet ? m_wallet->tokens() : QVector<TokenInfo>();
    for (auto it = m_tokenRawByKey.constBegin(); it != m_tokenRawByKey.constEnd(); ++it) {
        const QString tokenAddr = it.key().section(QLatin1Char('|'), 1);
        QString sym;
        for (const TokenInfo &t : toks)
            if (t.address.compare(tokenAddr, Qt::CaseInsensitive) == 0) {
                sym = t.symbol;
                break;
            }
        total += it.value() * unitPriceUsd(sym);
    }
    const QString shown = m_hideBalances ? QStringLiteral("\u2022\u2022\u2022\u2022") : fiatStr(total);
    m_homeTotalValue->setText(shown);
    if (m_recvTotalLabel)
        m_recvTotalLabel->setText(m_hideBalances ? tr("Total balance: hidden")
                                                 : tr("Total balance: %1").arg(shown));
}

// Rebuild the amount-unit selector for the currently selected send currency. ETH lets you enter
// The ETH/USD unit selector is only meaningful for ETH & WETH; stablecoins are already ~USD, so
// the whole selector is hidden for them.
void AeroMainWindow::updateAmountUnit() {
    if (!m_amountUnit) return;
    const QString sym = currentSymbol();
    if (isStablecoin(sym)) {
        m_amountUnit->hide();
        return;
    }
    QSignalBlocker block(m_amountUnit);
    m_amountUnit->clear();
    m_amountUnit->addItem(sym);                   // enter in the token
    m_amountUnit->addItem(QStringLiteral("USD")); // or in USD
    m_amountUnit->setCurrentIndex(1);             // default to USD for ETH/WETH
    m_amountUnit->show();
}

void AeroMainWindow::onAmountConversion() {
    bool ok = false;
    const double amount = sendUi.lineAmount->text().trimmed().toDouble(&ok);
    if (!ok || amount <= 0) {
        sendUi.label_conversionAmount->clear();
        return;
    }
    const QString sym = currentSymbol();
    // Stablecoins are ~$1: always show the USD (fiat) value, never an ETH figure.
    if (isStablecoin(sym)) {
        sendUi.label_conversionAmount->setText(tr("\u2248 %1").arg(fiatStr(amount)));
        return;
    }
    const double price = unitPriceUsd(sym);
    if (price <= 0) {
        sendUi.label_conversionAmount->setText(tr("(no price)"));
        return;
    }
    // If the amount is being entered in USD (ETH/WETH only), show the token equivalent; otherwise
    // show the USD value.
    const bool inUsd = m_amountUnit && m_amountUnit->isVisible() &&
                       m_amountUnit->currentText().compare(QStringLiteral("USD"), Qt::CaseInsensitive) == 0;
    if (inUsd)
        sendUi.label_conversionAmount->setText(
            tr("\u2248 %1 %2").arg(grouped(QString::number(amount / price, 'f', 6)), sym));
    else
        sendUi.label_conversionAmount->setText(tr("\u2248 %1").arg(fiatStr(amount * price)));
}

void AeroMainWindow::onBalanceUpdated(const BalanceInfo &eth, const QVector<BalanceInfo> &tokens) {
    double totalUsd = eth.formatted.toDouble() * unitPriceUsd(m_nativeSymbol);
    for (const BalanceInfo &t : tokens)
        totalUsd += t.formatted.toDouble() * unitPriceUsd(t.symbol);

    // Overall balance for the account, shown at the very bottom (status bar).
    QString status = tr("Balance: %1 %2").arg(formatBalance(eth.formatted), eth.symbol);
    if (totalUsd > 0)
        status += tr("   \u2248 %1").arg(fiatStr(totalUsd));
    m_balanceLabel->setText(m_hideBalances ? tr("Balance: hidden") : status);
}

void AeroMainWindow::populateSendCurrencies() {
    // The picker is built on demand; here we just reset the selected asset to the native coin.
    setSendAsset(m_nativeSymbol, QString(), 18);
}

void AeroMainWindow::openTokenPicker() {
    if (!m_wallet || !m_assetButton) return;

    // A Qt::Popup so clicking anywhere outside dismisses it (like a combo dropdown) — no forced "X".
    auto *popup = new QWidget(this, Qt::Popup);
    popup->setAttribute(Qt::WA_DeleteOnClose);
    popup->setObjectName(QStringLiteral("tokenPicker"));
    auto *v = new QVBoxLayout(popup);
    v->setContentsMargins(6, 6, 6, 6);
    auto *search = new QLineEdit(popup);
    search->setPlaceholderText(tr("Search symbol, or paste a 0x contract address"));
    v->addWidget(search);
    auto *list = new QListWidget(popup);
    v->addWidget(list, 1);

    // Only show assets the wallet has actually touched (held a balance in, or seen in history) and
    // that are verified — never the full curated list of tokens the wallet never interacted with.
    QSet<QString> touched;
    for (auto it = m_tokenRawByKey.constBegin(); it != m_tokenRawByKey.constEnd(); ++it)
        if (it.value() > 0.0)
            touched.insert(it.key().section(QLatin1Char('|'), 1).toLower());
    if (m_historyModel)
        for (int r = 0; r < m_historyModel->rowCount(); ++r) {
            const HistoryItem h = m_historyModel->itemAt(r);
            if (!h.token.isEmpty())
                touched.insert(h.token.toLower());
        }
    const QSet<QString> verified = verifiedTokenAddresses();

    struct Asset { QString symbol, address; quint8 decimals; };
    auto *assets = new QVector<Asset>();
    QSet<QString> seen;
    assets->push_back({m_nativeSymbol, QString(), 18}); // native coin is always available
    auto addAsset = [&](const QString &sym, const QString &addr, quint8 dec) {
        const QString key = addr.toLower();
        if (addr.isEmpty() || seen.contains(key))
            return;
        if (!touched.contains(key) || !verified.contains(key))
            return; // only wallet-touched, verified tokens (paste a contract for anything else)
        seen.insert(key);
        assets->push_back({sym, addr, dec});
    };
    for (const TokenInfo &t : m_wallet->tokens())   // tracked (metadata source)
        addAsset(t.symbol, t.address, t.decimals);
    for (const TokenInfo &t : curatedTopTokens())   // verified curated (metadata source)
        addAsset(t.symbol, t.address, t.decimals);

    // Held balance for an asset at the current "From" account ("" => ETH). -1 == unknown.
    const int fromIndex = m_fromCombo ? qMax(0, m_fromCombo->currentIndex()) : 0;
    auto heldBalance = [this, fromIndex](const QString &addr) -> double {
        if (addr.isEmpty())
            return m_ethRawByAccount.value(fromIndex, 0.0);
        return m_tokenRawByKey.value(QStringLiteral("%1|%2").arg(fromIndex).arg(addr), -1.0);
    };

    auto rebuild = [=](const QString &filter) {
        list->clear();
        const QString f = filter.trimmed();
        for (int i = 0; i < assets->size(); ++i) {
            const Asset &a = assets->at(i);
            if (!f.isEmpty() && !a.symbol.contains(f, Qt::CaseInsensitive) &&
                !a.address.contains(f, Qt::CaseInsensitive))
                continue;
            QString text = a.address.isEmpty()
                               ? a.symbol
                               : QStringLiteral("%1   %2").arg(a.symbol, shortAddr(a.address));
            const double bal = heldBalance(a.address);
            if (bal >= 0.0) // show the available balance for this token
                text += QStringLiteral("      %1 %2").arg(formatBalance(bal), a.symbol);
            auto *it = new QListWidgetItem(tokenIcon(a.symbol), text, list);
            it->setData(Qt::UserRole, i);
        }
        // Offer to look up a pasted-but-unknown contract address.
        if (f.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) && f.size() == 42 &&
            !seen.contains(f.toLower())) {
            auto *it = new QListWidgetItem(tr("Look up token %1 …").arg(shortAddr(f)), list);
            it->setData(Qt::UserRole, -1);
            it->setData(Qt::UserRole + 1, f);
        }
    };
    rebuild(QString());
    connect(search, &QLineEdit::textChanged, popup, [=](const QString &t) { rebuild(t); });

    auto activate = [this, popup, assets](QListWidgetItem *it) {
        const int i = it->data(Qt::UserRole).toInt();
        if (i >= 0) {
            const Asset &a = assets->at(i);
            setSendAsset(a.symbol, a.address, a.decimals);
        } else {
            // Pasted contract: resolve on-chain over Tor; onTokenMetaResolved sets the asset.
            m_pendingSendAsset = it->data(Qt::UserRole + 1).toString();
            m_assetButton->setText(tr("Looking up… \u25be"));
            m_wallet->resolveTokenMeta(m_pendingSendAsset);
        }
        popup->close();
    };
    connect(list, &QListWidget::itemClicked, popup, activate);
    connect(list, &QListWidget::itemActivated, popup, activate);
    connect(popup, &QObject::destroyed, [assets]() { delete assets; }); // free the candidate list

    popup->resize(qMax(320, m_assetButton->width() * 2), 420);
    popup->move(m_assetButton->mapToGlobal(QPoint(0, m_assetButton->height())));
    popup->show();
    search->setFocus();
}

void AeroMainWindow::onTokenMetaResolved(const QString &address, const QString &symbol,
                                          quint8 decimals) {
    if (address.compare(m_pendingSendAsset, Qt::CaseInsensitive) != 0)
        return; // not the token the picker is waiting on
    m_pendingSendAsset.clear();
    if (symbol.isEmpty()) {
        setSendAsset(m_nativeSymbol, QString(), 18); // revert the "Looking up…" label
        QMessageBox::warning(this, tr("Token"), tr("Couldn't read this token (not an ERC-20?)."));
        return;
    }
    setSendAsset(symbol, address, decimals);
}

QIcon AeroMainWindow::tokenIcon(const QString &symbol) const {
    const QString path = QStringLiteral(":/assets/images/tokens/%1.png").arg(symbol.toUpper());
    QIcon icon(path);
    if (!icon.isNull())
        return icon;
    // Native coins without a token logo (POL / BNB / AVAX / XDAI) use the chain icon.
    if (symbol.compare(m_nativeSymbol, Qt::CaseInsensitive) == 0)
        return QIcon(chainDefFor(m_chainId).icon);
    return QIcon(QStringLiteral(":/assets/images/tokens/ETH.png"));
}

void AeroMainWindow::onSendClicked() {
    if (!m_wallet) return;
    const QString to = sendUi.lineAddress->text();
    const QString amount = sendUi.lineAmount->text().trimmed();
    if (to.isEmpty() || amount.isEmpty()) {
        QMessageBox::warning(this, tr("Send"), tr("Enter a recipient address and amount."));
        return;
    }
    // Send from the account chosen in the "From" dropdown (each account is isolated).
    const int fromIndex = m_fromCombo ? qMax(0, m_fromCombo->currentIndex()) : 0;

    // The amount is in the selected asset, unless the USD unit is active (ETH/WETH), in which case
    // convert it to the token amount using the on-chain price.
    QString tokenAmount = amount;
    const bool inUsd = m_amountUnit && m_amountUnit->isVisible() &&
                       m_amountUnit->currentText().compare(QStringLiteral("USD"), Qt::CaseInsensitive) == 0;
    if (inUsd) {
        const double price = unitPriceUsd(currentSymbol());
        bool ok = false;
        const double usd = amount.toDouble(&ok);
        if (!ok || price <= 0) {
            QMessageBox::warning(this, tr("Send"),
                                 tr("No USD price available; enter the amount in %1.").arg(currentSymbol()));
            return;
        }
        tokenAmount = QString::number(usd / price, 'f', 8);
    }

    // Don't let the user send more than they have (available is in the selected asset).
    bool availOk = false, amtOk = false;
    const double avail = m_availAmount.toDouble(&availOk);
    const double sendAmt = tokenAmount.toDouble(&amtOk);
    if (availOk && amtOk && sendAmt > avail) {
        QMessageBox::warning(
            this, tr("Insufficient balance"),
            tr("Amount exceeds available balance of %1 %2.").arg(grouped(m_availAmount), currentSymbol()));
        return;
    }

    const QPair<QString, QString> fee = chosenFeeWei(); // empty = automatic

    // Watch-only: don't sign/send — build an unsigned tx to sign on an offline wallet.
    if (m_wallet->isWatchOnly()) {
        PendingEthTx tx;
        tx.fromIndex = static_cast<quint32>(fromIndex);
        tx.to = to;
        tx.token = currentTokenAddr();
        tx.fee.maxFee = fee.first;
        tx.fee.maxPriorityFee = fee.second;
        if (tx.token.isEmpty())
            tx.amountWei = Wallet::parseUnits(tokenAmount, 18);
        else
            tx.amountUnits = Wallet::parseUnits(tokenAmount, currentDecimals());
        m_wallet->buildUnsigned(tx); // result via onUnsignedTxReady
        return;
    }

    m_wallet->createTransaction(static_cast<quint32>(fromIndex), to, tokenAmount, currentTokenAddr(),
                                fee.first, fee.second, currentDecimals());
}

void AeroMainWindow::onTransactionCreated(const PendingEthTx &tx) {
    const QString sym = currentSymbol();
    const bool isEth = tx.token.isEmpty();

    // Amount (from the tx's base-unit value) + its USD value.
    double amount = 0.0, amountUsd = 0.0;
    if (isEth) {
        amount = tx.amountWei.toDouble() / 1e18;
        amountUsd = amount * unitPriceUsd(m_nativeSymbol);
    } else {
        quint8 dec = currentDecimals(); // the picker's selected-asset decimals
        for (const TokenInfo &t : m_wallet->tokens())
            if (t.address.compare(tx.token, Qt::CaseInsensitive) == 0) dec = t.decimals;
        amount = tx.amountUnits.toDouble() / std::pow(10.0, dec);
        amountUsd = amount * unitPriceUsd(sym);
    }

    // Network fee (gas price × gas units) is always paid in the chain's native coin.
    const double gasLimit = isEth ? 21000.0 : 65000.0;
    const double feeEth = tx.fee.maxFee.toDouble() * gasLimit / 1e18;
    const double feeUsd = feeEth * unitPriceUsd(m_nativeSymbol);

    auto amt = [](double v) { return grouped(trimZeros(QString::number(v, 'f', 8))); };
    auto withUsd = [&](const QString &base, double u) {
        return u > 0 ? tr("%1  (\u2248 %2)").arg(base, fiatStr(u)) : base;
    };

    const QString amountRow = withUsd(tr("%1 %2").arg(amt(amount), sym), amountUsd);
    const QString feeRow = withUsd(tr("\u2248 %1 %2").arg(amt(feeEth), m_nativeSymbol), feeUsd);
    QString totalRow;
    if (isEth)
        totalRow = withUsd(tr("%1 %2").arg(amt(amount + feeEth), m_nativeSymbol), amountUsd + feeUsd);
    else
        totalRow = withUsd(tr("%1 %2 + %3 %4 fee").arg(amt(amount), sym, amt(feeEth), m_nativeSymbol),
                           amountUsd + feeUsd);

    // Address shown in full (monospace) with the 0x… start and the ending emphasised, so the
    // user can eyeball both ends against the intended recipient (address-poisoning defence).
    const QString a = tx.to.trimmed();
    QString addrHtml;
    if (a.length() > 18) {
        const QString head = a.left(10).toHtmlEscaped();                 // 0x + 8
        const QString mid = a.mid(10, a.length() - 18).toHtmlEscaped();
        const QString tail = a.right(8).toHtmlEscaped();
        addrHtml = QStringLiteral("<b style='color:#4aa3ff;'>%1</b>"
                                  "<span style='color:#8a8a8a;'>%2</span>"
                                  "<b style='color:#4aa3ff;'>%3</b>")
                       .arg(head, mid, tail);
    } else {
        addrHtml = a.toHtmlEscaped();
    }

    QFont mono;
    mono.setFamily(QStringLiteral("monospace"));
    mono.setStyleHint(QFont::TypeWriter);

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Confirm transaction"));
    auto *v = new QVBoxLayout(&dlg);
    v->setSpacing(14);
    auto *warn = new QLabel(tr("You are about to send a transaction.\nVerify the details below."), &dlg);
    v->addWidget(warn);

    auto *form = new QFormLayout();
    form->setHorizontalSpacing(15);
    form->setVerticalSpacing(7);

    auto *addrLabel = new QLabel(addrHtml, &dlg);
    addrLabel->setTextFormat(Qt::RichText);
    addrLabel->setFont(mono);
    addrLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    addrLabel->setToolTip(a);
    form->addRow(tr("Address:"), addrLabel);

    auto *amountLabel = new QLabel(amountRow, &dlg);
    amountLabel->setFont(mono);
    amountLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    form->addRow(tr("Amount:"), amountLabel);

    auto *feeLabel = new QLabel(feeRow, &dlg);
    feeLabel->setFont(mono);
    feeLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    form->addRow(tr("Fee:"), feeLabel);

    auto *line = new QFrame(&dlg);
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    form->addRow(QString(), line);

    auto *totalLabel = new QLabel(totalRow, &dlg);
    totalLabel->setFont(mono);
    totalLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    form->addRow(tr("Total:"), totalLabel);

    v->addLayout(form);

    auto *box = new QDialogButtonBox(QDialogButtonBox::Cancel | QDialogButtonBox::Ok, &dlg);
    box->button(QDialogButtonBox::Ok)->setText(tr("Send"));
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    v->addWidget(box);

    if (dlg.exec() != QDialog::Accepted)
        return;
    // Optional: require the wallet password before broadcasting.
    if (m_confirmSend && m_wallet->hasPassword()) {
        bool ok = false;
        const QString pw = QInputDialog::getText(this, tr("Confirm send"),
                                                 tr("Enter your wallet password to send:"),
                                                 QLineEdit::Password, QString(), &ok);
        if (!ok)
            return;
        if (!m_wallet->passwordMatches(pw)) {
            QMessageBox::warning(this, tr("Confirm send"), tr("Incorrect password. Transaction cancelled."));
            return;
        }
    }
    m_wallet->commitTransaction(tx);
}

void AeroMainWindow::onTransactionCommitted(bool ok, const QString &txHash, const QString &error) {
    if (m_deviceDialog)
        m_deviceDialog->hide(); // dismiss the "confirm on device" prompt once the device responded
    if (ok) {
        const QString to = sendUi.lineAddress->text().trimmed();
        const QString amount = sendUi.lineAmount->text().trimmed();
        // Optimistically show the outgoing send in history immediately.
        m_historyModel->addLocalSend(txHash, to, amount, currentSymbol());
        notify(tr("Payment sent"), tr("%1 %2 to %3").arg(amount, currentSymbol(), shortAddr(to)));
        onRefresh();

        // Feather-style confirmation with the txid + copy.
        HistoryItem tx;
        tx.direction = QStringLiteral("out");
        tx.counterparty = to;
        tx.formatted = amount;
        tx.symbol = currentSymbol();
        tx.txHash = txHash;
        tx.timestamp = static_cast<quint64>(QDateTime::currentSecsSinceEpoch());
        showTransactionDialog(tx);
    } else {
        QMessageBox::warning(this, tr("Send failed"), error);
    }
}

void AeroMainWindow::showTransactionDialog(const HistoryItem &tx) {
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Transaction"));
    auto *v = new QVBoxLayout(&dlg);
    v->setSpacing(12);

    QFont mono;
    mono.setFamily(QStringLiteral("monospace"));
    mono.setStyleHint(QFont::TypeWriter);

    // Transaction ID group with Copy + View on explorer.
    auto *idBox = new QGroupBox(tr("Transaction ID:"), &dlg);
    auto *idLay = new QHBoxLayout(idBox);
    auto *txidLabel = new QLabel(tx.txHash, idBox);
    txidLabel->setFont(mono);
    txidLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    txidLabel->setWordWrap(true);
    idLay->addWidget(txidLabel, 1);
    auto *copyBtn = new QPushButton(tr("Copy"), idBox);
    connect(copyBtn, &QPushButton::clicked, &dlg,
            [hash = tx.txHash]() { QApplication::clipboard()->setText(hash); });
    idLay->addWidget(copyBtn);
    auto *explorerBtn = new QPushButton(tr("View on explorer"), idBox);
    connect(explorerBtn, &QPushButton::clicked, &dlg, [this, hash = tx.txHash]() {
        QDesktopServices::openUrl(QUrl(explorerTxUrl(hash)));
    });
    idLay->addWidget(explorerBtn);
    v->addWidget(idBox);

    // Details form.
    auto *form = new QFormLayout();
    form->setHorizontalSpacing(15);
    form->setVerticalSpacing(7);

    QString status;
    if (tx.failed)
        status = tr("Failed");
    else if (tx.block == 0)
        status = tr("Pending");
    else
        status = tr("Confirmed (block %1)").arg(tx.block);
    form->addRow(tr("Status:"), new QLabel(status, &dlg));

    if (tx.timestamp > 0)
        form->addRow(tr("Date:"),
                     new QLabel(QDateTime::fromSecsSinceEpoch(static_cast<qint64>(tx.timestamp))
                                    .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")), &dlg));

    form->addRow(tr("Direction:"),
                 new QLabel(tx.direction == "in" ? tr("Received") : tr("Sent"), &dlg));

    const double amountUsd = tx.formatted.toDouble() * unitPriceUsd(tx.symbol);
    QString amountStr = tr("%1 %2").arg(tx.formatted, tx.symbol);
    if (amountUsd > 0)
        amountStr += tr("  (\u2248 %1)").arg(fiatStr(amountUsd));
    auto *amountLabel = new QLabel(amountStr, &dlg);
    amountLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    form->addRow(tr("Amount:"), amountLabel);

    if (!tx.fee.isEmpty() && tx.fee != QLatin1String("0")) {
        const double feeEth = tx.fee.toDouble() / 1e18;
        const double feeUsd = feeEth * unitPriceUsd(m_nativeSymbol);
        QString feeStr = tr("%1 %2").arg(grouped(trimZeros(QString::number(feeEth, 'f', 8))),
                                         m_nativeSymbol);
        if (feeUsd > 0)
            feeStr += tr("  (\u2248 %1)").arg(fiatStr(feeUsd));
        form->addRow(tr("Fee:"), new QLabel(feeStr, &dlg));
    }

    // Counterparty with 0x-start and end emphasised (address-poisoning defence).
    const QString a = tx.counterparty.trimmed();
    QString addrHtml = a.toHtmlEscaped();
    if (a.length() > 18)
        addrHtml = QStringLiteral("<b style='color:#4aa3ff;'>%1</b>"
                                  "<span style='color:#8a8a8a;'>%2</span>"
                                  "<b style='color:#4aa3ff;'>%3</b>")
                       .arg(a.left(10).toHtmlEscaped(), a.mid(10, a.length() - 18).toHtmlEscaped(),
                            a.right(8).toHtmlEscaped());
    auto *cpLabel = new QLabel(addrHtml, &dlg);
    cpLabel->setTextFormat(Qt::RichText);
    cpLabel->setFont(mono);
    cpLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    cpLabel->setToolTip(a);
    form->addRow(tx.direction == "in" ? tr("From:") : tr("To:"), cpLabel);

    v->addLayout(form);

    auto *box = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    v->addWidget(box);

    dlg.exec();
}

QPixmap AeroMainWindow::renderQr(const QString &text) const {
    using qrcodegen::QrCode;
    const QrCode qr = QrCode::encodeText(text.toUtf8().constData(), QrCode::Ecc::MEDIUM);
    const int n = qr.getSize();
    const int scale = 3, border = 2;
    const int dim = (n + border * 2) * scale;
    QImage image(dim, dim, QImage::Format_RGB32);
    image.fill(Qt::white);
    QPainter p(&image);
    for (int y = 0; y < n; ++y)
        for (int x = 0; x < n; ++x)
            if (qr.getModule(x, y))
                p.fillRect((x + border) * scale, (y + border) * scale, scale, scale, Qt::black);
    p.end();
    return QPixmap::fromImage(image);
}
