// SPDX-License-Identifier: BSD-3-Clause
#include "AeroMainWindow.h"
#include "Updater.h"
#include "XmrTradeTab.h"

#include <algorithm>
#include <cmath>

#include <QEventLoop>
#include <QFutureWatcher>
#include <QProgressDialog>
#include <QtConcurrent>

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
#include <QDir>
#include <QCoreApplication>
#include <QFileDialog>
#include <QDoubleSpinBox>
#include <QListWidget>
#include <QListWidgetItem>
#include <QScrollArea>
#include <QSortFilterProxyModel>
#include <QTabWidget>
#include <QTreeWidget>
#include <QToolButton>
#include <QClipboard>
#include <QCloseEvent>
#include <QBoxLayout>
#include <QComboBox>
#include <QListView>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFont>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
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
#include <QCursor>
#include <QMenu>
#include <QMessageBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QDesktopServices>
#include <QPainter>
#include <QPushButton>
#include <QRadioButton>
#include <QScreen>
#include <QSettings>
#include <QSystemTrayIcon>
#include <QUrl>
#include <QTimer>
#include <QVBoxLayout>

#include "qrcodegen.hpp"

#include <cstring>
extern "C" {
#include "quirc/quirc.h"
}

// Defined in main.cpp: applies the persisted dark/light theme app-wide.
void aeroApplyTheme();

// Decode the first QR code found in an image (via the vendored quirc). Returns its text, or "".
static QString decodeQrImage(const QImage &in) {
    if (in.isNull())
        return QString();
    const QImage img = in.convertToFormat(QImage::Format_Grayscale8);
    struct quirc *q = quirc_new();
    if (!q)
        return QString();
    QString out;
    if (quirc_resize(q, img.width(), img.height()) >= 0) {
        int w = 0, h = 0;
        uint8_t *buf = quirc_begin(q, &w, &h);
        for (int y = 0; y < h; ++y)
            std::memcpy(buf + static_cast<size_t>(y) * w, img.constScanLine(y),
                        static_cast<size_t>(w));
        quirc_end(q);
        const int n = quirc_count(q);
        for (int i = 0; i < n; ++i) {
            struct quirc_code code;
            struct quirc_data data;
            quirc_extract(q, i, &code);
            if (quirc_decode(&code, &data) == QUIRC_SUCCESS) {
                out = QString::fromUtf8(reinterpret_cast<const char *>(data.payload),
                                        static_cast<int>(data.payload_len));
                break;
            }
        }
    }
    quirc_destroy(q);
    return out;
}

namespace {
const quint64 kChainId = 1;
// Keyless, Tor-reachable public RPCs. (eth.llamarpc.com was dropped: it's Cloudflare-fronted and
// returns HTTP 521 to Tor exit nodes; rpc.mevblocker.io is a tx-relay, not a general JSON-RPC.)
//
// The list is long on purpose. Public endpoints do not fail cleanly - they stay up and start
// refusing, with a rate limit or a sudden demand for an API key - and a wallet that depends on any
// one of them is a wallet that stops working the day that provider changes its policy. The core
// parks an endpoint that refuses and moves to the next, so depth here is what keeps the app working
// without anyone having to install a new build.
const QStringList kDefaultEndpoints = {
    QStringLiteral("https://ethereum-rpc.publicnode.com"),
    QStringLiteral("https://eth.drpc.org"),
    QStringLiteral("https://eth.merkle.io"),
    QStringLiteral("https://1rpc.io/eth"),
    QStringLiteral("https://rpc.flashbots.net"),
    QStringLiteral("https://eth-mainnet.public.blastapi.io"),
    QStringLiteral("https://eth.rpc.blxrbdn.com"),
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
    bool cow = false;            // CoW Protocol swaps available (mirrors core chains.rs cow_network)
    bool ethFlow = false;        // CoW eth-flow (native-ETH sells) available on this chain
    QString wrappedNative;       // wrapped-native ERC-20 (WETH/WMATIC/…) for swaps
};

const QList<ChainDef> &chainDefs() {
    static const QList<ChainDef> defs = {
        {1, QStringLiteral("Ethereum"), QStringLiteral("ETH"),
         QStringLiteral(":/assets/images/chains/ethereum.png"),
         kDefaultEndpoints,
         QStringLiteral("https://etherscan.io"),
         true, true, QStringLiteral("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")},
        {42161, QStringLiteral("Arbitrum One"), QStringLiteral("ETH"),
         QStringLiteral(":/assets/images/chains/arbitrum.png"),
         {QStringLiteral("https://arbitrum-one-rpc.publicnode.com"),
          QStringLiteral("https://arb1.arbitrum.io/rpc"),
          QStringLiteral("https://arbitrum.drpc.org"),
          QStringLiteral("https://arbitrum-one.public.blastapi.io"),
          QStringLiteral("https://arbitrum.meowrpc.com"),
          QStringLiteral("https://1rpc.io/arb")},
         QStringLiteral("https://arbiscan.io"),
         true, true, QStringLiteral("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1")},
        {8453, QStringLiteral("Base"), QStringLiteral("ETH"),
         QStringLiteral(":/assets/images/chains/base.png"),
         {QStringLiteral("https://base-rpc.publicnode.com"),
          QStringLiteral("https://mainnet.base.org"),
          QStringLiteral("https://base.drpc.org"),
          QStringLiteral("https://base.meowrpc.com"),
          QStringLiteral("https://1rpc.io/base")},
         QStringLiteral("https://basescan.org"),
         true, true, QStringLiteral("0x4200000000000000000000000000000000000006")},
        {10, QStringLiteral("Optimism"), QStringLiteral("ETH"),
         QStringLiteral(":/assets/images/chains/optimism.png"),
         {QStringLiteral("https://optimism-rpc.publicnode.com"),
          QStringLiteral("https://mainnet.optimism.io"),
          QStringLiteral("https://optimism.drpc.org"),
          QStringLiteral("https://1rpc.io/op")},
         QStringLiteral("https://optimistic.etherscan.io"),
         false, false, QStringLiteral("0x4200000000000000000000000000000000000006")},
        {137, QStringLiteral("Polygon"), QStringLiteral("POL"),
         QStringLiteral(":/assets/images/chains/polygon.png"),
         {QStringLiteral("https://polygon-bor-rpc.publicnode.com"),
          QStringLiteral("https://polygon.drpc.org"),
          QStringLiteral("https://1rpc.io/matic"),
          QStringLiteral("https://polygon-rpc.com")},
         QStringLiteral("https://polygonscan.com"),
         true, true, QStringLiteral("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270")},
        {56, QStringLiteral("BNB Smart Chain"), QStringLiteral("BNB"),
         QStringLiteral(":/assets/images/chains/bsc.png"),
         {QStringLiteral("https://bsc-rpc.publicnode.com"),
          QStringLiteral("https://bsc-dataseed.bnbchain.org"),
          QStringLiteral("https://bsc.meowrpc.com"),
          QStringLiteral("https://1rpc.io/bnb"),
          QStringLiteral("https://bsc.drpc.org")},
         QStringLiteral("https://bscscan.com"),
         true, true, QStringLiteral("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")},
        {100, QStringLiteral("Gnosis"), QStringLiteral("XDAI"),
         QStringLiteral(":/assets/images/chains/gnosis.png"),
         {QStringLiteral("https://gnosis-rpc.publicnode.com"),
          QStringLiteral("https://rpc.gnosischain.com"),
          QStringLiteral("https://gnosis.drpc.org"),
          QStringLiteral("https://1rpc.io/gnosis")},
         QStringLiteral("https://gnosisscan.io"),
         true, true, QStringLiteral("0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d")},
        {43114, QStringLiteral("Avalanche"), QStringLiteral("AVAX"),
         QStringLiteral(":/assets/images/chains/avalanche.png"),
         {QStringLiteral("https://avalanche-c-chain-rpc.publicnode.com"),
          QStringLiteral("https://api.avax.network/ext/bc/C/rpc"),
          QStringLiteral("https://avalanche.drpc.org"),
          QStringLiteral("https://1rpc.io/avax/c")},
         QStringLiteral("https://snowtrace.io"),
         true, true, QStringLiteral("0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7")},
        // Testnets (worthless coins, for safe testing). Shown only when "Show testnets" is enabled.
        {11155111, QStringLiteral("Sepolia (testnet)"), QStringLiteral("SepoliaETH"),
         QStringLiteral(":/assets/images/chains/ethereum.png"),
         {QStringLiteral("https://ethereum-sepolia-rpc.publicnode.com"),
          QStringLiteral("https://sepolia.drpc.org"),
          QStringLiteral("https://rpc.sepolia.org")},
         QStringLiteral("https://sepolia.etherscan.io"),
         false, false, QStringLiteral("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14")},
        {17000, QStringLiteral("Holesky (testnet)"), QStringLiteral("HoleskyETH"),
         QStringLiteral(":/assets/images/chains/ethereum.png"),
         {QStringLiteral("https://ethereum-holesky-rpc.publicnode.com"),
          QStringLiteral("https://holesky.drpc.org")},
         QStringLiteral("https://holesky.etherscan.io"),
         false, false, QString()},
    };
    return defs;
}

/// Testnets are hidden from the network selector unless the user enables them (they're worthless
/// coins and would clutter the list). Persisted preference.
bool aeroShowTestnets() {
    return QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
        .value(QStringLiteral("appearance/showTestnets"), false)
        .toBool();
}

bool aeroIsTestnet(quint64 id) { return id == 11155111 || id == 17000; }

const ChainDef &chainDefFor(quint64 id) {
    for (const auto &c : chainDefs())
        if (c.id == id)
            return c;
    return chainDefs().first(); // default to Ethereum
}

// Curated list of well-known ERC-20s per chain, auto-trusted in History (so legitimate transfers
// aren't hidden by the spam filter) and offered in the swap picker. Allow-list only: not
// balance-tracked unless the user adds them. Matched case-insensitively by address.
QVector<TokenInfo> curatedTopTokens(quint64 chainId) {
    switch (chainId) {
    case 42161: // Arbitrum One
        return {
            {QStringLiteral("0xaf88d065e77c8cC2239327C5EDb3A432268e5831"), QStringLiteral("USDC"), 6},
            {QStringLiteral("0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8"), QStringLiteral("USDC.e"), 6},
            {QStringLiteral("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"), QStringLiteral("USDT"), 6},
            {QStringLiteral("0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1"), QStringLiteral("DAI"), 18},
            {QStringLiteral("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"), QStringLiteral("WETH"), 18},
            {QStringLiteral("0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f"), QStringLiteral("WBTC"), 8},
            {QStringLiteral("0x912CE59144191C1204E64559FE8253a0e49E6548"), QStringLiteral("ARB"), 18},
            {QStringLiteral("0xf97f4df75117a78c1A5a0DBb814Af92458539FB4"), QStringLiteral("LINK"), 18},
        };
    case 8453: // Base
        return {
            {QStringLiteral("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"), QStringLiteral("USDC"), 6},
            {QStringLiteral("0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA"), QStringLiteral("USDbC"), 6},
            {QStringLiteral("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"), QStringLiteral("DAI"), 18},
            {QStringLiteral("0x4200000000000000000000000000000000000006"), QStringLiteral("WETH"), 18},
            {QStringLiteral("0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22"), QStringLiteral("cbETH"), 18},
        };
    case 10: // Optimism
        return {
            {QStringLiteral("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"), QStringLiteral("USDC"), 6},
            {QStringLiteral("0x7F5c764cBc14f9669B88837ca1490cCa17c31607"), QStringLiteral("USDC.e"), 6},
            {QStringLiteral("0x94b008aA00579c1307B0EF2c499aD98a8ce58e58"), QStringLiteral("USDT"), 6},
            {QStringLiteral("0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1"), QStringLiteral("DAI"), 18},
            {QStringLiteral("0x4200000000000000000000000000000000000006"), QStringLiteral("WETH"), 18},
            {QStringLiteral("0x4200000000000000000000000000000000000042"), QStringLiteral("OP"), 18},
            {QStringLiteral("0x68f180fcCe6836688e9084f035309E29Bf0A2095"), QStringLiteral("WBTC"), 8},
        };
    case 137: // Polygon
        return {
            {QStringLiteral("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"), QStringLiteral("USDC"), 6},
            {QStringLiteral("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"), QStringLiteral("USDC.e"), 6},
            {QStringLiteral("0xc2132D05D31c914a87C6611C10748AEb04B58e8F"), QStringLiteral("USDT"), 6},
            {QStringLiteral("0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063"), QStringLiteral("DAI"), 18},
            {QStringLiteral("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"), QStringLiteral("WPOL"), 18},
            {QStringLiteral("0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619"), QStringLiteral("WETH"), 18},
            {QStringLiteral("0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6"), QStringLiteral("WBTC"), 8},
            {QStringLiteral("0x53E0bca35eC356BD5ddDFebbD1Fc0fD03FaBad39"), QStringLiteral("LINK"), 18},
        };
    case 56: // BNB Smart Chain
        return {
            {QStringLiteral("0x55d398326f99059fF775485246999027B3197955"), QStringLiteral("USDT"), 18},
            {QStringLiteral("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"), QStringLiteral("USDC"), 18},
            {QStringLiteral("0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3"), QStringLiteral("DAI"), 18},
            {QStringLiteral("0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56"), QStringLiteral("BUSD"), 18},
            {QStringLiteral("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"), QStringLiteral("WBNB"), 18},
            {QStringLiteral("0x2170Ed0880ac9A755fd29B2688956BD959F933F8"), QStringLiteral("ETH"), 18},
            {QStringLiteral("0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c"), QStringLiteral("BTCB"), 18},
        };
    case 100: // Gnosis
        return {
            {QStringLiteral("0xDDAfbb505ad214D7b80b1f830fcCc89B60fb7A83"), QStringLiteral("USDC"), 6},
            {QStringLiteral("0x4ECaBa5870353805a9F068101A40E0f32ed605C6"), QStringLiteral("USDT"), 6},
            {QStringLiteral("0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d"), QStringLiteral("WXDAI"), 18},
            {QStringLiteral("0x6A023CCd1ff6F2045C3309768eAd9E68F978f6e1"), QStringLiteral("WETH"), 18},
            {QStringLiteral("0x9C58BAcC331c9aa871AFD802DB6379a98e80CEdb"), QStringLiteral("GNO"), 18},
        };
    case 43114: // Avalanche
        return {
            {QStringLiteral("0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E"), QStringLiteral("USDC"), 6},
            {QStringLiteral("0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7"), QStringLiteral("USDT"), 6},
            {QStringLiteral("0xd586E7F844cEa2F87f50152665BCbc2C279D8d70"), QStringLiteral("DAI.e"), 18},
            {QStringLiteral("0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7"), QStringLiteral("WAVAX"), 18},
            {QStringLiteral("0x49D5c2BdFfac6CE2BFdB6640F4F80f226bc10bAB"), QStringLiteral("WETH.e"), 18},
            {QStringLiteral("0x50b7545627a5162F82A992c33b87aDc75187B218"), QStringLiteral("WBTC.e"), 8},
        };
    case 1: // Ethereum mainnet
    default:
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
}

QString shortAddr(const QString &a) {
    if (a.size() < 12) return a;
    return a.left(8) + QStringLiteral("…") + a.right(6);
}

// A normal (non-editable) combo box that, when its dropdown opens, shows a search box PINNED AT THE
// TOP of the popup. Typing filters the rows live (matching each row's display text plus the full
// address stashed in Qt::UserRole). Clicking the field opens the dropdown as usual. Used for the Send
// "From" account selector, which can hold hundreds of accounts. No Q_OBJECT needed - it only
// overrides virtuals and wires a child line edit.
class SearchableComboBox : public QComboBox {
public:
    explicit SearchableComboBox(QWidget *parent = nullptr) : QComboBox(parent) {
        setMaxVisibleItems(18);
        m_filter = new QLineEdit(this);
        m_filter->setPlaceholderText(QObject::tr("Search account, label, or address…"));
        m_filter->setClearButtonEnabled(true);
        m_filter->hide();
        connect(m_filter, &QLineEdit::textChanged, this, [this](const QString &t) { filterRows(t); });
        // Enter selects the first matching row (so you can type + press Enter without reaching for the
        // mouse).
        connect(m_filter, &QLineEdit::returnPressed, this, [this]() {
            auto *lv = qobject_cast<QListView *>(view());
            if (!lv)
                return;
            for (int i = 0; i < count(); ++i)
                if (!lv->isRowHidden(i)) {
                    setCurrentIndex(i);
                    hidePopup();
                    return;
                }
        });
    }

protected:
    void showPopup() override {
        QComboBox::showPopup();
        // Inject the search box at the top of the popup container the first time, then reuse it.
        QWidget *container = view() ? view()->parentWidget() : nullptr;
        if (!container)
            return;
        if (m_filter->parentWidget() != container) {
            m_filter->setParent(container);
            if (auto *box = qobject_cast<QBoxLayout *>(container->layout()))
                box->insertWidget(0, m_filter);
        }
        setAllRowsVisible();
        {
            const QSignalBlocker block(m_filter); // resetting the text must not re-filter
            m_filter->clear();
        }
        m_filter->show();
        m_filter->setFocus();
        adjustPopupGeometry();
    }

private:
    void setAllRowsVisible() {
        if (auto *lv = qobject_cast<QListView *>(view()))
            for (int i = 0; i < count(); ++i)
                lv->setRowHidden(i, false);
    }

    int visibleRowCount() const {
        auto *lv = qobject_cast<QListView *>(view());
        if (!lv)
            return count();
        int n = 0;
        for (int i = 0; i < count(); ++i)
            if (!lv->isRowHidden(i))
                ++n;
        return n;
    }

    // Qt sizes the popup for the LIST ALONE, before our search box is added to the container's
    // layout - the box then eats that fixed height and only a row or two of accounts stays visible.
    // So size it ourselves: the list gets room for up to maxVisibleItems rows UNDER the search box,
    // and the popup is shifted up if it would run off the bottom of the screen.
    void adjustPopupGeometry() {
        QAbstractItemView *v = view();
        QWidget *c = v ? v->parentWidget() : nullptr;
        if (!c || !c->isVisible())
            return;
        int rowH = v->sizeHintForRow(0);
        if (rowH <= 0)
            rowH = fontMetrics().height() + 10;
        const int rows = qBound(1, visibleRowCount(), qMax(1, maxVisibleItems()));
        const int listH = rows * rowH + 2 * v->frameWidth() + 2;
        v->setMinimumHeight(listH);
        v->setMaximumHeight(listH);
        const int newH = listH + m_filter->sizeHint().height() + 12; // + container margins/spacing
        const QRect g = c->geometry();
        // Qt flips the popup above the combo when there is no room below; in that case keep its
        // bottom pinned and grow upward, otherwise it would ride up over the combo box itself.
        const bool opensUpward = g.y() < mapToGlobal(QPoint(0, 0)).y();
        int y = opensUpward ? g.bottom() + 1 - newH : g.y();
        if (const QScreen *scr = screen()) {
            const QRect avail = scr->availableGeometry();
            if (y + newH > avail.bottom())
                y = avail.bottom() - newH;
            y = qMax(y, avail.top());
        }
        c->setGeometry(g.x(), y, g.width(), newH);
    }

    void filterRows(const QString &text) {
        auto *lv = qobject_cast<QListView *>(view());
        if (!lv)
            return;
        const QString q = text.trimmed().toLower();
        for (int i = 0; i < count(); ++i) {
            const QString hay = (itemText(i) + QLatin1Char(' ') + itemData(i).toString()).toLower();
            lv->setRowHidden(i, !(q.isEmpty() || hay.contains(q)));
        }
        adjustPopupGeometry(); // grow/shrink the popup to the number of matches
    }
    QLineEdit *m_filter = nullptr;
};

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
            return number; // not a plain number - leave it untouched
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

// Stable per-wallet settings key remembering which account was last selected, so reopening a wallet
// returns to that account instead of jumping back to #0.
QString selectedAccountKey(const QString &walletPath) {
    const QByteArray h = QCryptographicHash::hash(walletPath.toUtf8(), QCryptographicHash::Md5);
    return QStringLiteral("ui/%1/selectedAccount").arg(QString::fromLatin1(h.toHex()));
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
    // One-time migration (must run before the Receive options menu is built): earlier builds
    // defaulted the "show only funded addresses" filter ON and persisted it, hiding most accounts
    // after importing a seed. Flip it OFF once so the full 0..last-used address list is shown.
    {
        QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
        if (!s.value(QStringLiteral("receive/fundedOnlyMigratedOff"), false).toBool()) {
            s.setValue(QStringLiteral("receive/fundedOnly"), false);
            s.setValue(QStringLiteral("receive/fundedOnlyMigratedOff"), true);
        }
    }

    ui.setupUi(this);
    ui.stackedWidget->setCurrentWidget(ui.page_wallet);

    setupTabs();
    setupStatusBar();

    // Settings menu -> RPC/Tor editor (no Connect/Refresh toolbar anymore).
    connect(ui.actionSettings, &QAction::triggered, this, &AeroMainWindow::onSettings);

    setWindowTitle(QStringLiteral("Aero"));
}

AeroMainWindow::~AeroMainWindow() {
    delete m_wallet;
}

void AeroMainWindow::closeEvent(QCloseEvent *event) {
    // FIRST: tell the core's background loops (funded scan / per-account history) to stop. They hold
    // the core lock while running (a scan holds it exclusively for its whole multi-minute run, made
    // longer by rate-limit backoff), and the blocking flush + save below need that lock. Without this
    // the window appears to hang on the X until the in-flight scan/history finishes. The loops poll
    // this flag between requests (and wake early from backoff sleeps), so they bail within ~1s.
    Wallet::requestShutdown();
    // Stop the debounced timers so they can't race the authoritative final save.
    if (m_histSaveTimer)
        m_histSaveTimer->stop();
    if (m_saveTimer)
        m_saveTimer->stop();

    if (m_wallet && !m_wallet->walletPath().isEmpty()) {
        // Assemble the FINAL metadata snapshot on the UI thread (cheap: just building JSON in memory -
        // history cache + labels/contacts/notes/balance cache). No core lock is taken here.
        if (m_historyModel)
            foldHistoryCacheIntoMeta();
        const QString metaJson =
            QString::fromUtf8(QJsonDocument(m_meta).toJson(QJsonDocument::Compact));

        // Then do the one blocking encrypt+write (apply metadata + save) on a WORKER thread, pumping
        // a local event loop so the window keeps repainting and NEVER freezes. Previously this ran on
        // the UI thread and took the core lock directly - so closing while a scan/history load held
        // the lock hung the window until that finished (the "freezes on close" bug). requestShutdown()
        // above makes those background reads bail promptly, so the worker gets the lock within a beat.
        // A safety timer caps the wait: the periodic saves already persisted almost everything, and
        // the wallet write is atomic, so closing before a slow final save can't corrupt the file.
        // `saved` is heap-allocated (shared with the worker) so that if the safety timer fires and
        // this function returns while the worker is still running, the worker doesn't write to a
        // destroyed stack variable.
        QSharedPointer<QAtomicInt> saved = QSharedPointer<QAtomicInt>::create(0);
        QProgressDialog prog(tr("Saving…"), QString(), 0, 0, this);
        prog.setWindowModality(Qt::ApplicationModal);
        prog.setCancelButton(nullptr);
        prog.setMinimumDuration(400); // don't flash the dialog for a fast save
        QFutureWatcher<void> watcher;
        QEventLoop loop;
        connect(&watcher, &QFutureWatcher<void>::finished, &loop, &QEventLoop::quit);
        watcher.setFuture(QtConcurrent::run([this, metaJson, saved]() {
            saved->storeRelease(m_wallet->saveWithMetadata(metaJson) ? 1 : 0);
        }));
        QTimer::singleShot(12000, &loop, &QEventLoop::quit); // hard cap so close can't hang
        prog.show();
        loop.exec();
        prog.close();

        // Only prompt on a real, completed save failure - never on the timeout (the background write
        // will finish on its own; blocking the close on it is exactly what we're avoiding).
        if (watcher.isFinished() && saved->loadAcquire() == 0) {
            const auto choice = QMessageBox::warning(
                this, tr("Could not save wallet"),
                tr("Your wallet could not be saved:\n\n%1\n\nAny recently imported keys or new "
                   "addresses may be lost if you close now. Close anyway?")
                    .arg(m_wallet->errorString()),
                QMessageBox::Close | QMessageBox::Cancel, QMessageBox::Cancel);
            if (choice != QMessageBox::Close) {
                event->ignore();
                return;
            }
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
    // The model owns filtering + sorting + pagination (500 rows/page) so only one page is ever
    // materialised - no sort proxy churning tens of thousands of rows. Header clicks drive sort();
    // the model's no-op-on-same-params guard prevents the view's post-reset re-sort recursion.
    histUi.history->setModel(m_historyModel);
    histUi.history->setSelectionBehavior(QAbstractItemView::SelectRows);
    histUi.history->setSortingEnabled(true);
    histUi.history->sortByColumn(HistoryModel::Column_Date, Qt::DescendingOrder); // newest first
    // Wire the (previously dead) history search box, and drop the Monero sync-notice banner.
    connect(histUi.search, &QLineEdit::textChanged, this,
            [this](const QString &t) { m_historyModel->setSearchText(t); });
    histUi.syncNotice->hide();
    // Double-click a transaction to open the Feather-style details dialog.
    connect(histUi.history, &QTreeView::doubleClicked, this, [this](const QModelIndex &idx) {
        if (idx.isValid())
            showTransactionDialog(m_historyModel->itemAt(idx.row()));
    });

    // Pagination bar below the table: Prev / Next + "Page X of Y (N transactions)".
    {
        auto *pager = new QWidget(histUi.history->parentWidget());
        auto *pl = new QHBoxLayout(pager);
        pl->setContentsMargins(0, 4, 0, 0);
        m_historyPrev = new QToolButton(pager);
        m_historyPrev->setText(tr("\u2039 Prev"));
        m_historyPrev->setToolButtonStyle(Qt::ToolButtonTextOnly);
        m_historyNext = new QToolButton(pager);
        m_historyNext->setText(tr("Next \u203a"));
        m_historyNext->setToolButtonStyle(Qt::ToolButtonTextOnly);
        m_historyPageLabel = new QLabel(pager);
        pl->addWidget(m_historyPrev);
        pl->addWidget(m_historyNext);
        pl->addStretch(1);
        pl->addWidget(m_historyPageLabel);
        histUi.verticalLayout->addWidget(pager);
        connect(m_historyPrev, &QToolButton::clicked, this,
                [this]() { m_historyModel->setPage(m_historyModel->currentPage() - 1); });
        connect(m_historyNext, &QToolButton::clicked, this,
                [this]() { m_historyModel->setPage(m_historyModel->currentPage() + 1); });
        connect(m_historyModel, &HistoryModel::pageChanged, this,
                [this](int page, int pages, int total) {
                    m_historyPrev->setEnabled(page > 0);
                    m_historyNext->setEnabled(page + 1 < pages);
                    if (total <= 0)
                        m_historyPageLabel->setText(tr("No transactions"));
                    else
                        m_historyPageLabel->setText(
                            tr("Page %1 of %2  (%3 transactions)").arg(page + 1).arg(pages).arg(total));
                    histUi.history->scrollToTop();
                });
    }

    // "Payment received" notifications are driven off History, not raw balance increases: History has
    // already run the spam filter, so a dust, zero-value or look-alike poisoning transfer that it
    // hides can never reach a notification. Fired only for genuinely new arrivals (see noteIncoming).
    connect(m_historyModel, &HistoryModel::incomingPayment, this,
            [this](quint32 account, const QString &formatted, const QString &symbol) {
                notify(tr("Payment received"),
                       tr("+%1 %2 to %3").arg(grouped(formatted), symbol, accountName(account)));
            });

    // History account filter: "All accounts" or a single account, placed at the left of the
    // search bar (Feather shows a similar account filter above the history view).
    m_historyCombo = new SearchableComboBox(histUi.frame_search); // searchable for many-account wallets
    m_historyCombo->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    m_historyCombo->setMinimumWidth(200);
    histUi.horizontalLayout_2->insertWidget(0, m_historyCombo);
    // The view outlives this constructor's `histUi`, so hold the pointer, not the form.
    m_historyView = histUi.history;
    connect(m_historyCombo, &QComboBox::currentIndexChanged, this, [this](int idx) {
        m_historyFilter = idx <= 0 ? -1 : (idx - 1); // item 0 = All; items 1..N = account idx-1
        // Filtered to one account, every row would name that same account: the combo above already
        // says it. The column earns its width only when more than one account is on screen.
        if (m_historyView)
            m_historyView->setColumnHidden(HistoryModel::Column_Account, m_historyFilter >= 0);
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
    // RIGHT (this is exactly the stock ReceiveWidget.ui layout - addresses | verticalLayout_2).
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
                // Mirror the new label into every account combo (Send, Swap "From", and the History
                // filter items 1..N) so a rename shows everywhere, not just on Send.
                auto relabel = [this](QComboBox *combo, int offset) {
                    if (!combo)
                        return;
                    QSignalBlocker block(combo);
                    for (int i = offset; i < combo->count(); ++i)
                        combo->setItemText(i, accountLabel(static_cast<quint32>(i - offset)));
                };
                relabel(m_fromCombo, 0);
                relabel(m_swapFrom, 0);
                relabel(m_historyCombo, 1); // item 0 is "All accounts"
                pushAccountNames();         // and into the History table's Account column
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

    // Show balances in USD instead of the native coin. Defaults ON so the value of each address is
    // obvious at a glance; toggled from the Receive "options" menu (built below). Remembered per install.
    m_recvUsd = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                    .value(QStringLiteral("receive/showUsd"), true)
                    .toBool();

    // Combined total across all accounts (like Home), pinned at the very bottom of the Receive tab.
    m_recvTotalLabel = new QLabel(tr("Total balance: -"), ui.tabReceive);
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
    recvUi.btn_createPaymentRequest->setToolTip(
        tr("Import an external private key as an account in this wallet, so you can move the funds "
           "sitting on it into one of your seed addresses."));
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
                               .value(QStringLiteral("receive/fundedOnly"), false).toBool();
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
        // Show balances in USD (default on) - applies to the address list + the per-address breakdown.
        auto *usdAct = menu->addAction(tr("Show balances in USD"));
        usdAct->setCheckable(true);
        usdAct->setChecked(m_recvUsd);
        connect(usdAct, &QAction::toggled, this, [this](bool on) {
            m_recvUsd = on;
            QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                .setValue(QStringLiteral("receive/showUsd"), on);
            updateReceive();                 // per-address breakdown under the QR
            refreshAddressBalancesDisplay(); // the address list's Balance column
        });
        connect(menu->addAction(tr("Rescan for funded addresses (all chains)")), &QAction::triggered,
                this, [this]() {
                    if (m_wallet) {
                        setConnectionState(m_connMode, tr("Scanning for your addresses…"));
                        startScanProgress();
                        m_wallet->scanFundedMulti(allChainsScanConfig(), 40); // silent, cross-chain
                    }
                });
        // The "Import private key" button lives under the QR, which is easy to miss - offer the same
        // action here too, where someone looking for wallet options will actually find it. This is
        // the path for pulling funds off a bare private key: import it, then send them to a seed
        // address.
        menu->addSeparator();
        connect(menu->addAction(tr("Import private key…")), &QAction::triggered, this,
                &AeroMainWindow::onImportKey);
        recvUi.toolBtn_options->setMenu(menu);
        recvUi.toolBtn_options->setPopupMode(QToolButton::InstantPopup);
    }

    // Click the QR to copy the selected address; live search filters the list.
    connect(recvUi.qrCode, &ClickableLabel::clicked, this, [this]() {
        if (m_wallet)
            QApplication::clipboard()->setText(m_wallet->address(m_account));
    });
    connect(recvUi.search, &QLineEdit::textChanged, this,
            [this](const QString &) { applyReceiveSearch(); });
    // A model reset (funded-toggle, refresh, new/imported address) clears row-hidden state; re-apply
    // the current search so a typed query isn't silently dropped and all rows suddenly reappear.
    connect(m_addressModel, &QAbstractItemModel::modelReset, this,
            [this]() { applyReceiveSearch(); });

    // "From" account selector at the top of the Send form (which account funds the send). Uses a
    // searchable dropdown: open it and a search field sits at the top of the list - type an account
    // number, label, or (full/partial) address to filter the list live. The full address is stashed
    // in each item's data role so it's searchable even though the row only shows a shortened form.
    m_fromCombo = new SearchableComboBox(ui.tabSend);
    sendUi.formLayout->insertRow(0, tr("From"), m_fromCombo);

    // The stock .ui uses two dropdowns (a currency combo + an ETH/USD unit toggle). Replace them
    // with a single row of clickable asset buttons (ETH / DAI / USDC / USDT / …): pick one, then
    // just type the amount in that asset.
    sendUi.comboCurrencySelection->hide();
    // Hide Monero/OpenAlias leftovers that were never wired for Ethereum.
    // Scan a QR code from an image file into the Pay-to field (which then auto-parses an
    // ethereum: URI or a plain address). Webcam scanning would need Qt Multimedia in the build.
    sendUi.btnScan->setToolTip(tr("Scan a QR code from an image file"));
    connect(sendUi.btnScan, &QAbstractButton::clicked, this, [this]() {
        const QString f = QFileDialog::getOpenFileName(
            this, tr("Scan QR from image"), QString(),
            tr("Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp)"));
        if (f.isEmpty())
            return;
        const QString text = decodeQrImage(QImage(f));
        if (text.trimmed().isEmpty()) {
            QMessageBox::warning(this, tr("Scan QR"), tr("No QR code found in that image."));
            return;
        }
        sendUi.lineAddress->setPlainText(text.trimmed()); // auto-parses ethereum:/address
        ui.tabWidget->setCurrentWidget(ui.tabSend);
    });
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
    connect(m_amountUnit, &QComboBox::currentIndexChanged, this,
            &AeroMainWindow::updateAvailableLabel); // flip "Available" between token and USD too

    // "Available" row (right under Amount) shows the spendable balance for the selected From
    // account + asset, and the Max button fills the amount with it.
    m_availLabel = new QLabel(tr("-"), ui.tabSend);
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
    // Remember the chosen "From" as the active account so Receive/Swap stay in sync with it.
    connect(m_fromCombo, &QComboBox::currentIndexChanged, this, [this](int i) {
        if (i >= 0) m_account = static_cast<quint32>(i);
    });
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
            // Match suggest_fees' 3x base-fee headroom so the reserved gas always covers the actual
            // automatic fee (otherwise Max could reserve too little and the send guard would reject it).
            double maxFeeWei = !fee.first.isEmpty()
                                   ? fee.first.toDouble()
                                   : (m_feeBaseWei * 3.0 + qMax(m_feeTipWei, 1e9));
            if (maxFeeWei <= 0.0)
                maxFeeWei = 3e9; // fees not loaded yet - assume a safe floor
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
    m_feeEstimateLabel = new QLabel(tr("-"), ui.tabSend);
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

    // "Pay to contact" picker under the estimated fee: choose a saved address-book contact to fill
    // the recipient field. Populated from the Contacts tab (refreshSendContacts) and kept in sync.
    m_sendContactsCombo = new QComboBox(ui.tabSend);
    m_sendContactsCombo->setToolTip(tr("Fill the recipient from a saved contact"));
    connect(m_sendContactsCombo, &QComboBox::activated, this, [this](int idx) {
        if (idx <= 0) return; // row 0 is the placeholder
        const QString addr = m_sendContactsCombo->itemData(idx).toString();
        if (!addr.isEmpty())
            sendUi.lineAddress->setPlainText(addr);
        m_sendContactsCombo->setCurrentIndex(0); // reset to the placeholder for the next pick
    });
    sendUi.formLayout->insertRow(feeRow >= 0 ? feeRow + 3 : 8, tr("Pay to contact"), m_sendContactsCombo);
    refreshSendContacts();

    connect(sendUi.combo_feePriority, &QComboBox::currentIndexChanged, this,
            &AeroMainWindow::onFeeModeChanged);
    connect(m_customMaxFee, &QLineEdit::textChanged, this, &AeroMainWindow::updateFeeEstimate);
    connect(m_customPriority, &QLineEdit::textChanged, this, &AeroMainWindow::updateFeeEstimate);

    setupHomeTab();
    setupNftTab();
    setupSwapTab();
    // Built once and inserted/removed per wallet, like Swap: it holds resting orders and a running
    // redemption, and rebuilding it on every wallet change would drop both.
    m_xmrTab = new XmrTradeTab();
    m_xmrTab->hide();
    // Deposits and withdrawals in the tab only work on Arbitrum One; when it asks, switch there.
    connect(m_xmrTab, &XmrTradeTab::switchToArbitrumRequested, this,
            [this]() { if (m_chainId != 42161) switchChain(42161); });
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
        double mp = m_customPriority->text().trimmed().toDouble() * gwei;
        if (mf <= 0)
            return {};
        // EIP-1559 requires maxPriorityFee <= maxFee; a node rejects the tx outright otherwise.
        // Clamp the priority to maxFee so a mis-entered custom fee can't produce an invalid tx.
        if (mp > mf)
            mp = mf;
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
        m_feeEstimateLabel->setText(tr("-"));
        return;
    }
    // Gas price (gwei) is a market rate - the same for any tx - but an ERC20 transfer needs far
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
    // (relativeFont(0)) and the percentage uses base-1pt (relativeFont(-1)) - no bold/enlarging.
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
    // Total balance FIRST (left) - it's the most important number and must always be visible. It used
    // to be pinned to the far right, but Aero's wide tab bar forces a window minimum wider than a small
    // (e.g. 1024px) screen, so a right-pinned box fell off the right edge and the user could never see
    // their total balance. Keeping everything left-aligned guarantees it's on-screen at any width.
    row->addWidget(makeTicker(tr("Total balance"), m_homeTotalValue, unused, false));
    row->addWidget(makeTicker(QStringLiteral("XMR"), m_homeXmrValue, m_homeXmrPct, true));
    m_homeNativeBox = makeTicker(m_nativeSymbol, m_homeEthValue, m_homeEthPct, true);
    row->addWidget(m_homeNativeBox);
    row->addStretch();
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

    // The NFTs tab is opt-in (off by default) - enable it in Settings -> Appearance.
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

// DefiLlama chain slug for a chain id (for building coin keys "<slug>:<addr>"). Empty if unknown.
static QString defillamaChain(quint64 id) {
    switch (id) {
    case 1: return QStringLiteral("ethereum");
    case 42161: return QStringLiteral("arbitrum");
    case 8453: return QStringLiteral("base");
    case 10: return QStringLiteral("optimism");
    case 137: return QStringLiteral("polygon");
    case 56: return QStringLiteral("bsc");
    case 100: return QStringLiteral("xdai");
    case 43114: return QStringLiteral("avax");
    default: return QString();
    }
}

// CoinGecko id for a chain's native coin (used for DefiLlama's "coingecko:<id>" key).
static QString nativeCoingeckoId(quint64 id) {
    switch (id) {
    case 137: return QStringLiteral("matic-network");
    case 56: return QStringLiteral("binancecoin");
    case 100: return QStringLiteral("xdai");
    case 43114: return QStringLiteral("avalanche-2");
    default: return QStringLiteral("ethereum"); // ETH-native chains (1/10/42161/8453)
    }
}

// Whether at least one keyless on-chain router (KyberSwap/Odos/Paraswap/OpenOcean) supports the
// chain. Mirrors the per-router slug maps in core/src/chains.rs.
static bool swapChainSupported(quint64 chainId) {
    switch (chainId) {
    case 1: case 10: case 56: case 137: case 8453: case 42161: case 43114:
        return true;
    default:
        return false;
    }
}

// A DefiLlama coin key for a swap asset (native -> coingecko:<id>, token -> <chain>:<addr>).
static QString defillamaKey(quint64 chainId, const QString &tokenAddr) {
    if (tokenAddr.isEmpty())
        return QStringLiteral("coingecko:%1").arg(nativeCoingeckoId(chainId));
    const QString slug = defillamaChain(chainId);
    return slug.isEmpty() ? QString() : QStringLiteral("%1:%2").arg(slug, tokenAddr);
}

void AeroMainWindow::setupSwapTab() {
    m_swapTab = new QWidget();
    auto *outer = new QVBoxLayout(m_swapTab);
    outer->setContentsMargins(12, 12, 12, 12);
    outer->setSpacing(10);

    // No page heading - the tab (icon + "Swap") already labels it.

    // Feather-style form: clean labeled rows (no flashy cards), width-capped so fields don't sprawl
    // edge-to-edge on a wide window - everything lines up to a consistent, sensible width.
    auto *formHost = new QWidget(m_swapTab);
    formHost->setMaximumWidth(520);
    auto *form = new QFormLayout(formHost);
    form->setContentsMargins(0, 0, 0, 0);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
    form->setHorizontalSpacing(12);
    form->setVerticalSpacing(6);

    // From account - fills the (capped) field column, doesn't grow to the long label text. Searchable
    // like the Send "From" so a many-account wallet is navigable.
    m_swapFrom = new SearchableComboBox(m_swapTab);
    m_swapFrom->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_swapFrom->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_swapFrom->setMinimumContentsLength(10);
    // The collapsed box stays compact, but widen the dropdown so the full label (with balance on
    // the right) is visible when opened.
    m_swapFrom->view()->setMinimumWidth(360);
    connect(m_swapFrom, &QComboBox::currentIndexChanged, this, [this](int i) {
        if (i >= 0) m_account = static_cast<quint32>(i); // keep the active account unified
        updateSwapAvailable();
        updateSwapPayUsd();
        if (m_swapQuoteTimer) m_swapQuoteTimer->start(200);
    });
    form->addRow(tr("From account"), m_swapFrom);

    // You pay: compact asset picker (hugs its content) + amount + Max, all together so Max sits
    // right next to the number it fills (not stranded at the far edge).
    auto *payRow = new QHBoxLayout();
    payRow->setSpacing(8);
    m_swapSellButton = new QToolButton(m_swapTab);
    m_swapSellButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_swapSellButton->setIconSize(QSize(16, 16));
    m_swapSellButton->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    m_swapSellButton->setCursor(Qt::PointingHandCursor);
    m_swapSellButton->setIcon(tokenIcon(m_nativeSymbol));
    m_swapSellButton->setText(m_nativeSymbol + QStringLiteral(" \u25be"));
    m_swapSellButton->setFixedHeight(28);
    connect(m_swapSellButton, &QToolButton::clicked, this, [this]() { openSwapPicker(true); });
    m_swapAmount = new QLineEdit(m_swapTab);
    m_swapAmount->setPlaceholderText(tr("0.0"));
    m_swapAmount->setAlignment(Qt::AlignRight);
    m_swapAmount->setFixedHeight(28);
    m_swapAmount->setFixedWidth(170); // a number field, not a full-width block
    auto *maxBtn = new QToolButton(m_swapTab);
    maxBtn->setText(tr("Max"));
    maxBtn->setCursor(Qt::PointingHandCursor);
    maxBtn->setAutoRaise(true);
    maxBtn->setFixedHeight(28);
    maxBtn->setToolTip(tr("Use your full available balance"));
    connect(maxBtn, &QToolButton::clicked, this, [this]() {
        double avail = swapAvailable();
        if (m_swapSellAddr.isEmpty() && avail > 0.0) {
            // Selling the native coin: reserve gas (value + gas must fit the balance) or the eth-flow
            // / router swap fails at the last step. Swaps are gas-heavier than a plain send, so use a
            // generous 250k-gas estimate at the 3x base-fee headroom the core uses.
            double maxFeeWei = m_feeBaseWei > 0 ? m_feeBaseWei * 3.0 + qMax(m_feeTipWei, 1e9) : 3e9;
            const double reserveEth = 250000.0 * maxFeeWei / 1e18 * 1.1;
            avail = qMax(0.0, avail - reserveEth);
        }
        if (avail > 0.0) {
            // Fill to the SELL token's own precision, not a blanket eight places. parse_units rejects
            // an amount with more decimals than the token has ("too many decimal places"), and the
            // swap reports that rejection as "no routes found" - which is exactly why Max on a
            // 6-decimal token like USDT (e.g. 1675.31670600) found nothing while a trimmed 1675 did.
            // Cap the places so an 18-decimal token isn't asked for more precision than a double
            // carries, and floor rather than round so Max never lands a hair above the real balance.
            const int sellDec = m_swapSellAddr.isEmpty() ? 18 : static_cast<int>(m_swapSellDecimals);
            const int places = qMin(sellDec, 8);
            const double scale = std::pow(10.0, places);
            const double shown = std::floor(avail * scale) / scale;
            m_swapAmount->setText(QString::number(shown, 'f', places));
        }
    });
    payRow->addWidget(m_swapSellButton);
    payRow->addWidget(m_swapAmount);
    payRow->addWidget(maxBtn);      // Max sits right against the amount it fills
    payRow->addStretch(1);          // keep the trio grouped compactly on the left
    form->addRow(tr("You pay"), payRow);

    // Sub-line under "You pay": available balance (left) and its USD value (right).
    auto *paySub = new QHBoxLayout();
    m_swapAvailLabel = new QLabel(tr("Available: -"), m_swapTab);
    m_swapAvailLabel->setStyleSheet(QStringLiteral("color:#8a8a8a; font-size:11px;"));
    m_swapPayUsd = new QLabel(m_swapTab);
    m_swapPayUsd->setStyleSheet(QStringLiteral("color:#8a8a8a; font-size:11px;"));
    paySub->addWidget(m_swapAvailLabel);
    paySub->addStretch(1);
    paySub->addWidget(m_swapPayUsd);
    form->addRow(QString(), paySub);

    // Reverse direction (swap the two assets). Transparent (no button chrome) horizontal ↔ arrows,
    // placed out in the empty space on the right rather than as a boxed button.
    auto *revRow = new QHBoxLayout();
    auto *reverseBtn = new QToolButton(m_swapTab);
    // U+FE0E forces text (monochrome) presentation so the glyph doesn't render as a colored emoji.
    reverseBtn->setText(QStringLiteral("\u21C4\uFE0E"));
    reverseBtn->setToolTip(tr("Reverse - swap the pay and receive assets"));
    reverseBtn->setCursor(Qt::PointingHandCursor);
    reverseBtn->setAutoRaise(true); // flat: no border/background
    reverseBtn->setStyleSheet(QStringLiteral(
        "QToolButton{border:none; background:transparent; color:#9aa0ab;}"
        "QToolButton:hover{color:#ffffff;}"));
    { QFont rf = reverseBtn->font(); rf.setPointSize(rf.pointSize() + 6); reverseBtn->setFont(rf); }
    connect(reverseBtn, &QToolButton::clicked, this, [this]() {
        if (m_swapBuySymbol.isEmpty())
            return; // need a "receive" asset to reverse into
        std::swap(m_swapSellSymbol, m_swapBuySymbol);
        std::swap(m_swapSellAddr, m_swapBuyAddr);
        std::swap(m_swapSellDecimals, m_swapBuyDecimals);
        std::swap(m_swapLlamaSellUsd, m_swapLlamaBuyUsd); // prices follow their assets (no wrong "≈ $")
        if (m_swapSellButton) {
            m_swapSellButton->setIcon(tokenIcon(m_swapSellSymbol));
            m_swapSellButton->setText(m_swapSellSymbol + QStringLiteral(" \u25be"));
        }
        if (m_swapBuyButton) {
            m_swapBuyButton->setIcon(tokenIcon(m_swapBuySymbol));
            m_swapBuyButton->setText(m_swapBuySymbol + QStringLiteral(" \u25be"));
        }
        m_swapQuoteJson.clear();
        resetSwapFlow(); // reversing the pair abandons any half-finished swap
        m_swapUserPickedRouter = false;
        if (m_swapConfirmBtn) m_swapConfirmBtn->setEnabled(false);
        if (m_swapList) m_swapList->clear();
        if (m_swapReceive) m_swapReceive->setText(QStringLiteral("-"));
        updateSwapAvailable();
        updateSwapPayUsd();
        refreshSwapQuote();
    });
    revRow->addWidget(reverseBtn); // sits at the start of the field column, between the two pickers
    revRow->addStretch(1);
    form->addRow(QString(), revRow);

    // You receive: compact asset picker + estimated output (from the picked route, with USD).
    auto *recvRow = new QHBoxLayout();
    recvRow->setSpacing(8);
    m_swapBuyButton = new QToolButton(m_swapTab);
    m_swapBuyButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_swapBuyButton->setIconSize(QSize(16, 16));
    m_swapBuyButton->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    m_swapBuyButton->setCursor(Qt::PointingHandCursor);
    m_swapBuyButton->setText(tr("Select \u25be"));
    m_swapBuyButton->setFixedHeight(28);
    connect(m_swapBuyButton, &QToolButton::clicked, this, [this]() { openSwapPicker(false); });
    m_swapReceive = new QLabel(QStringLiteral("-"), m_swapTab);
    m_swapReceive->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_swapReceive->setTextInteractionFlags(Qt::TextSelectableByMouse);
    recvRow->addWidget(m_swapBuyButton);
    recvRow->addSpacing(8);
    recvRow->addWidget(m_swapReceive, 1);
    form->addRow(tr("You receive"), recvRow);

    // Max slippage: Auto (scales with trade size, like CoW) / preset / Custom manual %.
    auto *slipRow = new QHBoxLayout();
    m_swapSlipCustom = new QDoubleSpinBox(m_swapTab);
    m_swapSlipCustom->setRange(0.05, 50.0);
    m_swapSlipCustom->setDecimals(2);
    m_swapSlipCustom->setSingleStep(0.1);
    m_swapSlipCustom->setValue(0.5);
    m_swapSlipCustom->setSuffix(QStringLiteral("%"));
    m_swapSlipCustom->setMaximumWidth(90);
    m_swapSlipCustom->setVisible(false);
    m_swapSlippage = new QComboBox(m_swapTab);
    m_swapSlippage->addItems({tr("Auto (dynamic)"), QStringLiteral("0.1%"), QStringLiteral("0.5%"),
                              QStringLiteral("1%"), QStringLiteral("2%"), tr("Custom\u2026")});
    m_swapSlippage->setCurrentIndex(0); // default: auto-detect the best slippage for the size
    connect(m_swapSlippage, &QComboBox::currentIndexChanged, this, [this](int idx) {
        // Detect "Custom" by INDEX (the last item), not by matching translated text - the label is
        // localized so a startsWith("Custom") check silently breaks under non-English locales.
        m_swapSlipCustom->setVisible(idx == m_swapSlippage->count() - 1);
        if (m_swapQuoteTimer) m_swapQuoteTimer->start(200);
    });
    connect(m_swapSlipCustom, &QDoubleSpinBox::valueChanged, this,
            [this](double) { if (m_swapQuoteTimer) m_swapQuoteTimer->start(300); });
    slipRow->addWidget(m_swapSlipCustom);
    slipRow->addWidget(m_swapSlippage);
    slipRow->addStretch(1);
    form->addRow(tr("Max slippage"), slipRow);

    // Effective slippage note (updates per trade; explains Auto).
    m_swapSlipNote = new QLabel(m_swapTab);
    m_swapSlipNote->setStyleSheet(QStringLiteral("color:#8a8a8a; font-size:11px;"));
    m_swapSlipNote->setWordWrap(true);
    form->addRow(QString(), m_swapSlipNote);

    outer->addWidget(formHost);

    auto *listLabel = new QLabel(tr("Routes (best first) - select one"), m_swapTab);
    listLabel->setStyleSheet(QStringLiteral("color:#8a8a8a; font-weight:bold;"));
    outer->addWidget(listLabel);

    // Comparison table: columns like Feather's tables; native full-row selection makes the picked
    // route unmistakable.
    m_swapList = new QTreeWidget(m_swapTab);
    m_swapList->setColumnCount(4);
    m_swapList->setHeaderLabels(
        {tr("Router"), tr("You receive"), tr("Net (after gas)"), tr("Type")});
    m_swapList->setRootIsDecorated(false);
    m_swapList->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_swapList->setSelectionMode(QAbstractItemView::SingleSelection);
    m_swapList->setAlternatingRowColors(true);
    m_swapList->setUniformRowHeights(true);
    m_swapList->setMinimumHeight(150);
    m_swapList->setAllColumnsShowFocus(true);
    m_swapList->header()->setStretchLastSection(false);
    m_swapList->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_swapList->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_swapList->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_swapList->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    // A click/keyboard activation is an explicit user pick - keep it sticky across live re-quotes.
    connect(m_swapList, &QTreeWidget::itemClicked, this,
            [this](QTreeWidgetItem *, int) { m_swapUserPickedRouter = true; });
    connect(m_swapList, &QTreeWidget::itemActivated, this,
            [this](QTreeWidgetItem *, int) { m_swapUserPickedRouter = true; });
    connect(m_swapList, &QTreeWidget::currentItemChanged, this,
            [this](QTreeWidgetItem *cur, QTreeWidgetItem *) {
                if (!cur) {
                    m_swapSelRouter.clear();
                    m_swapConfirmBtn->setEnabled(false);
                    return;
                }
                const QVariantMap d = cur->data(0, Qt::UserRole).toMap();
                m_swapSelRouter = d.value(QStringLiteral("router_id")).toString();
                m_swapSelKind = d.value(QStringLiteral("kind")).toString();
                m_swapSelLabel = d.value(QStringLiteral("label")).toString();
                m_swapSelBuyAmount = d.value(QStringLiteral("buy_amount")).toString();
                m_swapSelGasUsd = d.value(QStringLiteral("gas_usd")).toDouble();
                // Reflect the picked route's output (with USD) in the "You receive" field.
                if (m_swapReceive) {
                    const bool buyIsNative = m_swapBuyAddr.isEmpty();
                    const quint8 buyDec = buyIsNative ? 18 : m_swapBuyDecimals;
                    const double buyH = m_swapSelBuyAmount.toDouble() / std::pow(10.0, buyDec);
                    QString txt = QStringLiteral("%1 %2").arg(formatBalance(buyH), m_swapBuySymbol);
                    if (m_swapLlamaBuyUsd > 0.0)
                        txt += QStringLiteral("   \u2248 %1").arg(fiatStr(buyH * m_swapLlamaBuyUsd));
                    m_swapReceive->setText(txt);
                }
                m_swapConfirmBtn->setEnabled(!m_swapSelRouter.isEmpty());
            });
    outer->addWidget(m_swapList, 1);

    m_swapRate = new QLabel(m_swapTab);
    m_swapRate->setWordWrap(true);
    m_swapRate->setStyleSheet(QStringLiteral("color:#9a9a9a;"));
    outer->addWidget(m_swapRate);
    // No trailing stretch: the routes table (added with stretch 1) should absorb the extra vertical
    // space so all routers are visible and there's no dead gap above the pinned Confirm bar.

    // Debounced live quote: typing an amount waits 600ms, then re-fetches all router quotes.
    m_swapQuoteTimer = new QTimer(this);
    m_swapQuoteTimer->setSingleShot(true);
    connect(m_swapQuoteTimer, &QTimer::timeout, this, &AeroMainWindow::refreshSwapQuote);
    connect(m_swapAmount, &QLineEdit::textChanged, this, [this]() {
        m_swapQuoteJson.clear();
        resetSwapFlow(); // editing the amount abandons any half-finished swap; unblock re-quoting
        m_swapUserPickedRouter = false; // amount changed -> re-evaluate the best route
        m_swapConfirmBtn->setEnabled(false);
        if (m_swapReceive) m_swapReceive->setText(QStringLiteral("-"));
        updateSwapPayUsd();
        m_swapQuoteTimer->start(600);
    });

    // Wrap the content in a scroll area so the (tall) Swap page never forces the whole window to
    // grow past the screen - the window stays freely resizable/movable and the page scrolls instead.
    m_swapScroll = new QScrollArea();
    m_swapScroll->setWidgetResizable(true);
    m_swapScroll->setFrameShape(QFrame::NoFrame);
    m_swapScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_swapScroll->setWidget(m_swapTab);

    // Tab page = scroll on top + a PINNED status/Confirm bar at the bottom, so you never have to
    // scroll down to reach Confirm.
    m_swapPage = new QWidget();
    auto *pageLayout = new QVBoxLayout(m_swapPage);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(0);
    pageLayout->addWidget(m_swapScroll, 1);
    auto *bar = new QWidget(m_swapPage);
    auto *barLayout = new QVBoxLayout(bar);
    barLayout->setContentsMargins(12, 6, 12, 10);
    barLayout->setSpacing(6);
    m_swapStatus = new QLabel(bar);
    m_swapStatus->setWordWrap(true);
    barLayout->addWidget(m_swapStatus);
    auto *confirmRow = new QHBoxLayout();
    confirmRow->addStretch(1);
    m_swapConfirmBtn = new QPushButton(tr("Confirm Swap"), bar);
    m_swapConfirmBtn->setEnabled(false);
    m_swapConfirmBtn->setCursor(Qt::PointingHandCursor);
    m_swapConfirmBtn->setMinimumWidth(160);
    connect(m_swapConfirmBtn, &QPushButton::clicked, this, &AeroMainWindow::onSwapConfirm);
    confirmRow->addWidget(m_swapConfirmBtn);
    barLayout->addLayout(confirmRow);
    pageLayout->addWidget(bar);

    // Inserted after Send/Receive/History (position 3) when a router supports the chain.
    updateSwapTabEnabled();
}

quint32 AeroMainWindow::swapSlippageBps() const {
    if (!m_swapSlippage)
        return 50;
    // Detect the mode by combo INDEX, not translated text (items: 0=Auto, 1=0.1%, 2=0.5%, 3=1%,
    // 4=2%, 5=Custom). Text matching broke under any non-English locale.
    const int idx = m_swapSlippage->currentIndex();
    const int lastIdx = m_swapSlippage->count() - 1;
    if (idx == lastIdx) { // Custom
        const int bps = m_swapSlipCustom ? qRound(m_swapSlipCustom->value() * 100.0) : 50;
        return static_cast<quint32>(qBound(1, bps, 5000)); // 0.01% .. 50%
    }
    if (idx == 0) { // Auto (dynamic)
        // Dynamic: smaller trades tolerate more slippage so they still fill (like CoW's dynamic
        // slippage). Scale by the USD value of the trade when we have a price for the sell asset.
        double usd = 0.0;
        if (m_swapLlamaSellUsd > 0.0 && m_swapAmount)
            usd = m_swapAmount->text().trimmed().toDouble() * m_swapLlamaSellUsd;
        if (usd <= 0.0) return 50;    // unknown value -> 0.5%
        if (usd < 50.0) return 300;   // 3%
        if (usd < 200.0) return 200;  // 2%
        if (usd < 1000.0) return 100; // 1%
        if (usd < 10000.0) return 50; // 0.5%
        return 30;                    // 0.3% for large trades
    }
    switch (idx) {
    case 1: return 10;  // 0.1%
    case 3: return 100; // 1%
    case 4: return 200; // 2%
    default: return 50; // 0.5% (index 2)
    }
}

bool AeroMainWindow::isKnownRouter(const QString &addr) const {
    static const QSet<QString> known = {
        QStringLiteral("0xc92e8bdf79f0507f65a392b0ab4667716bfe0110"), // CoW Vault Relayer
        QStringLiteral("0x9008d19f58aabd9ed0d60971565aa8510560ab41"), // CoW Settlement
        QStringLiteral("0xba3cb449bd2b4adddbc894d8697f5170800eadec"), // CoW EthFlow (production)
        QStringLiteral("0x6131b5fae19ea4f9d964eac0408e4408b66337b5"), // KyberSwap MetaAggregationRouterV2
        QStringLiteral("0xdef171fe48cf0115b1d80b88dc8eab59176fee57"), // Paraswap AugustusSwapper
        QStringLiteral("0x216b4b4ba9f3e719726886d34a177484278bfcae"), // Paraswap TokenTransferProxy
        QStringLiteral("0xcf5540fffcdc3d510b18bfca6d2b9987b0772559"), // Odos router v2
        QStringLiteral("0x6352a56caadc4f1e25cd6c75970fa768a3304e64"), // OpenOcean Exchange
    };
    return !addr.isEmpty() && known.contains(addr.toLower());
}

void AeroMainWindow::updateSwapTabEnabled() {
    if (!m_swapPage)
        return;
    // Offered if ANY keyless router supports this chain (CoW, KyberSwap, Odos, Paraswap, OpenOcean).
    const ChainDef &cd = chainDefFor(m_chainId);
    const bool anyRouter = cd.cow || swapChainSupported(m_chainId);
    const bool supported = anyRouter && m_wallet && !m_wallet->isWatchOnly();
    const int cur = ui.tabWidget->indexOf(m_swapPage);
    if (supported && cur < 0) {
        ui.tabWidget->insertTab(qMin(3, ui.tabWidget->count()), m_swapPage,
                                QIcon(QStringLiteral(":/assets/images/tab_swap.png")), tr("Swap"));
        if (m_swapFrom && m_swapFrom->count() == 0)
            rebuildAccountCombos();
        updateSwapAvailable();
    } else if (!supported && cur >= 0) {
        ui.tabWidget->removeTab(cur); // widget retained via m_swapPage
    }
}

void AeroMainWindow::setSwapAsset(bool sell, const QString &symbol, const QString &address,
                                  quint8 decimals) {
    if (sell) {
        m_swapSellSymbol = symbol;
        m_swapSellAddr = address;
        m_swapSellDecimals = decimals;
        m_swapLlamaSellUsd = 0.0; // stale until the new asset's DefiLlama price lands
        if (m_swapSellButton) {
            m_swapSellButton->setIcon(tokenIcon(symbol));
            m_swapSellButton->setText(symbol + QStringLiteral("  \u25be"));
        }
    } else {
        m_swapBuySymbol = symbol;
        m_swapBuyAddr = address;
        m_swapBuyDecimals = decimals;
        m_swapLlamaBuyUsd = 0.0; // stale until the new asset's DefiLlama price lands
        if (m_swapBuyButton) {
            m_swapBuyButton->setIcon(tokenIcon(symbol));
            m_swapBuyButton->setText(symbol + QStringLiteral("  \u25be"));
        }
    }
    m_swapQuoteJson.clear();
    resetSwapFlow(); // changing an asset abandons any half-finished swap; unblock re-quoting
    m_swapUserPickedRouter = false; // new asset -> let the best route be chosen again
    if (m_swapConfirmBtn)
        m_swapConfirmBtn->setEnabled(false);
    if (m_swapList)
        m_swapList->clear();
    if (m_swapReceive)
        m_swapReceive->setText(QStringLiteral("-"));
    if (sell) {
        updateSwapAvailable();
        updateSwapPayUsd();
    }
    refreshSwapQuote();
}

double AeroMainWindow::swapAvailable() const {
    if (!m_swapFrom || !m_wallet)
        return 0.0;
    const int from = qMax(0, m_swapFrom->currentIndex());
    if (m_swapSellAddr.isEmpty())
        return m_ethRawByAccount.value(from, 0.0);
    // Case-insensitive key match (mirrors the picker): the sell address may be checksummed while the
    // cached balance is stored under a lowercased key, so an exact lookup can wrongly read 0.
    const QString want = QStringLiteral("%1|%2").arg(from).arg(m_swapSellAddr.toLower());
    for (auto it = m_tokenRawByKey.constBegin(); it != m_tokenRawByKey.constEnd(); ++it)
        if (it.key().toLower() == want)
            return it.value();
    return 0.0;
}

void AeroMainWindow::updateSwapAvailable() {
    if (!m_swapAvailLabel)
        return;
    m_swapAvailLabel->setText(
        tr("Available: %1 %2").arg(formatBalance(swapAvailable()), m_swapSellSymbol));
}

void AeroMainWindow::updateSwapPayUsd() {
    if (!m_swapPayUsd)
        return;
    const double amt = m_swapAmount ? m_swapAmount->text().trimmed().toDouble() : 0.0;
    // Prefer the DefiLlama sell price; fall back to the cached native-coin price so the value shows
    // immediately (before/without a DefiLlama round-trip) when selling the native coin.
    double price = m_swapLlamaSellUsd;
    if (price <= 0.0 && m_swapSellAddr.isEmpty())
        price = m_nativeUsd;
    if (amt > 0.0 && price > 0.0)
        m_swapPayUsd->setText(QStringLiteral("\u2248 %1").arg(fiatStr(amt * price)));
    else
        m_swapPayUsd->clear();
}

void AeroMainWindow::openSwapPicker(bool sell) {
    if (!m_wallet)
        return;
    auto *popup = new QWidget(this, Qt::Popup);
    popup->setAttribute(Qt::WA_DeleteOnClose);
    auto *v = new QVBoxLayout(popup);
    v->setContentsMargins(6, 6, 6, 6);
    auto *search = new QLineEdit(popup);
    search->setPlaceholderText(tr("Search symbol"));
    v->addWidget(search);
    auto *list = new QListWidget(popup);
    v->addWidget(list, 1);

    // Held balance for an asset at the selected "From" account ("" == native coin). The lookup is
    // case-insensitive so a checksum/lowercase mismatch in the cache key never reads as 0.
    const int fromIndex = m_swapFrom ? qMax(0, m_swapFrom->currentIndex()) : 0;
    auto heldOf = [this, fromIndex](const QString &addr) -> double {
        if (addr.isEmpty())
            return m_ethRawByAccount.value(fromIndex, 0.0);
        const QString want = QStringLiteral("%1|%2").arg(fromIndex).arg(addr.toLower());
        for (auto it = m_tokenRawByKey.constBegin(); it != m_tokenRawByKey.constEnd(); ++it)
            if (it.key().toLower() == want)
                return it.value();
        return 0.0;
    };

    struct Asset { QString symbol, address; quint8 decimals; double held; double usd; };
    auto *assets = new QVector<Asset>();
    QSet<QString> seen;
    auto add = [&](const QString &sym, const QString &addr, quint8 dec) {
        const QString key = addr.toLower();
        if (!addr.isEmpty() && seen.contains(key))
            return;
        if (!addr.isEmpty())
            seen.insert(key);
        const double h = heldOf(addr);
        assets->push_back({sym, addr, dec, h, h * unitPriceUsd(sym)});
    };
    add(m_nativeSymbol, QString(), 18); // native coin
    const ChainDef &cd = chainDefFor(m_chainId);
    if (!cd.wrappedNative.isEmpty())
        add(QStringLiteral("W%1").arg(m_nativeSymbol), cd.wrappedNative, 18);
    // Curated well-known tokens for THIS chain (correct per-chain addresses).
    for (const TokenInfo &t : curatedTopTokens(m_chainId))
        add(t.symbol, t.address, t.decimals);
    for (const TokenInfo &t : m_wallet->tokens()) // tracked tokens on any chain
        add(t.symbol, t.address, t.decimals);

    // "You pay" (sell): only assets you actually hold - keep native as a fallback so the list is
    // never empty. "You receive" (buy): keep everything. Both show held-first with the balance on
    // the right, so a funded token (e.g. DAI) surfaces at the top instead of needing a search.
    if (sell) {
        QVector<Asset> heldOnly;
        for (const Asset &a : *assets)
            if (a.held > 0.0)
                heldOnly.push_back(a);
        if (heldOnly.isEmpty()) {
            const double h = heldOf(QString());
            heldOnly.push_back({m_nativeSymbol, QString(), 18, h, h * unitPriceUsd(m_nativeSymbol)});
        }
        *assets = heldOnly;
    }
    // Highest holdings VALUE (USD) first - so the biggest position (e.g. DAI) is at the top, not
    // whichever token happens to have the largest raw count. Tie-break by token amount.
    std::stable_sort(assets->begin(), assets->end(), [](const Asset &a, const Asset &b) {
        if (a.usd != b.usd)
            return a.usd > b.usd;
        return a.held > b.held;
    });

    // Same plain row style as the Send tab's "you send" picker: icon + "SYMBOL  addr" with the held
    // balance appended on the right. Kept identical for consistency (no bold, no custom widgets).
    auto rebuild = [=](const QString &filter) {
        list->clear();
        const QString f = filter.trimmed();
        for (int i = 0; i < assets->size(); ++i) {
            const Asset &a = assets->at(i);
            if (!f.isEmpty() && !a.symbol.contains(f, Qt::CaseInsensitive))
                continue;
            QString text = a.address.isEmpty()
                               ? a.symbol
                               : QStringLiteral("%1   %2").arg(a.symbol, shortAddr(a.address));
            if (a.held > 0.0)
                text += QStringLiteral("      %1 %2").arg(formatBalance(a.held), a.symbol);
            auto *it = new QListWidgetItem(tokenIcon(a.symbol), text, list);
            it->setData(Qt::UserRole, i);
        }
    };
    rebuild(QString());
    connect(search, &QLineEdit::textChanged, popup, [=](const QString &t) { rebuild(t); });
    auto activate = [this, popup, assets, sell](QListWidgetItem *it) {
        const int i = it->data(Qt::UserRole).toInt();
        if (i >= 0 && i < assets->size()) {
            const Asset &a = assets->at(i);
            setSwapAsset(sell, a.symbol, a.address, a.decimals);
        }
        popup->close();
    };
    connect(list, &QListWidget::itemClicked, popup, activate);
    connect(popup, &QObject::destroyed, [assets]() { delete assets; });

    QToolButton *anchor = sell ? m_swapSellButton : m_swapBuyButton;
    popup->resize(qMax(300, anchor->width() * 2), 360);
    popup->move(anchor->mapToGlobal(QPoint(0, anchor->height())));
    popup->show();
    search->setFocus();
}

// Clear all "swap in flight" state so the live re-quote guard can't stay stuck (which would block
// all future quoting). Safe to call on user input or at any terminal state.
void AeroMainWindow::resetSwapFlow() {
    m_swapExecQuote.clear();
    m_swapBuiltTo.clear();
    m_swapAwaitingApprove = false;
    m_swapCowExecuting = false;
    m_swapApprovePolls = 0;
    m_swapAwaitingRouterApprove = false;
    m_swapRouterApprovePolls = 0;
    m_swapRouterExecuteAfterBuild = false;
    m_swapAwaitingApproveReset = false;
    m_swapApproveCap.clear();
}

void AeroMainWindow::refreshSwapQuote() {
    if (!m_wallet || !m_swapPage || ui.tabWidget->indexOf(m_swapPage) < 0)
        return;
    // CRITICAL: never re-quote while a swap is being confirmed / approved / submitted. The live
    // 20s refresh would wipe the routes, reset the selection, and overwrite the flow's status with
    // "Fetching quotes…", stranding the approve→submit sequence (the user would approve the token
    // but never get to complete the swap). Reschedule and resume once the swap settles.
    const bool midFlight = m_swapCowExecuting || m_swapAwaitingApprove ||
                           m_swapAwaitingRouterApprove || m_swapAwaitingApproveReset ||
                           !m_swapExecQuote.isEmpty() || !m_swapBuiltTo.isEmpty();
    if (midFlight) {
        if (m_swapQuoteTimer)
            m_swapQuoteTimer->start(20000);
        return;
    }
    if (m_swapBuySymbol.isEmpty()) {
        m_swapStatus->clear();
        return;
    }
    const bool sellIsNative = m_swapSellAddr.isEmpty();
    const bool buyIsNative = m_swapBuyAddr.isEmpty();
    if (sellIsNative && buyIsNative) {
        m_swapStatus->setText(tr("Pick two different assets."));
        return;
    }
    if (m_swapSellSymbol == m_swapBuySymbol && m_swapSellAddr.compare(m_swapBuyAddr,
                                                                      Qt::CaseInsensitive) == 0) {
        m_swapStatus->setText(tr("Pick two different assets."));
        return;
    }
    const QString amt = m_swapAmount->text().trimmed();
    bool ok = false;
    const double amtV = amt.toDouble(&ok);
    if (!ok || amtV <= 0.0) {
        m_swapStatus->clear();
        if (m_swapList) m_swapList->clear();
        return;
    }
    const quint8 sellDec = sellIsNative ? 18 : m_swapSellDecimals;
    const quint8 buyDec = buyIsNative ? 18 : m_swapBuyDecimals;
    const QString sellAmountWei = m_wallet->parseUnits(amt, sellDec);
    const int from = m_swapFrom ? qMax(0, m_swapFrom->currentIndex()) : 0;

    m_swapStatus->setText(tr("Fetching quotes from routers…"));
    const quint32 slipBps = swapSlippageBps();
    if (m_swapSlipNote) {
        const bool autoMode = m_swapSlippage &&
                              m_swapSlippage->currentText().startsWith(QStringLiteral("Auto"));
        const QString pct = QString::number(slipBps / 100.0, 'f', 2);
        m_swapSlipNote->setText(autoMode
            ? tr("Auto: %1% for this trade size - applied to all routers (incl. CoW min-received)").arg(pct)
            : tr("%1% max slippage - applied to all routers (incl. CoW min-received)").arg(pct));
    }
    // Empty address = native coin; core maps it to each router's native sentinel.
    m_wallet->swapQuotes(static_cast<quint32>(from), m_swapSellAddr, m_swapBuyAddr, sellAmountWei,
                         sellIsNative, sellDec, buyDec, slipBps);

    // Cross-check / value the outputs against DefiLlama in parallel.
    const QString sellKey = defillamaKey(m_chainId, sellIsNative ? QString() : m_swapSellAddr);
    const QString buyKey = defillamaKey(m_chainId, buyIsNative ? QString() : m_swapBuyAddr);
    if (!sellKey.isEmpty() && !buyKey.isEmpty())
        m_wallet->defillamaPrices(QStringLiteral("%1,%2").arg(sellKey, buyKey));
}

void AeroMainWindow::onSwapQuotesReady(const QString &json, const QString &error) {
    if (!m_swapTab || !m_swapList)
        return;
    // Remember the user's manual pick (if any) BEFORE clearing, so a live re-quote doesn't snap the
    // selection back to "best".
    const QString desiredRouter = m_swapUserPickedRouter ? m_swapSelRouter : QString();
    m_swapList->clear();
    m_swapSelRouter.clear();
    m_swapConfirmBtn->setEnabled(false);
    if (m_swapReceive)
        m_swapReceive->setText(QStringLiteral("-"));
    if (!error.isEmpty()) {
        m_swapStatus->setText(tr("No quotes: %1").arg(error));
        return;
    }
    const QJsonArray arr = QJsonDocument::fromJson(json.toUtf8())
                               .object().value(QStringLiteral("quotes")).toArray();
    if (arr.isEmpty()) {
        m_swapStatus->setText(tr("No routes found for this pair/amount."));
        return;
    }
    const bool buyIsNative = m_swapBuyAddr.isEmpty();
    const quint8 buyDec = buyIsNative ? 18 : m_swapBuyDecimals;

    // Current gas price (wei/gas) for estimating gas cost of routers that don't report a USD gas.
    const double gasPriceWei = m_feeBaseWei + m_feeTipWei;

    struct Row { QString id, label, kind, buyAmount; double buyH, gasUsd, net; };
    QList<Row> rows;
    for (const QJsonValue &v : arr) {
        const QJsonObject o = v.toObject();
        Row r;
        r.id = o.value(QStringLiteral("router_id")).toString();
        r.label = o.value(QStringLiteral("label")).toString();
        r.kind = o.value(QStringLiteral("kind")).toString();
        r.buyAmount = o.value(QStringLiteral("buy_amount")).toString();
        r.buyH = r.buyAmount.toDouble() / std::pow(10.0, buyDec);
        r.gasUsd = o.value(QStringLiteral("gas_usd")).toDouble();
        // Some routers (e.g. OpenOcean) report gas units but not USD - estimate it so the
        // net-after-gas comparison is fair and we can show a real fee.
        if (r.gasUsd <= 0.0 && r.kind != QLatin1String("signed-order")) {
            const double units = o.value(QStringLiteral("gas_estimate")).toString().toDouble();
            if (units > 0.0 && gasPriceWei > 0.0 && m_nativeUsd > 0.0)
                r.gasUsd = units * gasPriceWei / 1e18 * m_nativeUsd;
        }
        const double buyUsd = m_swapLlamaBuyUsd > 0.0 ? r.buyH * m_swapLlamaBuyUsd : 0.0;
        // Net-after-gas when we can value the output; else fall back to raw output.
        r.net = buyUsd > 0.0 ? buyUsd - r.gasUsd : r.buyH;
        rows.push_back(r);
    }
    std::sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) { return a.net > b.net; });

    for (int i = 0; i < rows.size(); ++i) {
        const Row &r = rows[i];
        const bool gasless = r.kind == QLatin1String("signed-order");

        auto *it = new QTreeWidgetItem(m_swapList);
        // Router column: best route gets a star marker.
        it->setText(0, i == 0 ? tr("\u2605 %1").arg(r.label) : r.label);
        it->setText(1, QStringLiteral("%1 %2").arg(formatBalance(r.buyH), m_swapBuySymbol));
        QString net = QStringLiteral("-");
        if (m_swapLlamaBuyUsd > 0.0) {
            const double buyUsd = r.buyH * m_swapLlamaBuyUsd;
            net = fiatStr(r.gasUsd > 0.0 ? buyUsd - r.gasUsd : buyUsd);
        }
        it->setText(2, net);
        it->setText(3, gasless ? tr("gasless") : tr("on-chain"));
        it->setTextAlignment(1, Qt::AlignRight | Qt::AlignVCenter);
        it->setTextAlignment(2, Qt::AlignRight | Qt::AlignVCenter);
        if (gasless)
            it->setToolTip(3, tr("MEV-protected off-chain order (no gas)"));
        else if (r.gasUsd > 0.0)
            it->setToolTip(3, tr("On-chain swap · est. gas ~%1").arg(fiatStr(r.gasUsd)));

        QVariantMap d;
        d[QStringLiteral("router_id")] = r.id;
        d[QStringLiteral("label")] = r.label;
        d[QStringLiteral("kind")] = r.kind;
        d[QStringLiteral("buy_amount")] = r.buyAmount;
        d[QStringLiteral("gas_usd")] = r.gasUsd;
        it->setData(0, Qt::UserRole, d);

        if (i == 0) { // emphasize the best route
            QFont bold = it->font(0);
            bold.setBold(true);
            for (int c = 0; c < 4; ++c)
                it->setFont(c, bold);
        }
    }
    m_swapStatus->clear();
    // Re-select the user's router if it's still available; otherwise default to the best (row 0).
    int selRow = 0;
    if (!desiredRouter.isEmpty()) {
        for (int i = 0; i < rows.size(); ++i)
            if (rows[i].id == desiredRouter) {
                selRow = i;
                break;
            }
    }
    m_swapList->setCurrentItem(m_swapList->topLevelItem(selRow));
    // Keep quotes fresh while the tab is open (rates and gas move).
    if (m_swapQuoteTimer)
        m_swapQuoteTimer->start(20000);
}

// CoW execution continuation: after the user picks CoW and confirms, we fetch a fresh full quote
// here, show the detailed confirm dialog, and either submit the signed order or run eth-flow.
void AeroMainWindow::onSwapQuoteReady(const QString &quoteJson, const QString &error) {
    if (!m_swapTab || !m_swapCowExecuting)
        return;
    m_swapCowExecuting = false;
    if (!error.isEmpty() || quoteJson.isEmpty()) {
        m_swapStatus->setText(tr("Quote failed: %1").arg(error.isEmpty() ? tr("no route") : error));
        m_swapConfirmBtn->setEnabled(true);
        return;
    }
    const QJsonObject root = QJsonDocument::fromJson(quoteJson.toUtf8()).object();
    const bool cowVerified = root.value(QStringLiteral("verified")).toBool();
    const QJsonObject q = root.value(QStringLiteral("quote")).toObject();
    const QString buyAmountStr = q.value(QStringLiteral("buyAmount")).toString();
    if (buyAmountStr.isEmpty()) {
        m_swapStatus->setText(tr("Quote failed: empty response."));
        m_swapConfirmBtn->setEnabled(true);
        return;
    }
    m_swapQuoteJson = quoteJson;
    const bool sellIsNative = m_swapSellAddr.isEmpty();
    const bool buyIsNative = m_swapBuyAddr.isEmpty();
    const quint8 sellDec = sellIsNative ? 18 : m_swapSellDecimals;
    const quint8 buyDec = buyIsNative ? 18 : m_swapBuyDecimals;
    const double sellH = m_swapAmount->text().trimmed().toDouble();
    const double buyH = buyAmountStr.toDouble() / std::pow(10.0, buyDec);
    const double feeH = q.value(QStringLiteral("feeAmount")).toString().toDouble()
                        / std::pow(10.0, sellDec);
    const qint64 validTo = static_cast<qint64>(q.value(QStringLiteral("validTo")).toDouble());
    const double sellUsd = m_swapLlamaSellUsd > 0.0 ? sellH * m_swapLlamaSellUsd : 0.0;
    const double buyUsd = m_swapLlamaBuyUsd > 0.0 ? buyH * m_swapLlamaBuyUsd : 0.0;
    const double feeUsd = m_swapLlamaSellUsd > 0.0 ? feeH * m_swapLlamaSellUsd : 0.0;
    const double refOut = (m_swapLlamaSellUsd > 0.0 && m_swapLlamaBuyUsd > 0.0)
                              ? sellH * m_swapLlamaSellUsd / m_swapLlamaBuyUsd : 0.0;
    const double diffPct = refOut > 0.0 ? (buyH - refOut) / refOut * 100.0 : 0.0;

    if (!swapConfirmDialog(sellIsNative, buyIsNative, sellH, buyH, feeH, sellUsd, buyUsd, feeUsd,
                           refOut, diffPct, validTo, m_swapExecFrom, cowVerified,
                           QStringLiteral("cow"), QStringLiteral("CoW Protocol"), QString(),
                           Wallet::cowVaultRelayer())) {
        m_swapConfirmBtn->setEnabled(true);
        return;
    }
    m_swapExecQuote = m_swapQuoteJson;
    m_swapExecNative = sellIsNative;
    if (sellIsNative) {
        m_swapStatus->setText(tr("Submitting eth-flow order on-chain…"));
        m_wallet->swapEthFlow(m_swapExecFrom, m_swapExecQuote, m_swapExecBuyAddr,
                              m_swapExecSlippageBps);
    } else {
        m_swapStatus->setText(tr("Checking token approval…"));
        m_wallet->swapAllowance(m_swapExecFrom, m_swapExecSellAddr);
    }
}

void AeroMainWindow::onDefillamaPricesReady(const QString &json, const QString &error) {
    if (!error.isEmpty() || !m_swapTab)
        return;
    const QJsonObject coins = QJsonDocument::fromJson(json.toUtf8()).object()
                                  .value(QStringLiteral("coins")).toObject();
    const bool sellIsNative = m_swapSellAddr.isEmpty();
    const bool buyIsNative = m_swapBuyAddr.isEmpty();
    const QString sellKey = defillamaKey(m_chainId, sellIsNative ? QString() : m_swapSellAddr);
    const QString buyKey = defillamaKey(m_chainId, buyIsNative ? QString() : m_swapBuyAddr);
    m_swapLlamaSellUsd = coins.value(sellKey).toObject().value(QStringLiteral("price")).toDouble();
    m_swapLlamaBuyUsd = coins.value(buyKey).toObject().value(QStringLiteral("price")).toDouble();
    updateSwapPayUsd(); // now that we have a sell-token price, show the "≈ $X" under You pay
}

// Inline swap result (Feather-style): no modal popup. Sets a check-marked status line on the Swap
// tab (with an optional explorer/CoW link) and refreshes History so the swap shows up there - as a
// pending CoW order or a freshly-mined on-chain swap.
// Show a just-placed swap as "pending" in History immediately (works on every network, including
// on-chain router swaps that only reach the explorer once mined). Reconciled by the model when the
// real row appears (CoW order by uid, or the mined tx by hash).
void AeroMainWindow::addPendingSwap(const QString &id) {
    if (!m_historyModel || id.isEmpty())
        return;
    HistoryItem h;
    h.kind = QStringLiteral("swap");
    h.status = QStringLiteral("pending");
    h.direction = QStringLiteral("swap");
    h.symbol = m_swapSellSymbol;
    h.formatted = m_swapAmount ? m_swapAmount->text().trimmed() : QString();
    h.buySymbol = m_swapBuySymbol;
    const bool buyIsNative = m_swapBuyAddr.isEmpty();
    const quint8 buyDec = buyIsNative ? 18 : m_swapBuyDecimals;
    const double buyH = m_swapSelBuyAmount.toDouble() / std::pow(10.0, buyDec);
    h.buyFormatted = QString::number(buyH, 'f', 6);
    h.txHash = id;
    h.counterparty = m_swapSelLabel;
    h.timestamp = static_cast<quint64>(QDateTime::currentSecsSinceEpoch());
    // For CoW orders, remember when the order actually expires (validTo) so the local row isn't
    // flipped to "failed" while it's still legitimately open. Mirror the core's floor of now+20min,
    // plus a small indexing grace. On-chain router swaps mine quickly, so leave expiry unknown (0).
    {
        const QJsonObject q = QJsonDocument::fromJson(m_swapExecQuote.toUtf8())
                                  .object().value(QStringLiteral("quote")).toObject();
        const qint64 validTo = static_cast<qint64>(q.value(QStringLiteral("validTo")).toDouble());
        if (validTo > 0) {
            const qint64 now = QDateTime::currentSecsSinceEpoch();
            h.expiry = static_cast<quint64>(qMax(validTo, now + 20 * 60) + 5 * 60);
        }
    }
    // The swap tab sells from whichever account is selected there, which is not always the one on
    // screen. Recording it is what lets the poll ask the right address about this order.
    h.account = m_swapExecFrom;
    m_historyModel->addLocalSwap(h);
    startCowPoll(); // keep re-checking status until it settles (CoW auctions can take minutes)
}

// While any swap is still pending, periodically re-pull history (which merges CoW order status and
// reconciles the pending row to filled/failed). Stops itself once nothing is pending, so it costs
// nothing in steady state.
void AeroMainWindow::startCowPoll() {
    if (!m_cowPollTimer) {
        m_cowPollTimer = new QTimer(this);
        m_cowPollTimer->setInterval(30000);
        connect(m_cowPollTimer, &QTimer::timeout, this, [this]() {
            if (!m_wallet || !m_historyModel) {
                m_cowPollTimer->stop();
                return;
            }
            // Give up on a local optimistic row the CoW API never returned, so it can't stick.
            m_historyModel->expireStalePendingSwaps(35 * 60);
            if (!m_historyModel->hasPendingSwaps()) {
                m_cowPollTimer->stop();
                return;
            }
            if (m_connMode <= 0)
                return; // offline: nothing to ask, but keep the timer for when we reconnect
            // Ask about every account holding an open order, not only the one on screen. A swap can
            // be placed from any account in the Swap tab, and after a restart the pending rows come
            // back from the cache remembering which account they belong to.
            QList<quint32> accounts = m_historyModel->pendingSwapAccounts();
            if (accounts.isEmpty())
                accounts.append(m_account); // an older cache, saved before rows recorded an account
            for (quint32 a : accounts) {
                // A single-account History view is served by refreshHistory(), whose batches
                // onAccountHistoryReady() deliberately drops - so route through it, or the filtered
                // view would never learn that the order settled.
                if (m_historyFilter >= 0 && a == static_cast<quint32>(m_historyFilter))
                    m_wallet->refreshHistory(a);
                else
                    ensureAccountHistory(a, /*force*/ true);
            }
        });
    }
    if (m_historyModel && m_historyModel->hasPendingSwaps())
        m_cowPollTimer->start();
}

void AeroMainWindow::swapInlineDone(const QString &summary, const QString &url,
                                    const QString &linkText) {
    if (m_swapStatus) {
        QString msg = QStringLiteral("\u2714  %1").arg(summary.toHtmlEscaped());
        if (!url.isEmpty())
            msg += QStringLiteral("&nbsp;&nbsp;<a href=\"%1\">%2</a>")
                       .arg(url, linkText.toHtmlEscaped());
        m_swapStatus->setTextFormat(Qt::RichText);
        // Not setOpenExternalLinks: that hands the URL straight to the system browser, outside Tor,
        // with no chance to warn.
        m_swapStatus->setOpenExternalLinks(false);
        // Reconnected each time a swap finishes, so drop the previous swap's handler first.
        disconnect(m_swapStatus, &QLabel::linkActivated, this, nullptr);
        connect(m_swapStatus, &QLabel::linkActivated, this,
                [this](const QString &href) { openOutsideTor(href); });
        m_swapStatus->setText(msg);
    }
    // The account that sold, which is not necessarily the account on screen.
    const quint32 from = m_swapExecFrom;
    ensureAccountHistory(from, /*force*/ true);
    // CoW/explorers need a moment to index; refresh once more so a just-placed order flips to a row.
    QTimer::singleShot(20000, this, [this, from]() { ensureAccountHistory(from, /*force*/ true); });
}

bool AeroMainWindow::swapConfirmDialog(bool sellIsNative, bool buyIsNative, double sellH,
                                       double buyH, double feeH, double sellUsd, double buyUsd,
                                       double feeUsd, double refOut, double diffPct, qint64 validTo,
                                       quint32 fromIndex, bool cowVerified, const QString &routerId,
                                       const QString &routerLabel, const QString &routerTo,
                                       const QString &routerSpender) {
    const bool isCow = routerId == QLatin1String("cow");
    const bool sellKnown = sellIsNative || isKnownToken(m_swapSellAddr);
    const bool buyKnown = buyIsNative || isKnownToken(m_swapBuyAddr);
    const bool routerKnown = isCow || isKnownRouter(routerTo);

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Confirm swap"));
    dlg.setMinimumWidth(500);
    dlg.setMaximumHeight(720);
    auto *root = new QVBoxLayout(&dlg);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // Scrollable content so a tall confirm never runs off-screen; buttons stay pinned below.
    auto *scroll = new QScrollArea(&dlg);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto *content = new QWidget();
    auto *cv = new QVBoxLayout(content);
    cv->setContentsMargins(16, 16, 16, 12);
    cv->setSpacing(12);

    auto *net = new QLabel(tr("on %1  ·  via %2").arg(chainDefFor(m_chainId).name, routerLabel),
                           content);
    net->setStyleSheet(QStringLiteral("color:#8a8a8a;"));
    cv->addWidget(net);

    // --- Summary: a clean group-box form (matches the Details/Interacting-with sections). ---
    auto *summary = new QGroupBox(tr("Swap"), content);
    auto *sg = new QFormLayout(summary);
    sg->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    sg->setHorizontalSpacing(12);
    sg->setVerticalSpacing(8);
    auto valueLabel = [&](double amt, const QString &sym, double usd) {
        QString t = QStringLiteral("%1 %2").arg(formatBalance(amt), sym);
        if (usd > 0.0)
            t += QStringLiteral("   (%1)").arg(fiatStr(usd));
        auto *l = new QLabel(t, summary);
        QFont f = l->font();
        f.setBold(true);
        l->setFont(f);
        l->setTextInteractionFlags(Qt::TextSelectableByMouse);
        return l;
    };
    sg->addRow(tr("You pay"), valueLabel(sellH, m_swapSellSymbol, sellUsd));
    sg->addRow(tr("You receive"), valueLabel(buyH, m_swapBuySymbol, buyUsd));
    cv->addWidget(summary);

    // --- Security banner (private, no-third-party alternative to Blockaid). ---
    {
        auto *sec = new QLabel(content);
        sec->setWordWrap(true);
        if (sellKnown && buyKnown && routerKnown && cowVerified) {
            // All good: a clean green confirmation line (no heavy filled box).
            sec->setText(isCow
                ? tr("\u2713 Verified contracts and known tokens\u2014CoW-verified price.")
                : tr("\u2713 Recognized %1 router and known tokens.").arg(routerLabel));
            sec->setStyleSheet(QStringLiteral("color:#4caf7d; padding:2px 0;"));
        } else {
            // Only surface a highlighted warning when something actually needs checking.
            QStringList notes;
            if (!sellKnown || !buyKnown)
                notes << tr("a token is NOT on your verified list \u2014 check its address below");
            if (!routerKnown)
                notes << tr("the router contract is not recognized \u2014 verify it");
            if (isCow && !cowVerified)
                notes << tr("CoW could not verify this price");
            sec->setText(tr("\u26a0 Review carefully: %1.").arg(notes.join(QStringLiteral("; "))));
            sec->setStyleSheet(QStringLiteral(
                "color:#c99a3a; background:rgba(200,150,0,0.10); border-radius:6px; padding:8px;"));
        }
        cv->addWidget(sec);
    }

    // --- Transaction details. ---
    auto *det = new QGroupBox(tr("Details"), content);
    auto *df = new QFormLayout(det);
    df->setLabelAlignment(Qt::AlignRight);
    df->addRow(tr("From"),
               new QLabel(tr("%1  ·  %2").arg(accountLabel(fromIndex),
                                              shortAddr(m_wallet->address(fromIndex))), det));
    if (sellH > 0.0)
        df->addRow(tr("Rate"),
                   new QLabel(tr("1 %1 \u2248 %2 %3").arg(m_swapSellSymbol, formatBalance(buyH / sellH),
                                                          m_swapBuySymbol), det));
    // `buyH` is only the EXPECTED amount at the quoted price. The order/router is actually signed to
    // accept as little as the slippage-adjusted floor, so show that as the "Minimum received" (the
    // number the user relies on to bound their loss) and keep the expected amount as a second line.
    const quint8 buyDecD = buyIsNative ? 18 : m_swapBuyDecimals;
    double minH;
    if (isCow) {
        // core's swap_submit/eth_flow sign buyAmount = quoted * (10000 - slippageBps) / 10000.
        minH = buyH * (10000.0 - static_cast<double>(m_swapExecSlippageBps)) / 10000.0;
    } else {
        // on-chain routers embed the exact min-out (m_swapBuiltMinBuy, in wei) in the calldata.
        const double m = m_swapBuiltMinBuy.toDouble();
        minH = m > 0.0 ? m / std::pow(10.0, buyDecD) : buyH;
    }
    df->addRow(tr("Minimum received"),
               new QLabel(isCow
                   ? tr("%1 %2  (guaranteed by the order)").arg(formatBalance(minH), m_swapBuySymbol)
                   : tr("%1 %2  (enforced on-chain by slippage)")
                         .arg(formatBalance(minH), m_swapBuySymbol),
                          det));
    df->addRow(tr("Expected received"),
               new QLabel(tr("%1 %2  (at the quoted price)").arg(formatBalance(buyH), m_swapBuySymbol),
                          det));
    if (isCow) {
        df->addRow(tr("Network fee"), new QLabel(feeUsd > 0.0
            ? tr("%1 %2  (%3)  ·  from the sold amount")
                  .arg(formatBalance(feeH), m_swapSellSymbol, fiatStr(feeUsd))
            : tr("%1 %2  ·  from the sold amount").arg(formatBalance(feeH), m_swapSellSymbol), det));
    } else {
        // On-chain routers: the fee is gas, paid separately. Show the estimate (native + USD).
        QString feeTxt;
        if (feeH > 0.0 && feeUsd > 0.0)
            feeTxt = tr("\u2248 %1 %2  (%3)  ·  network gas, est.")
                         .arg(formatBalance(feeH), m_nativeSymbol, fiatStr(feeUsd));
        else if (feeUsd > 0.0)
            feeTxt = tr("\u2248 %1  ·  network gas, est.").arg(fiatStr(feeUsd));
        else
            feeTxt = tr("paid separately in %1 gas (estimate unavailable)").arg(m_nativeSymbol);
        df->addRow(tr("Network fee"), new QLabel(feeTxt, det));
    }
    if (refOut > 0.0) {
        auto *ref = new QLabel(tr("\u2248 %1 %2  (%3%4% vs quote)")
                                   .arg(formatBalance(refOut), m_swapBuySymbol,
                                        diffPct >= 0 ? QStringLiteral("+") : QString(),
                                        QString::number(diffPct, 'f', 2)), det);
        if (diffPct < -5.0)
            ref->setStyleSheet(QStringLiteral("color:#d0a000;"));
        df->addRow(tr("DefiLlama price"), ref);
    }
    if (validTo > 0)
        df->addRow(tr("Order expires"),
                   new QLabel(QDateTime::fromSecsSinceEpoch(validTo).toString(Qt::TextDate), det));
    df->addRow(tr("Method"), new QLabel(isCow
        ? (sellIsNative ? tr("On-chain (eth-flow) - you pay gas")
                        : tr("Off-chain signature (EIP-712) - gasless"))
        : tr("On-chain via %1 - you pay gas").arg(routerLabel), det));
    cv->addWidget(det);

    // --- Interacting with - exact contract addresses + verified/unverified badges. ---
    auto *contracts = new QGroupBox(tr("Interacting with (verify addresses)"), content);
    auto *xf = new QFormLayout(contracts);
    xf->setLabelAlignment(Qt::AlignRight);
    auto addrRow = [&](const QString &name, const QString &addr, int trust) {
        auto *w = new QWidget(contracts);
        auto *h = new QHBoxLayout(w);
        h->setContentsMargins(0, 0, 0, 0);
        auto *l = new QLabel(addr, w);
        l->setTextInteractionFlags(Qt::TextSelectableByMouse);
        l->setStyleSheet(QStringLiteral("font-family:Consolas,monospace;"));
        h->addWidget(l, 1);
        if (trust >= 0) {
            auto *badge = new QLabel(trust == 1 ? tr("\u2713 verified") : tr("\u26a0 unverified"), w);
            // Green for verified, amber for unverified - the address-verification signal the user wants.
            badge->setStyleSheet(trust == 1 ? QStringLiteral("color:#4caf7d; font-size:11px;")
                                            : QStringLiteral("color:#d0a000; font-size:11px;"));
            h->addWidget(badge);
        }
        xf->addRow(name, w);
    };
    addrRow(tr("Sell token"), sellIsNative ? tr("native %1").arg(m_nativeSymbol) : m_swapSellAddr,
            sellIsNative ? -1 : (sellKnown ? 1 : 0));
    addrRow(tr("Buy token"), buyIsNative ? tr("native %1").arg(m_nativeSymbol) : m_swapBuyAddr,
            buyIsNative ? -1 : (buyKnown ? 1 : 0));
    if (isCow) {
        if (sellIsNative)
            addrRow(tr("CoW eth-flow"), Wallet::cowEthFlow(), 1);
        addrRow(tr("GPv2 Settlement"), Wallet::cowSettlement(), 1);
        if (!sellIsNative)
            addrRow(tr("Vault Relayer (spender)"), Wallet::cowVaultRelayer(), 1);
    } else {
        addrRow(tr("%1 router").arg(routerLabel), routerTo, isKnownRouter(routerTo) ? 1 : 0);
        if (!sellIsNative)
            addrRow(tr("Approval spender"), routerSpender, isKnownRouter(routerSpender) ? 1 : 0);
    }
    cv->addWidget(contracts);

    auto *tip = new QLabel(isCow
        ? tr("Tip: try a small amount first. Orders are settled by CoW solvers.")
        : tr("Tip: try a small amount first. This sends an on-chain swap via %1.").arg(routerLabel),
        content);
    tip->setWordWrap(true);
    tip->setStyleSheet(QStringLiteral("color:#8a8a8a; font-size:11px;"));
    cv->addWidget(tip);
    cv->addStretch(1);

    scroll->setWidget(content);
    root->addWidget(scroll, 1);

    // --- Pinned button bar (outside the scroll). ---
    auto *btnBar = new QWidget(&dlg);
    auto *bh = new QHBoxLayout(btnBar);
    bh->setContentsMargins(16, 8, 16, 12);
    bh->addStretch(1);
    auto *rejectBtn = new QPushButton(tr("Reject"), btnBar);
    rejectBtn->setCursor(Qt::PointingHandCursor);
    // Native (theme) buttons - no custom green fill; the default button is the primary action.
    auto *confirmBtn = new QPushButton(tr("Confirm swap"), btnBar);
    confirmBtn->setDefault(true);
    confirmBtn->setCursor(Qt::PointingHandCursor);
    connect(rejectBtn, &QPushButton::clicked, &dlg, &QDialog::reject);
    connect(confirmBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    bh->addWidget(rejectBtn);
    bh->addWidget(confirmBtn);
    root->addWidget(btnBar);

    return dlg.exec() == QDialog::Accepted;
}

bool AeroMainWindow::isKnownToken(const QString &addr) const {
    return !addr.isEmpty() && verifiedTokenAddresses().contains(addr.toLower());
}

QString AeroMainWindow::spendingApprovalDialog(const QString &tokenSymbol, const QString &tokenAddr,
                                               const QString &spenderName, const QString &spenderAddr,
                                               const QString &exactHuman, const QString &exactWei) {
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Approve spending cap"));
    dlg.setMinimumWidth(460);
    auto *root = new QVBoxLayout(&dlg);
    root->setSpacing(10);

    auto *header = new QLabel(tr("Allow %1 to use your %2?").arg(spenderName, tokenSymbol), &dlg);
    QFont hf = header->font();
    hf.setBold(true);
    hf.setPointSize(hf.pointSize() + 2);
    header->setFont(hf);
    header->setWordWrap(true);
    root->addWidget(header);

    auto *desc = new QLabel(tr("The router settles swaps by pulling the token you sell from your "
                               "wallet, so it needs a one-time on-chain approval (costs gas). Approve "
                               "only what this swap needs - a smaller cap limits what could ever be "
                               "moved."),
                            &dlg);
    desc->setWordWrap(true);
    desc->setStyleSheet(QStringLiteral("color:#8a8a8a;"));
    root->addWidget(desc);

    // Editable spending cap: exact (recommended) or unlimited - MetaMask-style.
    auto *capBox = new QGroupBox(tr("Spending cap"), &dlg);
    auto *cv = new QVBoxLayout(capBox);
    auto *rbExact = new QRadioButton(
        tr("This swap only - %1 %2  (recommended)").arg(exactHuman, tokenSymbol), capBox);
    auto *rbMax = new QRadioButton(tr("Unlimited - don't ask again for %1").arg(tokenSymbol), capBox);
    // Default to unlimited so a token is approved ONCE per spender: an exact cap is consumed by each
    // swap and forces a fresh approval (extra tx + gas) every single time. The exact option remains
    // for cautious users.
    rbMax->setChecked(true);
    cv->addWidget(rbExact);
    cv->addWidget(rbMax);
    auto *maxWarn = new QLabel(
        tr("\u26a0 Unlimited lets the spender move any amount of your %1 in the future.")
            .arg(tokenSymbol), capBox);
    maxWarn->setWordWrap(true);
    maxWarn->setStyleSheet(QStringLiteral("color:#d0a000;"));
    maxWarn->setVisible(true); // shown by default since Unlimited is preselected
    cv->addWidget(maxWarn);
    connect(rbMax, &QRadioButton::toggled, maxWarn, &QLabel::setVisible);
    root->addWidget(capBox);

    auto *box = new QGroupBox(tr("Details"), &dlg);
    auto *f = new QFormLayout(box);
    auto addr = [&](const QString &n, const QString &a, bool known) {
        auto *w = new QWidget(box);
        auto *h = new QHBoxLayout(w);
        h->setContentsMargins(0, 0, 0, 0);
        auto *l = new QLabel(a, w);
        l->setTextInteractionFlags(Qt::TextSelectableByMouse);
        l->setStyleSheet(QStringLiteral("font-family:Consolas,monospace;"));
        h->addWidget(l, 1);
        auto *badge = new QLabel(known ? tr("\u2713 verified") : tr("\u26a0 unverified"), w);
        badge->setStyleSheet(known ? QStringLiteral("color:#4caf7d;")
                                   : QStringLiteral("color:#d0a000;"));
        h->addWidget(badge);
        f->addRow(n, w);
    };
    addr(tr("Token"), tokenAddr, isKnownToken(tokenAddr));
    addr(tr("Spender"), spenderAddr, isKnownRouter(spenderAddr));
    f->addRow(tr("Network"), new QLabel(chainDefFor(m_chainId).name, box));
    // Estimated gas cost of THIS one-time ERC-20 approval tx (~55k gas), so it's not a mystery fee.
    {
        const double gasPriceWei = m_feeBaseWei + m_feeTipWei;
        QString feeText;
        if (gasPriceWei > 0.0) {
            const double feeNative = 55000.0 * gasPriceWei / 1e18;
            feeText = QStringLiteral("\u2248 %1 %2").arg(QString::number(feeNative, 'f', 6),
                                                         m_nativeSymbol);
            if (m_nativeUsd > 0.0)
                feeText += QStringLiteral("  (%1)").arg(fiatStr(feeNative * m_nativeUsd));
        } else {
            feeText = tr("estimated at approval time");
        }
        auto *feeLbl = new QLabel(feeText, box);
        feeLbl->setToolTip(tr("Gas for the one-time approval transaction - not the swap itself."));
        f->addRow(tr("Network fee"), feeLbl);
    }
    root->addWidget(box);

    auto *note = new QLabel(tr("You can revoke this anytime via Tools \u2192 Revoke Token Approvals."),
                            &dlg);
    note->setWordWrap(true);
    note->setStyleSheet(QStringLiteral("color:#8a8a8a;"));
    root->addWidget(note);

    auto *bb = new QDialogButtonBox(&dlg);
    auto *ok = bb->addButton(tr("Approve"), QDialogButtonBox::AcceptRole);
    bb->addButton(tr("Reject"), QDialogButtonBox::RejectRole);
    ok->setDefault(true);
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    root->addWidget(bb);
    if (dlg.exec() != QDialog::Accepted)
        return QString();
    return rbMax->isChecked() ? QStringLiteral("max") : exactWei;
}

void AeroMainWindow::onSwapConfirm() {
    if (!m_wallet || m_swapSelRouter.isEmpty())
        return;
    const bool sellIsNative = m_swapSellAddr.isEmpty();
    const int from = m_swapFrom ? qMax(0, m_swapFrom->currentIndex()) : 0;
    const quint8 sellDec = sellIsNative ? 18 : m_swapSellDecimals;
    const QString sellAmountWei = m_wallet->parseUnits(m_swapAmount->text().trimmed(), sellDec);

    // Capture the execution context shared by both the CoW and on-chain-router paths.
    m_swapExecFrom = static_cast<quint32>(from);
    m_swapExecSellAddr = m_swapSellAddr;
    m_swapExecBuyAddr = m_swapBuyAddr;
    m_swapExecSellAmountWei = sellAmountWei;
    m_swapExecNative = sellIsNative;
    m_swapExecSlippageBps = swapSlippageBps(); // lock the slippage for this swap
    m_swapBuiltTo.clear();
    m_swapAwaitingApprove = false; // fresh attempt
    m_swapApprovePolls = 0;
    m_swapAwaitingRouterApprove = false;
    m_swapRouterApprovePolls = 0;
    m_swapRouterExecuteAfterBuild = false;
    m_swapConfirmBtn->setEnabled(false);

    if (m_swapSelKind == QLatin1String("signed-order")) {
        // CoW: fetch a fresh full quote, then onSwapQuoteReady shows the confirm + executes.
        m_swapCowExecuting = true;
        m_swapStatus->setText(tr("Getting a fresh CoW quote…"));
        const QString buyParam = m_swapBuyAddr.isEmpty() ? Wallet::buyEthSentinel() : m_swapBuyAddr;
        m_wallet->swapQuote(m_swapExecFrom, m_swapSellAddr, buyParam, sellAmountWei, sellIsNative);
    } else {
        // On-chain router: build fresh calldata, then onRouterBuilt shows the confirm + executes.
        m_swapStatus->setText(tr("Building %1 transaction…").arg(m_swapSelLabel));
        m_wallet->routerBuild(m_swapSelRouter, m_swapExecFrom, m_swapSellAddr, m_swapBuyAddr,
                              sellAmountWei, sellIsNative,
                              sellIsNative ? 18 : m_swapSellDecimals,
                              m_swapBuyAddr.isEmpty() ? 18 : m_swapBuyDecimals, swapSlippageBps());
    }
}

void AeroMainWindow::onRouterBuilt(const QString &json, const QString &error) {
    if (m_swapSelKind != QLatin1String("onchain"))
        return;
    if (!error.isEmpty() || json.isEmpty()) {
        m_swapStatus->setText(tr("Couldn't build the swap: %1").arg(error));
        m_swapConfirmBtn->setEnabled(true);
        return;
    }
    const QJsonObject o = QJsonDocument::fromJson(json.toUtf8()).object();
    m_swapBuiltTo = o.value(QStringLiteral("to")).toString();
    m_swapBuiltData = o.value(QStringLiteral("data")).toString();
    m_swapBuiltValue = o.value(QStringLiteral("value")).toString();
    m_swapBuiltSpender = o.value(QStringLiteral("spender")).toString();
    m_swapBuiltMinBuy = o.value(QStringLiteral("min_buy_amount")).toString();
    const QString buyAmountStr = o.value(QStringLiteral("buy_amount")).toString();
    if (m_swapBuiltTo.isEmpty() || m_swapBuiltData.isEmpty()) {
        m_swapStatus->setText(tr("Couldn't build the swap: empty transaction."));
        m_swapConfirmBtn->setEnabled(true);
        return;
    }

    // Re-built with FRESH calldata right after the approval mined: the user already confirmed and the
    // allowance is now live, so send the swap straight through (no dialog / allowance re-check).
    if (m_swapRouterExecuteAfterBuild) {
        m_swapRouterExecuteAfterBuild = false;
        // The on-chain min-out already protects funds, but if the fresh quote is materially worse
        // than what the user confirmed (>1%), re-prompt so they aren't surprised by the outcome.
        const double confirmed = m_swapConfirmedMinBuy.toDouble();
        const double fresh = m_swapBuiltMinBuy.toDouble();
        if (confirmed > 0.0 && fresh > 0.0 && fresh < confirmed * 0.99) {
            const double dropPct = (1.0 - fresh / confirmed) * 100.0;
            const auto ans = QMessageBox::question(
                this, tr("Rate moved"),
                tr("The price changed while your approval confirmed. You'll now receive at least "
                   "about %1%% less than when you confirmed. Proceed with the swap?")
                    .arg(QString::number(dropPct, 'f', 1)),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            if (ans != QMessageBox::Yes) {
                m_swapStatus->setText(tr("Swap cancelled - the rate moved."));
                resetSwapFlow();
                return;
            }
        }
        m_swapStatus->setText(tr("Sending swap through %1…").arg(m_swapSelLabel));
        m_wallet->routerSwap(m_swapExecFrom, m_swapBuiltTo, m_swapBuiltValue, m_swapBuiltData);
        return;
    }

    const bool sellIsNative = m_swapExecNative;
    const bool buyIsNative = m_swapExecBuyAddr.isEmpty();
    const quint8 sellDec = sellIsNative ? 18 : m_swapSellDecimals;
    const quint8 buyDec = buyIsNative ? 18 : m_swapBuyDecimals;
    const double sellH = m_swapAmount->text().trimmed().toDouble();
    const double buyH = buyAmountStr.toDouble() / std::pow(10.0, buyDec);
    const double sellUsd = m_swapLlamaSellUsd > 0.0 ? sellH * m_swapLlamaSellUsd : 0.0;
    const double buyUsd = m_swapLlamaBuyUsd > 0.0 ? buyH * m_swapLlamaBuyUsd : 0.0;
    const double refOut = (m_swapLlamaSellUsd > 0.0 && m_swapLlamaBuyUsd > 0.0)
                              ? sellH * m_swapLlamaSellUsd / m_swapLlamaBuyUsd : 0.0;
    const double diffPct = refOut > 0.0 ? (buyH - refOut) / refOut * 100.0 : 0.0;
    Q_UNUSED(sellDec);
    // On-chain fee = estimated gas: show it in native + USD. feeH is the native-coin amount.
    const double feeUsd = m_swapSelGasUsd;
    const double feeH = (m_nativeUsd > 0.0) ? m_swapSelGasUsd / m_nativeUsd : 0.0;

    if (!swapConfirmDialog(sellIsNative, buyIsNative, sellH, buyH, feeH, sellUsd, buyUsd, feeUsd,
                           refOut, diffPct, 0, m_swapExecFrom, isKnownRouter(m_swapBuiltTo),
                           m_swapSelRouter, m_swapSelLabel, m_swapBuiltTo, m_swapBuiltSpender)) {
        m_swapConfirmBtn->setEnabled(true);
        m_swapBuiltTo.clear();
        return;
    }

    if (sellIsNative) {
        m_swapStatus->setText(tr("Sending swap through %1…").arg(m_swapSelLabel));
        m_wallet->routerSwap(m_swapExecFrom, m_swapBuiltTo, m_swapBuiltValue, m_swapBuiltData);
    } else {
        m_swapStatus->setText(tr("Checking token approval…"));
        m_wallet->routerAllowance(m_swapExecFrom, m_swapExecSellAddr, m_swapBuiltSpender);
    }
}

void AeroMainWindow::onRouterAllowanceReady(const QString &token, const QString &spender,
                                            const QString &allowanceWei, const QString &error) {
    // Only act during an on-chain swap awaiting its approval check.
    if (m_swapSelKind != QLatin1String("onchain") || m_swapBuiltTo.isEmpty() ||
        token.compare(m_swapExecSellAddr, Qt::CaseInsensitive) != 0 ||
        spender.compare(m_swapBuiltSpender, Qt::CaseInsensitive) != 0)
        return;
    if (!error.isEmpty()) {
        m_swapStatus->setText(tr("Approval check failed: %1").arg(error));
        m_swapConfirmBtn->setEnabled(true);
        resetSwapFlow();
        return;
    }
    auto geq = [](const QString &a, const QString &b) {
        const QString x = a.isEmpty() ? QStringLiteral("0") : a;
        const QString y = b.isEmpty() ? QStringLiteral("0") : b;
        if (x.length() != y.length())
            return x.length() > y.length();
        return x >= y;
    };
    // Waiting for a just-sent approve to mine (mirrors the CoW path): the router's transferFrom
    // reverts (TRANSFER_FROM_FAILED) if we swap before the allowance is live on-chain. Poll the
    // allowance; once it's sufficient, REBUILD fresh calldata (the ~1-block wait can stale the quote)
    // and execute.
    if (m_swapAwaitingRouterApprove) {
        if (geq(allowanceWei, m_swapExecSellAmountWei)) {
            m_swapAwaitingRouterApprove = false;
            m_swapRouterExecuteAfterBuild = true;
            // Snapshot the min-out the user just confirmed; the fresh rebuild below may quote worse
            // after the ~1-block approval wait, and we re-prompt if it drops materially.
            m_swapConfirmedMinBuy = m_swapBuiltMinBuy;
            m_swapStatus->setText(tr("Approval confirmed. Preparing swap through %1…")
                                      .arg(m_swapSelLabel));
            m_wallet->routerBuild(m_swapSelRouter, m_swapExecFrom, m_swapExecSellAddr,
                                  m_swapExecBuyAddr, m_swapExecSellAmountWei, false,
                                  m_swapSellDecimals,
                                  m_swapExecBuyAddr.isEmpty() ? 18 : m_swapBuyDecimals,
                                  m_swapExecSlippageBps);
        } else if (++m_swapRouterApprovePolls <= 15) {
            m_swapStatus->setText(tr("Waiting for the approval to confirm on-chain… (%1)")
                                      .arg(m_swapRouterApprovePolls));
            const QString sp = m_swapBuiltSpender;
            QTimer::singleShot(8000, this, [this, sp]() {
                if (m_wallet && m_swapAwaitingRouterApprove && !m_swapBuiltTo.isEmpty())
                    m_wallet->routerAllowance(m_swapExecFrom, m_swapExecSellAddr, sp);
            });
        } else {
            m_swapStatus->setText(tr("Approval hasn't confirmed yet. Once it does, press Confirm "
                                     "Swap again."));
            m_swapConfirmBtn->setEnabled(true);
            resetSwapFlow();
        }
        return;
    }
    // A USDT-style reset is in flight. Wait for the allowance to actually read zero before asking
    // for the real one, because the whole point of the reset is that the token refuses the second
    // approve until the first has mined.
    if (m_swapAwaitingApproveReset) {
        if (allowanceWei.isEmpty() || allowanceWei == QLatin1String("0")) {
            m_swapAwaitingApproveReset = false;
            m_swapStatus->setText(tr("Previous approval cleared. Approving %1…").arg(m_swapSellSymbol));
            m_wallet->routerApprove(m_swapExecFrom, m_swapExecSellAddr, spender, m_swapApproveCap);
        } else if (++m_swapRouterApprovePolls <= 15) {
            m_swapStatus->setText(tr("Waiting for the previous approval to clear… (%1)")
                                      .arg(m_swapRouterApprovePolls));
            const QString sp = m_swapBuiltSpender;
            QTimer::singleShot(8000, this, [this, sp]() {
                if (m_wallet && m_swapAwaitingApproveReset && !m_swapBuiltTo.isEmpty())
                    m_wallet->routerAllowance(m_swapExecFrom, m_swapExecSellAddr, sp);
            });
        } else {
            m_swapStatus->setText(tr("The approval reset hasn't confirmed yet. Once it does, press "
                                     "Confirm Swap again."));
            m_swapConfirmBtn->setEnabled(true);
            resetSwapFlow();
        }
        return;
    }
    if (geq(allowanceWei, m_swapExecSellAmountWei)) {
        m_swapStatus->setText(tr("Sending swap through %1…").arg(m_swapSelLabel));
        m_wallet->routerSwap(m_swapExecFrom, m_swapBuiltTo, m_swapBuiltValue, m_swapBuiltData);
    } else {
        const QString cap = spendingApprovalDialog(
            m_swapSellSymbol, m_swapExecSellAddr, tr("%1 router").arg(m_swapSelLabel), spender,
            m_swapAmount->text().trimmed(), m_swapExecSellAmountWei);
        if (cap.isEmpty()) {
            m_swapStatus->setText(tr("Approval cancelled."));
            m_swapBuiltTo.clear();
            m_swapConfirmBtn->setEnabled(true);
            return;
        }
        // The allowance is too small but not zero. USDT and the tokens that copied it revert an
        // approve that moves a non-zero allowance straight to another non-zero value, so clear it
        // first. One extra transaction, and only in this case. The bridge already did this; the
        // swap path did not, which left USDT swaps stuck on a reverting approval with no way
        // forward from inside the app.
        const bool nonZero = !allowanceWei.isEmpty() && allowanceWei != QLatin1String("0");
        if (nonZero) {
            m_swapApproveCap = cap;
            m_swapAwaitingApproveReset = true;
            m_swapRouterApprovePolls = 0;
            m_swapStatus->setText(tr("Clearing the previous %1 approval first (some tokens require "
                                     "it) - this needs two transactions.")
                                      .arg(m_swapSellSymbol));
            m_wallet->routerApprove(m_swapExecFrom, m_swapExecSellAddr, spender,
                                    QStringLiteral("0"));
            return;
        }
        m_swapStatus->setText(tr("Approving %1…").arg(m_swapSellSymbol));
        m_wallet->routerApprove(m_swapExecFrom, m_swapExecSellAddr, spender, cap);
    }
}

void AeroMainWindow::onRouterApproved(const QString &txHash, const QString &error) {
    if (m_swapSelKind != QLatin1String("onchain") || m_swapBuiltTo.isEmpty())
        return;
    if (!error.isEmpty() || txHash.isEmpty()) {
        m_swapStatus->setText(tr("Approval failed: %1").arg(error));
        m_swapConfirmBtn->setEnabled(true);
        resetSwapFlow();
        return;
    }
    // That was the approve(0) of a two-step reset, not the approval itself. Poll until the token
    // reports zero, then onRouterAllowanceReady sends the real one.
    if (m_swapAwaitingApproveReset) {
        m_swapStatus->setText(tr("Clearing approval (%1). Waiting for it to confirm on-chain…")
                                  .arg(shortAddr(txHash)));
        const QString sp = m_swapBuiltSpender;
        QTimer::singleShot(8000, this, [this, sp]() {
            if (m_wallet && m_swapAwaitingApproveReset && !m_swapBuiltTo.isEmpty())
                m_wallet->routerAllowance(m_swapExecFrom, m_swapExecSellAddr, sp);
        });
        return;
    }
    // The approve is only BROADCAST here. Sending the swap now would revert with
    // TransferHelper: TRANSFER_FROM_FAILED because the router can't transferFrom until the allowance
    // is MINED. Poll the on-chain allowance and only then rebuild + send the swap (see the
    // m_swapAwaitingRouterApprove branch in onRouterAllowanceReady).
    m_swapAwaitingRouterApprove = true;
    m_swapRouterApprovePolls = 0;
    m_swapStatus->setText(tr("Approval sent (%1). Waiting for it to confirm on-chain…")
                              .arg(shortAddr(txHash)));
    const QString sp = m_swapBuiltSpender;
    QTimer::singleShot(8000, this, [this, sp]() {
        if (m_wallet && m_swapAwaitingRouterApprove && !m_swapBuiltTo.isEmpty())
            m_wallet->routerAllowance(m_swapExecFrom, m_swapExecSellAddr, sp);
    });
}

void AeroMainWindow::onRouterSwapSent(const QString &txHash, const QString &error) {
    if (m_swapSelKind != QLatin1String("onchain"))
        return;
    m_swapBuiltTo.clear();
    if (!error.isEmpty() || txHash.isEmpty()) {
        m_swapStatus->setText(tr("Swap failed: %1").arg(error));
        m_swapConfirmBtn->setEnabled(true);
        return;
    }
    addPendingSwap(txHash); // pending in History immediately (reconciled when the tx is mined)
    // An on-chain router swap is atomic - the bought tokens arrive when this tx mines, so watch its
    // receipt to refresh balances the instant it confirms (same fast path as a send). Clear the
    // send-optimistic marker so its balance clamp doesn't misapply to this swap.
    m_lastSendFrom = 0xFFFFFFFFu;
    applyOptimisticSwap(); // instantly drop the sold asset (the mined receipt then reconciles it)
    startReceiptWatch(txHash);
    swapInlineDone(tr("Swap sent via %1 - %2 → %3. Tracking in History.")
                       .arg(m_swapSelLabel, m_swapSellSymbol, m_swapBuySymbol),
                   explorerTxUrl(txHash), tr("View transaction"));
    notify(tr("Swap submitted"), tr("%1 → %2 via %3").arg(m_swapSellSymbol, m_swapBuySymbol,
                                                          m_swapSelLabel));
}

void AeroMainWindow::onSwapAllowanceReady(const QString &token, const QString &allowanceWei,
                                          const QString &error) {
    // Only react while a swap is mid-flight for this token.
    if (m_swapExecNative || m_swapExecQuote.isEmpty() ||
        token.compare(m_swapExecSellAddr, Qt::CaseInsensitive) != 0)
        return;
    if (!error.isEmpty()) {
        m_swapStatus->setText(tr("Approval check failed: %1").arg(error));
        m_swapConfirmBtn->setEnabled(true);
        resetSwapFlow();
        return;
    }
    // Compare allowance vs needed (both decimal-wei strings - compare as big values via double is
    // imprecise, so compare lengths then lexically for equal length).
    auto geq = [](const QString &a, const QString &b) {
        const QString x = a.isEmpty() ? QStringLiteral("0") : a;
        const QString y = b.isEmpty() ? QStringLiteral("0") : b;
        if (x.length() != y.length())
            return x.length() > y.length();
        return x >= y;
    };
    const bool sufficient = geq(allowanceWei, m_swapExecSellAmountWei);

    // If we're polling after an approve, CoW's order-book rejects the order until the approve tx is
    // actually mined (it checks the on-chain allowance). Wait here until it's sufficient, then submit.
    if (m_swapAwaitingApprove) {
        if (sufficient) {
            m_swapAwaitingApprove = false;
            m_swapStatus->setText(tr("Approval confirmed. Signing and submitting order…"));
            m_wallet->swapSubmit(m_swapExecFrom, m_swapExecQuote, m_swapExecSlippageBps);
        } else if (++m_swapApprovePolls <= 15) {
            m_swapStatus->setText(tr("Waiting for the approval to confirm on-chain… (%1)")
                                      .arg(m_swapApprovePolls));
            QTimer::singleShot(8000, this, [this]() {
                if (m_wallet && m_swapAwaitingApprove && !m_swapExecQuote.isEmpty())
                    m_wallet->swapAllowance(m_swapExecFrom, m_swapExecSellAddr);
            });
        } else {
            m_swapAwaitingApprove = false;
            m_swapStatus->setText(tr("Approval hasn't confirmed yet. Once it does, press Confirm "
                                     "Swap again."));
            m_swapConfirmBtn->setEnabled(true);
        }
        return;
    }

    if (sufficient) {
        m_swapStatus->setText(tr("Signing and submitting order…"));
        m_wallet->swapSubmit(m_swapExecFrom, m_swapExecQuote, m_swapExecSlippageBps);
    } else {
        // MetaMask-style spending-cap approval before the on-chain approve tx. Defaults to the exact
        // amount this swap needs; the user can opt into unlimited.
        const QString cap = spendingApprovalDialog(
            m_swapSellSymbol, m_swapExecSellAddr, tr("CoW Vault Relayer"), Wallet::cowVaultRelayer(),
            m_swapAmount->text().trimmed(), m_swapExecSellAmountWei);
        if (cap.isEmpty()) {
            m_swapStatus->setText(tr("Approval cancelled."));
            m_swapExecQuote.clear();
            m_swapConfirmBtn->setEnabled(true);
            return;
        }
        m_swapStatus->setText(cap == QLatin1String("max")
            ? tr("Approving unlimited %1 for the CoW Vault Relayer…").arg(m_swapSellSymbol)
            : tr("Approving %1 %2 for the CoW Vault Relayer…").arg(m_swapAmount->text().trimmed(),
                                                                   m_swapSellSymbol));
        m_wallet->swapApprove(m_swapExecFrom, m_swapExecSellAddr, cap);
    }
}

void AeroMainWindow::onSwapApproved(const QString &txHash, const QString &error) {
    if (m_swapExecNative || m_swapExecQuote.isEmpty())
        return;
    if (!error.isEmpty() || txHash.isEmpty()) {
        m_swapStatus->setText(tr("Approval failed: %1").arg(error));
        m_swapConfirmBtn->setEnabled(true);
        resetSwapFlow();
        return;
    }
    // The approve is only BROADCAST here - CoW needs it MINED before it will accept the order
    // (otherwise: "order owner must give allowance to VaultRelayer"). Poll the on-chain allowance
    // and submit once it's live.
    m_swapAwaitingApprove = true;
    m_swapApprovePolls = 0;
    m_swapStatus->setText(tr("Approval sent (%1). Waiting for it to confirm on-chain…")
                              .arg(shortAddr(txHash)));
    QTimer::singleShot(8000, this, [this]() {
        if (m_wallet && m_swapAwaitingApprove && !m_swapExecQuote.isEmpty())
            m_wallet->swapAllowance(m_swapExecFrom, m_swapExecSellAddr);
    });
}

void AeroMainWindow::onSwapSubmitted(const QString &orderUid, const QString &error) {
    m_swapAwaitingApprove = false;
    if (!error.isEmpty() || orderUid.isEmpty()) {
        m_swapStatus->setText(tr("Order failed: %1").arg(error));
        m_swapConfirmBtn->setEnabled(true);
        resetSwapFlow();
        return;
    }
    m_swapExecQuote.clear();
    addPendingSwap(orderUid); // show it as pending in History right away (reconciled via cow_orders)
    applyOptimisticSwap();    // instantly drop the sold asset so a follow-up swap sees it reduced
    const QString url = QStringLiteral("https://explorer.cow.fi/orders/%1").arg(orderUid);
    swapInlineDone(tr("Order placed - %1 → %2. Tracking in History.")
                       .arg(m_swapSellSymbol, m_swapBuySymbol),
                   url, tr("Track on CoW Explorer"));
    notify(tr("Swap submitted"), tr("%1 → %2 order placed.").arg(m_swapSellSymbol, m_swapBuySymbol));
}

void AeroMainWindow::onSwapEthFlowSent(const QString &txHash, const QString &error) {
    if (!m_swapExecNative)
        return;
    if (!error.isEmpty() || txHash.isEmpty()) {
        m_swapExecQuote.clear();
        m_swapStatus->setText(tr("eth-flow order failed: %1").arg(error));
        m_swapConfirmBtn->setEnabled(true);
        return;
    }
    // eth-flow orders are CoW orders created on-chain: the bought tokens arrive when a solver fills
    // the order, not when this tx mines. So track it exactly like an ERC-20 CoW order - show a
    // pending History row now and start the CoW status poll (reads m_swapExecQuote, so do it BEFORE
    // clearing that below).
    addPendingSwap(txHash);
    applyOptimisticSwap(); // instantly drop the sold native coin (eth-flow) so it doesn't linger
    m_swapExecQuote.clear();
    swapInlineDone(tr("Swap sent - %1 → %2. Tracking in History.")
                       .arg(m_swapSellSymbol, m_swapBuySymbol),
                   explorerTxUrl(txHash), tr("View transaction"));
    notify(tr("Swap submitted"), tr("%1 → %2 order sent.").arg(m_swapSellSymbol, m_swapBuySymbol));
}

// Well-known token-approval spenders to scan for. These are Ethereum-mainnet router/permit
// addresses; on other chains an allowance() call to a non-existent spender simply returns 0 and is
// filtered out, so listing them is harmless. Users can add any token+spender manually.
struct SpenderDef { QString name, address; };
static const QList<SpenderDef> &curatedSpenders() {
    static const QList<SpenderDef> defs = {
        {QStringLiteral("CoW Vault Relayer"), QStringLiteral("0xC92E8bdf79f0507f65a392b0ab4667716BFE0110")},
        {QStringLiteral("Uniswap V2 Router"), QStringLiteral("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")},
        {QStringLiteral("Uniswap Universal Router"), QStringLiteral("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD")},
        {QStringLiteral("Permit2"), QStringLiteral("0x000000000022D473030F116dDEE9F6B43aC78BA3")},
        {QStringLiteral("1inch Aggregation Router v5"), QStringLiteral("0x1111111254EEB25477B68fb85Ed929f73A960582")},
        {QStringLiteral("0x Exchange Proxy"), QStringLiteral("0xDef1C0ded9bec7F1a1670819833240f027b25EfF")},
    };
    return defs;
}

// --- Across cross-chain bridge -------------------------------------------------------------------
// Chains where Across has a deployment. This only decides whether the Bridge window will open -
// which assets and destinations it then offers is asked of Across itself (Wallet::acrossAssets), so
// that a route it retires stops being offered instead of failing at the quote. It dropped DAI, which
// this window used to advertise on every chain.
static QList<quint64> acrossChains() { return {1, 10, 8453, 42161, 137, 56, 43114}; }
static bool acrossSupportedChain(quint64 id) { return acrossChains().contains(id); }

void AeroMainWindow::showBridgeDialog() {
    if (!m_wallet)
        return;
    // One dialog only: a second one would connect its own handlers to the same wallet signals and
    // both would react to every quote/approval/deposit.
    if (m_bridgeDialog) {
        m_bridgeDialog->raise();
        m_bridgeDialog->activateWindow();
        return;
    }
    if (m_wallet->isWatchOnly()) {
        QMessageBox::information(this, tr("Bridge"),
                                 tr("This is a watch-only wallet; it can't send bridge transactions."));
        return;
    }
    const quint64 origin = m_chainId;
    Wallet *const w = m_wallet; // guard against the wallet being closed/swapped under the dialog
    if (!acrossSupportedChain(origin)) {
        QMessageBox::information(
            this, tr("Bridge (Across)"),
            tr("Across bridging isn't available on %1. Switch to Ethereum, Arbitrum, Optimism, Base, "
               "Polygon, Avalanche or BNB Smart Chain first.")
                .arg(chainDefFor(m_chainId).name));
        return;
    }

    // Per-dialog state shared by the async signal handlers (freed with the dialog).
    struct BridgeState {
        quint32 account = 0;        // frozen at open: everything quotes/approves/sends from THIS one
        quint64 dest = 0;
        // `symbol` is Across's own name for the asset (which can be chain-suffixed, e.g. USDC-BNB)
        // and is what the core is asked for; `display` is the ticker shown to the user. `decimals`
        // comes from the token itself - the same ticker is 6-decimal on one chain and 18 on another.
        QString symbol, display, amountWei;
        quint8 decimals = 18;
        QString to, data, value, spender, inputToken, outputAmount;
        bool native = false;
        bool bridging = false;      // a build/approve/send is in flight
        // Approval progress. Tokens like USDT reject a non-zero -> non-zero approve, so an existing
        // insufficient allowance has to be zeroed first: stage 1 waits for that reset to confirm,
        // stage 2 waits for the real approval.
        enum { NoApproval = 0, AwaitingReset = 1, AwaitingApproval = 2 };
        int approveStage = NoApproval;
        int approvePolls = 0;
        // Across bakes a quote timestamp and an output amount into the deposit calldata, and the
        // SpokePool rejects a quote older than its buffer while relayers ignore one whose output no
        // longer reflects the fee. Approving a token takes one transaction, or two for USDT, so by
        // the time the deposit could be sent the calldata built before the confirm dialog can be
        // minutes old. Rebuild it and send that instead.
        bool rebuildBeforeSend = false;
        QString confirmedOutput;   // what the user was promised, to catch a fee move on the rebuild
    };
    auto *st = new BridgeState;
    st->account = m_account;

    auto *dlg = new QDialog(this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setWindowTitle(tr("Bridge to another chain - Across"));
    dlg->resize(500, 0);
    m_bridgeDialog = dlg;
    connect(dlg, &QObject::destroyed, [st]() { delete st; });

    auto *v = new QVBoxLayout(dlg);
    v->setSpacing(10);
    auto *info = new QLabel(
        tr("Move assets to another chain via Across Protocol. Funds arrive at the SAME address on "
           "the destination chain, usually within a minute."),
        dlg);
    info->setWordWrap(true);
    info->setStyleSheet(QStringLiteral("color:#8a8a8a;"));
    v->addWidget(info);

    auto *form = new QFormLayout();
    form->setHorizontalSpacing(12);
    form->setVerticalSpacing(8);
    form->addRow(tr("From"), new QLabel(chainDefFor(origin).name, dlg));
    // The account is frozen for the life of the dialog (switching accounts elsewhere must not
    // redirect a quoted bridge), so it has to be visible here.
    auto *acctLabel = new QLabel(m_wallet->address(st->account), dlg);
    acctLabel->setToolTip(tr("Funds are taken from - and arrive at - this address."));
    acctLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    form->addRow(tr("Account"), acctLabel);

    auto *assetCombo = new QComboBox(dlg);
    assetCombo->setEnabled(false); // until Across has told us what it will take from this chain
    form->addRow(tr("Asset"), assetCombo);

    auto *destCombo = new QComboBox(dlg);
    form->addRow(tr("To"), destCombo);

    auto *amountEdit = new QLineEdit(dlg);
    amountEdit->setPlaceholderText(tr("Amount to bridge"));
    auto *amountRow = new QHBoxLayout();
    amountRow->addWidget(amountEdit, 1);
    auto *maxBtn = new QPushButton(tr("Max"), dlg);
    amountRow->addWidget(maxBtn);
    auto *amountWrap = new QWidget(dlg);
    amountWrap->setLayout(amountRow);
    amountRow->setContentsMargins(0, 0, 0, 0);
    form->addRow(tr("Amount"), amountWrap);
    v->addLayout(form);

    auto *status = new QLabel(dlg);
    status->setWordWrap(true);
    status->setTextFormat(Qt::RichText);
    // The bridge's status line carries explorer links for both chains. They leave Tor, so they go
    // through the same warning as every other outbound link.
    status->setOpenExternalLinks(false);
    connect(status, &QLabel::linkActivated, this,
            [this](const QString &href) { openOutsideTor(href); });
    v->addWidget(status);

    auto *btnRow = new QHBoxLayout();
    auto *quoteBtn = new QPushButton(tr("Get quote"), dlg);
    auto *bridgeBtn = new QPushButton(tr("Bridge"), dlg);
    bridgeBtn->setEnabled(false);
    btnRow->addWidget(quoteBtn);
    btnRow->addWidget(bridgeBtn);
    btnRow->addStretch(1);
    auto *closeBtn = new QPushButton(tr("Close"), dlg);
    btnRow->addWidget(closeBtn);
    v->addLayout(btnRow);
    connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);

    // The selected asset's entry from Across: {symbol, display, decimals, native, destinations}.
    auto asset = [=]() {
        return assetCombo->currentIndex() < 0 ? QVariantMap()
                                              : assetCombo->currentData().toMap();
    };
    auto assetDecimals = [=]() -> quint8 {
        const QVariantMap a = asset();
        return a.isEmpty() ? 18 : static_cast<quint8>(a.value(QStringLiteral("decimals")).toUInt());
    };

    // Destinations come from the selected asset - Across routes each asset to its own set of chains,
    // and that set changes without notice.
    auto rebuildDest = [=]() {
        destCombo->clear();
        for (const QVariant &id : asset().value(QStringLiteral("destinations")).toList()) {
            const quint64 chain = id.toULongLong();
            if (chain == origin)
                continue;
            destCombo->addItem(chainDefFor(chain).name, static_cast<qulonglong>(chain));
        }
        bridgeBtn->setEnabled(false);
        status->clear();
    };
    connect(assetCombo, &QComboBox::currentIndexChanged, dlg, [=](int) { rebuildDest(); });

    // Ask Across what it will bridge out of this chain, and build the menus from the answer.
    status->setText(tr("Checking which assets Across is bridging from %1…").arg(chainDefFor(origin).name));
    quoteBtn->setEnabled(false);
    connect(m_wallet, &Wallet::acrossAssetsReady, dlg, [=](const QString &json, const QString &err) {
        const QJsonArray assets = QJsonDocument::fromJson(json.toUtf8())
                                      .object().value(QStringLiteral("assets")).toArray();
        if (!err.isEmpty() || assets.isEmpty()) {
            status->setText(err.isEmpty()
                                ? tr("Across isn't bridging anything out of %1 at the moment.")
                                      .arg(chainDefFor(origin).name)
                                : tr("Couldn't reach Across: %1").arg(err.toHtmlEscaped()));
            return;
        }
        assetCombo->blockSignals(true);
        assetCombo->clear();
        for (const QJsonValue &a : assets) {
            const QJsonObject o = a.toObject();
            QVariantList dests;
            for (const QJsonValue &d : o.value(QStringLiteral("destinations")).toArray())
                dests << static_cast<qulonglong>(d.toDouble());
            QVariantMap m;
            m[QStringLiteral("symbol")] = o.value(QStringLiteral("symbol")).toString();
            m[QStringLiteral("display")] = o.value(QStringLiteral("display")).toString();
            m[QStringLiteral("decimals")] = o.value(QStringLiteral("decimals")).toInt(18);
            m[QStringLiteral("native")] = o.value(QStringLiteral("native")).toBool(false);
            m[QStringLiteral("destinations")] = dests;
            assetCombo->addItem(m.value(QStringLiteral("display")).toString(), m);
        }
        assetCombo->blockSignals(false);
        assetCombo->setEnabled(true);
        quoteBtn->setEnabled(true);
        rebuildDest();
        status->clear();
    });
    m_wallet->acrossAssets();
    connect(destCombo, &QComboBox::currentIndexChanged, dlg, [=](int) {
        bridgeBtn->setEnabled(false);
        status->clear();
    });
    connect(amountEdit, &QLineEdit::textChanged, dlg, [=](const QString &) {
        bridgeBtn->setEnabled(false); // a new amount needs a fresh quote
    });
    rebuildDest();

    // Native-coin cushion for the deposit's gas. A SpokePool depositV3 runs ~150k gas; pricing it at
    // the same worst-case maxFeePerGas the send guard uses means "Max" can never hand back an amount
    // that the guard then rejects (a flat 0.002 reserve was far too small on a busy mainnet).
    auto gasReserve = [this]() {
        const double maxFeePerGas =
            m_feeBaseWei > 0 ? m_feeBaseWei * 3.0 + qMax(m_feeTipWei, 1e9) : 30e9;
        return maxFeePerGas * 150000.0 / 1e18;
    };
    // Max: native coin uses the account's balance minus that cushion; tokens use the tracked balance.
    connect(maxBtn, &QPushButton::clicked, dlg, [=]() {
        const QString sym = assetCombo->currentText();
        double bal = 0.0;
        if (asset().value(QStringLiteral("native")).toBool()) {
            bal = qMax(0.0, m_ethRawByAccount.value(st->account, 0.0) - gasReserve());
        } else {
            bal = qMax(0.0, tokenBalanceOnThisChain(st->account, sym));
        }
        if (bal > 0.0)
            amountEdit->setText(trimZeros(QString::number(bal, 'f', 8)));
    });

    auto amountWei = [=]() -> QString {
        return Wallet::parseUnits(amountEdit->text().trimmed(), assetDecimals());
    };
    auto geq = [](const QString &a, const QString &b) {
        const QString x = a.isEmpty() ? QStringLiteral("0") : a;
        const QString y = b.isEmpty() ? QStringLiteral("0") : b;
        if (x.length() != y.length())
            return x.length() > y.length();
        return x >= y;
    };

    // Everything here is quoted for one wallet on one chain; if either changed while the dialog sat
    // open, the numbers on screen no longer describe what would actually be sent.
    auto contextStillValid = [=]() {
        if (m_wallet != w) {
            status->setText(tr("The wallet changed. Close this window and open Bridge again."));
            bridgeBtn->setEnabled(false);
            return false;
        }
        if (m_chainId != origin) {
            status->setText(tr("The network changed to %1. Close this window and open Bridge again "
                               "to bridge from there.")
                                .arg(chainDefFor(m_chainId).name));
            bridgeBtn->setEnabled(false);
            return false;
        }
        return true;
    };

    // --- Quote ---
    connect(quoteBtn, &QPushButton::clicked, dlg, [=]() {
        const QVariantMap a = asset();
        if (a.isEmpty() || destCombo->currentIndex() < 0) return;
        if (!contextStillValid()) return;
        st->dest = destCombo->currentData().toULongLong();
        st->symbol = a.value(QStringLiteral("symbol")).toString();
        st->display = a.value(QStringLiteral("display")).toString();
        st->decimals = static_cast<quint8>(a.value(QStringLiteral("decimals")).toUInt());
        const QString sym = st->symbol;
        const QString wei = amountWei();
        if (wei.isEmpty() || wei == QLatin1String("0")) {
            status->setText(tr("Enter an amount to bridge."));
            return;
        }
        status->setText(tr("Fetching Across quote…"));
        quoteBtn->setEnabled(false);
        m_wallet->acrossQuote(st->account, sym, st->dest, wei);
    });

    connect(m_wallet, &Wallet::acrossQuoteReady, dlg, [=](const QString &json, const QString &err) {
        quoteBtn->setEnabled(true);
        if (!err.isEmpty()) {
            status->setText(tr("Quote failed: %1").arg(err.toHtmlEscaped()));
            bridgeBtn->setEnabled(false);
            return;
        }
        const QJsonObject o = QJsonDocument::fromJson(json.toUtf8()).object();
        // The ticker the user picked, not Across's internal name for it (USDC-BNB and the like).
        const QString sym = st->display.isEmpty() ? o.value(QStringLiteral("symbol")).toString()
                                                 : st->display;
        const quint8 dec = static_cast<quint8>(o.value(QStringLiteral("decimals")).toInt(18));
        const double outAmt = o.value(QStringLiteral("output_amount")).toString().toDouble()
                              / std::pow(10.0, dec);
        const double inAmt = o.value(QStringLiteral("input_amount")).toString().toDouble()
                             / std::pow(10.0, dec);
        const double fee = inAmt - outAmt;
        const int etaSec = o.value(QStringLiteral("est_fill_time_sec")).toInt(0);
        const bool tooLow = o.value(QStringLiteral("is_amount_too_low")).toBool(false);
        const double minDep = o.value(QStringLiteral("min_deposit")).toString().toDouble()
                              / std::pow(10.0, dec);
        if (tooLow) {
            status->setText(tr("Amount is below the Across minimum (~%1 %2). Increase it.")
                                .arg(trimZeros(QString::number(minDep, 'f', 8)), sym));
            bridgeBtn->setEnabled(false);
            return;
        }
        // Guard the route capacity: depositing above maxDeposit succeeds on-chain but no relayer will
        // fill it, so the funds would sit until the deadline (then refund on the origin) - a scary
        // delay. Block it and tell the user the cap.
        const double maxDep = o.value(QStringLiteral("max_deposit")).toString().toDouble()
                              / std::pow(10.0, dec);
        if (maxDep > 0.0 && inAmt > maxDep) {
            status->setText(tr("Amount exceeds the Across route capacity (~%1 %2). Lower it, or the "
                               "bridge could be stuck until it's refunded.")
                                .arg(trimZeros(QString::number(maxDep, 'f', 8)), sym));
            bridgeBtn->setEnabled(false);
            return;
        }
        st->outputAmount = o.value(QStringLiteral("output_amount")).toString(); // compared at confirm
        const quint64 dst = static_cast<quint64>(o.value(QStringLiteral("dest_chain")).toDouble());
        status->setText(tr("<b>Send:</b> %1 %2<br><b>Receive on %3:</b> ~%4 %2<br>"
                           "<b>Bridge fee:</b> ~%5 %2<br><b>ETA:</b> ~%6s")
                            .arg(trimZeros(QString::number(inAmt, 'f', 8)), sym,
                                 chainDefFor(dst).name, trimZeros(QString::number(outAmt, 'f', 8)),
                                 trimZeros(QString::number(fee, 'f', 8)))
                            .arg(etaSec));
        bridgeBtn->setEnabled(true);
    });

    // --- Bridge: build fresh calldata, then confirm + approve/send ---
    // The deposit is recorded by the window (onBridgeBroadcast), not here, so closing the dialog
    // while it is on the wire can't lose the transaction.
    auto sendBuilt = [=]() {
        // Last gate before broadcast. Minutes can pass here waiting on an approval, and this calldata
        // names the ORIGIN chain's SpokePool - replaying it on a different network would send the
        // funds to an address that means nothing there. Never broadcast on a changed context.
        if (m_wallet != w || m_chainId != origin) {
            st->bridging = false;
            bridgeBtn->setEnabled(false);
            status->setText(tr("The network changed before the deposit was sent, so it was cancelled. "
                               "Switch back to %1 and bridge again.")
                                .arg(chainDefFor(origin).name));
            return;
        }
        status->setText(tr("Sending bridge deposit over Tor…"));
        m_pendingBridge.active = true;
        m_pendingBridge.account = st->account;
        m_pendingBridge.dest = st->dest;
        m_pendingBridge.symbol = st->display;
        m_pendingBridge.tokenAddr = st->native ? QString() : st->inputToken;
        m_pendingBridge.to = st->to;
        m_pendingBridge.amountHuman = trimZeros(
            QString::number(st->amountWei.toDouble() / std::pow(10.0, st->decimals), 'f', 8));
        beginSendProgress(tr("Broadcasting bridge deposit…"));
        m_wallet->bridgeSend(st->account, st->to, st->value, st->data);
    };
    connect(bridgeBtn, &QPushButton::clicked, dlg, [=]() {
        if (st->bridging) return;
        if (destCombo->currentIndex() < 0) return;
        if (!contextStillValid()) return;
        // Two transactions built at the same instant would read the same pending nonce and one would
        // silently replace the other - the same failure mode as the old double-send.
        if (m_sendInFlight) {
            status->setText(tr("Another transaction is being broadcast. Try again in a moment."));
            return;
        }
        const QString wei = amountWei();
        if (wei.isEmpty() || wei == QLatin1String("0")) return;

        // Balance guard (mirrors the Send tab): don't broadcast a deposit that would revert. The
        // network fee is always paid in the native coin; a bridge deposit costs ~150k gas.
        const QVariantMap a = asset();
        if (a.isEmpty()) return;
        const QString gsym = a.value(QStringLiteral("display")).toString();
        const bool isNative = a.value(QStringLiteral("native")).toBool();
        const double amt = wei.toDouble() / std::pow(10.0, assetDecimals());
        const double nativeBal = m_ethRawByAccount.value(st->account, 0.0);
        const double feeNative = gasReserve();
        if (isNative) {
            if (amt + feeNative > nativeBal + 1e-15) {
                status->setText(tr("The amount plus the ~%1 %2 network fee exceeds your balance. "
                                   "Lower the amount (Max already reserves gas).")
                                    .arg(trimZeros(QString::number(feeNative, 'f', 8)), m_nativeSymbol));
                return;
            }
        } else {
            if (nativeBal < feeNative) {
                status->setText(tr("Bridging a token still costs a ~%1 %2 network fee paid in %2, but "
                                   "this account only has %3 %2. Fund it with a little %2 first.")
                                    .arg(trimZeros(QString::number(feeNative, 'f', 8)), m_nativeSymbol,
                                         trimZeros(QString::number(nativeBal, 'f', 8))));
                return;
            }
            // If the balance for this chain's contract is known, make sure it covers the amount.
            const double tokBal = tokenBalanceOnThisChain(st->account, gsym);
            if (tokBal >= 0.0 && amt > tokBal + 1e-15) {
                status->setText(tr("Amount exceeds your %1 balance of %2.")
                                    .arg(gsym, trimZeros(QString::number(tokBal, 'f', 8))));
                return;
            }
        }

        // Re-read the current selection so the built calldata + confirm always match what's on screen
        // (a fresh quote is fetched inside acrossBuild for exactly this dest/asset/amount).
        st->dest = destCombo->currentData().toULongLong();
        st->symbol = a.value(QStringLiteral("symbol")).toString();
        st->display = gsym;
        st->decimals = assetDecimals();
        st->amountWei = wei; // freeze the amount for the whole build/approve/send flow
        st->bridging = true;
        st->approveStage = BridgeState::NoApproval;
        st->approvePolls = 0;
        bridgeBtn->setEnabled(false);
        status->setText(tr("Preparing bridge transaction…"));
        m_wallet->acrossBuild(st->account, st->symbol, st->dest, wei);
    });

    connect(m_wallet, &Wallet::acrossBuilt, dlg, [=](const QString &json, const QString &err) {
        if (!st->bridging) return;
        if (!err.isEmpty() || json.isEmpty()) {
            st->bridging = false;
            bridgeBtn->setEnabled(true);
            status->setText(tr("Couldn't build the bridge tx: %1")
                                .arg(err.isEmpty() ? tr("no route") : err.toHtmlEscaped()));
            return;
        }
        const QJsonObject o = QJsonDocument::fromJson(json.toUtf8()).object();
        st->to = o.value(QStringLiteral("to")).toString();
        st->data = o.value(QStringLiteral("data")).toString();
        st->value = o.value(QStringLiteral("value")).toString();
        st->spender = o.value(QStringLiteral("spender")).toString();
        st->inputToken = o.value(QStringLiteral("input_token")).toString();
        st->native = o.value(QStringLiteral("native")).toBool(false);
        // Confirm (amount/symbol/decimals were frozen at click time).
        const QString sym = st->display;
        const double dec = st->decimals;
        const double amt = st->amountWei.toDouble() / std::pow(10.0, dec);
        // A rebuild after the approval confirmed. The user already agreed to this bridge, so send
        // the fresh calldata straight out - unless the fee moved enough that what they agreed to is
        // no longer what they would get, in which case ask again rather than decide for them.
        if (st->rebuildBeforeSend) {
            st->rebuildBeforeSend = false;
            const double freshOut =
                o.value(QStringLiteral("output_amount")).toString().toDouble() / std::pow(10.0, dec);
            const double promised = st->confirmedOutput.toDouble() / std::pow(10.0, dec);
            if (promised > 0.0 && freshOut < promised * 0.99) {
                const QString ask =
                    tr("The bridge fee rose while the approval confirmed.\n\nYou would now receive "
                       "about %1 %2 instead of the %3 %2 you agreed to. Continue?")
                        .arg(trimZeros(QString::number(freshOut, 'f', 8)), sym,
                             trimZeros(QString::number(promised, 'f', 8)));
                if (QMessageBox::question(dlg, tr("Confirm bridge"), ask) != QMessageBox::Yes) {
                    st->bridging = false;
                    bridgeBtn->setEnabled(true);
                    status->setText(tr("Bridge cancelled. The approval stays in place."));
                    return;
                }
                if (!contextStillValid()) {
                    st->bridging = false;
                    return;
                }
            }
            sendBuilt();
            return;
        }
        // acrossBuild re-quotes, so the amount that will actually be delivered is the one baked into
        // THIS calldata - show that, and flag it when fees moved against the earlier estimate.
        const QString freshOut = o.value(QStringLiteral("output_amount")).toString();
        const double outAmt = freshOut.toDouble() / std::pow(10.0, dec);
        const double quotedOut = st->outputAmount.toDouble() / std::pow(10.0, dec);
        QString body = tr("Bridge %1 %2 from %3 to %4?\n\nYou receive about %5 %2 at your address "
                          "on %4 via Across.")
                           .arg(trimZeros(QString::number(amt, 'f', 8)), sym,
                                chainDefFor(origin).name, chainDefFor(st->dest).name,
                                trimZeros(QString::number(outAmt, 'f', 8)));
        if (quotedOut > 0.0 && outAmt < quotedOut * 0.99)
            body += tr("\n\nHeads up: the bridge fee rose since your quote - this is %1 %2 less than "
                       "the %3 %2 quoted.")
                        .arg(trimZeros(QString::number(quotedOut - outAmt, 'f', 8)), sym,
                             trimZeros(QString::number(quotedOut, 'f', 8)));
        if (QMessageBox::question(dlg, tr("Confirm bridge"), body) != QMessageBox::Yes) {
            st->bridging = false;
            bridgeBtn->setEnabled(true);
            status->setText(tr("Bridge cancelled."));
            return;
        }
        if (!contextStillValid()) { // the network/wallet may have changed while the prompt was up
            st->bridging = false;
            return;
        }
        st->confirmedOutput = freshOut; // what was promised, to compare against a post-approval requote
        if (st->native) {
            sendBuilt(); // native deposit sends value directly, no approval
        } else {
            status->setText(tr("Checking token approval…"));
            m_wallet->bridgeAllowance(st->account, st->inputToken, st->spender);
        }
    });

    connect(m_wallet, &Wallet::bridgeAllowanceReady, dlg,
            [=](const QString &token, const QString &spender, const QString &wei, const QString &err) {
                if (!st->bridging || st->native)
                    return;
                if (token.compare(st->inputToken, Qt::CaseInsensitive) != 0 ||
                    spender.compare(st->spender, Qt::CaseInsensitive) != 0)
                    return;
                if (!err.isEmpty()) {
                    st->bridging = false;
                    bridgeBtn->setEnabled(true);
                    status->setText(tr("Approval check failed: %1").arg(err.toHtmlEscaped()));
                    return;
                }
                // The same token symbol maps to a different contract on every chain, so an approval
                // sent after a network switch would hand an allowance to the wrong token entirely.
                if (!contextStillValid()) {
                    st->bridging = false;
                    st->approveStage = BridgeState::NoApproval;
                    return;
                }
                const bool sufficient = geq(wei, st->amountWei);
                const bool isZero = wei.isEmpty() || wei == QLatin1String("0");
                // Re-poll the allowance until the pending approval lands. `nextStep` runs once it has.
                auto poll = [=](const QString &waitingFor, const std::function<void()> &nextStep,
                                bool reached) {
                    if (reached) {
                        st->approvePolls = 0;
                        nextStep();
                    } else if (++st->approvePolls <= 15) {
                        status->setText(waitingFor);
                        QTimer::singleShot(8000, dlg, [=]() {
                            if (st->bridging && st->approveStage != BridgeState::NoApproval)
                                m_wallet->bridgeAllowance(st->account, st->inputToken, st->spender);
                        });
                    } else {
                        st->bridging = false;
                        st->approveStage = BridgeState::NoApproval;
                        bridgeBtn->setEnabled(true);
                        status->setText(tr("The approval hasn't confirmed yet. Press Bridge again "
                                           "once it does."));
                    }
                };
                if (st->approveStage == BridgeState::AwaitingReset) {
                    // The old allowance is cleared - now approve the amount we actually need.
                    poll(tr("Waiting for the allowance reset to confirm… (%1)").arg(st->approvePolls + 1),
                         [=]() {
                             st->approveStage = BridgeState::AwaitingApproval;
                             status->setText(tr("Approving %1 for the bridge…").arg(st->symbol));
                             m_pendingBridge.approving = true;
                             beginSendProgress(tr("Broadcasting approval…"));
                             m_wallet->bridgeApprove(st->account, st->inputToken, st->spender,
                                                     st->amountWei);
                         },
                         isZero);
                    return;
                }
                if (st->approveStage == BridgeState::AwaitingApproval) {
                    poll(tr("Waiting for the approval to confirm on-chain… (%1)").arg(st->approvePolls + 1),
                         [=]() {
                             st->approveStage = BridgeState::NoApproval;
                             // The calldata was built before the approval; re-quote so the deposit
                             // carries a timestamp and an output amount relayers will still honour.
                             st->rebuildBeforeSend = true;
                             status->setText(tr("Approval confirmed. Refreshing the bridge quote…"));
                             m_wallet->acrossBuild(st->account, st->symbol, st->dest, st->amountWei);
                         },
                         sufficient);
                    return;
                }
                if (sufficient) {
                    sendBuilt();
                    return;
                }
                if (m_sendInFlight) {
                    st->bridging = false;
                    bridgeBtn->setEnabled(true);
                    status->setText(tr("Another transaction is being broadcast. Try again in a moment."));
                    return;
                }
                m_pendingBridge.approving = true;
                if (!isZero) {
                    // A leftover, too-small allowance: tokens such as USDT revert an approve that
                    // moves a non-zero allowance straight to another non-zero value, so clear it
                    // first. Costs one extra transaction, only in this rare case.
                    st->approveStage = BridgeState::AwaitingReset;
                    status->setText(tr("Clearing the previous %1 approval first (some tokens require "
                                       "it) - this needs two transactions.")
                                        .arg(st->symbol));
                    beginSendProgress(tr("Broadcasting approval reset…"));
                    m_wallet->bridgeApprove(st->account, st->inputToken, st->spender,
                                            QStringLiteral("0"));
                } else {
                    st->approveStage = BridgeState::AwaitingApproval;
                    status->setText(tr("Approving %1 for the bridge…").arg(st->symbol));
                    beginSendProgress(tr("Broadcasting approval…"));
                    m_wallet->bridgeApprove(st->account, st->inputToken, st->spender, st->amountWei);
                }
            });

    connect(m_wallet, &Wallet::bridgeApproved, dlg, [=](const QString &txHash, const QString &err) {
        if (!st->bridging || st->native)
            return;
        if (!err.isEmpty() || txHash.isEmpty()) {
            st->bridging = false;
            st->approveStage = BridgeState::NoApproval;
            bridgeBtn->setEnabled(true);
            status->setText(tr("Approval failed: %1").arg(err.toHtmlEscaped()));
            return;
        }
        st->approvePolls = 0;
        status->setText(st->approveStage == BridgeState::AwaitingReset
                            ? tr("Allowance reset sent (%1). Waiting for it to confirm…")
                                  .arg(shortAddr(txHash))
                            : tr("Approval sent (%1). Waiting for it to confirm…").arg(shortAddr(txHash)));
        QTimer::singleShot(8000, dlg, [=]() {
            if (st->bridging && st->approveStage != BridgeState::NoApproval)
                m_wallet->bridgeAllowance(st->account, st->inputToken, st->spender);
        });
    });

    // Status only - the history row, receipt watch and notification live in onBridgeBroadcast so they
    // still happen if this dialog was closed while the deposit was in flight.
    connect(m_wallet, &Wallet::bridgeSent, dlg, [=](const QString &txHash, const QString &err) {
        if (!st->bridging)
            return;
        st->bridging = false;
        if (!err.isEmpty() || txHash.isEmpty()) {
            bridgeBtn->setEnabled(true);
            status->setText(tr("Bridge failed: %1").arg(err.toHtmlEscaped()));
            return;
        }
        status->setText(tr("\u2714 Bridge submitted to %1. Funds arrive at your address there "
                           "shortly.&nbsp;&nbsp;<a href=\"%2\">View transaction</a>")
                            .arg(chainDefFor(st->dest).name, explorerTxUrl(txHash)));
    });

    dlg->show();
}

// A bridge approval finished broadcasting. Only clears the shared send guard - success/failure is
// reported by the dialog, which drives the approve -> deposit sequence.
void AeroMainWindow::onBridgeApproveBroadcast(const QString &, const QString &) {
    if (!m_pendingBridge.approving)
        return;
    m_pendingBridge.approving = false;
    endSendProgress();
}

// A bridge deposit finished broadcasting. Owned by the window (not the dialog) so a transaction that
// is already on the wire is always recorded, even if the user closed the dialog while it was sending.
void AeroMainWindow::onBridgeBroadcast(const QString &txHash, const QString &err) {
    if (!m_pendingBridge.active)
        return;
    m_pendingBridge.active = false;
    endSendProgress();
    if (!err.isEmpty() || txHash.isEmpty())
        return; // the dialog shows the error; nothing was broadcast
    // A bridge is an outgoing send to the SpokePool: show it as pending right away and let the
    // receipt watch reconcile it.
    m_historyModel->addLocalSend(txHash, m_pendingBridge.to, m_pendingBridge.amountHuman,
                                 m_pendingBridge.symbol, m_pendingBridge.tokenAddr);
    startReceiptWatch(txHash);
    // applyOptimisticSend drops the balance of the account the tx was committed from.
    m_committedFrom = m_pendingBridge.account;
    applyOptimisticSend(m_pendingBridge.amountHuman, m_pendingBridge.tokenAddr);
    notify(tr("Bridge submitted"), tr("%1 %2 to %3").arg(m_pendingBridge.amountHuman,
                                                         m_pendingBridge.symbol,
                                                         chainDefFor(m_pendingBridge.dest).name));
}

// --- XMR1 on Hyperliquid -------------------------------------------------------------------------

// Offered as a tab only where it can actually be used. Orders are signed with a key derived from
// the account key, which a watch-only wallet does not have and a hardware wallet does not expose -
// so for those the tab is absent rather than present and failing at the point of signing.
void AeroMainWindow::updateXmrTabEnabled() {
    if (!m_xmrTab)
        return;
    const bool supported = m_wallet && !m_wallet->isWatchOnly() && !m_wallet->isHardware();
    const int cur = ui.tabWidget->indexOf(m_xmrTab);
    if (supported && cur < 0) {
        ui.tabWidget->insertTab(qMin(4, ui.tabWidget->count()), m_xmrTab,
                                QIcon(QStringLiteral(":/assets/images/tab_swap.png")),
                                tr("Buy XMR"));
    } else if (!supported && cur >= 0) {
        ui.tabWidget->removeTab(cur); // widget retained via m_xmrTab
    }
    if (supported)
        m_xmrTab->setWallet(m_wallet, m_account, m_wallet->address(m_account));
    else
        m_xmrTab->setWallet(nullptr, 0, QString());
}

void AeroMainWindow::showXmrTradeTab() {
    if (!m_xmrTab)
        return;
    if (ui.tabWidget->indexOf(m_xmrTab) < 0) {
        if (m_wallet && m_wallet->isWatchOnly()) {
            QMessageBox::information(this, tr("Buy XMR"),
                                     tr("This is a watch-only wallet; it can't sign orders."));
        } else if (m_wallet && m_wallet->isHardware()) {
            QMessageBox::information(
                this, tr("Buy XMR"),
                tr("Trading on Hyperliquid isn't available for hardware wallets yet - orders are "
                   "signed with a trading key derived from the account key, which never leaves your "
                   "device.\n\nA software wallet on this machine can trade, and you can send the "
                   "proceeds to your hardware wallet afterwards."));
        }
        return;
    }
    ui.tabWidget->setCurrentWidget(m_xmrTab);
}

void AeroMainWindow::showRevokeApprovals() {
    if (!m_wallet)
        return;
    if (m_wallet->isWatchOnly()) {
        QMessageBox::information(this, tr("Revoke Approvals"),
                                 tr("This is a watch-only wallet; it can't send revoke transactions."));
        return;
    }

    auto *dlg = new QDialog(this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setWindowTitle(tr("Revoke Token Approvals"));
    dlg->resize(740, 480);
    auto *v = new QVBoxLayout(dlg);
    v->setSpacing(8);

    auto *info = new QLabel(
        tr("Approvals let a contract (a \u201cspender\u201d) move your tokens. This lists who can "
           "move which token for the selected account on %1 \u2014 revoke any you no longer trust.")
            .arg(chainDefFor(m_chainId).name),
        dlg);
    info->setWordWrap(true);
    info->setStyleSheet(QStringLiteral("color:#8a8a8a;"));
    v->addWidget(info);

    auto *topRow = new QHBoxLayout();
    topRow->addWidget(new QLabel(tr("Account:"), dlg));
    auto *acct = new QComboBox(dlg);
    acct->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    const quint32 n = m_wallet->numAccounts();
    for (quint32 i = 0; i < n; ++i)
        acct->addItem(tokenIcon(m_nativeSymbol), accountLabel(i));
    acct->setCurrentIndex(qMin<int>(m_account, n > 0 ? n - 1 : 0));
    topRow->addWidget(acct, 1);
    auto *scanBtn = new QPushButton(tr("Rescan"), dlg);
    topRow->addWidget(scanBtn);
    v->addLayout(topRow);

    // Manual entry.
    auto *manRow = new QHBoxLayout();
    auto *manToken = new QLineEdit(dlg);
    manToken->setPlaceholderText(tr("Token 0x…"));
    auto *manSpender = new QLineEdit(dlg);
    manSpender->setPlaceholderText(tr("Spender 0x…"));
    auto *manCheck = new QPushButton(tr("Check"), dlg);
    manRow->addWidget(manToken, 2);
    manRow->addWidget(manSpender, 2);
    manRow->addWidget(manCheck);
    v->addLayout(manRow);

    auto *table = new QTableWidget(dlg);
    table->setColumnCount(4);
    table->setHorizontalHeaderLabels({tr("Token"), tr("Spender"), tr("Allowance"), QString()});
    table->horizontalHeader()->setStretchLastSection(false);
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionMode(QAbstractItemView::NoSelection);
    v->addWidget(table, 1);

    auto *status = new QLabel(dlg);
    status->setWordWrap(true);
    v->addWidget(status);

    // Address -> friendly label (symbol for tokens, name for spenders).
    auto *symbolFor = new QHash<QString, QString>();
    for (const TokenInfo &t : m_wallet->tokens())
        symbolFor->insert(t.address.toLower(), t.symbol);
    for (const TokenInfo &t : curatedTopTokens(m_chainId))
        symbolFor->insert(t.address.toLower(), t.symbol);
    auto *spenderName = new QHash<QString, QString>();
    for (const SpenderDef &s : curatedSpenders())
        spenderName->insert(s.address.toLower(), s.name);
    // Token -> decimals, so a finite allowance is shown as a human amount (e.g. "1,000 USDC") rather
    // than raw base units ("1000000000"). -1 == decimals unknown.
    auto *decimalsFor = new QHash<QString, int>();
    for (const TokenInfo &t : m_wallet->tokens())
        decimalsFor->insert(t.address.toLower(), t.decimals);
    for (const TokenInfo &t : curatedTopTokens(m_chainId))
        decimalsFor->insert(t.address.toLower(), t.decimals);
    // Pending queue for "Revoke All" (each revoke is a separate tx, sent sequentially so nonces
    // don't collide - the next fires only after the previous is broadcast).
    auto *revokeQueue = new QList<QPair<QString, QString>>();
    connect(dlg, &QObject::destroyed, [symbolFor, spenderName, decimalsFor, revokeQueue]() {
        delete symbolFor;
        delete spenderName;
        delete decimalsFor;
        delete revokeQueue;
    });
    // A friendly allowance label: "Unlimited" for effectively-max approvals, a human token amount
    // when we know the token's decimals, else the raw base-unit value as a safe fallback.
    auto allowanceLabel = [decimalsFor](const QString &wei, const QString &token) -> QString {
        if (wei.length() >= 30) // ~1e30+ base units => practically unlimited
            return tr("Unlimited");
        const int dec = decimalsFor->value(token.toLower(), -1);
        if (dec < 0)
            return wei; // unknown decimals: show raw base units rather than a wrong amount
        bool ok = false;
        const double v = wei.toDouble(&ok);
        if (!ok)
            return wei;
        return formatBalance(v / std::pow(10.0, dec));
    };

    // Adds/updates one row with a Revoke button.
    auto addRow = [=](const QString &token, const QString &spender, const QString &wei) {
        const int r = table->rowCount();
        table->insertRow(r);
        const QString tsym = symbolFor->value(token.toLower(), shortAddr(token));
        const QString sname = spenderName->value(spender.toLower(), shortAddr(spender));
        auto *tItem = new QTableWidgetItem(tsym);
        tItem->setToolTip(token);
        auto *sItem = new QTableWidgetItem(sname);
        sItem->setToolTip(spender);
        table->setItem(r, 0, tItem);
        table->setItem(r, 1, sItem);
        auto *aItem = new QTableWidgetItem(allowanceLabel(wei, token));
        aItem->setToolTip(tr("%1 base units").arg(wei));
        table->setItem(r, 2, aItem);
        auto *revoke = new QPushButton(tr("Revoke"), table);
        table->setCellWidget(r, 3, revoke);
        const quint32 idx = static_cast<quint32>(acct->currentIndex());
        connect(revoke, &QPushButton::clicked, dlg, [=]() {
            if (QMessageBox::question(dlg, tr("Revoke"),
                                      tr("Revoke %1's approval for %2?").arg(sname, tsym))
                != QMessageBox::Yes)
                return;
            revoke->setEnabled(false);
            revoke->setText(tr("Revoking…"));
            m_wallet->revokeApproval(idx, token, spender);
        });
    };

    connect(m_wallet, &Wallet::tokenAllowancesReady, dlg,
            [=](const QString &json, const QString &error) {
                scanBtn->setEnabled(true);
                scanBtn->setText(tr("Scan"));
                if (!error.isEmpty()) {
                    status->setText(tr("Scan failed: %1").arg(error));
                    return;
                }
                const QJsonArray arr = QJsonDocument::fromJson(json.toUtf8())
                                           .object().value(QStringLiteral("allowances")).toArray();
                for (const QJsonValue &vv : arr) {
                    const QJsonObject o = vv.toObject();
                    addRow(o.value(QStringLiteral("token")).toString(),
                           o.value(QStringLiteral("spender")).toString(),
                           o.value(QStringLiteral("allowance")).toString());
                }
                status->setText(arr.isEmpty() ? tr("No outstanding approvals found.")
                                              : tr("Found %1 approval(s).").arg(arr.size()));
            });

    connect(m_wallet, &Wallet::approvalRevoked, dlg,
            [=](const QString &token, const QString &spender, const QString &txHash,
                const QString &error) {
                Q_UNUSED(token);
                Q_UNUSED(spender);
                if (!error.isEmpty() || txHash.isEmpty()) {
                    status->setText(tr("Revoke failed: %1").arg(error));
                    revokeQueue->clear(); // stop the batch on any failure
                    for (int r = 0; r < table->rowCount(); ++r)
                        if (auto *b = qobject_cast<QPushButton *>(table->cellWidget(r, 3))) {
                            b->setEnabled(true);
                            b->setText(tr("Revoke"));
                        }
                    return;
                }
                // If a "Revoke All" batch is running, fire the next one now that this was broadcast.
                if (!revokeQueue->isEmpty()) {
                    const QPair<QString, QString> next = revokeQueue->takeFirst();
                    status->setText(tr("Revoke sent (%1). %2 more…")
                                        .arg(shortAddr(txHash)).arg(revokeQueue->size() + 1));
                    m_wallet->revokeApproval(static_cast<quint32>(acct->currentIndex()), next.first,
                                             next.second);
                } else {
                    status->setText(tr("Revoke sent (%1). Rescan to confirm.").arg(shortAddr(txHash)));
                }
            });

    auto runScan = [=]() {
        const quint32 fromIndex = static_cast<quint32>(acct->currentIndex());
        table->setRowCount(0);
        QSet<QString> tokenSet;
        auto addTok = [&](const QString &a) {
            if (!a.isEmpty()) tokenSet.insert(a);
        };
        for (const TokenInfo &t : m_wallet->tokens())
            addTok(t.address);
        for (const TokenInfo &t : curatedTopTokens(m_chainId))
            addTok(t.address);
        if (!chainDefFor(m_chainId).wrappedNative.isEmpty())
            addTok(chainDefFor(m_chainId).wrappedNative);
        if (m_historyModel)
            for (int r = 0; r < m_historyModel->rowCount(); ++r) {
                const HistoryItem h = m_historyModel->itemAt(r);
                addTok(h.token);
            }
        QJsonArray tokens;
        for (const QString &t : tokenSet)
            tokens.append(t);
        QJsonArray spenders;
        for (const SpenderDef &s : curatedSpenders())
            spenders.append(s.address);
        if (tokens.isEmpty()) {
            status->setText(tr("No tokens to scan (add tokens or use manual check)."));
            return;
        }
        scanBtn->setEnabled(false);
        scanBtn->setText(tr("Scanning…"));
        status->setText(tr("Scanning %1 token(s) × %2 spender(s)…")
                            .arg(tokens.size()).arg(spenders.size()));
        m_wallet->tokenAllowances(fromIndex, QString::fromUtf8(QJsonDocument(tokens).toJson(
                                                 QJsonDocument::Compact)),
                                  QString::fromUtf8(QJsonDocument(spenders).toJson(
                                      QJsonDocument::Compact)));
    };
    connect(scanBtn, &QPushButton::clicked, dlg, runScan);
    // Switching account re-scans for that account's approvals.
    connect(acct, &QComboBox::currentIndexChanged, dlg, [runScan](int) { runScan(); });

    connect(manCheck, &QPushButton::clicked, dlg, [=]() {
        const QString tk = manToken->text().trimmed();
        const QString sp = manSpender->text().trimmed();
        if (tk.size() != 42 || sp.size() != 42) {
            status->setText(tr("Enter a valid token and spender address."));
            return;
        }
        QJsonArray tokens{tk};
        QJsonArray spenders{sp};
        status->setText(tr("Checking…"));
        m_wallet->tokenAllowances(static_cast<quint32>(acct->currentIndex()),
                                  QString::fromUtf8(QJsonDocument(tokens).toJson(QJsonDocument::Compact)),
                                  QString::fromUtf8(QJsonDocument(spenders).toJson(QJsonDocument::Compact)));
    });

    auto *btnRow = new QHBoxLayout();
    auto *revokeAllBtn = new QPushButton(tr("Revoke All"), dlg);
    revokeAllBtn->setToolTip(tr("Send a revoke transaction for every approval listed above."));
    connect(revokeAllBtn, &QPushButton::clicked, dlg, [=]() {
        const int rows = table->rowCount();
        if (rows == 0) {
            status->setText(tr("Nothing to revoke."));
            return;
        }
        if (QMessageBox::question(
                dlg, tr("Revoke All"),
                tr("Revoke all %1 approval(s) for this account? This sends %1 transaction(s) "
                   "(you pay gas for each).").arg(rows)) != QMessageBox::Yes)
            return;
        revokeQueue->clear();
        for (int r = 0; r < rows; ++r) {
            const QString token = table->item(r, 0)->toolTip();   // full address (tooltip)
            const QString spender = table->item(r, 1)->toolTip();
            revokeQueue->append({token, spender});
            if (auto *b = qobject_cast<QPushButton *>(table->cellWidget(r, 3))) {
                b->setEnabled(false);
                b->setText(tr("Queued…"));
            }
        }
        const QPair<QString, QString> first = revokeQueue->takeFirst();
        status->setText(tr("Revoking all %1… (1 of %1)").arg(rows));
        m_wallet->revokeApproval(static_cast<quint32>(acct->currentIndex()), first.first,
                                 first.second);
    });
    btnRow->addWidget(revokeAllBtn);
    btnRow->addStretch(1);
    auto *closeBtn = new QPushButton(tr("Close"), dlg);
    connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    btnRow->addWidget(closeBtn);
    v->addLayout(btnRow);

    dlg->show();
    runScan();
}

// Load a QPixmap from raw image bytes; returns a null pixmap if the format isn't supported.
static QPixmap pixmapFromBytes(const QByteArray &data) {
    QPixmap pm;
    pm.loadFromData(data);
    return pm;
}

void AeroMainWindow::refreshNfts() {
    if (!m_wallet || !m_nftEnabled) // skip entirely when the tab is off
        return;
    // Lazy (Electrum/Feather-style): NFTs are only shown on the NFTs tab, and fetching them hits the
    // Blockscout NFT API + downloads thumbnail images. Don't do that on connect or on every account
    // switch - only when the NFTs tab is actually being viewed.
    if (m_nftTab && ui.tabWidget->currentWidget() != m_nftTab)
        return;
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
        refreshSendContacts(); // keep the Send "Pay to contact" picker in sync
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
        if (m_wallet) m_wallet->saveAsync(); // off-thread Argon2 + atomic write; never blocks the UI
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
    connect(ui.menuTools->addAction(tr("Send to Many…")), &QAction::triggered, this,
            &AeroMainWindow::onSendMany);
    connect(ui.menuTools->addAction(tr("Revoke Token Approvals…")), &QAction::triggered, this,
            &AeroMainWindow::showRevokeApprovals);
    connect(ui.menuTools->addAction(tr("Bridge to another chain (Across)…")), &QAction::triggered,
            this, &AeroMainWindow::showBridgeDialog);
    connect(ui.menuTools->addAction(tr("Buy XMR (Hyperliquid)…")), &QAction::triggered, this,
            &AeroMainWindow::showXmrTradeTab);
    ui.menuTools->addSeparator();
    m_speedUpAction = ui.menuTools->addAction(tr("Speed Up Last Transaction"));
    m_cancelTxAction = ui.menuTools->addAction(tr("Cancel Last Transaction"));
    m_speedUpAction->setEnabled(false); // enabled once a tx is sent this session
    m_cancelTxAction->setEnabled(false);
    connect(m_speedUpAction, &QAction::triggered, this, &AeroMainWindow::onSpeedUpLast);
    connect(m_cancelTxAction, &QAction::triggered, this, &AeroMainWindow::onCancelLast);

    // --- Help: keep About and Check for Updates; the rest have no Aero targets. ---
    connect(ui.actionAbout, &QAction::triggered, this, [this]() {
        QMessageBox::about(
            this, tr("About Aero"),
            tr("<b>Aero %1</b> - a lightweight, Tor-routed Ethereum wallet.<br><br>"
               "Local key custody, trustless RPC over Tor, no telemetry.<br><br>"
               "Updates are accepted only when signed by the Aero release key<br><tt>%2</tt>")
                .arg(Updater::currentVersion(), Updater::signingKeyFingerprint()));
    });
    ui.actionCheckForUpdates->setVisible(true);
    ui.actionCheckForUpdates->setEnabled(true);
    connect(ui.actionCheckForUpdates, &QAction::triggered, this, [this]() {
        updater()->checkNow();
    });
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

    m_balanceLabel = new QLabel(tr("Balance: -"), this);
    m_balanceLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_connLabel = new QLabel(tr("Offline"), this);
    m_connIcon = new QLabel(this);
    m_connIcon->setFixedSize(18, 18);
    m_connIcon->setScaledContents(true);
    // Click the connection status to open Tor controls (status / Reconnect / New circuit).
    m_connIcon->setCursor(Qt::PointingHandCursor);
    m_connLabel->setCursor(Qt::PointingHandCursor);
    m_connIcon->setToolTip(tr("Click for Tor controls"));
    m_connLabel->setToolTip(tr("Click for Tor controls"));
    m_connIcon->installEventFilter(this);
    m_connLabel->installEventFilter(this);

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
        // Rebuild on open so the "Show testnets" preference takes effect immediately (no restart).
        connect(menu, &QMenu::aboutToShow, this, [this, menu]() {
            menu->clear();
            const bool showTest = aeroShowTestnets();
            for (const ChainDef &c : chainDefs()) {
                // Hide testnets unless enabled - but always keep the currently-active one selectable.
                if (aeroIsTestnet(c.id) && !showTest && c.id != m_chainId)
                    continue;
                QAction *a = menu->addAction(QIcon(c.icon), c.name);
                const quint64 id = c.id;
                connect(a, &QAction::triggered, this, [this, id]() {
                    if (id != m_chainId) switchChain(id);
                });
            }
        });
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

// Every byte Aero sends goes through Tor. The system browser does not. Opening an explorer link in
// it fetches a page named after the user's own transaction, from the user's own address, seconds
// after that transaction was broadcast - which is precisely the link Tor was there to prevent. So
// ask, offer the clipboard instead, and let anyone who has a Tor browser open say so once.
void AeroMainWindow::openOutsideTor(const QString &url) {
    if (url.isEmpty())
        return;
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    if (s.value(QStringLiteral("privacy/allowClearnetLinks"), false).toBool()) {
        QDesktopServices::openUrl(QUrl(url));
        return;
    }

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Open outside Tor?"));
    dlg.setModal(true);
    auto *v = new QVBoxLayout(&dlg);
    auto *warn = new QLabel(
        tr("This opens in your normal browser, which does not use Tor.\n\n"
           "The explorer will see your real IP address next to this transaction. Copying the link "
           "and pasting it into Tor Browser keeps that connection hidden."),
        &dlg);
    warn->setWordWrap(true);
    v->addWidget(warn);

    auto *link = new QLabel(url, &dlg);
    link->setWordWrap(true);
    link->setTextInteractionFlags(Qt::TextSelectableByMouse);
    link->setStyleSheet(QStringLiteral("color:#8a8a8a;"));
    v->addWidget(link);

    auto *remember = new QCheckBox(tr("Don't ask again; my browser is set up for this"), &dlg);
    v->addWidget(remember);

    auto *row = new QHBoxLayout();
    auto *copyBtn = new QPushButton(tr("Copy link"), &dlg);
    copyBtn->setDefault(true);
    auto *openBtn = new QPushButton(tr("Open anyway"), &dlg);
    auto *cancelBtn = new QPushButton(tr("Cancel"), &dlg);
    row->addStretch(1);
    row->addWidget(copyBtn);
    row->addWidget(openBtn);
    row->addWidget(cancelBtn);
    v->addLayout(row);

    int choice = 0; // 1 = copy, 2 = open
    connect(copyBtn, &QPushButton::clicked, &dlg, [&]() { choice = 1; dlg.accept(); });
    connect(openBtn, &QPushButton::clicked, &dlg, [&]() { choice = 2; dlg.accept(); });
    connect(cancelBtn, &QPushButton::clicked, &dlg, &QDialog::reject);
    dlg.exec();

    if (choice == 1) {
        QApplication::clipboard()->setText(url);
        return;
    }
    if (choice != 2)
        return;
    // Only remember a choice to open, since that is the only one there is anything to remember.
    if (remember->isChecked())
        s.setValue(QStringLiteral("privacy/allowClearnetLinks"), true);
    QDesktopServices::openUrl(QUrl(url));
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
    // Clicking the status-bar connection area opens the Tor controls menu.
    if (event->type() == QEvent::MouseButtonPress && (obj == m_connIcon || obj == m_connLabel)) {
        showConnectionMenu();
        return true;
    }
    return QMainWindow::eventFilter(obj, event);
}

// The Tor controls popup: current state + Reconnect + New circuit. Also reachable from Settings.
void AeroMainWindow::showConnectionMenu() {
    QMenu menu(this);
    QString status = m_connText.isEmpty() ? (m_connLabel ? m_connLabel->text() : tr("Offline"))
                                          : m_connText;
    if (m_tor && !m_tor->isReady() && m_tor->bootstrapPercent() > 0 &&
        m_tor->bootstrapPercent() < 100)
        status = tr("Bootstrapping Tor… %1%").arg(m_tor->bootstrapPercent());
    QAction *head = menu.addAction(status);
    head->setEnabled(false);
    if (m_tor)
        menu.addAction(tr("SOCKS: %1").arg(m_tor->socksProxy()))->setEnabled(false);
    menu.addSeparator();
    connect(menu.addAction(tr("Reconnect")), &QAction::triggered, this,
            [this]() { reconnectTor(tr("manual reconnect")); });
    connect(menu.addAction(tr("New Tor circuit")), &QAction::triggered, this,
            [this]() { newTorCircuit(); });
    QPoint at = m_connIcon ? m_connIcon->mapToGlobal(QPoint(0, -4)) : QCursor::pos();
    menu.exec(at);
}

// Re-establish the connection. If our bundled Tor died, restart it (its ready() re-triggers the
// connect); otherwise just re-probe the RPC over the existing circuit.
void AeroMainWindow::reconnectTor(const QString &reason) {
    if (!m_wallet || m_reconnecting)
        return;
    m_reconnecting = true;
    m_connHealthFails = 0;
    setConnectionState(0, tr("Reconnecting… (%1)").arg(reason));
    if (m_tor && !m_tor->isReady() && !m_tor->isRunning()) {
        m_tor->start(); // bundled Tor is down - bring it back up; ready() -> connectCurrentChain
    } else {
        connectCurrentChain(); // circuit likely fine - just re-probe
    }
}

void AeroMainWindow::newTorCircuit() {
    // Sharing an external Tor means not owning its process, so there is nothing here to restart.
    // Reconnecting is enough anyway: it builds a new provider, and a new provider asks Tor for its
    // circuits under names it has never used, which is a new circuit and a new exit whoever owns
    // the daemon.
    if (!externalSocks().isEmpty()) {
        reconnectTor(tr("external Tor"));
        return;
    }
    if (!m_tor) {
        reconnectTor(tr("new circuit"));
        return;
    }
    m_reconnecting = true;
    m_connHealthFails = 0;
    setConnectionState(0, tr("Getting a fresh Tor circuit…"));
    m_tor->restart(); // relaunch bundled Tor; ready() -> connectCurrentChain
}

void AeroMainWindow::changeEvent(QEvent *event) {
    if (event->type() == QEvent::WindowStateChange && m_lockOnMinimize && isMinimized())
        QTimer::singleShot(0, this, &AeroMainWindow::lockWallet);
    // Adaptive polling: speed the block poll up when the window is in use and slow it right down when
    // it's idle in the background (like Electrum going quiet / Feather idling once synced). On regain
    // of focus, catch up immediately so the user never sees stale data.
    if (event->type() == QEvent::ActivationChange || event->type() == QEvent::WindowStateChange) {
        const bool active = isActiveWindow() && !isMinimized();
        updatePollCadence();
        if (active && m_wallet && m_connMode > 0) {
            m_wallet->refreshBlockNumber(); // instant catch-up on focus
            refreshAllBalances();
        }
    }
    QMainWindow::changeEvent(event);
}

// Block-head poll cadence: 6s while the window is focused or a send is still confirming (responsive),
// 20s when idle in the background (minimal Tor traffic). Incoming payments are still detected within
// 20s while idle, and instantly on refocus (see changeEvent).
void AeroMainWindow::updatePollCadence() {
    if (!m_blockTimer)
        return;
    const bool active = isActiveWindow() && !isMinimized();
    const bool sending = !m_pendingReceiptHash.isEmpty();
    const int interval = (active || sending) ? 6000 : 20000;
    if (m_blockTimer->interval() != interval)
        m_blockTimer->setInterval(interval);
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
    // A bridge tracked against the previous wallet can never resolve now, so drop its state instead
    // of leaving the send guard (and its spinner) stuck on.
    if (m_pendingBridge.active || m_pendingBridge.approving) {
        m_pendingBridge = PendingBridge{};
        endSendProgress();
    }
    connect(m_wallet, &Wallet::balanceUpdated, this, &AeroMainWindow::onBalanceUpdated);
    connect(m_wallet, &Wallet::historyRefreshed, this,
            [this](const QVector<HistoryItem> &items, quint64 chainId) {
        if (chainId != m_chainId)
            return; // a previous chain's fetch that landed after a network switch - ignore it
        // Single-account / one-shot path.
        m_historyModel->setKnownTokens(verifiedTokenAddresses());
        updateHistoryOwnAddresses();
        m_historyModel->onHistoryRefreshed(items);
        checkUntrackedTokenLiquidity(); // auto-trust unknown-but-liquid tokens (DexScreener/Tor)
        requestHistoricalPrices(items); // value each native-coin tx at its date
    });
    // Start of an all-account refresh: clear the model + dedup up front (runs before any batch, so
    // out-of-order parallel batches can't append onto stale rows).
    connect(m_wallet, &Wallet::historyRefreshStarted, this, [this]() {
        m_historyModel->beginFullRefresh();
        m_historyModel->setKnownTokens(verifiedTokenAddresses());
        updateHistoryOwnAddresses(); // keep the poisoning look-alike index current
    });
    // Incremental all-account path: batches arrive per account (in completion order), appended live.
    connect(m_wallet, &Wallet::historyBatch, this,
            [this](const QVector<HistoryItem> &items, quint32 done, quint32 total, quint64 chainId) {
                if (chainId != m_chainId)
                    return; // stale batch from a chain we've since switched away from
                m_historyModel->appendBatch(items);
                requestHistoricalPrices(items);
                // Only touch the status bar when we're actually connected (m_connMode>0). Otherwise a
                // history refresh triggered while still "Connecting to Tor…" / "Offline" would clobber
                // that with a misleading "Connected". Also skip while a funded scan owns the status.
                const bool scanning = m_scanProgressTimer && m_scanProgressTimer->isActive();
                if (m_connMode > 0 && !scanning) {
                    if (done < total)
                        setConnectionState(m_connMode,
                                           tr("Loading history… %1/%2").arg(done).arg(total));
                    else
                        setConnectionState(m_connMode,
                                           m_connText.isEmpty() ? tr("Connected") : m_connText);
                }
                if (done == total)
                    checkUntrackedTokenLiquidity();
            });
    // Targeted single-account history (lazy / on-demand / status-gated) - appended, not cleared.
    connect(m_wallet, &Wallet::accountHistoryReady, this, &AeroMainWindow::onAccountHistoryReady);
    connect(m_wallet, &Wallet::txReceiptReady, this, &AeroMainWindow::onTxReceiptReady);
    // After the address cache is warmed (post-scan), rebuild the account combos from the hot cache.
    connect(m_wallet, &Wallet::addressesWarmed, this, [this]() { rebuildAccountCombos(); });
    connect(m_wallet, &Wallet::accountAdded, this, &AeroMainWindow::onAccountAdded);
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
    connect(m_wallet, &Wallet::historicalPriceReady, this, &AeroMainWindow::onHistoricalPrice);
    connect(m_wallet, &Wallet::nftsRefreshed, this, &AeroMainWindow::onNftsRefreshed);
    connect(m_wallet, &Wallet::imageReady, this, &AeroMainWindow::onImageReady);
    connect(m_wallet, &Wallet::fiatRate, this, &AeroMainWindow::onFiatRate);
    connect(m_wallet, &Wallet::tokenMetaResolved, this, &AeroMainWindow::onTokenMetaResolved);

    // Hardware wallets: reflect the device in the title, and prompt "confirm on device" while it
    // signs (cleared when the broadcast result arrives).
    if (m_wallet->isHardware()) {
        const QString dev = m_wallet->hwKind() == QLatin1String("ledger") ? tr("Ledger") : tr("Trezor");
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
        setWindowTitle(tr("Aero - watch-only wallet"));
        if (sendUi.btnSend) {
            sendUi.btnSend->setText(tr("Export Unsigned Tx"));
            sendUi.btnSend->setToolTip(
                tr("Watch-only: builds an unsigned transaction to sign on an offline wallet"));
        }
    }
    connect(m_wallet, &Wallet::unsignedTxReady, this, &AeroMainWindow::onUnsignedTxReady);
    connect(m_wallet, &Wallet::manySent, this, &AeroMainWindow::onManySent);
    // CoW swap signals.
    connect(m_wallet, &Wallet::swapQuoteReady, this, &AeroMainWindow::onSwapQuoteReady);
    connect(m_wallet, &Wallet::defillamaPricesReady, this, &AeroMainWindow::onDefillamaPricesReady);
    connect(m_wallet, &Wallet::swapAllowanceReady, this, &AeroMainWindow::onSwapAllowanceReady);
    connect(m_wallet, &Wallet::swapApproved, this, &AeroMainWindow::onSwapApproved);
    connect(m_wallet, &Wallet::swapSubmitted, this, &AeroMainWindow::onSwapSubmitted);
    connect(m_wallet, &Wallet::swapEthFlowSent, this, &AeroMainWindow::onSwapEthFlowSent);
    // Multi-router aggregator signals.
    connect(m_wallet, &Wallet::swapQuotesReady, this, &AeroMainWindow::onSwapQuotesReady);
    connect(m_wallet, &Wallet::routerBuilt, this, &AeroMainWindow::onRouterBuilt);
    connect(m_wallet, &Wallet::routerAllowanceReady, this, &AeroMainWindow::onRouterAllowanceReady);
    connect(m_wallet, &Wallet::routerApproved, this, &AeroMainWindow::onRouterApproved);
    // Bridge bookkeeping lives on the window so a broadcast deposit is recorded even if the bridge
    // dialog was closed while it was in flight.
    connect(m_wallet, &Wallet::bridgeSent, this, &AeroMainWindow::onBridgeBroadcast);
    connect(m_wallet, &Wallet::bridgeApproved, this, &AeroMainWindow::onBridgeApproveBroadcast);
    connect(m_wallet, &Wallet::routerSwapSent, this, &AeroMainWindow::onRouterSwapSent);
    // Event-driven history: after a batched balance refresh, only re-pull the (heavy) history if a
    // balance actually changed. This keeps steady-state bandwidth to the cheap balance batch.
    connect(m_wallet, &Wallet::allBalancesRefreshed, this, [this]() {
        // The whole batch has arrived - do the (single) authoritative total + used-flag recompute.
        scheduleHomeRecompute();
        m_balancesFromCache = false; // first live refresh done; grown balances are real from now on
        saveBalanceCache(); // persist (debounced) so the next open shows balances instantly
        if (m_swapPage && ui.tabWidget->indexOf(m_swapPage) >= 0) {
            updateSwapAvailable(); // keep the Swap "Available" line current
            updateSwapPayUsd();
        }
        // Only refetch history for the accounts whose balance actually changed (status-gated), never
        // a full all-account reload. Usually nothing changed, so a new block costs no history requests.
        m_balancesChanged = false;
        refreshDirtyHistory();
    });

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
                           .value(QStringLiteral("receive/fundedOnly"), false).toBool();
    applyFundedFilter();
    updateHistoryPricing(); // seed the History dust filter with the tracked-token symbols
    loadLiquidityCache();   // restore auto-trust (DEX liquidity) decisions
    applyVerifiedTokens();  // seed the History spam allow-list (curated top tokens + tracked)

    rebuildAccountCombos();
    populateSendCurrencies();
    // Reopen at the account last selected for THIS wallet (persisted per-wallet), not always #0.
    QSettings accSettings(QStringLiteral("Aero"), QStringLiteral("Aero"));
    const QString acctKey = selectedAccountKey(m_wallet->walletPath());
    const bool hasSavedSelection = accSettings.contains(acctKey);
    quint32 savedAcct = accSettings.value(acctKey, 0).toUInt();
    if (savedAcct >= m_wallet->numAccounts())
        savedAcct = 0;
    // ONLY on the very first open of this wallet (no selection saved yet) do we prefer the lowest
    // funded account, so a fresh wallet doesn't open on an empty #0. Once the user has selected an
    // address we ALWAYS restore that exact selection - never override it with a funded/biggest one.
    if (!hasSavedSelection && !m_fundedAccounts.isEmpty() && !m_fundedAccounts.contains(savedAcct)) {
        quint32 lowest = savedAcct;
        bool found = false;
        for (quint32 i : m_fundedAccounts)
            if (!found || i < lowest) {
                lowest = i;
                found = true;
            }
        if (found)
            savedAcct = lowest;
    }
    m_account = savedAcct;
    selectAddressRow(savedAcct); // selects the Receive row (fires onAccountChanged if visible)
    updateReceive();
    updateSwapTabEnabled(); // Swap tab depends on chain (CoW) + watch-only status
    updateXmrTabEnabled();  // Buy XMR needs a software wallet that can derive a trading key

    loadBalanceCache(); // show last-known balances instantly; the Tor refresh below overwrites them
    loadHistoryCache(); // restore this chain's history from the wallet file (0 network requests)
    loadHistoricalPrices(); // restore cached per-date fiat prices (never re-fetched)
    primeZeroBalances(); // fresh/empty wallet: show 0 right away instead of a blank "-"

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

    // Fees are only polled per-block while the Send tab is open (see onBlockNumber), so refresh
    // them once when the user switches to Send to make sure the estimate is current.
    connect(ui.tabWidget, &QTabWidget::currentChanged, this, [this](int) {
        if (!m_wallet)
            return;
        QWidget *w = ui.tabWidget->currentWidget();
        // Carry the account selected in Receive (the "active" account) into Send / Swap so it's
        // already chosen as "From" when you switch tabs - no re-picking needed.
        if (w == ui.tabSend) {
            if (m_fromCombo && static_cast<int>(m_account) < m_fromCombo->count())
                m_fromCombo->setCurrentIndex(static_cast<int>(m_account));
            m_wallet->refreshFees();
        } else if (w == m_swapPage) {
            if (m_swapFrom && static_cast<int>(m_account) < m_swapFrom->count())
                m_swapFrom->setCurrentIndex(static_cast<int>(m_account));
            m_wallet->refreshFees(); // populate gas price for route net-after-gas + approval fee est.
        } else if (w == ui.tabReceive) {
            // Reverse sync: if the active account changed elsewhere (e.g. the Send/Swap "From"
            // combo), re-select its row and refresh the QR/address so the highlighted row, the QR,
            // and "click to copy" all point at the SAME address (never a stale one).
            selectAddressRow(m_account);
            updateReceive();
        } else if (w == m_nftTab) {
            refreshNfts(); // lazy-load NFTs only when the tab is opened
        }
    });
}

void AeroMainWindow::onBlockNumber(quint64 block) {
    if (block == 0) {
        // The block poll failed. Once we've connected at least once, treat a run of failures as a
        // dropped connection and self-heal (restart Tor if it died, else re-probe). Guarded so it
        // never fires during the initial Tor bootstrap, and keeps retrying if a recovery fails.
        if (m_everConnected && !m_reconnecting && ++m_connHealthFails >= 3) {
            m_connHealthFails = 0;
            reconnectTor(tr("connection lost"));
        }
        return;
    }
    m_connHealthFails = 0; // a good poll: connection is healthy
    if (block <= m_lastBlock)
        return;
    const bool firstSeen = (m_lastBlock == 0);
    m_lastBlock = block;
    if (firstSeen)
        return; // baseline; the connect handler already did the initial refresh
    // A new block landed. Refresh ONLY the account currently on screen - NOT a full sweep of every
    // account. On a large HD wallet, re-fetching all N accounts' balances every ~12s is a perpetual
    // RPC request storm that trips rate limits and starves the initial load so it never finishes.
    // The one-time full sweep happens on connect; per-block we just keep the viewed account live.
    if (m_wallet->numAccounts() <= 8)
        refreshAllBalances();
    else
        m_wallet->refreshAccountBalance(m_account);
    if (ui.tabWidget->currentWidget() == ui.tabSend)
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

// Hand the core whatever history API the user chose for `chainId`, if any. Called on every connect
// and whenever the setting changes, so a keyless explorer that has gone away or tightened its limits
// is a line somebody edits here rather than a release everybody has to install.
void AeroMainWindow::applyHistoryApis(quint64 chainId) const {
    const QString csv = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                            .value(QStringLiteral("node/%1/historyApi").arg(chainId))
                            .toString()
                            .trimmed();
    Wallet::setHistoryApis(chainId, csv);
}

// SOCKS proxy for `chainId`: if the user saved a custom node they may also have set (or blanked, to
// go direct) a proxy for it. Otherwise everything routes over the running Tor proxy.
QString AeroMainWindow::socksFor(quint64 chainId) const {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    const QString key = QStringLiteral("node/%1/socks").arg(chainId);
    if (s.contains(key)) return s.value(key).toString(); // may be "" => direct (own node)
    // Share another app's Tor (Feather / Tor Browser / system) if the user chose that; else our own.
    const QString ext = externalSocks();
    if (!ext.isEmpty())
        return ext;
    return m_tor ? m_tor->socksProxy() : kDefaultSocks;
}

// The updater, pointed at whatever Tor is in effect at the moment it is asked.
//
// Per-chain node proxies are deliberately not consulted: those describe how to reach someone's own
// Ethereum node, which has nothing to do with fetching a release from GitHub. Update traffic gets
// the wallet's ordinary Tor path, on its own circuit.
Updater *AeroMainWindow::updater() {
    if (!m_updater)
        m_updater = new Updater(this);
    const QString ext = externalSocks();
    m_updater->setSocksProxy(!ext.isEmpty() ? ext
                                            : (m_tor ? m_tor->socksProxy() : kDefaultSocks));
    return m_updater;
}

// The external Tor SOCKS the user opted into (Settings -> Tor), normalised to a socks5h:// URL so DNS
// is resolved through Tor. Empty when the bundled Tor should be used.
QString AeroMainWindow::externalSocks() const {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    if (!s.value(QStringLiteral("tor/external"), false).toBool())
        return QString();
    QString hp = s.value(QStringLiteral("tor/socks")).toString().trimmed();
    if (hp.isEmpty())
        return QString();
    // Force socks5h:// so DNS resolves through Tor. `socks5://` resolves hostnames locally (leaking
    // them); a bare host:port has no scheme. (The core normalizes too - this keeps the UI honest.)
    if (hp.startsWith(QStringLiteral("socks5://"), Qt::CaseInsensitive))
        hp = QStringLiteral("socks5h://") + hp.mid(9);
    else if (!hp.contains(QStringLiteral("://")))
        hp = QStringLiteral("socks5h://") + hp;
    return hp;
}

// Build the JSON config (endpoints + socks per chain) for a cross-chain funded-address scan, using
// each chain's custom node if set, else its bundled endpoints over the current Tor proxy.
QString AeroMainWindow::allChainsScanConfig() const {
    QJsonArray arr;
    const bool showTest = aeroShowTestnets();
    for (const ChainDef &c : chainDefs()) {
        if (aeroIsTestnet(c.id) && !showTest)
            continue; // don't waste scan time on testnets unless the user uses them
        QJsonObject o;
        o[QStringLiteral("chain_id")] = static_cast<double>(c.id);
        QJsonArray eps;
        for (const QString &e : endpointsFor(c.id))
            eps.append(e);
        o[QStringLiteral("endpoints")] = eps;
        o[QStringLiteral("socks")] = socksFor(c.id);
        arr.append(o);
    }
    return QString::fromUtf8(QJsonDocument(arr).toJson(QJsonDocument::Compact));
}

// (Re)connect the active chain using the resolved node settings. A custom node with a blank proxy
// connects directly (for a local/own node); otherwise we go over Tor.
void AeroMainWindow::connectCurrentChain() {
    if (!m_wallet) return;
    applyHistoryApis(m_chainId);
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

    // If the user chose to share an external Tor (Feather / Tor Browser / system Tor), don't launch
    // our own tor.exe at all - just connect over that SOCKS proxy. Still 100% over Tor, no clearnet.
    {
        const QString ext = externalSocks();
        if (!ext.isEmpty()) {
            setConnectionState(0, tr("Connecting via external Tor (%1)…").arg(ext));
            connectCurrentChain(); // socksFor() returns the external SOCKS
            scheduleUpdateCheck();
            return;
        }
    }

    setConnectionState(0, tr("Connecting to Tor…"));

    // Otherwise always route through Tor - start (or reuse) Tor first, then connect only once it has
    // bootstrapped. There is no clearnet fallback, so the wallet never leaks the user's IP.
    if (!m_tor) {
        m_tor = new TorManager(this);
        connect(m_tor, &TorManager::statusChanged, this,
                [this](const QString &msg) { setConnectionState(0, msg); });
        connect(m_tor, &TorManager::ready, this, [this]() {
            setConnectionState(0, tr("Connecting to Tor…"));
            connectCurrentChain();
            scheduleUpdateCheck();
        });
        connect(m_tor, &TorManager::failed, this, [this](const QString &err) {
            m_reconnecting = false;
            setConnectionState(0, tr("Tor unavailable - %1").arg(err));
        });
        // Self-heal: if Tor dies after being up, bring it back and reconnect automatically.
        connect(m_tor, &TorManager::ended, this, [this]() { reconnectTor(tr("Tor restarted")); });
    }
    if (m_tor->isReady()) {
        connectCurrentChain();
        scheduleUpdateCheck();
    } else {
        m_tor->start();
    }
}

// Arm the automatic update check, once per run and only once there is a Tor path to use.
//
// Delayed rather than immediate: startup is already busy loading a wallet, bootstrapping Tor and
// fetching balances, and an update prompt landing in the middle of that is both slower and more
// startling than one that arrives when things have settled. A check that runs before Tor is usable
// would also fail and then count as the day's check, so it waits for Tor rather than for the clock.
void AeroMainWindow::scheduleUpdateCheck() {
    if (m_updateCheckScheduled)
        return;
    m_updateCheckScheduled = true;
    QTimer::singleShot(60000, this, [this]() { updater()->checkQuietly(); });
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
    if (m_historyModel) {
        m_historyModel->clearLocal();            // drop the old chain's optimistic pending rows
        m_historyModel->onHistoryRefreshed({});  // drop previous chain's fetched history
    }
    // History is per-chain: forget what we fetched so the new chain reloads lazily (see onProviderConnected).
    m_histFetched.clear();
    m_dirtyHistory.clear();
    m_historyLoadedChain = ~Q_UINT64_C(0);
    // The spam/known-token allow-list is chain-specific (curated top tokens differ per chain), so
    // recompute it for the new chain - otherwise legit tokens get hidden as spam / wrong ones trusted.
    // The liquidity verdicts feeding that list are per-chain too, so reload them first.
    loadLiquidityCache();
    m_liquidityInFlight.clear(); // in-flight checks belong to the chain we just left
    applyVerifiedTokens();

    // Reflect the new chain in the selector button.
    if (m_networkButton) {
        m_networkButton->setIcon(QIcon(c.icon));
        m_networkButton->setText(c.name);
        m_networkButton->setToolTip(tr("Network: %1").arg(c.name));
    }
    // Reset the Send asset to the new chain's native coin.
    setSendAsset(m_nativeSymbol, QString(), 18);
    updateAmountUnit();

    // Reset the Swap tab for the new chain (native sell asset, clear buy/quote) and show/hide it
    // depending on whether CoW supports this chain.
    m_swapSellSymbol = m_nativeSymbol;
    m_swapSellAddr.clear();
    m_swapSellDecimals = 18;
    m_swapBuySymbol.clear();
    m_swapBuyAddr.clear();
    m_swapQuoteJson.clear();
    m_swapSelRouter.clear();
    m_swapUserPickedRouter = false;
    resetSwapFlow(); // switching chains abandons any in-flight swap
    if (m_swapSellButton) m_swapSellButton->setText(m_nativeSymbol + QStringLiteral("  \u25be"));
    if (m_swapBuyButton) m_swapBuyButton->setText(tr("Select \u25be"));
    if (m_swapList) m_swapList->clear();
    if (m_swapReceive) m_swapReceive->setText(QStringLiteral("-"));
    if (m_swapRate) m_swapRate->clear();
    if (m_swapStatus) m_swapStatus->clear();
    if (m_swapConfirmBtn) m_swapConfirmBtn->setEnabled(false);
    updateSwapTabEnabled();

    // Update the Home native ticker label + any native-symbol labels.
    relabelNative();

    loadBalanceCache(); // instantly show the new chain's last-known balances while it reconnects
    loadHistoryCache(); // and its persisted history (0 requests); connect then only status-gates
    primeZeroBalances();

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
    // Clear the self-heal guard on any outcome so a failed attempt can be retried; only a genuine
    // success resets the failed-poll counter.
    m_reconnecting = false;
    if (mode > 0) {
        m_connHealthFails = 0;
        m_everConnected = true;
    }
    const QString text = mode > 0 ? tr("%1 · %2").arg(message, chainDefFor(m_chainId).name) : message;
    m_connMode = mode;      // remembered so the "Scanning…" state can restore the connected status
    m_connText = text;
    setConnectionState(mode, text);
    if (mode > 0) {
        // Only now that we can actually reach an RPC do we pull balances + prices. Each of these is
        // a single (or batched) request - no per-account fan-out and no duplicate refreshes.
        // Launch the quick, single-request refreshes FIRST so they grab net-pool threads before the
        // history fan-out (which can queue one task per account and would otherwise starve them -
        // delaying balances/prices behind the whole history load).
        refreshAllBalances();               // batched: native + tokens for every account
        fetchCuratedForCurrentAccount();    // + this account's curated tokens (USDC etc.) on big wallets
        m_wallet->refreshEthUsdPrice();     // native/USD (Chainlink or fallback)
        m_wallet->refreshMarketPrices();    // XMR + native market prices for Home
        m_wallet->refreshFees();            // gas suggestion
        if (m_fiatCurrency.compare(QStringLiteral("USD"), Qt::CaseInsensitive) != 0)
            m_wallet->refreshFiatRate(m_fiatCurrency); // USD->fiat rate for display
        refreshNfts();
        // History: only do a full (re)load when the chain changed or on first connect. A plain
        // reconnect on the same chain just refreshes the viewed account + anything that changed -
        // it must NOT re-clear and re-fetch every funded account (that would storm on auto-reconnect).
        if (m_historyLoadedChain != m_chainId) {
            m_historyLoadedChain = m_chainId;
            refreshHistoryView();           // clear + fetch viewed + funded accounts (targeted)
        } else {
            ensureAccountHistory(m_account, /*force*/ true);
            // A named or token-only account may have no cached history yet (older builds only ever
            // fetched funded accounts), so pull those once here too - it is deduped against the
            // cache, so accounts already loaded cost nothing.
            ensureFundedAndLabeledHistory();
            refreshDirtyHistory();
        }
        // First time we can reach the chain: if we've never scanned this wallet for funded
        // addresses, do it now - silently, across all chains (an address funded on any chain is
        // discovered even though we're connected to one).
        if (!m_fundedScanned && !m_fundedScanTried) {
            m_fundedScanTried = true;
            // Keep the connected icon but show progress; onFundedScanned restores the status.
            setConnectionState(m_connMode, tr("Scanning for your addresses…"));
            startScanProgress();
            m_wallet->scanFundedMulti(allChainsScanConfig(), 40);
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

// Poll the core's live scan counters and show them in the status bar, so the user actively sees the
// scan progress ("N checked, M found") instead of a static "Scanning…".
void AeroMainWindow::startScanProgress() {
    if (!m_scanProgressTimer) {
        m_scanProgressTimer = new QTimer(this);
        m_scanProgressTimer->setInterval(300);
        connect(m_scanProgressTimer, &QTimer::timeout, this, [this]() {
            if (!m_wallet) return;
            const quint64 checked = m_wallet->scanProgress();
            const quint64 found = m_wallet->scanFound();
            setConnectionState(m_connMode,
                               tr("Scanning addresses… %1 checked, %2 found")
                                   .arg(checked).arg(found));
        });
    }
    m_scanProgressTimer->start();
}

void AeroMainWindow::onFundedScanned(const QList<quint32> &indices) {
    if (m_scanProgressTimer)
        m_scanProgressTimer->stop();
    m_fundedScanned = true;
    m_fundedAccounts.clear();
    // The core scan (across all derivation schemes) already registered each funded address as an
    // account (and backfilled the contiguous gaps) and returns the funded unified indices; we mark
    // them funded and refresh.
    for (quint32 i : indices)
        m_fundedAccounts.insert(i);
    // PERSIST FIRST, GUARANTEED - and UNCONDITIONALLY. The scan mutated account_order in memory
    // (potentially hundreds of accounts) and produced the funded set. Write BOTH to disk NOW with a
    // blocking save behind a modal, rather than the debounced saveAsync - otherwise killing the app
    // (or a later UI stall) before the debounce fires loses the funded metadata even though a
    // background balance-cache save already persisted account_order. That mismatch is exactly the
    // "reopened and only ~4 addresses show, nothing red" bug: the accounts were on disk but the
    // funded set was not. We always mark funded_done so a reopen doesn't needlessly auto-rescan, and
    // always write the (possibly empty) funded array so it can never be left stale. This runs BEFORE
    // any combo rebuild, so even if the UI were to stall afterwards the data is already durable.
    {
        QJsonArray fundedArr;
        for (quint32 i : m_fundedAccounts)
            fundedArr.append(static_cast<double>(i));
        m_meta[QStringLiteral("funded")] = fundedArr;
        m_meta[QStringLiteral("funded_done")] = true;
        // Persist NON-BLOCKING. Do NOT use a modal blocking save here: the moment the scan releases
        // the core write lock, the herd of balance/history reader tasks that queued up during the
        // scan grabs read locks, which would starve a UI-thread write-lock save - freezing the app
        // "as soon as scanning finishes". queueMetadata + saveAsync applies this metadata and writes
        // off the UI thread as soon as the lock is free; closeEvent also flushes on exit.
        m_wallet->queueMetadata(QString::fromUtf8(QJsonDocument(m_meta).toJson(QJsonDocument::Compact)));
        m_wallet->saveAsync();
    }
    // Warm the address cache off-thread REGARDLESS of the funded count: the scan invalidated the
    // cache and grew account_order, so the next rebuildAccountCombos() (and the setWallet path) would
    // otherwise derive every address on the UI thread. addressesWarmed -> rebuildAccountCombos builds
    // from the hot cache with no stall.
    m_addressModel->refresh();
    m_wallet->warmAddresses(m_wallet->numAccounts());
    if (!m_fundedAccounts.isEmpty()) {
        refreshAllBalances();
        // Now that we know which accounts are funded, load their history once (targeted, deduped).
        // Empty accounts are skipped entirely - no fan-out over the whole derivation range.
        refreshHistoryView();
    }
    // Mark funded rows red immediately (before balances load); refreshUsedFlags() keeps them live
    // after each balance batch.
    for (quint32 i : m_fundedAccounts)
        m_addressModel->setUsed(i, true);
    // (The discovered accounts + funded set were already persisted synchronously above.)
    applyFundedFilter();
    // Keep the user's current selection if it's still a visible row after the scan; only fall back to
    // the first visible address when the selected account got filtered out.
    if (m_addressModel->rowCount() > 0) {
        const bool stillVisible = m_addressModel->rowForAccount(m_account) >= 0;
        selectAddressRow(stillVisible ? m_account : m_addressModel->accountAt(0));
    }
    // Restore the real connected status (Tor/direct). Only when actually connected - never overwrite
    // a "Connecting…"/"Offline" state with a bogus "Connected".
    if (m_connMode > 0)
        setConnectionState(m_connMode, m_connText.isEmpty() ? tr("Connected") : m_connText);
    notify(tr("Scan complete"),
           tr("Found %1 funded address(es).").arg(m_fundedAccounts.size()));
}

void AeroMainWindow::refreshAllBalances() {
    if (!m_wallet) return;
    // ONE batched request fetches native + tracked-token balances for every account, instead of
    // firing numAccounts × (1 + numTokens) independent Tor calls. Results arrive via per-account signals.
    //
    // The curated top-tokens are added as EXTRAS only for SMALL wallets. Each extra token adds one
    // eth_call PER ACCOUNT, so bundling ~24 curated tokens across a big HD wallet (e.g. 167 accounts)
    // meant ~24×167 mostly-zero token reads - which blew the per-request budget down to one account
    // per batch, instantly tripped the public RPC's rate limit, and (with retries) thrashed forever so
    // balances never finished loading. For a large wallet we fetch native + the user's TRACKED tokens
    // only; the current account's curated-token balances are loaded on demand elsewhere (Send/Swap).
    QJsonArray extra;
    if (m_wallet->numAccounts() <= 8) {
        for (const TokenInfo &t : curatedTopTokens(m_chainId)) {
            QJsonObject o;
            o[QStringLiteral("address")] = t.address;
            o[QStringLiteral("symbol")] = t.symbol;
            o[QStringLiteral("decimals")] = static_cast<int>(t.decimals);
            extra.append(o);
        }
    }
    const QString extraJson = QString::fromUtf8(QJsonDocument(extra).toJson(QJsonDocument::Compact));
    m_wallet->refreshAllBalances(m_wallet->numAccounts(), extraJson);
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
    // setLabel() above only emits dataChanged for rows currently visible in the Receive list, so the
    // dataChanged handler's pushAccountNames() misses any labelled-but-hidden account (funded filter
    // on, or addresses not warmed yet). Push the names to the History Account column directly so
    // labels show on open without needing a filter/sort to force a rebuild.
    pushAccountNames();
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

// Persist the current chain's last-known balances (per account) into the encrypted wallet metadata,
// so the next open can show them INSTANTLY - before Tor even connects - then refresh in the
// background. Keyed by chain id (balances differ per chain). Debounced via scheduleSave().
void AeroMainWindow::saveBalanceCache() {
    if (!m_wallet) return;
    QJsonObject eth, disp, tok;
    for (auto it = m_ethRawByAccount.constBegin(); it != m_ethRawByAccount.constEnd(); ++it)
        eth[QString::number(it.key())] = it.value();
    for (auto it = m_accountBalances.constBegin(); it != m_accountBalances.constEnd(); ++it)
        disp[QString::number(it.key())] = it.value();
    for (auto it = m_tokenRawByKey.constBegin(); it != m_tokenRawByKey.constEnd(); ++it)
        tok[it.key()] = it.value();
    QJsonObject snap;
    snap[QStringLiteral("eth")] = eth;
    snap[QStringLiteral("disp")] = disp;
    snap[QStringLiteral("tok")] = tok;
    snap[QStringLiteral("usd")] = m_nativeUsd; // so the fiat total is roughly right immediately
    QJsonObject cache = m_meta.value(QStringLiteral("balcache")).toObject();
    cache[QString::number(m_chainId)] = snap;
    m_meta[QStringLiteral("balcache")] = cache;
    // Update m_meta every time (cheap), but only push it to the core + encrypt+write at most every
    // 30s - balances refresh each block and re-running Argon2 that often is wasteful. saveMetadata()
    // queues the whole m_meta (incl. this balcache) into the core, then persists (debounced).
    // closeEvent also flushes the latest m_meta, so nothing is lost between throttled writes.
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (now - m_lastBalCacheSaveMs >= 30000) {
        m_lastBalCacheSaveMs = now;
        saveMetadata();
    }
}

// Populate the in-memory balance caches + UI from the persisted snapshot for the current chain, so
// balances appear immediately on open/chain-switch. The live refresh over Tor overwrites them.
void AeroMainWindow::loadBalanceCache() {
    if (!m_wallet) return;
    const QJsonObject snap = m_meta.value(QStringLiteral("balcache"))
                                 .toObject()
                                 .value(QString::number(m_chainId))
                                 .toObject();
    if (snap.isEmpty())
        return;
    // These are stale (last-session) values used only for instant display; the first live refresh
    // must not treat a grown balance as an incoming payment.
    m_balancesFromCache = true;
    const QJsonObject eth = snap.value(QStringLiteral("eth")).toObject();
    for (auto it = eth.constBegin(); it != eth.constEnd(); ++it)
        m_ethRawByAccount.insert(it.key().toUInt(), it.value().toDouble());
    const QJsonObject tok = snap.value(QStringLiteral("tok")).toObject();
    for (auto it = tok.constBegin(); it != tok.constEnd(); ++it) {
        // Normalize the "index|addr" key's address to lowercase so a cache written by an older build
        // (mixed-case) still matches today's lowercase lookups.
        const QString idx = it.key().section(QLatin1Char('|'), 0, 0);
        const QString addr = it.key().section(QLatin1Char('|'), 1).toLower();
        m_tokenRawByKey.insert(QStringLiteral("%1|%2").arg(idx, addr), it.value().toDouble());
    }
    const double usd = snap.value(QStringLiteral("usd")).toDouble();
    if (usd > 0.0 && m_nativeUsd <= 0.0)
        m_nativeUsd = usd;
    const QJsonObject disp = snap.value(QStringLiteral("disp")).toObject();
    for (auto it = disp.constBegin(); it != disp.constEnd(); ++it) {
        const quint32 idx = it.key().toUInt();
        const QString s = it.value().toString();
        m_accountBalances.insert(idx, s);
        if (m_addressModel)
            m_addressModel->setBalance(idx, addressListBalance(idx));
        if (m_fromCombo && static_cast<int>(idx) < m_fromCombo->count()) {
            QSignalBlocker b(m_fromCombo);
            m_fromCombo->setItemText(static_cast<int>(idx), accountLabel(idx));
        }
        if (m_swapFrom && static_cast<int>(idx) < m_swapFrom->count()) {
            QSignalBlocker b(m_swapFrom);
            m_swapFrom->setItemText(static_cast<int>(idx), accountLabel(idx));
        }
    }
    recomputeHomeTotal();
    refreshUsedFlags();
    showCachedBalance(m_account);
    updateReceive();
}

// --- Per-chain history persistence (Electrum's DB / Feather's block cache) -----------------------
// A HistoryItem <-> JSON round-trip so fetched history survives a restart. Keys are terse to keep
// the encrypted wallet file small.
static QJsonObject histItemToJson(const HistoryItem &h) {
    QJsonObject o;
    o[QStringLiteral("d")] = h.direction;
    o[QStringLiteral("c")] = h.counterparty;
    o[QStringLiteral("a")] = h.amount;
    o[QStringLiteral("f")] = h.formatted;
    o[QStringLiteral("h")] = h.txHash;
    o[QStringLiteral("b")] = static_cast<double>(h.block);
    o[QStringLiteral("t")] = h.token;
    o[QStringLiteral("s")] = h.symbol;
    o[QStringLiteral("ts")] = static_cast<double>(h.timestamp);
    if (!h.fee.isEmpty()) o[QStringLiteral("fee")] = h.fee;
    if (h.failed) o[QStringLiteral("x")] = true;
    if (!h.kind.isEmpty()) o[QStringLiteral("k")] = h.kind;
    if (!h.buySymbol.isEmpty()) o[QStringLiteral("bs")] = h.buySymbol;
    if (!h.buyFormatted.isEmpty()) o[QStringLiteral("bf")] = h.buyFormatted;
    if (!h.status.isEmpty()) o[QStringLiteral("st")] = h.status;
    // Kept so a swap that was still open when the app closed can be judged on reopen: without its
    // deadline there is no way to tell an order that is still working from one that died unremarked.
    if (h.expiry) o[QStringLiteral("ex")] = static_cast<double>(h.expiry);
    // Which account a row belongs to has to survive the write. Dropping it meant every restored row
    // came back as "unknown account": the Account column was blank, and - because the pending-order
    // poll only asks about accounts it can name - a CoW order left open at shutdown was never
    // queried again and sat at "pending" until it aged out as failed.
    if (h.account != HistoryItem::unknownAccount)
        o[QStringLiteral("ac")] = static_cast<double>(h.account);
    return o;
}
static HistoryItem histItemFromJson(const QJsonObject &o) {
    HistoryItem h;
    h.direction = o.value(QStringLiteral("d")).toString();
    h.counterparty = o.value(QStringLiteral("c")).toString();
    h.amount = o.value(QStringLiteral("a")).toString();
    h.formatted = o.value(QStringLiteral("f")).toString();
    h.txHash = o.value(QStringLiteral("h")).toString();
    h.block = static_cast<quint64>(o.value(QStringLiteral("b")).toDouble());
    h.token = o.value(QStringLiteral("t")).toString();
    h.symbol = o.value(QStringLiteral("s")).toString();
    h.timestamp = static_cast<quint64>(o.value(QStringLiteral("ts")).toDouble());
    h.fee = o.value(QStringLiteral("fee")).toString();
    h.failed = o.value(QStringLiteral("x")).toBool(false);
    h.kind = o.value(QStringLiteral("k")).toString();
    h.buySymbol = o.value(QStringLiteral("bs")).toString();
    h.buyFormatted = o.value(QStringLiteral("bf")).toString();
    h.status = o.value(QStringLiteral("st")).toString();
    h.expiry = static_cast<quint64>(o.value(QStringLiteral("ex")).toDouble());
    h.account = o.contains(QStringLiteral("ac"))
                    ? static_cast<quint32>(o.value(QStringLiteral("ac")).toDouble())
                    : HistoryItem::unknownAccount;
    return h;
}

void AeroMainWindow::scheduleHistorySave() {
    if (!m_wallet) return;
    if (!m_histSaveTimer) {
        m_histSaveTimer = new QTimer(this);
        m_histSaveTimer->setSingleShot(true);
        m_histSaveTimer->setInterval(5000); // coalesce a burst of per-account batches into one write
        connect(m_histSaveTimer, &QTimer::timeout, this, [this]() { saveHistoryCache(); });
    }
    if (!m_histSaveTimer->isActive())
        m_histSaveTimer->start();
}

void AeroMainWindow::saveHistoryCache() {
    foldHistoryCacheIntoMeta();
    if (m_wallet && m_historyModel)
        saveMetadata();
}

// Build this chain's history snapshot into m_meta WITHOUT triggering a save. closeEvent uses this to
// assemble the final metadata on the UI thread, then persists it once on a worker (so the UI-thread
// save can't freeze the close).
void AeroMainWindow::foldHistoryCacheIntoMeta() {
    if (!m_wallet || !m_historyModel) return;
    QVector<HistoryItem> items = m_historyModel->fetchedItems();

    // The model holds whatever the last refresh fetched, which after viewing a single account is
    // that account alone. Writing it straight out therefore replaced the whole chain's snapshot with
    // one account's rows: quit while filtered to "Account #3" and every other account's history was
    // gone on reopen - and, because a restored account is marked already-fetched, it did not come
    // back without a forced rescan. Carry forward the stored rows for accounts this refresh did not
    // cover. An account present in `items` is authoritative, so nothing is duplicated.
    QSet<quint32> covered;
    for (const HistoryItem &h : items)
        covered.insert(h.account);
    const QJsonArray previous = m_meta.value(QStringLiteral("histcache"))
                                    .toObject()
                                    .value(QString::number(m_chainId))
                                    .toObject()
                                    .value(QStringLiteral("items"))
                                    .toArray();
    for (const QJsonValue &v : previous) {
        const HistoryItem h = histItemFromJson(v.toObject());
        if (!covered.contains(h.account))
            items.append(h);
    }

    // Bound the file, but generously: a wallet with many funded accounts legitimately has thousands
    // of transactions, and the on-reopen cache is marked "already fetched" per account (status-gate),
    // so anything dropped here is NOT re-fetched - it just vanishes from the restored view until a
    // forced rescan. A tight cap (the old 4000) therefore truncated real history on reopen. Keep the
    // newest 30k rows (by timestamp, then block) per chain - enough to never truncate a realistic
    // wallet, while still bounding the encrypted file. AES over a few MB is sub-millisecond; the
    // Argon2id cost is on the key and independent of blob size.
    std::sort(items.begin(), items.end(), [](const HistoryItem &a, const HistoryItem &b) {
        if (a.timestamp != b.timestamp) return a.timestamp > b.timestamp;
        return a.block > b.block;
    });
    if (items.size() > 30000)
        items.resize(30000);
    QJsonArray arr;
    for (const HistoryItem &h : items)
        arr.append(histItemToJson(h));
    QJsonObject status; // account -> balance when its history was last fetched (status-gate baseline)
    for (auto it = m_histStatus.constBegin(); it != m_histStatus.constEnd(); ++it)
        status[QString::number(it.key())] = it.value();
    QJsonObject snap;
    snap[QStringLiteral("items")] = arr;
    snap[QStringLiteral("status")] = status;
    QJsonObject cache = m_meta.value(QStringLiteral("histcache")).toObject();
    cache[QString::number(m_chainId)] = snap;
    m_meta[QStringLiteral("histcache")] = cache;
}

void AeroMainWindow::loadHistoryCache() {
    if (!m_wallet || !m_historyModel) return;
    const QJsonObject snap = m_meta.value(QStringLiteral("histcache"))
                                 .toObject()
                                 .value(QString::number(m_chainId))
                                 .toObject();
    if (snap.isEmpty())
        return;
    QVector<HistoryItem> items;
    const QJsonArray arr = snap.value(QStringLiteral("items")).toArray();
    items.reserve(arr.size());
    for (const QJsonValue &v : arr)
        items.append(histItemFromJson(v.toObject()));
    m_historyModel->loadCachedHistory(items);
    // Restore the per-account status baseline + mark those accounts as already loaded, so connect
    // only refetches accounts whose balance has since changed (usually none) - zero-request restart.
    m_histFetched.clear();
    m_histStatus.clear();
    const QJsonObject status = snap.value(QStringLiteral("status")).toObject();
    for (auto it = status.constBegin(); it != status.constEnd(); ++it) {
        const quint32 idx = it.key().toUInt();
        m_histStatus.insert(idx, it.value().toDouble());
        m_histFetched.insert(idx);
    }
    m_historyLoadedChain = m_chainId; // we already have this chain's history; connect just status-gates
    // A swap that was still open when the app closed comes back from the cache saying "pending", and
    // nothing was left running to ever ask again. The poll starts itself only when an order is
    // placed, so without this the row keeps that status for good - it was true once, and looked true
    // forever. startCowPoll() is a no-op when nothing is pending.
    startCowPoll();
}

// Show 0 immediately for any account we don't yet have a balance for, so a freshly created wallet (or
// a newly derived address) reads "0 <coin>" at once instead of a blank "-" while Tor connects. Only
// the DISPLAY is primed - the raw balance stays "unknown", so the first live refresh can't be
// mistaken for an incoming payment.
// Immediately reflect a just-broadcast send in the displayed balance (native or token) for the
// account it was sent from, so the balance drops at once instead of waiting for the tx to mine. The
// scheduled/per-block refresh then reconciles the exact value (including gas). Marks the account +
// time so a pre-mine refresh reading the still-higher on-chain balance isn't shown as an incoming
// payment.
void AeroMainWindow::applyOptimisticSend(const QString &amount, const QString &tokenAddr) {
    if (!m_wallet) return;
    const double amt = amount.toDouble();
    if (amt <= 0.0) return;
    // Use the account the tx was ACTUALLY sent from (captured at commit), not the live "From" combo -
    // the user may have switched accounts during the async broadcast, which would drop the wrong one.
    const quint32 fromIdx =
        m_committedFrom != 0xFFFFFFFFu
            ? m_committedFrom
            : ((m_fromCombo && m_fromCombo->currentIndex() >= 0)
                   ? static_cast<quint32>(m_fromCombo->currentIndex())
                   : m_account);
    m_lastSendFrom = fromIdx;
    m_lastSendMs = QDateTime::currentMSecsSinceEpoch();

    if (tokenAddr.isEmpty()) {
        // Native send: subtract the amount (gas is small; the refresh corrects it).
        const double nv = qMax(0.0, m_ethRawByAccount.value(fromIdx, 0.0) - amt);
        m_ethRawByAccount.insert(fromIdx, nv);
        const QString disp = tr("%1 %2").arg(formatBalance(nv), m_nativeSymbol);
        m_accountBalances.insert(fromIdx, disp);
        if (m_addressModel)
            m_addressModel->setBalance(fromIdx, addressListBalance(fromIdx));
    } else {
        // Token send: find this account's balance for the token (case-insensitive key match) and drop it.
        const QString prefix = QStringLiteral("%1|").arg(fromIdx);
        const QString addrLc = tokenAddr.toLower();
        for (auto it = m_tokenRawByKey.begin(); it != m_tokenRawByKey.end(); ++it) {
            if (!it.key().startsWith(prefix))
                continue;
            if (!it.key().mid(prefix.size()).toLower().contains(addrLc))
                continue;
            it.value() = qMax(0.0, it.value() - amt);
            break;
        }
    }
    // Refresh the account combos + the bottom-left / Receive balance for the affected account.
    if (m_fromCombo && static_cast<int>(fromIdx) < m_fromCombo->count()) {
        QSignalBlocker b(m_fromCombo);
        m_fromCombo->setItemText(static_cast<int>(fromIdx), accountLabel(fromIdx));
    }
    if (m_swapFrom && static_cast<int>(fromIdx) < m_swapFrom->count()) {
        QSignalBlocker b(m_swapFrom);
        m_swapFrom->setItemText(static_cast<int>(fromIdx), accountLabel(fromIdx));
    }
    if (fromIdx == m_account) {
        showCachedBalance(m_account);
        updateReceive();
    }
    scheduleHomeRecompute();
}

// Instantly drop the SOLD asset from the balance the moment a swap is submitted (like the send
// optimistic drop), so a follow-up swap sees the reduced "Available" and the sold token doesn't
// linger. A clamp (see onAccountBalance/onAvailableBalance) then keeps it dropped until the swap
// actually settles, instead of a pre-settle refresh flickering it back up for ~a minute.
void AeroMainWindow::applyOptimisticSwap() {
    if (!m_wallet)
        return;
    const quint32 fromIdx = m_swapExecFrom;
    const bool sellNative = m_swapExecNative;
    const quint8 dec = sellNative ? 18 : m_swapSellDecimals;
    const double amt = m_swapExecSellAmountWei.toDouble() / std::pow(10.0, dec);
    if (amt <= 0.0)
        return;
    if (sellNative) {
        const double nv = qMax(0.0, m_ethRawByAccount.value(fromIdx, 0.0) - amt);
        m_ethRawByAccount.insert(fromIdx, nv);
        const QString disp = tr("%1 %2").arg(formatBalance(nv), m_nativeSymbol);
        m_accountBalances.insert(fromIdx, disp);
        if (m_addressModel)
            m_addressModel->setBalance(fromIdx, addressListBalance(fromIdx));
        m_swapPendingSellToken.clear();
    } else {
        const QString prefix = QStringLiteral("%1|").arg(fromIdx);
        const QString addrLc = m_swapExecSellAddr.toLower();
        for (auto it = m_tokenRawByKey.begin(); it != m_tokenRawByKey.end(); ++it) {
            if (!it.key().startsWith(prefix))
                continue;
            if (!it.key().mid(prefix.size()).toLower().contains(addrLc))
                continue;
            it.value() = qMax(0.0, it.value() - amt);
            break;
        }
        m_swapPendingSellToken = addrLc;
    }
    // Arm the clamp so a pre-settle balance refresh can't revert the drop (5 min ceiling - CoW
    // auctions/settlement can take a few minutes; on-chain/eth-flow settle much faster).
    m_swapPendingFrom = fromIdx;
    m_swapPendingUntilMs = QDateTime::currentMSecsSinceEpoch() + 5 * 60 * 1000;

    if (m_fromCombo && static_cast<int>(fromIdx) < m_fromCombo->count()) {
        QSignalBlocker b(m_fromCombo);
        m_fromCombo->setItemText(static_cast<int>(fromIdx), accountLabel(fromIdx));
    }
    if (m_swapFrom && static_cast<int>(fromIdx) < m_swapFrom->count()) {
        QSignalBlocker b(m_swapFrom);
        m_swapFrom->setItemText(static_cast<int>(fromIdx), accountLabel(fromIdx));
    }
    if (fromIdx == m_account) {
        showCachedBalance(m_account);
        updateReceive();
    }
    updateSwapAvailable(); // so an immediate follow-up swap sees the reduced available balance
    scheduleHomeRecompute();
}

// Repopulate the Send "Pay to contact" picker from the address book (m_contactsTable). Row 0 is a
// placeholder; the rest carry the contact's address in itemData. Disabled when there are no contacts.
void AeroMainWindow::refreshSendContacts() {
    if (!m_sendContactsCombo)
        return;
    QSignalBlocker b(m_sendContactsCombo);
    m_sendContactsCombo->clear();
    m_sendContactsCombo->addItem(tr("Select a saved contact…"), QString());
    if (m_contactsTable) {
        for (int r = 0; r < m_contactsTable->rowCount(); ++r) {
            const QString name = m_contactsTable->item(r, 0) ? m_contactsTable->item(r, 0)->text() : QString();
            const QString addr = m_contactsTable->item(r, 1) ? m_contactsTable->item(r, 1)->text() : QString();
            if (addr.isEmpty())
                continue;
            const QString label =
                name.isEmpty() ? shortAddr(addr) : tr("%1  ·  %2").arg(name, shortAddr(addr));
            m_sendContactsCombo->addItem(label, addr);
        }
    }
    m_sendContactsCombo->setCurrentIndex(0);
    m_sendContactsCombo->setEnabled(m_sendContactsCombo->count() > 1);
}

void AeroMainWindow::primeZeroBalances() {
    if (!m_wallet) return;
    const QString zero = tr("0 %1").arg(m_nativeSymbol);
    const quint32 n = m_wallet->numAccounts();
    for (quint32 i = 0; i < n; ++i) {
        if (m_accountBalances.contains(i))
            continue;
        m_accountBalances.insert(i, zero);
        if (m_addressModel)
            m_addressModel->setBalance(i, addressListBalance(i));
    }
    showCachedBalance(m_account);
    updateReceive();
}

void AeroMainWindow::saveMetadata() {
    if (!m_wallet) return;
    // Queue the metadata lock-free (never touches the core lock on the UI thread) and defer the
    // encrypt+write. Applying it under the core write lock here would freeze the UI while the funded
    // scan holds that lock - which is exactly the "double-click a label freezes" bug.
    m_wallet->queueMetadata(QString::fromUtf8(QJsonDocument(m_meta).toJson(QJsonDocument::Compact)));
    scheduleSave();
}

// Debounced, non-blocking save. Coalesces a burst of edits (e.g. typing a label) into a single
// off-thread encrypt+atomic-write so the UI never freezes on Argon2id.
void AeroMainWindow::scheduleSave() {
    if (!m_wallet) return;
    if (!m_saveTimer) {
        m_saveTimer = new QTimer(this);
        m_saveTimer->setSingleShot(true);
        m_saveTimer->setInterval(400);
        connect(m_saveTimer, &QTimer::timeout, this, [this]() {
            if (m_wallet) m_wallet->saveAsync();
        });
    }
    m_saveTimer->start(); // (re)start the debounce window
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
    refreshSendContacts(); // populate the Send "Pay to contact" picker for this wallet
    ui.notes->setPlainText(m_meta.value(QStringLiteral("notes")).toString());
    // Per-transaction notes (txHash -> note) into the History model.
    if (m_historyModel) {
        const QJsonObject tn = m_meta.value(QStringLiteral("txnotes")).toObject();
        QHash<QString, QString> notes;
        for (auto it = tn.constBegin(); it != tn.constEnd(); ++it)
            notes.insert(it.key(), it.value().toString());
        m_historyModel->setTxNotes(notes);
    }
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
    // An empty `formatted` means the read FAILED (a genuine zero comes through as "0"); ignore it so
    // a transient Tor/RPC hiccup can't flicker the cached balance to 0 and fire a spurious
    // "payment received" on the next good read.
    if (!token.isEmpty() && !formatted.isEmpty()) {
        // Normalize the token address to lowercase in the key so every reader (Receive breakdown,
        // Home total, Swap "Available") finds it regardless of the casing it looks up with.
        const QString key = QStringLiteral("%1|%2").arg(index).arg(token.toLower());
        const double newBal = formatted.toDouble();
        const double oldBal = m_tokenRawByKey.value(key, -1.0);
        // Same pre-mine clamp as native: while a send of THIS token from this account is confirming,
        // don't let a fetched (pre-mine) balance flicker the optimistic drop back up.
        if (index == m_lastSendFrom && !m_pendingReceiptHash.isEmpty() &&
            token.compare(m_committedTokenAddr, Qt::CaseInsensitive) == 0 && oldBal >= 0.0 &&
            newBal > oldBal + 1e-12)
            return;
        // Same clamp for a pending TOKEN-selling swap: ignore a pre-settle read that would raise this
        // sold token's balance back above the optimistic drop; release once it settles (or expires).
        if (m_swapPendingFrom == index && token.toLower() == m_swapPendingSellToken) {
            if (QDateTime::currentMSecsSinceEpoch() < m_swapPendingUntilMs) {
                if (oldBal >= 0.0 && newBal > oldBal + 1e-12)
                    return;
            }
            m_swapPendingFrom = 0xFFFFFFFFu; // settled or expired
        }
        m_tokenRawByKey.insert(key, newBal);
        // Instant red for a positive balance; the full/authoritative recompute is debounced so a
        // bulk refresh of hundreds of accounts doesn't run recomputeHomeTotal thousands of times.
        if (newBal > 0.0 && m_addressModel)
            m_addressModel->setUsed(index, true);
        scheduleHomeRecompute();
        // Any change (incoming or outgoing) means a new tx touched this address -> refresh history.
        // The account has to be marked dirty as well, not just the "something moved" flag: only the
        // dirty set actually drives a refetch, and receiving an ERC-20 does not move the native
        // balance, so a plain incoming USDC transfer left History showing nothing new until some
        // later, unrelated native transaction happened to touch the same account. On chains where
        // tokens are most of the activity this is nearly every receipt.
        if (oldBal >= 0.0 && qAbs(newBal - oldBal) > 1e-9) {
            m_balancesChanged = true;
            m_dirtyHistory.insert(index);
        }
        // No "Payment received" notification here: it now hangs off HistoryModel::incomingPayment,
        // which fires only for transfers the spam filter kept. Driving it from a raw balance increase
        // could not see the sender, so a look-alike poisoning transfer of a verified token would slip
        // past even the dust check. The balance change still marks history dirty (above), so the row
        // is fetched, classified, and - if genuine - announced from there.
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
    updateAvailableLabel();
}

// Show the Send "Available" balance in the token, or in USD when the amount unit toggle is set to
// USD (ETH/WETH), so it matches what the user is typing amounts in.
void AeroMainWindow::updateAvailableLabel() {
    if (!m_availLabel)
        return;
    if (m_availAmount.isEmpty()) {
        m_availLabel->setText(tr("-"));
        return;
    }
    const QString sym = currentSymbol();
    const double amt = m_availAmount.toDouble();
    const bool inUsd =
        m_amountUnit && m_amountUnit->isVisible() &&
        m_amountUnit->currentText().compare(QStringLiteral("USD"), Qt::CaseInsensitive) == 0;
    const double price = unitPriceUsd(sym);
    if (inUsd && price > 0.0)
        m_availLabel->setText(fiatStr(amt * price));
    else
        m_availLabel->setText(tr("%1 %2").arg(formatBalance(amt), sym));
}

// Build an account row label with a caller-supplied balance string (so callers that already have the
// account's USD value can avoid recomputing it).
// Just the account's name, with no address or balance attached: what the History table shows, and
// the first part of the longer label the account selectors show.
QString AeroMainWindow::accountName(quint32 index) const {
    if (m_addressModel) {
        const QString custom = m_addressModel->labelAt(index);
        if (!custom.isEmpty())
            return custom;
    }
    // An imported key is not the seed's account #index - showing it as "Account #index" makes it look
    // like one of the derived accounts, when it shares nothing with them. Name it by its own imported
    // ordinal so it reads as what it is. A user-set label (above) still wins.
    if (m_wallet) {
        const int imp = m_wallet->accountImportedOrdinal(index);
        if (imp >= 0)
            return tr("Imported #%1").arg(imp + 1);
    }
    return tr("Account #%1").arg(index);
}

// Hand the History table the name of every account, so its Account column can say "Savings" rather
// than the index it stores.
void AeroMainWindow::pushAccountNames() {
    if (!m_historyModel || !m_wallet)
        return;
    QHash<quint32, QString> names;
    QHash<quint32, QString> importedNames;
    const quint32 n = m_wallet->numAccounts();
    for (quint32 i = 0; i < n; ++i) {
        names.insert(i, accountName(i));
        const int imp = m_wallet->accountImportedOrdinal(i);
        if (imp >= 0)
            importedNames.insert(i, tr("Imported #%1").arg(imp + 1));
    }
    m_historyModel->setAccountNames(names);
    if (m_addressModel)
        m_addressModel->setImportedNames(importedNames);
}

QString AeroMainWindow::accountLabelWith(quint32 index, const QString &balanceStr) const {
    // Use the address's Receive label if the user has set one; otherwise "Account #i".
    const QString name = accountName(index);
    QString label = tr("%1  ·  %2").arg(name, shortAddr(m_wallet->address(index)));
    if (!balanceStr.isEmpty())
        label += QStringLiteral("  ·  %1").arg(balanceStr);
    return label;
}

QString AeroMainWindow::accountLabel(quint32 index) const {
    // Match the Receive USD toggle: show the account's FULL value in USD (native + tokens) when it's
    // on, otherwise the cached native-coin balance string. Until an account's balance has actually
    // loaded, show no balance suffix (rather than a misleading "$0.00").
    const bool known = m_ethRawByAccount.contains(index) || m_accountBalances.contains(index);
    if (m_recvUsd && m_nativeUsd > 0.0)
        return accountLabelWith(index, known ? fiatStr(accountUsdValue(index)) : QString());
    return accountLabelWith(index, m_accountBalances.value(index));
}

// Re-label the Send/Swap "From" combos from accountLabel() (respecting the USD toggle). Skips a combo
// whose dropdown is open so it never disturbs an in-progress search.
void AeroMainWindow::refreshAccountCombosText() {
    auto upd = [this](QComboBox *c) {
        if (!c || (c->view() && c->view()->isVisible()))
            return;
        QSignalBlocker b(c);
        const int n = c->count();
        for (int i = 0; i < n; ++i)
            c->setItemText(i, accountLabel(static_cast<quint32>(i)));
    };
    upd(m_fromCombo);
    upd(m_swapFrom);
}

void AeroMainWindow::rebuildAccountCombos() {
    if (!m_wallet) return;
    const quint32 n = m_wallet->numAccounts();
    // GUARD AGAINST THE UI FREEZE: accountLabel() below reads m_wallet->address(i) for EVERY account.
    // If those addresses aren't cached yet (fresh open, or right after a funded scan invalidated the
    // cache), each read re-derives an HD key under the core lock - with hundreds of accounts that is a
    // multi-second stall on the UI thread (the "create address freezes" bug). Instead, warm the whole
    // range off-thread; warmAddresses() emits addressesWarmed -> rebuildAccountCombos(), which then
    // finds the cache hot and builds instantly. We still refresh the address model now so the Receive
    // list (which derives lazily per visible row) updates immediately.
    if (n > 0 && !m_wallet->addressesCached(n)) {
        if (m_addressModel)
            m_addressModel->refresh();
        m_wallet->warmAddresses(n);
        // The Account column's names don't need warmed addresses (just labels + index), so push them
        // now rather than leaving the History view showing "Account #n" until warming completes.
        pushAccountNames();
        return;
    }
    // Send's "From" selector lists every address. The full address goes into Qt::UserRole so the
    // searchable dropdown (SearchableComboBox) can match on it even though the row shows a short form.
    if (m_fromCombo) {
        QSignalBlocker block(m_fromCombo);
        const int prev = m_fromCombo->currentIndex();
        m_fromCombo->clear();
        for (quint32 i = 0; i < n; ++i) {
            m_fromCombo->addItem(tokenIcon(m_nativeSymbol), accountLabel(i));
            m_fromCombo->setItemData(static_cast<int>(i), m_wallet->address(i)); // full addr, searchable
        }
        m_fromCombo->setCurrentIndex(prev >= 0 && prev < static_cast<int>(n) ? prev : 0);
    }
    // Swap's "From" selector mirrors the Send one (searchable, full address in UserRole).
    if (m_swapFrom) {
        QSignalBlocker block(m_swapFrom);
        const int prev = m_swapFrom->currentIndex();
        m_swapFrom->clear();
        for (quint32 i = 0; i < n; ++i) {
            m_swapFrom->addItem(tokenIcon(m_nativeSymbol), accountLabel(i));
            m_swapFrom->setItemData(static_cast<int>(i), m_wallet->address(i));
        }
        m_swapFrom->setCurrentIndex(prev >= 0 && prev < static_cast<int>(n) ? prev : 0);
    }
    if (m_addressModel)
        m_addressModel->refresh();
    rebuildHistoryCombo();
    updateHistoryOwnAddresses(); // addresses are hot here - refresh the poisoning look-alike index
}

// Feed the wallet's own receive addresses to the history model so it can flag vanity look-alike
// address-poisoning. Only runs when the address cache is already hot, so it never derives HD keys on
// the UI thread (see the freeze note in rebuildAccountCombos).
void AeroMainWindow::updateHistoryOwnAddresses() {
    if (!m_wallet || !m_historyModel)
        return;
    const quint32 n = m_wallet->numAccounts();
    if (n == 0 || !m_wallet->addressesCached(n))
        return;
    QSet<QString> addrs;
    addrs.reserve(static_cast<int>(n));
    for (quint32 i = 0; i < n; ++i)
        addrs.insert(m_wallet->address(i).toLower());
    m_historyModel->setOwnAddresses(addrs);
}

void AeroMainWindow::rebuildHistoryCombo() {
    if (!m_historyCombo || !m_wallet)
        return;
    QSignalBlocker block(m_historyCombo);
    m_historyCombo->clear();
    m_historyCombo->addItem(tr("All accounts"));
    const quint32 n = m_wallet->numAccounts();
    for (quint32 i = 0; i < n; ++i) {
        m_historyCombo->addItem(tokenIcon(m_nativeSymbol), accountLabel(i));
        m_historyCombo->setItemData(static_cast<int>(i) + 1, m_wallet->address(i)); // full addr, searchable
    }
    int want = (m_historyFilter < 0) ? 0 : (m_historyFilter + 1);
    if (want >= m_historyCombo->count())
        want = 0;
    m_historyCombo->setCurrentIndex(want);
    // Rebuilt whenever the account list changes, which is exactly when the Account column needs to
    // learn about a new account.
    pushAccountNames();
    if (m_historyView)
        m_historyView->setColumnHidden(HistoryModel::Column_Account, m_historyFilter >= 0);
}

// Full (re)load of the History view. Feather/Electrum model: do NOT fan out a fetch across every
// (mostly empty) account - clear once, then fetch only the account being viewed plus the known
// funded accounts (targeted + deduped). Empty accounts have no history, so this drops the request
// storm without losing any transactions. Steady-state refresh is handled by refreshDirtyHistory().
void AeroMainWindow::refreshHistoryView() {
    if (!m_wallet)
        return;
    if (m_historyFilter >= 0) {
        m_wallet->refreshHistory(static_cast<quint32>(m_historyFilter)); // single-account filter view
        return;
    }
    if (m_historyModel)
        m_historyModel->beginFullRefresh(); // clear + reset dedup once
    m_histFetched.clear();
    m_dirtyHistory.clear();
    ensureAccountHistory(m_account);        // the account on screen, first
    ensureFundedAndLabeledHistory();        // then every funded OR labelled account
}

// Load history for every funded account and every account the user has given a label. Funded
// accounts carry the balance-bearing activity, but an account that only ever held a token (no native
// balance) - or one the user named and cares about - is not in the funded set, and fetching only
// funded left its rows, and its Account label, missing from the All-accounts view. Labels are
// user-curated and few, so this stays targeted rather than fanning out across every derived (mostly
// empty) HD account. Deduped by m_histFetched, so accounts already loaded (incl. from cache) are not
// refetched, making this a one-time cost per account and free in steady state.
void AeroMainWindow::ensureFundedAndLabeledHistory() {
    if (!m_wallet)
        return;
    QSet<quint32> want = m_fundedAccounts;
    const quint32 n = m_wallet->numAccounts();
    for (quint32 i = 0; i < n; ++i)
        if (m_addressModel && !m_addressModel->labelAt(i).isEmpty())
            want.insert(i);
    for (quint32 i : want)
        ensureAccountHistory(i);
}

// Fetch one account's history on demand (lazy). Marks it fetched up front so overlapping triggers
// (connect + selection + a balance change) never queue duplicate requests for the same account.
void AeroMainWindow::ensureAccountHistory(quint32 index, bool force) {
    if (!m_wallet)
        return;
    if (!force && m_histFetched.contains(index))
        return;
    m_histFetched.insert(index);
    m_wallet->refreshAccountHistory(index);
}

// Per-block refresh: refetch ONLY the accounts whose balance changed since last time (the ETH analog
// of Electrum's scripthash-status gate). Usually that's zero accounts, so a new block costs nothing.
void AeroMainWindow::refreshDirtyHistory() {
    if (!m_wallet || m_dirtyHistory.isEmpty())
        return;
    const QSet<quint32> dirty = m_dirtyHistory;
    m_dirtyHistory.clear();
    if (m_historyFilter >= 0) {
        // A single-account filtered view is served by refreshHistory()/onHistoryRefreshed(), not the
        // per-account merge - so refetch it directly when THAT account changes (otherwise a filtered
        // view never updates on new blocks).
        if (dirty.contains(static_cast<quint32>(m_historyFilter)))
            m_wallet->refreshHistory(static_cast<quint32>(m_historyFilter));
        return;
    }
    for (quint32 i : dirty)
        ensureAccountHistory(i, /*force*/ true);
}

// A targeted single-account history batch arrived: merge it into the (deduped) all-accounts model.
void AeroMainWindow::onAccountHistoryReady(quint32 index, const QVector<HistoryItem> &items,
                                           quint64 chainId) {
    if (chainId != m_chainId)
        return; // a previous chain's targeted fetch that landed after a network switch - drop it
    if (m_historyFilter >= 0)
        return; // a single-account filter view is driven by refreshHistory()/onHistoryRefreshed()
    if (!m_historyModel)
        return;
    m_historyModel->appendBatch(items);
    requestHistoricalPrices(items);      // value the new rows at their historical price
    checkUntrackedTokenLiquidity();      // auto-trust liquid tokens that just appeared
    // Record the balance at which we now hold this account's history, so a later change is detected
    // (across restarts too), and persist the updated cache.
    m_histStatus.insert(index, m_ethRawByAccount.value(index, m_histStatus.value(index, 0.0)));
    scheduleHistorySave();
}

void AeroMainWindow::onAccountBalance(quint32 index, const QString &formatted, const QString &symbol) {
    if (formatted.isEmpty()) return; // offline / no balance yet - don't append an empty suffix
    const double newBal = formatted.toDouble();
    const double oldBal = m_ethRawByAccount.value(index, -1.0);
    // While a send from this account is still confirming, ignore a fetched balance that's HIGHER than
    // our optimistic (reduced) value - that's the pre-mine balance and would flicker the number back
    // up. We accept it once the tx mines (the value drops below the optimistic figure).
    if (index == m_lastSendFrom && !m_pendingReceiptHash.isEmpty() && oldBal >= 0.0 &&
        newBal > oldBal + 1e-12)
        return;
    // Same clamp for a pending NATIVE-selling swap: ignore a pre-settle read that would raise the
    // balance back above the optimistic drop; release the clamp once it genuinely settles (or expires).
    if (m_swapPendingFrom == index && m_swapPendingSellToken.isEmpty()) {
        if (QDateTime::currentMSecsSinceEpoch() < m_swapPendingUntilMs) {
            if (oldBal >= 0.0 && newBal > oldBal + 1e-12)
                return;
        }
        m_swapPendingFrom = 0xFFFFFFFFu; // settled or expired
    }
    m_ethRawByAccount.insert(index, newBal); // raw, for the combined total
    // Instant red for a positive balance; full recompute is debounced (see scheduleHomeRecompute).
    if (newBal > 0.0 && m_addressModel)
        m_addressModel->setUsed(index, true);
    scheduleHomeRecompute();
    // Any change (incoming or outgoing) means a new tx touched this address -> refresh just this
    // account's history (targeted), not the whole wallet's.
    if (oldBal >= 0.0 && qAbs(newBal - oldBal) > 1e-12) {
        m_balancesChanged = true;
        m_dirtyHistory.insert(index);
    }
    // Cross-restart status gate (Electrum's scripthash-status equivalent): if this account's balance
    // differs from what it was when we cached its history, it saw activity while we were away -
    // refetch just this account. If it matches, we keep the cached history with zero requests.
    if (m_histStatus.contains(index) && qAbs(newBal - m_histStatus.value(index)) > 1e-9)
        m_dirtyHistory.insert(index);
    // No "Payment received" notification from the balance delta any more - it is driven by
    // HistoryModel::incomingPayment, which only fires for a transfer the spam filter kept (so dust
    // and look-alike poisoning can't announce themselves). The delta above still marks the account
    // dirty, so the incoming transfer is fetched and, if genuine, announced from History.
    const QString display = tr("%1 %2").arg(formatBalance(formatted), symbol);
    m_accountBalances.insert(index, display);
    if (m_addressModel)
        m_addressModel->setBalance(index, addressListBalance(index));
    if (m_fromCombo && static_cast<int>(index) < m_fromCombo->count()) {
        QSignalBlocker block(m_fromCombo);
        m_fromCombo->setItemText(static_cast<int>(index), accountLabel(index));
    }
    // Same for the Swap tab's "From account" selector, so its dropdown shows balances too.
    if (m_swapFrom && static_cast<int>(index) < m_swapFrom->count()) {
        QSignalBlocker block(m_swapFrom);
        m_swapFrom->setItemText(static_cast<int>(index), accountLabel(index));
    }
    if (index == m_account) {
        showCachedBalance(m_account); // bottom-left status balance (native + tokens), from the batch
        updateReceive();              // refresh the balance shown under the QR
    }
}

// Balance of a token, named by ticker, on the chain that is currently connected. Returns -1 when it
// cannot be determined, which callers must treat as "unknown" rather than "zero".
//
// The distinction matters because a ticker does not identify a contract. The wallet's tracked-token
// list is chain-agnostic and seeded with Ethereum addresses, so looking up "USDC" in it while
// connected to Arbitrum finds the mainnet contract, whose balance on Arbitrum was never fetched and
// so reads as zero. That is what made bridging USDC off any L2 refuse to send with "exceeds your
// USDC balance of 0". The curated list is per-chain and does identify the right contract, so it is
// consulted first; if the balance for that contract has not come back yet, the answer is unknown.
double AeroMainWindow::tokenBalanceOnThisChain(quint32 account, const QString &symbol) const {
    auto lookup = [&](const QString &addr) {
        return m_tokenRawByKey.value(QStringLiteral("%1|%2").arg(account).arg(addr.toLower()), -1.0);
    };
    for (const TokenInfo &t : curatedTopTokens(m_chainId))
        if (t.symbol.compare(symbol, Qt::CaseInsensitive) == 0)
            return lookup(t.address);
    const ChainDef cd = chainDefFor(m_chainId);
    if (!cd.wrappedNative.isEmpty() &&
        symbol.compare(QStringLiteral("W%1").arg(m_nativeSymbol), Qt::CaseInsensitive) == 0)
        return lookup(cd.wrappedNative);
    // Only fall back to a tracked token when its address is one this chain actually uses.
    if (m_wallet) {
        for (const TokenInfo &t : m_wallet->tokens()) {
            if (t.symbol.compare(symbol, Qt::CaseInsensitive) != 0)
                continue;
            const double bal = lookup(t.address);
            if (bal >= 0.0)
                return bal;
        }
    }
    return -1.0;
}

// Total USD value of an account: native coin + every tracked/curated token it holds. Mirrors the
// per-account slice of recomputeHomeTotal so a single-account update shows the full value at once.
double AeroMainWindow::accountUsdValue(quint32 index) const {
    double total = m_ethRawByAccount.value(index, 0.0) * m_nativeUsd;
    if (!m_tokenRawByKey.isEmpty()) {
        QHash<QString, QString> symByAddr;
        if (m_wallet)
            for (const TokenInfo &t : m_wallet->tokens())
                symByAddr.insert(t.address.toLower(), t.symbol);
        for (const TokenInfo &t : curatedTopTokens(m_chainId))
            symByAddr.insert(t.address.toLower(), t.symbol);
        const QString prefix = QStringLiteral("%1|").arg(index);
        for (auto it = m_tokenRawByKey.constBegin(); it != m_tokenRawByKey.constEnd(); ++it) {
            if (!it.key().startsWith(prefix))
                continue;
            const QString addr = it.key().section(QLatin1Char('|'), 1).toLower();
            total += it.value() * unitPriceUsd(symByAddr.value(addr));
        }
    }
    return total;
}

// The Balance shown in the Receive address list for one account: native coin by default, or the
// account's FULL value in USD (native + all tokens) when the "Show values in USD" toggle is on
// (falling back to the native string until a native price is known).
QString AeroMainWindow::addressListBalance(quint32 index) const {
    if (m_recvUsd && m_nativeUsd > 0.0)
        return fiatStr(accountUsdValue(index));
    return m_accountBalances.value(index);
}

// Re-format the address-list Balance cells (e.g. when the USD toggle flips). In USD mode the full
// per-account totals are computed in one efficient pass by recomputeHomeTotal; in native mode we
// just restore the cached native strings.
void AeroMainWindow::refreshAddressBalancesDisplay() {
    if (!m_addressModel)
        return;
    if (m_recvUsd) {
        recomputeHomeTotal(); // one O(N + tokenKeys) pass: sets each account's full USD value + combos
        return;
    }
    for (auto it = m_accountBalances.constBegin(); it != m_accountBalances.constEnd(); ++it)
        m_addressModel->setBalance(it.key(), it.value());
    refreshAccountCombosText(); // back to native-coin labels in the From combos
}

void AeroMainWindow::updateReceive() {
    if (!m_wallet) return;
    const QString addr = m_wallet->address(m_account);
    const QPixmap qr = renderQr(addr);
    recvUi.qrCode->setPixmap(qr);
    recvUi.qrCode->setFixedSize(qr.size());
    recvUi.qrCode->setToolTip(tr("Click to copy"));

    // Full per-address balance: native coin + every tracked token, each with its logo. When the USD
    // toggle is on we show each asset's fiat value (falling back to units when no price is known, e.g.
    // an untracked token) plus a combined per-address USD total so the address value is obvious.
    const bool usd = m_recvUsd;
    double addrUsdTotal = 0.0;
    auto row = [&](const QString &iconPath, const QString &symbol, double balance) {
        QString valueText;
        if (usd) {
            const double price = unitPriceUsd(symbol);
            if (price > 0.0) {
                addrUsdTotal += balance * price;
                valueText = fiatStr(balance * price);
            } else {
                valueText = formatBalance(balance) + QStringLiteral(" ") + symbol; // no price: show units
            }
        } else {
            valueText = formatBalance(balance) + QStringLiteral(" ") + symbol;
        }
        return QStringLiteral(
                   "<tr><td><img src='%2' width='16' height='16'></td>"
                   "<td>&nbsp;%1</td></tr>")
            .arg(valueText.toHtmlEscaped(), iconPath);
    };
    QString html = QStringLiteral("<div align='center'>%1<br><br><table align='center' cellspacing='2'>")
                       .arg(addr.toHtmlEscaped());
    // Always show the native coin; only show a token if this address actually holds some of it, so
    // the breakdown stays clean (ETH by default, other assets appear as they arrive).
    html += row(chainDefFor(m_chainId).icon, m_nativeSymbol,
                m_ethRawByAccount.value(m_account, 0.0));
    // Hide sub-cent priced token dust (e.g. a fraction of WETH worth $0.00) so it doesn't clutter the
    // breakdown with a duplicate-looking $0.00 row. Tokens with no known price are still shown (we
    // can't judge their value).
    const double dustUsd = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                               .value(QStringLiteral("history/dustUsd"), 0.005).toDouble();
    // Tracked tokens plus the curated tokens for THIS chain, deduped by address. Tracked tokens are
    // stored as their Ethereum-mainnet contracts, so on an L2 like Arbitrum they read as zero and
    // fall away below; the curated per-chain list is what carries native USDC (0xaf88…) and the rest,
    // which the balance refresh already fetches. Without this, Arbitrum USDC is fetched but never
    // shown here, which is exactly "my USDC won't appear in Receive".
    QVector<TokenInfo> shown = m_wallet->tokens();
    QSet<QString> seen;
    for (const TokenInfo &t : shown)
        seen.insert(t.address.toLower());
    for (const TokenInfo &t : curatedTopTokens(m_chainId))
        if (!seen.contains(t.address.toLower())) {
            shown.append(t);
            seen.insert(t.address.toLower());
        }
    for (const TokenInfo &t : shown) {
        const double bal =
            m_tokenRawByKey.value(QStringLiteral("%1|%2").arg(m_account).arg(t.address.toLower()), 0.0);
        if (bal <= 0.0)
            continue;
        const double price = unitPriceUsd(t.symbol);
        if (price > 0.0 && bal * price < dustUsd)
            continue; // sub-cent dust - skip
        html += row(QStringLiteral(":/assets/images/tokens/%1.png").arg(t.symbol), t.symbol, bal);
    }
    html += QStringLiteral("</table>");
    if (usd)
        html += QStringLiteral("<br><b>%1</b>").arg(tr("This address: %1").arg(fiatStr(addrUsdTotal)));
    html += QStringLiteral("</div>");

    m_recvBalanceLabel->setTextFormat(Qt::RichText);
    m_recvBalanceLabel->setText(html);
}

void AeroMainWindow::fetchCuratedForCurrentAccount() {
    if (!m_wallet)
        return;
    // Small wallets already read the curated tokens in the batched refresh (see refreshAllBalances),
    // so only large wallets - where the batch skips them to stay under the RPC budget - need this.
    // Scoped to the one selected account, so it is a handful of reads, not curated×accounts.
    if (m_wallet->numAccounts() <= 8)
        return;
    for (const TokenInfo &t : curatedTopTokens(m_chainId))
        m_wallet->fetchAvailable(m_account, t.address);
}

void AeroMainWindow::onAccountChanged(int index) {
    if (index < 0 || !m_wallet) return;
    m_account = static_cast<quint32>(index);
    // Remember this account (per-wallet) so the next open reopens here, not at #0.
    QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
        .setValue(selectedAccountKey(m_wallet->walletPath()), m_account);
    showCachedBalance(m_account); // instant bottom-left balance from cache (Feather-style)
    updateReceive();
    fetchCuratedForCurrentAccount(); // top up this account's curated tokens (e.g. USDC) on big wallets
    // History follows the selected account ONLY when a single-account filter is already active. If the
    // user is on "All accounts" (m_historyFilter < 0) we leave it - so "All" is never silently
    // overridden just by clicking around the Receive list (previously it snapped on every tab open).
    if (m_historyCombo && m_historyFilter >= 0) {
        const int comboIdx = index + 1;
        if (comboIdx < m_historyCombo->count() && m_historyCombo->currentIndex() != comboIdx)
            m_historyCombo->setCurrentIndex(comboIdx); // triggers the filtered refresh
    }
    // Switching accounts must be cheap: balances are already kept fresh per-block for every account,
    // and prices/fees are wallet-wide - so DON'T re-run the whole onRefresh() storm here. Just make
    // sure this account's history is loaded (lazy, once) and refresh its per-account NFTs.
    ensureAccountHistory(m_account);
    refreshNfts();
    // Orders, balances and redemptions all belong to one address, so the trading tab follows the
    // selected account rather than keeping the one it was opened with.
    if (m_xmrTab && m_wallet)
        m_xmrTab->setWallet(m_wallet, m_account, m_wallet->address(m_account));
}

// Populate the bottom-left balance label from already-fetched data so switching addresses is
// instant; the async refresh in onRefresh() then updates it with fresh numbers.
void AeroMainWindow::showCachedBalance(quint32 index) {
    if (!m_balanceLabel || !m_accountBalances.contains(index))
        return; // nothing cached yet - leave the current text until the refresh arrives
    if (m_hideBalances) {
        m_balanceLabel->setText(tr("Balance: hidden"));
        return;
    }
    QString status = tr("Balance: %1").arg(m_accountBalances.value(index));
    double totalUsd = m_ethRawByAccount.value(index, 0.0) * unitPriceUsd(m_nativeSymbol);
    if (m_wallet) {
        // Tracked tokens plus this chain's curated tokens, deduped - so an L2 asset like Arbitrum
        // USDC (held under its per-chain address, not the mainnet one the tracked list stores)
        // counts towards the balance shown here, matching the Receive breakdown and Home total.
        QSet<QString> counted;
        auto add = [&](const TokenInfo &t) {
            const QString addr = t.address.toLower();
            if (counted.contains(addr))
                return;
            counted.insert(addr);
            totalUsd += m_tokenRawByKey.value(QStringLiteral("%1|%2").arg(index).arg(addr), 0.0) *
                        unitPriceUsd(t.symbol);
        };
        for (const TokenInfo &t : m_wallet->tokens())
            add(t);
        for (const TokenInfo &t : curatedTopTokens(m_chainId))
            add(t);
    }
    if (totalUsd > 0)
        status += tr("   \u2248 %1").arg(fiatStr(totalUsd));
    m_balanceLabel->setText(status);
}

void AeroMainWindow::ensureMinAddresses(quint32 count) {
    if (!m_wallet) return;
    // Hardware wallets derive their accounts up front (via the device at create time), and
    // watch-only wallets have no keys to derive from - never fabricate extra HD entries for either.
    if (m_wallet->isHardware() || m_wallet->isWatchOnly()) return;
    while (m_wallet->numAccounts() < count)
        m_wallet->addAccount();
}

void AeroMainWindow::applyReceiveSearch() {
    if (!m_wallet || !m_addressModel)
        return;
    const QString needle = recvUi.search ? recvUi.search->text().trimmed() : QString();
    const int rows = m_addressModel->rowCount();
    for (int r = 0; r < rows; ++r) {
        const quint32 acct = m_addressModel->accountAt(r);
        const bool match = needle.isEmpty() ||
                           m_wallet->address(acct).contains(needle, Qt::CaseInsensitive) ||
                           m_addressModel->labelAt(acct).contains(needle, Qt::CaseInsensitive);
        recvUi.addresses->setRowHidden(r, QModelIndex(), !match);
    }
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
                                 tr("A watch-only wallet can't derive new addresses - it only "
                                    "tracks the addresses you added."));
        return;
    }
    if (m_wallet->isHardware()) {
        // Derive the next address from the device off the UI thread - a slow/unresponsive device
        // would otherwise freeze the app for the whole USB timeout.
        quint32 idx = 0xFFFFFFFFu;
        runBusy(tr("Confirm on your device…"), [&]() { idx = m_wallet->addHardwareAccount(); });
        if (idx == 0xFFFFFFFFu) {
            QMessageBox::warning(this, tr("Create address"),
                                 tr("Couldn't derive an address from the device:\n%1")
                                     .arg(m_wallet->errorString()));
            return;
        }
        onAccountAdded(idx);
        return;
    }
    // Software wallet: derive off the UI thread (onAccountAdded fires when done). This can't freeze
    // even if the funded scan currently holds the core lock - the derivation just waits on the pool.
    m_wallet->addAccountAsync();
}

// Finish creating an address once the (possibly off-thread) derivation completes.
void AeroMainWindow::onAccountAdded(quint32 idx) {
    m_account = idx;
    // Persist the new account NOW, not on the 400 ms debounce: a new HD account is a deliberate,
    // one-off action the user expects to survive an immediate close/kill. saveAsync() runs the
    // encrypt+write off the UI thread, so this is durable within ~a second without any freeze.
    m_wallet->saveAsync();
    rebuildAccountCombos();
    selectAddressRow(idx);
    // A freshly derived address has no funds and no history: show 0 immediately, then fetch just its
    // balance + history (targeted) rather than re-running the whole-wallet refresh storm.
    const QString zero = tr("0 %1").arg(m_nativeSymbol);
    m_accountBalances.insert(idx, zero);
    if (m_addressModel)
        m_addressModel->setBalance(idx, addressListBalance(idx));
    updateReceive();
    showCachedBalance(idx);
    m_wallet->refreshAccountBalance(idx); // 1 request: confirm the new account's native balance
    ensureAccountHistory(idx);            // and its (usually empty) history
    refreshNfts();
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

    // importPrivateKey takes the core WRITE lock (stalls behind a running scan) and save() runs
    // Argon2id - do both off the UI thread behind a busy dialog so the app never freezes.
    const QString hexKey = key.trimmed();
    quint32 idx = 0xFFFFFFFFu;
    bool saved = true;
    const bool hasPath = !m_wallet->walletPath().isEmpty();
    runBusy(tr("Importing key…"), [&]() {
        idx = m_wallet->importPrivateKey(hexKey);
        if (idx != 0xFFFFFFFFu && hasPath)
            saved = m_wallet->save();
    });
    if (idx == 0xFFFFFFFFu) {
        QMessageBox::warning(this, tr("Import failed"), m_wallet->errorString());
        return;
    }
    // Imported keys are the ONLY funds not recoverable from the seed, so persistence must succeed.
    // If the save fails, tell the user loudly (and keep the key on screen so they can retry/back it
    // up) instead of silently losing it on the next close.
    if (!hasPath) {
        QMessageBox::warning(
            this, tr("Not saved"),
            tr("The key was imported but this wallet isn't saved to a file, so it will be lost when "
               "you close. Save the wallet first, then re-import."));
    } else if (!saved) {
        QMessageBox::critical(
            this, tr("Import not saved"),
            tr("The private key was imported but could NOT be written to your wallet file:\n\n%1\n\n"
               "This key is NOT recoverable from your seed. Do not close the wallet - back up the "
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

    // Export private key - warn before revealing.
    if (QMessageBox::warning(
            this, tr("Export private key"),
            tr("Anyone with this private key can spend everything at address #%1.\n"
               "Never share it. Reveal it now?").arg(row),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;

    QString key;
    runBusy(tr("Exporting key…"), [&]() { key = m_wallet->exportPrivateKey(row); });
    if (key.isEmpty()) {
        QMessageBox::warning(this, tr("Export failed"), m_wallet->errorString());
        return;
    }

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Private key - address #%1").arg(row));
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

    // Where transaction history is read from. Separate from the link base above, because that one
    // only decides which website a transaction opens in. Aero ships keyless explorers for most
    // networks and moves on when one stops answering, but they are free services that can tighten
    // their limits or disappear - so this is the way to point history somewhere else without waiting
    // for a new build.
    auto *historyEdit = new QLineEdit(nodeTab);
    historyEdit->setText(QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                             .value(QStringLiteral("node/%1/historyApi").arg(m_chainId))
                             .toString());
    historyEdit->setPlaceholderText(tr("built-in explorers"));
    historyEdit->setToolTip(
        tr("Comma-separated, tried in order before the built-in ones. Any Etherscan-compatible\n"
           "API works: a Blockscout host such as https://eth.blockscout.com, or a URL carrying\n"
           "your own key such as\n"
           "https://api.etherscan.io/v2/api?chainid=%1&apikey=YOURKEY\n"
           "which covers every network Aero supports, including ones with no keyless explorer.\n"
           "Leave blank to use the built-in list.")
            .arg(m_chainId));
    nodeForm->addRow(tr("History API (optional)"), historyEdit);
    tabs->addTab(nodeTab, tr("Node"));

    // --- Tor tab: live status + controls (Reconnect / New circuit) + external-Tor option ---
    QCheckBox *torExternalChk = nullptr;
    QLineEdit *torSocksEdit = nullptr;
    {
        auto *torTab = new QWidget(&dlg);
        auto *torLay = new QVBoxLayout(torTab);
        const QString torState = m_connText.isEmpty()
                                     ? (m_connLabel ? m_connLabel->text() : tr("Offline"))
                                     : m_connText;
        torLay->addWidget(new QLabel(tr("Status: %1").arg(torState), torTab));
        torLay->addWidget(new QLabel(tr("SOCKS proxy in use: %1").arg(socksFor(m_chainId)), torTab));

        QSettings ts(QStringLiteral("Aero"), QStringLiteral("Aero"));
        torExternalChk = new QCheckBox(
            tr("Use an external Tor instead of the bundled one (share Feather / Tor Browser / system Tor)"),
            torTab);
        torExternalChk->setChecked(ts.value(QStringLiteral("tor/external"), false).toBool());
        torLay->addWidget(torExternalChk);

        auto *socksRow = new QHBoxLayout();
        socksRow->addWidget(new QLabel(tr("External SOCKS:"), torTab));
        torSocksEdit = new QLineEdit(
            ts.value(QStringLiteral("tor/socks"), QStringLiteral("127.0.0.1:9050")).toString(), torTab);
        torSocksEdit->setPlaceholderText(QStringLiteral("127.0.0.1:9050"));
        torSocksEdit->setEnabled(torExternalChk->isChecked());
        connect(torExternalChk, &QCheckBox::toggled, torSocksEdit, &QLineEdit::setEnabled);
        socksRow->addWidget(torSocksEdit, 1);
        torLay->addLayout(socksRow);

        auto *torInfo = new QLabel(
            tr("By default Aero runs its own bundled Tor (no clearnet fallback) and reconnects "
               "automatically. A Tor SOCKS proxy is app-agnostic, so you can instead point Aero at "
               "another running Tor and share one instance:\n"
               "  \u2022 system Tor / Feather's Tor: usually 127.0.0.1:9050\n"
               "  \u2022 Tor Browser: 127.0.0.1:9150\n"
               "When enabled, Aero won't launch its own tor.exe. (Per-network overrides in the Node "
               "tab still win.)"),
            torTab);
        torInfo->setWordWrap(true);
        torInfo->setStyleSheet(QStringLiteral("color:#8a8a8a;"));
        torLay->addWidget(torInfo);

        auto *btnRow = new QHBoxLayout();
        auto *reconnectBtn = new QPushButton(tr("Reconnect"), torTab);
        auto *newCircuitBtn = new QPushButton(tr("New Tor circuit"), torTab);
        connect(reconnectBtn, &QPushButton::clicked, &dlg,
                [this]() { reconnectTor(tr("settings")); });
        connect(newCircuitBtn, &QPushButton::clicked, &dlg, [this]() { newTorCircuit(); });
        btnRow->addWidget(reconnectBtn);
        btnRow->addWidget(newCircuitBtn);
        btnRow->addStretch(1);
        torLay->addLayout(btnRow);
        torLay->addStretch(1);
        tabs->addTab(torTab, tr("Tor"));
    }

    // --- Security / General tab ---
    auto *secTab = new QWidget(&dlg);
    auto *secForm = new QFormLayout(secTab);
    auto *notifChk = new QCheckBox(tr("Show transaction notifications"), secTab);
    notifChk->setChecked(m_notifications);
    secForm->addRow(notifChk);
    auto *confirmChk = new QCheckBox(tr("Require password before sending"), secTab);
    confirmChk->setChecked(m_confirmSend);
    secForm->addRow(confirmChk);
    auto *testnetChk = new QCheckBox(tr("Show test networks (Sepolia / Holesky)"), secTab);
    testnetChk->setChecked(aeroShowTestnets());
    secForm->addRow(testnetChk);
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

    auto *themeCombo = new QComboBox(appTab);
    themeCombo->addItem(tr("Dark"), QStringLiteral("dark"));
    themeCombo->addItem(tr("Light"), QStringLiteral("light"));
    {
        const QString cur = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                                .value(QStringLiteral("appearance/theme"), QStringLiteral("dark"))
                                .toString();
        themeCombo->setCurrentIndex(cur == QLatin1String("light") ? 1 : 0);
    }
    appForm->addRow(tr("Theme"), themeCombo);

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

    // --- Updates tab: the automatic check, and what the check is actually trusting ---
    QCheckBox *autoUpdateChk = nullptr;
    {
        auto *updTab = new QWidget(&dlg);
        auto *updLay = new QVBoxLayout(updTab);

        updLay->addWidget(new QLabel(tr("You are running Aero %1.").arg(Updater::currentVersion()),
                                     updTab));

        autoUpdateChk = new QCheckBox(tr("Check for updates automatically (once a day, over Tor)"),
                                      updTab);
        autoUpdateChk->setChecked(Updater::automaticChecksEnabled());
        updLay->addWidget(autoUpdateChk);

        auto *checkBtn = new QPushButton(tr("Check for updates now"), updTab);
        connect(checkBtn, &QPushButton::clicked, &dlg, [this, &dlg]() {
            dlg.accept();
            updater()->checkNow();
        });
        updLay->addWidget(checkBtn);

        // The security story is the feature, so state it where the setting lives rather than only
        // in a README. A user who understands what the fingerprint is for can compare it against
        // the key published elsewhere; one who does not still learns that their wallets are not
        // part of what an update replaces.
        auto *updInfo = new QLabel(
            tr("Aero installs an update only if it is signed by the Aero release key:\n"
               "  %1\n\n"
               "Nothing is downloaded until that signature checks out, and nothing is installed "
               "until the archive matches the hash the signed release notes gave. An update can "
               "never move you to an older version.\n\n"
               "Updates replace Aero's own program files only. Your wallets, settings, Trezor "
               "pairing and Tor data are never touched.\n\n"
               "With automatic checks off, Aero contacts nothing on its own; use the button above "
               "or Help \u2023 Check for Updates.")
                .arg(Updater::signingKeyFingerprint()),
            updTab);
        updInfo->setWordWrap(true);
        updInfo->setStyleSheet(QStringLiteral("color:#8a8a8a; font-size:11px;"));
        updLay->addWidget(updInfo);
        updLay->addStretch(1);
        tabs->addTab(updTab, tr("Updates"));
    }

    outer->addWidget(tabs);
    auto *box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    outer->addWidget(box);

    if (dlg.exec() != QDialog::Accepted) return;

    // Updates.
    if (autoUpdateChk)
        Updater::setAutomaticChecksEnabled(autoUpdateChk->isChecked());

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
    {
        const QString theme = themeCombo->currentData().toString();
        QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
        if (s.value(QStringLiteral("appearance/theme"), QStringLiteral("dark")).toString() != theme) {
            s.setValue(QStringLiteral("appearance/theme"), theme);
            aeroApplyTheme(); // switch dark/light live
        }
    }
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
        QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
            .setValue(QStringLiteral("appearance/showTestnets"), testnetChk->isChecked());
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

    // Tor: bundled vs external (shared) Tor. Persisted globally; autoConnect/socksFor respect it.
    {
        QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
        const bool ext = torExternalChk && torExternalChk->isChecked();
        s.setValue(QStringLiteral("tor/external"), ext);
        if (torSocksEdit)
            s.setValue(QStringLiteral("tor/socks"), torSocksEdit->text().trimmed());
        s.sync();
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
        const QString historyKey = QStringLiteral("node/%1/historyApi").arg(chainId);
        const QString history = historyEdit->text().trimmed();
        if (history.isEmpty())
            s.remove(historyKey);
        else
            s.setValue(historyKey, history);
        // Take effect now rather than at the next connect, so someone who has just pasted a working
        // explorer in to escape a broken one sees history load instead of wondering what to restart.
        Wallet::setHistoryApis(chainId, history);
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
        const bool customNode = !endpoints.isEmpty() && endpoints != chainDefFor(chainId).rpcs;
        if (chainId != m_chainId && chainDefFor(chainId).id == chainId) {
            switchChain(chainId); // uses socksFor() -> honours bundled/external Tor
        } else if (customNode) {
            m_chainId = chainId;
            setConnectionState(0, tr("Connecting…"));
            m_wallet->connectProvider(chainId, endpoints, socks); // explicit custom node
        } else {
            // No custom node: reconnect via autoConnect so the (possibly just-toggled) Tor mode -
            // bundled vs shared external Tor - takes effect.
            m_chainId = chainId;
            autoConnect();
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
    for (const TokenInfo &t : curatedTopTokens(m_chainId))
        if (!trackedAddrs.contains(t.address.toLower()))
            addRow(t.address, t.symbol, t.decimals, Curated, !disabled.contains(t.address.toLower()));
    // Wallet-tracked tokens (the defaults + anything imported) - always shown, checked.
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
    // An empty password still encrypts the file, but with a trivially-derivable key - warn before
    // effectively removing the passphrase protection.
    if (p1->text().isEmpty() &&
        QMessageBox::warning(
            this, tr("Change password"),
            tr("An empty password offers no protection - anyone with the wallet file could open "
               "it.\n\nContinue without a password?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;
    // store() re-encrypts (fresh salt + nonce) with the new password and retains it for future
    // saves. It runs Argon2id (~1s), so do it OFF the UI thread behind a modal busy dialog.
    const QString path = m_wallet->walletPath();
    const QString newPw = p1->text();
    bool ok = false;
    runBusy(tr("Updating password…"), [&]() { ok = m_wallet->store(path, newPw); });
    if (ok)
        QMessageBox::information(this, tr("Change password"), tr("Password updated."));
    else
        QMessageBox::warning(this, tr("Change password"), m_wallet->errorString());
}

// Run a blocking wallet op off the UI thread behind a modal, cancel-less busy dialog. A local event
// loop keeps the UI responsive (repaints, the spinner animates) while the worker runs; `work` may
// write into caller-owned variables since we only read them after the future has completed.
void AeroMainWindow::runBusy(const QString &message, const std::function<void()> &work) {
    QProgressDialog prog(message, QString(), 0, 0, this);
    prog.setWindowModality(Qt::ApplicationModal);
    prog.setCancelButton(nullptr);
    prog.setMinimumDuration(0);
    QFutureWatcher<void> watcher;
    QEventLoop loop;
    connect(&watcher, &QFutureWatcher<void>::finished, &loop, &QEventLoop::quit);
    watcher.setFuture(QtConcurrent::run(work));
    prog.show();
    loop.exec();
    prog.close();
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
    sig->setPlaceholderText(tr("0x… - produced by Sign, or paste a signature to Verify"));
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
        QString s;
        const QString message = msg->toPlainText();
        runBusy(tr("Signing…"), [&]() { s = m_wallet->signMessage(idx, message); });
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
            result->setText(tr("<span style='color:#e74c3c;'>Invalid signature - could not "
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
    auto *scanRow = new QHBoxLayout();
    auto *scanBtn = new QPushButton(tr("Scan QR…"), &dlg);
    scanRow->addWidget(scanBtn);
    scanRow->addStretch();
    v->addLayout(scanRow);
    connect(scanBtn, &QPushButton::clicked, &dlg, [this, edit]() {
        const QString t = scanQrFromFile();
        if (!t.isEmpty())
            edit->setPlainText(t);
    });
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
    // We don't know this relayed tx's amount/recipient/account - treat it like a replacement so
    // onTransactionCommitted skips the optimistic "Payment sent"/balance-drop path entirely (never
    // reusing a previous send's committed details).
    m_committedIsReplacement = true;
    beginSendProgress(tr("Broadcasting the raw transaction over Tor…"));
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
    auto *qrBtn = new QPushButton(tr("Show QR"), &dlg);
    auto *closeBtn = new QPushButton(tr("Close"), &dlg);
    row->addWidget(copyBtn);
    row->addWidget(saveBtn);
    row->addWidget(qrBtn);
    row->addStretch();
    row->addWidget(closeBtn);
    v->addLayout(row);
    connect(qrBtn, &QPushButton::clicked, &dlg,
            [this, json]() { showQrPopup(tr("Unsigned transaction"), json); });
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
                               "wallet). It is signed locally - no network is used."),
                            &dlg));
    auto *in = new QPlainTextEdit(&dlg);
    in->setMinimumHeight(120);
    v->addWidget(in);
    auto *inRow = new QHBoxLayout();
    auto *scanBtn = new QPushButton(tr("Scan QR…"), &dlg);
    auto *signBtn = new QPushButton(tr("Sign"), &dlg);
    inRow->addWidget(scanBtn);
    inRow->addStretch();
    inRow->addWidget(signBtn);
    v->addLayout(inRow);
    v->addWidget(new QLabel(tr("Signed raw transaction (broadcast this on an online wallet):"), &dlg));
    auto *out = new QPlainTextEdit(&dlg);
    out->setReadOnly(true);
    out->setMinimumHeight(90);
    v->addWidget(out);
    auto *row = new QHBoxLayout();
    auto *copyBtn = new QPushButton(tr("Copy raw tx"), &dlg);
    auto *outQrBtn = new QPushButton(tr("Show QR"), &dlg);
    auto *closeBtn = new QPushButton(tr("Close"), &dlg);
    row->addWidget(copyBtn);
    row->addWidget(outQrBtn);
    row->addStretch();
    row->addWidget(closeBtn);
    v->addLayout(row);
    connect(scanBtn, &QPushButton::clicked, &dlg, [this, in]() {
        const QString t = scanQrFromFile();
        if (!t.isEmpty())
            in->setPlainText(t);
    });
    connect(signBtn, &QPushButton::clicked, &dlg, [this, in, out]() {
        const QString raw = m_wallet->signUnsigned(in->toPlainText().trimmed());
        if (raw.isEmpty())
            out->setPlainText(tr("Sign failed: %1").arg(m_wallet->errorString()));
        else
            out->setPlainText(raw);
    });
    connect(outQrBtn, &QPushButton::clicked, &dlg, [this, out]() {
        const QString s = out->toPlainText().trimmed();
        if (s.startsWith(QLatin1String("0x")))
            showQrPopup(tr("Signed transaction"), s);
    });
    connect(copyBtn, &QPushButton::clicked, &dlg, [out]() {
        const QString s = out->toPlainText().trimmed();
        if (s.startsWith(QLatin1String("0x")))
            QApplication::clipboard()->setText(s);
    });
    connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    dlg.exec();
}

void AeroMainWindow::onSendMany() {
    if (!m_wallet) return;
    if (m_wallet->isWatchOnly()) {
        QMessageBox::information(this, tr("Watch-only wallet"),
                                 tr("This is a watch-only wallet - it can't send."));
        return;
    }
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Send to Many"));
    dlg.setMinimumWidth(560);
    auto *v = new QVBoxLayout(&dlg);

    auto *form = new QFormLayout();
    auto *fromCombo = new QComboBox(&dlg);
    const quint32 n = m_wallet->numAccounts();
    for (quint32 i = 0; i < n; ++i)
        fromCombo->addItem(accountLabel(i));
    if (m_fromCombo && m_fromCombo->currentIndex() >= 0)
        fromCombo->setCurrentIndex(m_fromCombo->currentIndex());
    form->addRow(tr("From"), fromCombo);

    auto *assetCombo = new QComboBox(&dlg);
    assetCombo->addItem(m_nativeSymbol, QString()); // native: empty address
    assetCombo->setItemData(0, 18, Qt::UserRole + 1);
    for (const TokenInfo &t : m_wallet->tokens()) {
        assetCombo->addItem(t.symbol, t.address);
        assetCombo->setItemData(assetCombo->count() - 1, t.decimals, Qt::UserRole + 1);
    }
    form->addRow(tr("Asset"), assetCombo);
    v->addLayout(form);

    v->addWidget(new QLabel(tr("One recipient per line, as  address, amount"), &dlg));
    auto *edit = new QPlainTextEdit(&dlg);
    edit->setPlaceholderText(QStringLiteral("0xabc…, 0.1\n0xdef…, 0.25"));
    edit->setMinimumHeight(140);
    v->addWidget(edit);

    auto *box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    box->button(QDialogButtonBox::Ok)->setText(tr("Send all"));
    v->addWidget(box);
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    if (dlg.exec() != QDialog::Accepted)
        return;

    QVector<QPair<QString, QString>> recipients;
    for (const QString &raw : edit->toPlainText().split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        const QString line = raw.trimmed();
        if (line.isEmpty()) continue;
        const int comma = line.lastIndexOf(QLatin1Char(','));
        if (comma < 0) {
            QMessageBox::warning(this, tr("Send to Many"),
                                 tr("Each line must be:  address, amount\n\nOffending line:\n%1").arg(line));
            return;
        }
        const QString addr = line.left(comma).trimmed();
        const QString amt = line.mid(comma + 1).trimmed();
        bool ok = false;
        if (!(addr.startsWith(QLatin1String("0x")) && addr.size() == 42) || amt.toDouble(&ok) <= 0 || !ok) {
            QMessageBox::warning(this, tr("Send to Many"),
                                 tr("Invalid address or amount:\n%1").arg(line));
            return;
        }
        recipients.append({addr, amt});
    }
    if (recipients.isEmpty())
        return;

    const QString sym = assetCombo->currentText();
    if (QMessageBox::question(
            this, tr("Send to Many"),
            tr("Send %1 separate %2 transactions (one per recipient)? This broadcasts %1 txs at "
               "sequential nonces.").arg(recipients.size()).arg(sym),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;

    const QString tokenAddr = assetCombo->currentData().toString();
    const quint8 dec = static_cast<quint8>(assetCombo->currentData(Qt::UserRole + 1).toUInt());
    const QPair<QString, QString> fee = chosenFeeWei();
    m_wallet->sendMany(static_cast<quint32>(qMax(0, fromCombo->currentIndex())), recipients,
                       tokenAddr, dec, fee.first, fee.second);
}

void AeroMainWindow::onManySent(const QString &resultJson, const QString &error) {
    if (!error.isEmpty()) {
        QMessageBox::warning(this, tr("Send to Many"), error);
        return;
    }
    const QJsonArray arr = QJsonDocument::fromJson(resultJson.toUtf8()).array();
    int sent = 0;
    bool stopped = false;
    QString detail, failed;
    for (const QJsonValue &v : arr) {
        const QJsonObject o = v.toObject();
        const QString to = o.value(QStringLiteral("to")).toString();
        if (o.contains(QStringLiteral("tx_hash"))) {
            ++sent;
            detail += tr("%1 → %2\n").arg(o.value(QStringLiteral("tx_hash")).toString().left(14), to);
        } else {
            stopped = true;
            // Sequential ERC-20 path stops at the first failure to avoid a nonce gap that would
            // strand later sends. Tell the user exactly where it stopped and how to finish.
            failed = tr("\n\n⚠ Stopped at %1:\n%2\n\nThis recipient and every recipient AFTER it "
                        "were NOT sent. Re-run Send to Many with just the remaining recipients "
                        "(starting from this one) to finish.")
                         .arg(to, o.value(QStringLiteral("error")).toString());
        }
    }
    if (stopped)
        QMessageBox::warning(this, tr("Send to Many - partially sent"),
                             tr("Broadcast %1 transaction(s) successfully.\n\n%2%3")
                                 .arg(sent).arg(detail, failed));
    else
        QMessageBox::information(this, tr("Send to Many"),
                                 tr("Broadcast %1 transaction(s).\n\n%2").arg(sent).arg(detail));
    refreshAllBalances();
    refreshHistoryView();
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
    double priority = qMax(tip * 2.0, 2e9);   // at least ~2 gwei tip
    double maxFee = base * 3.0 + priority;    // generous cap to ensure the replacement wins
    // A node rejects a replacement that isn't ~12.5% above the ORIGINAL fee ("replacement transaction
    // underpriced"). If the original was sent with a high custom fee, the market-derived bump above
    // can be lower than it - so floor both at 1.15x the original.
    const double origMax = m_lastSent.fee.maxFee.toDouble();
    const double origTip = m_lastSent.fee.maxPriorityFee.toDouble();
    if (origMax > 0)
        maxFee = qMax(maxFee, origMax * 1.15);
    if (origTip > 0)
        priority = qMax(priority, origTip * 1.15);
    if (priority > maxFee) // keep the EIP-1559 invariant
        priority = maxFee;
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
    m_committedIsReplacement = true; // replaces an already-shown tx - don't re-drop the balance
    beginSendProgress(tr("Rebroadcasting at a higher fee over Tor…"));
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
    m_committedIsReplacement = true; // a 0-value replacement - don't drop the balance or add a row
    beginSendProgress(tr("Broadcasting the cancel transaction over Tor…"));
    m_wallet->cancelTransaction(m_lastSent.fromIndex, m_lastSent.nonce, fee.first, fee.second);
}

void AeroMainWindow::onShowSeed() {
    if (!m_wallet) return;
    if (m_wallet->isHardware()) {
        QMessageBox::information(this, tr("Show seed"),
                                 tr("This is a hardware wallet - the seed stays on your device and "
                                    "is never shown here."));
        return;
    }
    if (QMessageBox::warning(
            this, tr("Show seed"),
            tr("Your seed phrase controls all your funds. Never share it, and make sure no one is "
               "watching your screen.\n\nReveal it now?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;

    QString seed;
    runBusy(tr("Reading seed…"), [&]() { seed = m_wallet->getSeed(); });
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
    // Every chain renames its dollars. Base has USDbC, Polygon and Avalanche carry the bridged
    // USDC.e / USDT.e / DAI.e, and BSC uses BUSD. Listing only the three mainnet tickers left those
    // valued at $0, which is not merely a blank Value column: Auto slippage reads this to size the
    // trade, so a $10k USDC.e sell looked like an unknown amount and fell back to a wide default.
    static const QSet<QString> kDollar = {
        QStringLiteral("USDT"),   QStringLiteral("USDC"),   QStringLiteral("DAI"),
        QStringLiteral("USDC.E"), QStringLiteral("USDT.E"), QStringLiteral("DAI.E"),
        QStringLiteral("USDBC"),  QStringLiteral("BUSD"),   QStringLiteral("USDC.B"),
    };
    return kDollar.contains(s);
}

double AeroMainWindow::unitPriceUsd(const QString &symbol) const {
    const QString s = symbol.toUpper();
    if (s == m_nativeSymbol.toUpper()) return m_nativeUsd;
    // The wrapped coin is redeemable 1:1 for the native one, so it carries the native price - but
    // only where it really is this chain's coin. "W" + native symbol covers WETH on Ethereum and the
    // ETH L2s, WPOL on Polygon, WBNB on BSC, WXDAI on Gnosis and WAVAX on Avalanche; previously only
    // WETH-on-an-ETH-chain was handled and the other four priced at zero. WETH on Polygon or Gnosis
    // is a bridged asset, not the coin, so it deliberately does not match here.
    if (s == QLatin1String("W") + m_nativeSymbol.toUpper())
        return m_nativeUsd;
    // Polygon renamed MATIC to POL and both names are still in circulation.
    if ((s == "WMATIC" || s == "MATIC") && m_nativeSymbol.compare(QStringLiteral("POL"),
                                                                 Qt::CaseInsensitive) == 0)
        return m_nativeUsd;
    if (isStablecoin(s)) return 1.0; // stablecoins ~ $1
    return 0.0; // unknown -> no conversion
}

void AeroMainWindow::onEthUsdPrice(double usdPerEth) {
    m_nativeUsd = usdPerEth;
    // On non-ETH chains the Home native ticker is driven by this chain-aware price.
    if (m_homeEthValue && m_nativeSymbol.compare(QStringLiteral("ETH"), Qt::CaseInsensitive) != 0) {
        m_homeEthValue->setText(m_nativeUsd > 0 ? fiatStr(m_nativeUsd) : QStringLiteral("-"));
        if (m_homeEthPct) m_homeEthPct->clear();
    }
    onAmountConversion();
    recomputeHomeTotal(); // native valuation uses the chain-aware price
    updateFeeEstimate();  // fee is also shown in USD
    updateHistoryPricing(); // dust filter values incoming transfers in USD
    updateSwapPayUsd();    // Swap "You pay" USD (native fallback uses this price)
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
    for (const TokenInfo &t : curatedTopTokens(m_chainId))
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

// A liquidity verdict belongs to one contract on one chain, so the keys carry the chain id. Stored
// flat, a decision made on Arbitrum was reused on Ethereum for whatever happened to sit at the same
// address - and the same address across two chains is usually two unrelated contracts. That turned
// an auto-trust into a green "verified" badge on a token nobody had ever checked.
static QString liquidityKey(const char *name, quint64 chainId) {
    return QStringLiteral("tokens/%1/%2").arg(QLatin1String(name)).arg(chainId);
}

void AeroMainWindow::loadLiquidityCache() {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    m_liquidityThresholdUsd = s.value(QStringLiteral("tokens/liquidityUsd"), 1000000.0).toDouble();
    m_liquidityVerified.clear();
    for (const QString &a : s.value(liquidityKey("liquidityVerified", m_chainId)).toStringList())
        m_liquidityVerified.insert(a.toLower());
    m_liquidityChecked.clear();
    for (const QString &a : s.value(liquidityKey("liquidityChecked", m_chainId)).toStringList())
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

// For each native-coin transfer, fetch the coin's USD price on that transaction's date so History
// can show its fiat value at the time (not just the current price). Deduped per date and capped so
// a long history doesn't flood Tor; stablecoins/tokens keep the current-price valuation.
void AeroMainWindow::requestHistoricalPrices(const QVector<HistoryItem> &items) {
    if (!m_wallet) return;
    int budget = 60; // cap per refresh
    for (const HistoryItem &h : items) {
        if (budget <= 0) break;
        if (h.timestamp == 0 || h.symbol.compare(m_nativeSymbol, Qt::CaseInsensitive) != 0)
            continue; // historical valuation is for the native coin only
        const QString date =
            QDateTime::fromSecsSinceEpoch(static_cast<qint64>(h.timestamp), Qt::UTC)
                .toString(QStringLiteral("yyyy-MM-dd"));
        const QString key = m_nativeSymbol.toUpper() + QLatin1Char('|') + date;
        if (m_histPriceRequested.contains(key))
            continue;
        m_histPriceRequested.insert(key);
        m_wallet->historicalPrice(m_nativeSymbol, date);
        --budget;
    }
}

void AeroMainWindow::onHistoricalPrice(const QString &symbol, const QString &date, double usd) {
    if (usd <= 0.0 || !m_historyModel)
        return;
    const QString key = symbol.toUpper() + QLatin1Char('|') + date;
    m_historyModel->setHistoricalUnitPrice(key, usd);
    // A coin's price on a past date never changes - persist it so every date is fetched at most once,
    // ever (across restarts). This turns a per-session storm of Coinbase lookups into a one-time cost.
    QJsonObject hp = m_meta.value(QStringLiteral("histprices")).toObject();
    if (!hp.contains(key)) {
        hp[key] = usd;
        m_meta[QStringLiteral("histprices")] = hp;
        scheduleHistorySave(); // debounced; bundles with the history-cache write
    }
}

// Restore persisted per-date prices (immutable) and mark those dates as already-known so
// requestHistoricalPrices() never re-fetches them.
void AeroMainWindow::loadHistoricalPrices() {
    if (!m_historyModel)
        return;
    const QJsonObject hp = m_meta.value(QStringLiteral("histprices")).toObject();
    for (auto it = hp.constBegin(); it != hp.constEnd(); ++it) {
        const double usd = it.value().toDouble();
        if (usd > 0.0) {
            m_historyModel->setHistoricalUnitPrice(it.key(), usd);
            m_histPriceRequested.insert(it.key());
        }
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
    s.setValue(liquidityKey("liquidityChecked", m_chainId),
               QStringList(m_liquidityChecked.values()));
    if (trusted) {
        s.setValue(liquidityKey("liquidityVerified", m_chainId),
                   QStringList(m_liquidityVerified.values()));
        applyVerifiedTokens(); // token is now trusted -> its history rows become visible
    }
}

void AeroMainWindow::onMarketPrices(double xmrUsd, double xmrChangePct, double ethUsd,
                                     double ethChangePct) {
    m_xmrUsd = xmrUsd;
    auto setTicker = [this](QLabel *value, QLabel *pct, double price, double chg) {
        if (value)
            value->setText(price > 0 ? fiatStr(price) : QStringLiteral("-"));
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
            m_homeEthValue->setText(m_nativeUsd > 0 ? fiatStr(m_nativeUsd) : QStringLiteral("-"));
        if (m_homeEthPct)
            m_homeEthPct->clear();
    }
}

void AeroMainWindow::recomputeHomeTotal() {
    if (!m_homeTotalValue) return;
    // Accumulate the grand total AND each account's own USD value in the same single pass, so the
    // Receive address list can show a full per-account value (native + tokens) without extra scans.
    QHash<quint32, double> perAcct;
    double total = 0.0;
    for (auto it = m_ethRawByAccount.constBegin(); it != m_ethRawByAccount.constEnd(); ++it) {
        const double v = it.value() * m_nativeUsd;
        perAcct[it.key()] += v;
        total += v;
    }
    // Build an address->symbol map ONCE (was an O(tokens) inner scan per balance key, i.e. O(N*T^2)
    // across a bulk refresh - the main scale freeze). Now O(N + T).
    QHash<QString, QString> symByAddr;
    if (m_wallet)
        for (const TokenInfo &t : m_wallet->tokens())
            symByAddr.insert(t.address.toLower(), t.symbol);
    for (const TokenInfo &t : curatedTopTokens(m_chainId))
        symByAddr.insert(t.address.toLower(), t.symbol);
    for (auto it = m_tokenRawByKey.constBegin(); it != m_tokenRawByKey.constEnd(); ++it) {
        const quint32 idx = it.key().section(QLatin1Char('|'), 0, 0).toUInt();
        const QString tokenAddr = it.key().section(QLatin1Char('|'), 1).toLower();
        const double v = it.value() * unitPriceUsd(symByAddr.value(tokenAddr));
        perAcct[idx] += v;
        total += v;
    }
    const QString shown = m_hideBalances ? QStringLiteral("\u2022\u2022\u2022\u2022") : fiatStr(total);
    m_homeTotalValue->setText(shown);
    if (m_recvTotalLabel)
        m_recvTotalLabel->setText(m_hideBalances ? tr("Total balance: hidden")
                                                 : tr("Total balance: %1").arg(shown));
    // Receive address list + Send/Swap "From" combos: show each account's FULL value in USD (native +
    // tokens) when the toggle is on, reusing perAcct so there's no extra per-account token scan.
    if (m_recvUsd && m_nativeUsd > 0.0 && !m_hideBalances) {
        if (m_addressModel) {
            QSet<quint32> idxs;
            for (auto it = m_accountBalances.constBegin(); it != m_accountBalances.constEnd(); ++it)
                idxs.insert(it.key());
            for (auto it = perAcct.constBegin(); it != perAcct.constEnd(); ++it)
                idxs.insert(it.key());
            for (quint32 i : idxs)
                m_addressModel->setBalance(i, fiatStr(perAcct.value(i, 0.0)));
        }
        auto updCombo = [&](QComboBox *c) {
            if (!c || (c->view() && c->view()->isVisible()))
                return; // don't disturb an open/searching dropdown
            QSignalBlocker b(c);
            const int n = c->count();
            for (int i = 0; i < n; ++i) {
                const quint32 idx = static_cast<quint32>(i);
                const bool known = m_ethRawByAccount.contains(idx) || m_accountBalances.contains(idx);
                const QString label =
                    accountLabelWith(idx, known ? fiatStr(perAcct.value(idx, 0.0)) : QString());
                if (c->itemText(i) != label) // only touch items that actually changed
                    c->setItemText(i, label);
            }
        };
        updCombo(m_fromCombo);
        updCombo(m_swapFrom);
    }
}

// Debounced home-total + used-flag recompute. Per-balance-signal handlers call this instead of
// running the (previously per-signal) recompute directly, so a bulk refresh of hundreds of accounts
// coalesces into a single recompute after the burst - the UI never blocks.
void AeroMainWindow::scheduleHomeRecompute() {
    if (!m_homeTotalTimer) {
        m_homeTotalTimer = new QTimer(this);
        m_homeTotalTimer->setSingleShot(true);
        m_homeTotalTimer->setInterval(150);
        connect(m_homeTotalTimer, &QTimer::timeout, this, [this]() {
            recomputeHomeTotal();
            refreshUsedFlags();
        });
    }
    m_homeTotalTimer->start();
}

// Recompute every account's "used" (red) flag once, in a single O(N + tokenKeys) pass, from the
// in-memory balances - instead of looping the tracked-token list per account per balance signal.
void AeroMainWindow::refreshUsedFlags() {
    if (!m_addressModel || !m_wallet)
        return;
    QSet<quint32> hasToken;
    for (auto it = m_tokenRawByKey.constBegin(); it != m_tokenRawByKey.constEnd(); ++it)
        if (it.value() > 0.0)
            hasToken.insert(it.key().section(QLatin1Char('|'), 0, 0).toUInt());
    const quint32 n = m_wallet->numAccounts();
    for (quint32 i = 0; i < n; ++i) {
        // A funded account (discovered by the scan) stays red REGARDLESS of whether its live balance
        // has loaded yet. Without this, the first balance batch to arrive would recompute `used` from
        // only the handful of balances fetched so far and clear the red flag on every funded account
        // still waiting on its (rate-limited, slow) balance - the "only the first few stay red" bug.
        const bool used = m_fundedAccounts.contains(i) ||
                          m_ethRawByAccount.value(i, 0.0) > 0.0 || hasToken.contains(i);
        m_addressModel->setUsed(i, used); // no-op when unchanged
    }
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

    // A Qt::Popup so clicking anywhere outside dismisses it (like a combo dropdown) - no forced "X".
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
    // that are verified - never the full curated list of tokens the wallet never interacted with.
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
    for (const TokenInfo &t : curatedTopTokens(m_chainId))   // verified curated (metadata source)
        addAsset(t.symbol, t.address, t.decimals);

    // Held balance for an asset at the current "From" account ("" => ETH). -1 == unknown.
    const int fromIndex = m_fromCombo ? qMax(0, m_fromCombo->currentIndex()) : 0;
    auto heldBalance = [this, fromIndex](const QString &addr) -> double {
        if (addr.isEmpty())
            return m_ethRawByAccount.value(fromIndex, 0.0);
        return m_tokenRawByKey.value(QStringLiteral("%1|%2").arg(fromIndex).arg(addr.toLower()), -1.0);
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
    // Guard against a double-send: while a previous transaction is still being broadcast (which can
    // take a while over Tor), refuse a new one so an impatient re-click can't send twice.
    if (m_sendInFlight) {
        QMessageBox::information(
            this, tr("Send in progress"),
            tr("A transaction is already being broadcast. Please wait for it to finish before "
               "sending again."));
        return;
    }
    QString to = sendUi.lineAddress->text().trimmed();
    // ENS: if the recipient looks like a name (has a dot, not a 0x address), resolve it to an address
    // first (mainnet only). We show the resolved 0x address in the confirm dialog so it's verifiable.
    if (!to.isEmpty() && !to.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) && to.contains('.')) {
        const QString name = to;
        QString resolved;
        runBusy(tr("Resolving %1…").arg(name), [&]() { resolved = m_wallet->resolveEns(name); });
        if (resolved.isEmpty()) {
            QMessageBox::warning(this, tr("Send"),
                                 tr("Couldn't resolve \u201c%1\u201d.\n\n%2")
                                     .arg(name, m_wallet->errorString()));
            return;
        }
        to = resolved;
        sendUi.lineAddress->setText(resolved); // reflect the resolved address in the field
    }
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

    QPair<QString, QString> fee = chosenFeeWei(); // (maxFee, priority) wei, empty = automatic
    // Fill an "automatic" fee from the LIVE cached estimate that's ALREADY shown on the Send tab, so
    // the confirm dialog appears INSTANTLY. Otherwise createTransaction() fetched a fresh fee suggestion
    // over Tor before the prompt could show - several seconds normally, and up to ~40s while the
    // history load saturates the connection. The tx broadcasts with this same fee (what the user saw).
    if (fee.first.isEmpty()) {
        const double maxFeeWei = m_feeBaseWei > 0 ? m_feeBaseWei * 3.0 + qMax(m_feeTipWei, 1e9) : 30e9;
        const double tipWei = m_feeTipWei > 0 ? m_feeTipWei : 1e9;
        fee.first = QString::number(static_cast<qulonglong>(maxFeeWei));
        fee.second = QString::number(static_cast<qulonglong>(tipWei));
    }

    // Gas-aware balance checks (the network fee is always paid in the native coin).
    const bool isNativeSend = currentTokenAddr().isEmpty();
    const double maxFeePerGas =
        !fee.first.isEmpty()
            ? fee.first.toDouble()
            : (m_feeBaseWei > 0 ? m_feeBaseWei * 3.0 + qMax(m_feeTipWei, 1e9) : 30e9);
    const double gasLimit = isNativeSend ? 21000.0 : 65000.0;
    const double feeNative = maxFeePerGas * gasLimit / 1e18;
    const double nativeBal = m_ethRawByAccount.value(static_cast<quint32>(fromIndex), 0.0);

    bool availOk = false, amtOk = false;
    const double avail = m_availAmount.toDouble(&availOk);
    const double sendAmt = tokenAmount.toDouble(&amtOk);
    if (availOk && amtOk && sendAmt > avail) {
        QMessageBox::warning(
            this, tr("Insufficient balance"),
            tr("Amount exceeds available balance of %1 %2.").arg(grouped(m_availAmount), currentSymbol()));
        return;
    }
    // Native send must leave room for gas (a full-balance send would be rejected by the node).
    if (isNativeSend && amtOk && sendAmt + feeNative > nativeBal + 1e-15) {
        QMessageBox::warning(
            this, tr("Insufficient balance for fee"),
            tr("The amount plus the ~%1 %2 network fee exceeds your balance. Use \u201cMax\u201d to "
               "send the most you can, or lower the amount.")
                .arg(trimZeros(QString::number(feeNative, 'f', 8)), m_nativeSymbol));
        return;
    }
    // ERC-20 send needs native coin for gas even though the token balance is separate.
    if (!isNativeSend && nativeBal < feeNative) {
        QMessageBox::warning(
            this, tr("Not enough %1 for gas").arg(m_nativeSymbol),
            tr("Sending a token still costs a network fee (~%1 %2) paid in %2, but this account only "
               "has %3 %2. Fund it with a little %2 first.")
                .arg(trimZeros(QString::number(feeNative, 'f', 8)), m_nativeSymbol,
                     trimZeros(QString::number(nativeBal, 'f', 8))));
        return;
    }

    // Watch-only: don't sign/send - build an unsigned tx to sign on an offline wallet.
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
        // Air-gapped signing: let the user pin an explicit nonce (e.g. to queue behind another tx or
        // build several to sign in order). Blank = fetch the account's next (pending) nonce as before.
        bool ok = false;
        const QString nonceStr = QInputDialog::getText(
            this, tr("Nonce (optional)"),
            tr("Leave blank to use the account's next (pending) nonce automatically,\n"
               "or enter an explicit nonce to build the transaction at:"),
            QLineEdit::Normal, QString(), &ok);
        if (!ok)
            return; // user cancelled the export
        const QString ns = nonceStr.trimmed();
        if (!ns.isEmpty()) {
            bool nok = false;
            const qulonglong n = ns.toULongLong(&nok);
            if (!nok) {
                QMessageBox::warning(this, tr("Invalid nonce"),
                                     tr("The nonce must be a whole number."));
                return;
            }
            tx.nonce = n;
        }
        m_wallet->buildUnsigned(tx); // result via onUnsignedTxReady
        return;
    }

    // Build the tx locally and show the confirmation IMMEDIATELY. Everything needed is already known
    // (amount + the fee resolved above), so there's no worker hop, no core lock, and no network call
    // before the prompt - it pops up instantly. The nonce and any gas specifics are resolved later,
    // off-thread, when the user actually confirms and it broadcasts (commitTransaction).
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
    onTransactionCreated(tx);
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
    // Capture the ACTUAL amount/symbol/recipient of this tx (from its base units), so the post-send
    // UI doesn't misread the raw Amount field (which may be entered in USD).
    m_committedAmount = trimZeros(QString::number(amount, 'f', 8));
    m_committedSymbol = sym;
    m_committedTokenAddr = tx.token;
    m_committedTo = tx.to.trimmed();
    m_committedFrom = tx.fromIndex; // the account it's really sent from (the combo may change meanwhile)
    m_committedIsReplacement = false;
    beginSendProgress(tr("Broadcasting your transaction over Tor…\nThis can take a moment - please "
                         "don't send again."));
    m_wallet->commitTransaction(tx);
}

// Watch a just-broadcast tx's receipt and confirm the moment it mines. Polls every 2.5s (a small
// receipt request each) and stops on confirmation or after ~5 min. Much faster + more precise than
// fixed timers, and it only runs while a send is unconfirmed.
void AeroMainWindow::startReceiptWatch(const QString &txHash) {
    if (!m_wallet || txHash.isEmpty())
        return;
    m_pendingReceiptHash = txHash;
    m_receiptPolls = 0;
    if (!m_receiptTimer) {
        m_receiptTimer = new QTimer(this);
        m_receiptTimer->setInterval(2500);
        connect(m_receiptTimer, &QTimer::timeout, this, [this]() {
            if (!m_wallet || m_pendingReceiptHash.isEmpty() || ++m_receiptPolls > 120) {
                m_receiptTimer->stop();
                // Gave up (~5 min without a receipt): clear the pending-send state so the pre-mine
                // balance clamp goes inert and can't suppress future balance updates for this
                // account/token forever.
                m_pendingReceiptHash.clear();
                m_committedAmount.clear();
                m_committedSymbol.clear();
                m_committedTokenAddr.clear();
                m_committedTo.clear();
                m_committedFrom = 0xFFFFFFFFu;
                m_lastSendFrom = 0xFFFFFFFFu;
                updatePollCadence();
                return;
            }
            m_wallet->txReceipt(m_pendingReceiptHash);
        });
    }
    m_receiptTimer->start();
    updatePollCadence(); // keep the block poll fast while the send confirms, even if unfocused
    m_wallet->txReceipt(txHash); // and check right away (L2s can mine in well under a second)
}

void AeroMainWindow::onTxReceiptReady(const QString &txHash, bool mined, bool success) {
    if (txHash != m_pendingReceiptHash || !mined)
        return; // stale, or not mined yet - keep polling
    m_pendingReceiptHash.clear();
    if (m_receiptTimer)
        m_receiptTimer->stop();
    updatePollCadence(); // send confirmed - allow the poll to relax again if we're idle
    // Settle the optimistic pending row on the receipt itself, so it stops saying "pending" within
    // seconds of mining instead of waiting for the explorer to index the transaction (which can lag
    // several minutes). The forced history refetch below still replaces it with the authoritative
    // mined row once that lands.
    if (m_historyModel)
        m_historyModel->confirmLocalSend(txHash, !success);
    // A router (on-chain) swap is optimistically pending too, and it is atomic: the receipt is the
    // whole truth, so settle it here rather than waiting for the explorer to index both legs.
    if (m_historyModel)
        m_historyModel->confirmLocalSwap(txHash, !success);
    // Mined: pull the exact post-mine balance now, and refresh the sender's history so the row flips
    // from pending to confirmed (or failed) immediately.
    refreshAllBalances();
    ensureAccountHistory(m_lastSendFrom != 0xFFFFFFFFu ? m_lastSendFrom : m_account, /*force*/ true);
    if (!success)
        notify(tr("Transaction failed"), tr("Your last transaction reverted on-chain."));
    // The send has resolved and the pre-mine clamp is now inert (m_pendingReceiptHash cleared), so
    // drop the committed details - a later Broadcast-Raw can't reuse this send's amount/recipient.
    m_committedAmount.clear();
    m_committedSymbol.clear();
    m_committedTokenAddr.clear();
    m_committedTo.clear();
    m_committedFrom = 0xFFFFFFFFu;
    m_lastSendFrom = 0xFFFFFFFFu;
}

// Show a modal, non-cancellable "Broadcasting…" spinner and mark a send as in-flight. This both
// gives the user feedback while the (possibly slow, Tor-routed) broadcast runs AND blocks a second
// Send from being fired - the double-send bug was caused by re-clicking during this silent window.
void AeroMainWindow::beginSendProgress(const QString &text) {
    m_sendInFlight = true;
    if (sendUi.btnSend)
        sendUi.btnSend->setEnabled(false);
    if (!m_sendProgress) {
        m_sendProgress = new QProgressDialog(text, QString(), 0, 0, this); // no cancel button
        m_sendProgress->setWindowTitle(tr("Sending"));
        m_sendProgress->setWindowModality(Qt::ApplicationModal);
        m_sendProgress->setMinimumDuration(0);
        m_sendProgress->setAutoClose(false);
        m_sendProgress->setAutoReset(false);
    }
    m_sendProgress->setLabelText(text);
    m_sendProgress->show();
}

void AeroMainWindow::endSendProgress() {
    m_sendInFlight = false;
    if (sendUi.btnSend)
        sendUi.btnSend->setEnabled(true);
    if (m_sendProgress) {
        m_sendProgress->hide();
        m_sendProgress->reset();
    }
}

void AeroMainWindow::onTransactionCommitted(bool ok, const QString &txHash, const QString &error) {
    endSendProgress(); // broadcast resolved - clear the in-flight guard + dismiss the spinner
    if (m_deviceDialog)
        m_deviceDialog->hide(); // dismiss the "confirm on device" prompt once the device responded
    if (ok) {
        // Use the amount/symbol/recipient captured at commit time (the real token amount) - NOT the
        // raw Amount field, which may be in USD. Empty (e.g. a pasted raw tx) => skip the details.
        const QString to = !m_committedTo.isEmpty() ? m_committedTo : sendUi.lineAddress->text().trimmed();
        const QString amount = m_committedAmount;
        const QString sym = !m_committedSymbol.isEmpty() ? m_committedSymbol : currentSymbol();
        const bool replacement = m_committedIsReplacement;

        if (!replacement && !amount.isEmpty()) {
            // Optimistically show the send in history + drop the displayed balance immediately (like
            // MetaMask/Feather's pending balance). A speed-up/cancel is skipped - the original tx is
            // already shown, so we'd otherwise double-count it.
            m_historyModel->addLocalSend(txHash, to, amount, sym, m_committedTokenAddr);
            // No "Payment sent" notification - outgoing sends are user-initiated, so a popup is just
            // noise. Notifications are reserved for INCOMING payments (and a failed-tx alert below).
            applyOptimisticSend(amount, m_committedTokenAddr);
        }
        // NOTE: deliberately no immediate refreshAllBalances/refreshHistoryView here - that would read
        // the PRE-mine balance (reverting the optimistic drop) and clear the pending row. The receipt
        // watch refreshes both the instant the tx actually mines.
        // Confirm as fast as physically possible: watch the tx's receipt and refresh the instant it
        // mines (rather than fixed 10s/25s timers). One block time is the floor - ~12s on mainnet,
        // sub-second on L2s - and we detect it within a couple seconds of it landing.
        startReceiptWatch(txHash);

        // Return the Send form to blank - the transfer is on its way.
        sendUi.lineAddress->clear();
        sendUi.lineAmount->clear();

        if (!replacement && !amount.isEmpty()) {
            // Feather-style confirmation with the txid + copy.
            HistoryItem tx;
            tx.direction = QStringLiteral("out");
            tx.counterparty = to;
            tx.formatted = amount;
            tx.symbol = sym;
            tx.txHash = txHash;
            tx.timestamp = static_cast<quint64>(QDateTime::currentSecsSinceEpoch());
            showTransactionDialog(tx);
        }
        // NOTE: m_committed* are deliberately NOT cleared here - the pre-mine balance clamp (native +
        // token) needs them until the tx actually mines. They're cleared in onTxReceiptReady once the
        // send resolves. Broadcast-Raw guards itself by setting m_committedIsReplacement (see
        // onBroadcastRaw), so it can never reuse a prior send's details.
        m_committedIsReplacement = false; // reset for the next send
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
    // A CoW order's id is a 112-hex order UID (not a 64-hex tx hash), so a block-explorer /tx/<uid>
    // link 404s ("tx not found"). Route those to the CoW explorer's order page instead; on-chain
    // swaps and normal txs keep the block-explorer link.
    const bool isCowOrder = tx.kind == QLatin1String("swap") && tx.txHash.length() > 66;
    auto *explorerBtn =
        new QPushButton(isCowOrder ? tr("View on CoW Explorer") : tr("View on explorer"), idBox);
    connect(explorerBtn, &QPushButton::clicked, &dlg, [this, hash = tx.txHash, isCowOrder]() {
        openOutsideTor(isCowOrder ? QStringLiteral("https://explorer.cow.fi/orders/%1").arg(hash)
                                  : explorerTxUrl(hash));
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

    // Which of the wallet's accounts this went through. Omitted rather than guessed for rows cached
    // before history recorded one.
    if (tx.account != HistoryItem::unknownAccount && m_wallet) {
        QString who = accountName(tx.account);
        const QString addr = m_wallet->address(tx.account);
        if (!addr.isEmpty())
            who += tr("  \u00b7  %1").arg(shortAddr(addr));
        auto *acctLabel = new QLabel(who, &dlg);
        acctLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        form->addRow(tr("Account:"), acctLabel);
    }

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

    // Per-transaction note (Electrum-style): a private label stored in the encrypted wallet metadata.
    auto *noteEdit = new QLineEdit(m_historyModel ? m_historyModel->txNote(tx.txHash) : QString(), &dlg);
    noteEdit->setPlaceholderText(tr("Add a private note for this transaction…"));
    form->addRow(tr("Note:"), noteEdit);

    v->addLayout(form);

    auto *box = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
    // For a still-pending OUTGOING tx, offer replace-by-fee: speed it up or cancel it (any pending
    // tx from history, not just the last one - the core re-derives its nonce + fields from the hash).
    const bool pendingOut = tx.block == 0 && !tx.failed &&
                            tx.direction == QLatin1String("out") &&
                            tx.kind != QLatin1String("swap") && !tx.txHash.isEmpty();
    if (pendingOut && m_wallet && !m_wallet->isWatchOnly()) {
        const quint32 acct =
            m_historyFilter >= 0 ? static_cast<quint32>(m_historyFilter) : m_account;
        const QString hash = tx.txHash;
        auto *speedBtn = box->addButton(tr("Speed up"), QDialogButtonBox::ActionRole);
        auto *cancelTxBtn = box->addButton(tr("Cancel tx"), QDialogButtonBox::ActionRole);
        connect(speedBtn, &QPushButton::clicked, &dlg, [this, acct, hash, &dlg]() {
            const auto fee = bumpedFeeWei();
            m_committedIsReplacement = true; // don't re-drop balance / duplicate the row
            m_lastSendFrom = acct;
            m_wallet->replaceTx(acct, hash, fee.first, fee.second, /*cancel*/ false);
            dlg.accept();
        });
        connect(cancelTxBtn, &QPushButton::clicked, &dlg, [this, acct, hash, &dlg]() {
            const auto fee = bumpedFeeWei();
            m_committedIsReplacement = true;
            m_lastSendFrom = acct;
            m_wallet->replaceTx(acct, hash, fee.first, fee.second, /*cancel*/ true);
            dlg.accept();
        });
    }
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    v->addWidget(box);

    dlg.exec();

    // Persist the note if it changed (keyed by lower-case tx hash, inside the encrypted metadata).
    if (m_historyModel) {
        const QString newNote = noteEdit->text().trimmed();
        if (newNote != m_historyModel->txNote(tx.txHash)) {
            m_historyModel->setTxNote(tx.txHash, newNote);
            QJsonObject tn = m_meta.value(QStringLiteral("txnotes")).toObject();
            if (newNote.isEmpty())
                tn.remove(tx.txHash.toLower());
            else
                tn[tx.txHash.toLower()] = newNote;
            m_meta[QStringLiteral("txnotes")] = tn;
            saveMetadata();
        }
    }
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

void AeroMainWindow::showQrPopup(const QString &title, const QString &text) {
    QPixmap pm;
    try {
        // A single QR tops out ~2.9 KB; unsigned/signed EVM txs are a few hundred bytes, so they fit.
        using qrcodegen::QrCode;
        const QrCode qr = QrCode::encodeText(text.toUtf8().constData(), QrCode::Ecc::MEDIUM);
        const int n = qr.getSize();
        const int scale = 5, border = 3;
        const int dim = (n + border * 2) * scale;
        QImage image(dim, dim, QImage::Format_RGB32);
        image.fill(Qt::white);
        QPainter p(&image);
        for (int y = 0; y < n; ++y)
            for (int x = 0; x < n; ++x)
                if (qr.getModule(x, y))
                    p.fillRect((x + border) * scale, (y + border) * scale, scale, scale, Qt::black);
        p.end();
        pm = QPixmap::fromImage(image);
    } catch (...) {
        QMessageBox::warning(this, title,
                             tr("This transaction is too large to fit in a single QR code - use "
                                "the Copy / Save-to-file option instead."));
        return;
    }
    QDialog dlg(this);
    dlg.setWindowTitle(title);
    auto *v = new QVBoxLayout(&dlg);
    v->addWidget(new QLabel(tr("Scan this with the other machine (Tools → Sign / Broadcast → "
                               "Scan QR)."),
                            &dlg));
    auto *lbl = new QLabel(&dlg);
    lbl->setPixmap(pm);
    lbl->setAlignment(Qt::AlignCenter);
    v->addWidget(lbl);
    auto *close = new QPushButton(tr("Close"), &dlg);
    connect(close, &QPushButton::clicked, &dlg, &QDialog::accept);
    v->addWidget(close);
    dlg.exec();
}

QString AeroMainWindow::scanQrFromFile() {
    const QString f = QFileDialog::getOpenFileName(
        this, tr("Open QR image"), QString(),
        tr("Images (*.png *.jpg *.jpeg *.bmp);;All files (*)"));
    if (f.isEmpty())
        return {};
    const QString text = decodeQrImage(QImage(f));
    if (text.isEmpty())
        QMessageBox::warning(this, tr("Scan QR"),
                             tr("No QR code could be read from that image."));
    return text;
}
