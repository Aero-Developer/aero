// SPDX-License-Identifier: BSD-3-Clause
#include "XmrTradeTab.h"

#include "ethwallet/Wallet.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDoubleValidator>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QLinearGradient>
#include <QMessageBox>
#include <QPushButton>
#include <QResizeEvent>
#include <QScrollArea>
#include <QScrollBar>
#include <QSettings>
#include <QSplitter>
#include <QTabWidget>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>

namespace {

// How far through the book a market order is allowed to reach. The XMR1 book is a few units deep
// per level, so an uncapped market order could fill far from the mid; this bounds the damage while
// still crossing comfortably.
constexpr double kMarketSlippage = 0.02; // 2%

// Hyperliquid refuses any order worth less than this, spot included. Checked here so a too-small
// order is answered in the ticket instead of after a round trip to the exchange.
constexpr double kMinOrderUsdc = 10.0;

// The fraction of the USDC balance a Max buy commits. It cannot be the whole balance: the exchange
// charges a taker fee (well under 0.1% on spot) that the order still has to leave room for, or it is
// rejected for insufficient balance. A tenth of a percent covers that fee with a little to spare,
// where the old half-percent quietly left thirty dollars of a six-thousand-dollar balance unspent -
// which is exactly the "Max isn't the max" this is. Selling is exact and takes no haircut: the
// balance itself is what moves, and any fee comes out of the USDC received.
constexpr double kMaxBuyCommit = 0.999;

// How far a limit price may sit through the book before the confirmation treats it as a mistake
// rather than an intention. A limit order priced past the touch does not rest, it trades - so a
// price typed with a digit too many is not an order that can be cancelled, it is a trade that has
// already swept every level up to it.
constexpr double kFatFinger = 0.10; // 10% beyond the best price on the other side

// The book is refreshed on a timer rather than a socket: this is one market on one screen, and a
// few seconds of staleness costs nothing while a websocket would be another thing to keep alive
// over Tor.
constexpr int kPollMs = 5000;

// How long a book request is given before a fresh poll is allowed to start regardless. Generous
// because this may be going over Tor, but finite: a request that is never answered must not stop
// the screen updating for the rest of the session.
constexpr int kRequestTimeoutMs = 30000;

// Most levels shown per side. The actual count is whatever fits the box, capped here: beyond a
// dozen levels the far end of the book is noise on a market this thin.
constexpr int kBookLevels = 12;

// Fewest levels shown per side, whatever the height. Below three a side the book stops showing the
// shape of the market and starts showing an arbitrary corner of it.
constexpr int kMinBookLevels = 3;

// Aero's palette, as used across the rest of the window.
const char *kUp = "#27ae60";
const char *kDown = "#e74c3c";
const char *kMuted = "#8a8a8a";

QString money(double v, int decimals) {
    return QLocale().toString(v, 'f', decimals);
}

// Round *down* to `decimals`. Used wherever a figure is derived from a balance: rounding 1.239 up
// to 1.24 asks to sell more than is held, and the exchange simply refuses it.
//
// A bare floor is not enough. `0.29` cannot be held exactly in binary, so `0.29 * 100` is
// 28.999999999999996 and flooring it gives 0.28 - a whole step less than the balance, on 137 of the
// first 2000 hundredths. Anything within a hair of a whole step counts as that step; the tolerance
// scales with the number, so it stays far below one step at any size and far above the error being
// corrected for.
double truncTo(double v, int decimals) {
    const double factor = std::pow(10.0, decimals);
    const double scaled = v * factor;
    const double eps = 1e-12 * std::max(1.0, std::abs(scaled));
    const double steps =
        std::abs(std::round(scaled) - scaled) <= eps ? std::round(scaled) : std::floor(scaled);
    return steps / factor;
}

QString truncNum(double v, int decimals) {
    return QString::number(truncTo(v, decimals), 'f', decimals);
}

QString trimNum(double v, int decimals) {
    QString s = QString::number(v, 'f', decimals);
    if (s.contains('.')) {
        while (s.endsWith('0'))
            s.chop(1);
        if (s.endsWith('.'))
            s.chop(1);
    }
    return s;
}

// Whether a string could be a Monero address at all: the right prefix, the right length, and only
// characters from Monero's Base58 alphabet, which drops 0, I, O and l so look-alikes can't be
// confused. Deliberately not a checksum test - the core verifies properly before it commits to
// anything, and this only exists to answer an obviously wrong paste while it is being typed.
bool looksLikeMoneroAddress(const QString &address) {
    static const QString alphabet =
        QStringLiteral("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    if (!address.startsWith(QLatin1Char('4')) && !address.startsWith(QLatin1Char('8')))
        return false;
    if (address.size() != 95 && address.size() != 106)
        return false;
    return std::all_of(address.cbegin(), address.cend(),
                       [](QChar c) { return alphabet.contains(c); });
}

// Aero's tables: a flat tree with no expanders, matching the routes and history lists.
QTreeWidget *makeTable(QWidget *parent, const QStringList &headers, bool alternating) {
    auto *t = new QTreeWidget(parent);
    t->setColumnCount(headers.size());
    t->setHeaderLabels(headers);
    t->setRootIsDecorated(false);
    t->setUniformRowHeights(true);
    t->setAlternatingRowColors(alternating);
    t->setAllColumnsShowFocus(true);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->header()->setStretchLastSection(true);
    return t;
}

} // namespace

XmrTradeTab::XmrTradeTab(QWidget *parent) : QWidget(parent) {
    buildUi();
    restoreLayout();
    // Also on teardown: closing the window while this tab is showing never sends it a hide event.
    connect(qApp, &QCoreApplication::aboutToQuit, this, [this]() { saveLayout(); });
    m_poll = new QTimer(this);
    m_poll->setInterval(kPollMs);
    connect(m_poll, &QTimer::timeout, this, [this]() { refresh(false); });

    m_ageTick = new QTimer(this);
    m_ageTick->setInterval(1000);
    connect(m_ageTick, &QTimer::timeout, this, &XmrTradeTab::updateFreshness);
}

XmrTradeTab::~XmrTradeTab() { saveLayout(); }

bool XmrTradeTab::eventFilter(QObject *watched, QEvent *event) {
    if (m_book && watched == m_book->viewport() && event->type() == QEvent::Resize
        && !m_lastOverview.isEmpty()) {
        const int rowHeight = qMax(1, m_book->fontMetrics().height() + 6);
        const int fits = qMax(kMinBookLevels * 2 + 1,
                              static_cast<QResizeEvent *>(event)->size().height() / rowHeight);
        // Only when the number of rows that fit actually changes, and never from inside the layout
        // pass that delivered this event: redrawing the book sets its minimum height, which would
        // re-enter the layout that is still running.
        if (fits != m_bookRows)
            QTimer::singleShot(0, this, [this]() {
                if (!m_lastOverview.isEmpty())
                    fillBook(m_lastOverview);
            });
    }
    return QWidget::eventFilter(watched, event);
}

void XmrTradeTab::setWallet(Wallet *wallet, quint32 account, const QString &address) {
    if (m_wallet == wallet && m_account == account)
        return;
    // Whether the reply to anything already sent can still reach this tab. If the wallet object
    // itself changes, disconnecting drops that reply on the floor - and with it the setBusy(false)
    // that ends the busy state, leaving the ticket disabled for the rest of the session. Switching
    // accounts on the same wallet is different: the connection is remade below and the reply lands.
    const bool sameWallet = m_wallet == wallet;
    if (m_wallet)
        m_wallet->disconnect(this);

    m_wallet = wallet;
    m_account = account;
    m_address = address;

    // Anything on screen belongs to the previous account.
    m_xmr1 = m_usdc = m_bestBid = m_bestAsk = 0.0;
    m_agentReady = false;
    m_rawBids.clear();
    m_rawAsks.clear();
    m_lastOverview = QJsonObject();
    m_lastUpdate = QDateTime();  // nothing on screen is live until this account has answered
    m_refreshInFlight = false;
    if (!sameWallet)
        setBusy(false);
    m_book->clear();
    m_liquidity->clear();
    m_orders->clear();
    m_fills->clear();
    m_status->clear();
    // Shortened, so a 42-character address cannot set the width of the whole column; the full one is
    // a hover away and is what gets copied.
    const QString shortAddr = m_address.size() > 16
                                  ? m_address.left(8) + QStringLiteral("…") + m_address.right(6)
                                  : m_address;
    m_tradingAs->setText(m_address.isEmpty() ? QString() : tr("Trading as %1").arg(shortAddr));
    m_tradingAs->setToolTip(m_address);

    // A redemption in progress is deliberately NOT forgotten here. The XMR1 has already left and the
    // order id is the user's only handle on where it went, so switching accounts leaves it tracked
    // and reported rather than silently dropping it off the screen.
    if (!m_redeemOrderId.isEmpty())
        m_status->setText(tr("Still tracking redemption %1 from the previous account.")
                              .arg(m_redeemOrderId));

    if (!m_wallet)
        return;

    connect(m_wallet, &Wallet::hlOverviewReady, this, &XmrTradeTab::onOverview);
    connect(m_wallet, &Wallet::hlAgentReadyResult, this, &XmrTradeTab::onAgentReady);
    connect(m_wallet, &Wallet::hlAgentApproved, this, &XmrTradeTab::onAgentApproved);
    connect(m_wallet, &Wallet::hlOrderPlaced, this, &XmrTradeTab::onOrderPlaced);
    connect(m_wallet, &Wallet::hlOrderCancelled, this, &XmrTradeTab::onOrderCancelled);
    connect(m_wallet, &Wallet::hlWithdrawn, this, &XmrTradeTab::onWithdrawn);
    connect(m_wallet, &Wallet::hlClassTransferred, this, &XmrTradeTab::onClassTransferred);
    connect(m_wallet, &Wallet::hlDeposited, this, &XmrTradeTab::onDeposited);
    connect(m_wallet, &Wallet::xmrRedeemed, this, &XmrTradeTab::onRedeemed);
    connect(m_wallet, &Wallet::xmrRedeemStatusReady, this, &XmrTradeTab::onRedeemStatus);

    // A redemption from a previous run of Aero is still out there if it never reached a final state.
    if (m_redeemOrderId.isEmpty())
        restoreRedemption();

    if (isVisible())
        startPolling();
}

// Both entry points run this, because either order happens: the tab can be shown after a wallet is
// open, or a wallet can be bound while the tab is already showing. Starting the timers in showEvent
// alone left the second case with one snapshot and nothing after it - a screen that looked live and
// was not.
void XmrTradeTab::startPolling() {
    if (!m_wallet)
        return;
    m_wallet->hlAgentReady(m_account);
    refresh(true);
    m_poll->start();
    m_ageTick->start();
    updateFreshness();
}

void XmrTradeTab::showEvent(QShowEvent *event) {
    QWidget::showEvent(event);
    // Start at the top. In a window short enough to need scrolling, giving the price field focus
    // scrolls it into view, which opens the page below the warning about what XMR1 actually is.
    if (m_scroll)
        m_scroll->verticalScrollBar()->setValue(0);
    startPolling();
}

void XmrTradeTab::hideEvent(QHideEvent *event) {
    QWidget::hideEvent(event);
    m_poll->stop();
    m_ageTick->stop();
    saveLayout();
}

void XmrTradeTab::buildUi() {
    // Scrolling content with a pinned bar at the bottom, the same shape as the Swap tab. Without it
    // a short window squeezes the panels below their minimum and Qt overlaps the order form on
    // itself; this way the page scrolls and the funding buttons stay reachable.
    auto *content = new QWidget();
    auto *root = new QVBoxLayout(content);
    root->setContentsMargins(10, 10, 10, 10);
    root->setSpacing(8);

    // What XMR1 actually is, said plainly and before anything else. A user who reads only one line
    // in this tab should read this one.
    m_warning = new QLabel(
        tr("<b>XMR1 is not Monero.</b> It is a claim on Monero held by Wagyu, a pseudonymous "
           "operator with no proof of reserves that was accused in May 2026 of stalling "
           "redemptions. It is also <b>not private</b>: every balance and transfer is public on "
           "Hyperliquid. Redeeming it for real Monero costs 2%."),
        content);
    m_warning->setWordWrap(true);
    m_warning->setStyleSheet(QStringLiteral(
        "color:#c99a3a; background:rgba(200,150,0,0.10); border-radius:6px; padding:6px 8px; "
        "font-size:11px;"));
    root->addWidget(m_warning);

    m_agentRow = new QWidget(content);
    auto *agentLayout = new QHBoxLayout(m_agentRow);
    agentLayout->setContentsMargins(0, 0, 0, 0);
    m_agentBanner = new QLabel(m_agentRow);
    m_agentBanner->setWordWrap(true);
    m_agentBanner->setStyleSheet(QStringLiteral("color:%1;").arg(QString::fromLatin1(kMuted)));
    m_enableBtn = new QPushButton(tr("Enable trading"), m_agentRow);
    m_enableBtn->setCursor(Qt::PointingHandCursor);
    agentLayout->addWidget(m_agentBanner, 1);
    agentLayout->addWidget(m_enableBtn);
    root->addWidget(m_agentRow);
    connect(m_enableBtn, &QPushButton::clicked, this, [this]() {
        if (!m_wallet)
            return;
        const auto answer = QMessageBox::question(
            this, tr("Enable trading"),
            tr("Aero will ask the exchange to let a separate key place orders for this account.\n\n"
               "That key can only trade. It cannot withdraw or move funds, so orders never need the "
               "key that can. You sign this once."),
            QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Ok);
        if (answer != QMessageBox::Ok)
            return;
        setBusy(true);
        m_status->setText(tr("Authorising…"));
        m_wallet->hlApproveAgent(m_account);
    });

    // --- Order book ---
    // One caption line instead of a framed box. The frame cost a title bar, a border and two sets of
    // margins for no information, and at Aero's default window height that was the difference
    // between the market and the Buy button both being on screen.
    auto *bookBox = new QWidget(content);
    auto *bookLayout = new QVBoxLayout(bookBox);
    bookLayout->setContentsMargins(0, 0, 0, 0);
    bookLayout->setSpacing(4);

    // Grouping the book into coarser price steps is how you see where the size actually is: at the
    // exchange's 0.01 tick a hundred XMR1 spread over a cent of price reads as a dozen thin rows,
    // and at 0.50 the same depth reads as one line you can act on.
    auto *bookHeader = new QHBoxLayout();
    // How much there is to trade is the headline, in the place a panel title would otherwise sit.
    // "XMR1/USDC" was a title that told nobody anything they did not already know from the tab they
    // clicked, and this line costs no extra height for something they came here to find out.
    m_depth = new QLabel(bookBox);
    m_depth->setTextFormat(Qt::RichText);
    // Not wrapped, and its width ignored: a wrapping label reports a minimum height for the
    // narrowest width it might ever be given, which reserved three lines for one line of text.
    m_depth->setWordWrap(false);
    m_depth->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    // Free to be squeezed by a narrow column rather than setting a floor under one: without this the
    // sentence would be the reason the book could not be dragged narrower than its own text.
    m_depth->setMinimumWidth(1);
    m_depth->setToolTip(tr("Counts every price level the exchange publishes for this market, which "
                           "is the twenty nearest the spread on each side."));
    bookHeader->addWidget(m_depth);
    m_live = new QLabel(bookBox);
    bookHeader->addWidget(m_live);
    bookHeader->addStretch(1);
    auto *groupLbl = new QLabel(tr("Group by"), bookBox);
    groupLbl->setStyleSheet(
        QStringLiteral("color:%1; font-size:11px;").arg(QString::fromLatin1(kMuted)));
    m_group = new QComboBox(bookBox);
    for (double step : {0.01, 0.10, 0.50, 1.00})
        m_group->addItem(QStringLiteral("%1").arg(step, 0, 'f', 2), step);
    m_group->setCurrentIndex(1); // 0.10 - a tenth of a dollar on a ~$380 coin
    m_group->setFixedWidth(80);
    bookHeader->addWidget(groupLbl);
    bookHeader->addWidget(m_group);
    bookLayout->addLayout(bookHeader);
    // Re-bucket from the snapshot in hand rather than waiting up to five seconds for the next poll.
    connect(m_group, &QComboBox::currentIndexChanged, this, [this](int) {
        if (!m_lastOverview.isEmpty())
            fillBook(m_lastOverview);
    });

    m_book = makeTable(bookBox, {tr("Price (USDC)"), tr("Size (XMR1)"), tr("Total")}, false);
    m_book->header()->setSectionResizeMode(QHeaderView::Stretch);
    for (int c = 0; c < 3; ++c)
        m_book->headerItem()->setTextAlignment(c, Qt::AlignRight | Qt::AlignVCenter);
    // The level count is fitted to whatever height the box gets, so the whole book is always on
    // screen: it is read as a shape around the spread, and scrolling one hides the half that matters.
    m_book->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_book->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    // A price level isn't a thing you select, it's a thing you click to take the price. Leaving
    // selection on left a highlighted row sitting over the depth shading long after the click, which
    // reads as state that doesn't exist.
    m_book->setSelectionMode(QAbstractItemView::NoSelection);
    m_book->setFocusPolicy(Qt::NoFocus);
    // Five levels or so at the default window size, growing into whatever a larger window gives it.
    m_book->setMinimumHeight(140);
    // The height it asks for is ignored, so it takes what is going and no more. A table's own size
    // hint is a generic 192 pixels, and inside a scroll area that asking price became a scrollbar
    // and a page that opened below its own first line.
    m_book->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Ignored);
    // Figures in a book are read as columns of digits, so they get the system's fixed-width face:
    // with proportional digits the decimal points wander from row to row and the depth is much
    // harder to compare down the column.
    QFont bookFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    bookFont.setPointSizeF(m_book->font().pointSizeF());
    m_book->setFont(bookFont);
    m_book->viewport()->installEventFilter(this);
    bookLayout->addWidget(m_book, 1);

    // The book and the cost table stack in the same column as the order form beside them, so the
    // page is only as tall as the taller column. Stacked below both instead, the two would add up
    // and push everything past the fold at Aero's default window size.
    //
    // The divisions that are worth dragging are splitters, because how much of the screen the book
    // deserves against the order form or the open-order list depends on what you are doing. This one
    // is not among them: the cost table is exactly as tall as its five rows, so all that is left to
    // decide is that everything else goes to the book.
    auto *leftPane = new QWidget(content);
    auto *leftCol = new QVBoxLayout(leftPane);
    leftCol->setContentsMargins(0, 0, 0, 0);
    leftCol->setSpacing(6);
    leftCol->addWidget(bookBox, 1);

    // Clicking a level puts its price in the ticket - the reason anyone looks at a book.
    connect(m_book, &QTreeWidget::itemClicked, this, [this](QTreeWidgetItem *item, int) {
        if (!item)
            return;
        const double px = item->data(0, Qt::UserRole).toDouble();
        if (px <= 0.0)
            return;
        m_price->setText(trimNum(px, m_pxDecimals));
        if (m_type->currentIndex() != 0)
            m_type->setCurrentIndex(0); // a clicked price means a limit order
        updateTotals();
    });

    // --- Order ticket ---
    // Captioned, not framed, to match the book beside it. A framed box next to an unframed one read
    // as two unrelated things bolted together, and the frame cost this column a title bar and two
    // sets of margins that the Buy button was being pushed off the bottom of the window by.
    auto *ticket = new QWidget(content);
    auto *t = new QVBoxLayout(ticket);
    t->setContentsMargins(0, 0, 0, 0);
    t->setSpacing(5);
    auto *ticketCaption = new QLabel(tr("Place an order"), ticket);
    ticketCaption->setStyleSheet(
        QStringLiteral("color:%1; font-weight:bold;").arg(QString::fromLatin1(kMuted)));
    t->addWidget(ticketCaption);

    m_balances = new QLabel(ticket);
    m_balances->setTextFormat(Qt::RichText);
    m_balances->setWordWrap(true);
    t->addWidget(m_balances);

    // The on-chain USDC this wallet holds on Arbitrum One - what a deposit would move onto the
    // exchange. Kept next to the balances so "how much can I deposit" is answered before the button
    // is pressed, not inside the dialog after it.
    m_walletUsdc = new QLabel(ticket);
    m_walletUsdc->setTextFormat(Qt::RichText);
    m_walletUsdc->setWordWrap(true);
    m_walletUsdc->setOpenExternalLinks(false);
    connect(m_walletUsdc, &QLabel::linkActivated, this,
            [this](const QString &) { emit switchToArbitrumRequested(); });
    t->addWidget(m_walletUsdc);
    m_walletUsdc->hide();

    // Shown only when USDC has landed in the perp wallet but is not yet in spot - a fresh deposit,
    // most often. Without this the money is simply invisible on the trading screen, which is exactly
    // what "it says it credited but I have 0.00" looks like.
    auto *perpRow = new QHBoxLayout();
    perpRow->setContentsMargins(0, 0, 0, 0);
    m_perpNote = new QLabel(ticket);
    m_perpNote->setTextFormat(Qt::RichText);
    m_perpNote->setWordWrap(true);
    m_toSpotBtn = new QPushButton(tr("Move to spot"), ticket);
    m_toSpotBtn->setCursor(Qt::PointingHandCursor);
    perpRow->addWidget(m_perpNote, 1);
    perpRow->addWidget(m_toSpotBtn, 0, Qt::AlignTop);
    t->addLayout(perpRow);
    m_perpNote->hide();
    m_toSpotBtn->hide();
    connect(m_toSpotBtn, &QPushButton::clicked, this, &XmrTradeTab::moveToSpot);

    auto *form = new QFormLayout();
    form->setVerticalSpacing(4);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    auto *sideRow = new QHBoxLayout();
    m_side = new QComboBox(ticket);
    m_side->addItem(tr("Buy XMR1"));
    m_side->addItem(tr("Sell XMR1"));
    m_type = new QComboBox(ticket);
    m_type->addItem(tr("Limit"));
    m_type->addItem(tr("Market"));
    sideRow->addWidget(m_side, 1);
    sideRow->addWidget(m_type, 1);
    form->addRow(tr("Order"), sideRow);

    m_price = new QLineEdit(ticket);
    // The validator is pinned to the C locale because every reader of these fields is
    // QString::toDouble(), which only ever understands '.'. Left on the system locale, a machine
    // that writes decimals with a comma would accept "1,5" here and trade 1 - the wrong amount,
    // silently.
    auto *priceValidator = new QDoubleValidator(0.0, 1e9, 8, m_price);
    priceValidator->setLocale(QLocale::c());
    m_price->setValidator(priceValidator);
    m_price->setPlaceholderText(tr("USDC per XMR1"));
    form->addRow(tr("Price"), m_price);

    auto *sizeRow = new QHBoxLayout();
    m_size = new QLineEdit(ticket);
    auto *sizeValidator = new QDoubleValidator(0.0, 1e9, 8, m_size);
    sizeValidator->setLocale(QLocale::c());
    m_size->setValidator(sizeValidator);
    m_size->setPlaceholderText(tr("XMR1"));
    m_maxBtn = new QPushButton(tr("Max"), ticket);
    m_maxBtn->setFixedWidth(48);
    m_maxBtn->setCursor(Qt::PointingHandCursor);
    sizeRow->addWidget(m_size, 1);
    sizeRow->addWidget(m_maxBtn);
    form->addRow(tr("Amount"), sizeRow);

    // Post-only turns a resting limit from GTC into ALO: it adds liquidity or is rejected, so it
    // never crosses the book and never pays the taker fee. It has no meaning on a market order, so
    // it is shown only for limit orders and passed through only then.
    m_postOnly = new QCheckBox(tr("Post-only (maker)"), ticket);
    m_postOnly->setCursor(Qt::PointingHandCursor);
    m_postOnly->setToolTip(tr("Only add liquidity. The order rests on the book and is rejected if it "
                              "would trade immediately, so it always pays the maker fee rather than "
                              "the taker fee."));
    m_postOnly->setStyleSheet(
        QStringLiteral("color:%1; font-size:11px;").arg(QString::fromLatin1(kMuted)));
    form->addRow(QString(), m_postOnly);

    t->addLayout(form);

    m_total = new QLabel(ticket);
    m_total->setTextFormat(Qt::RichText);
    m_total->setWordWrap(true);
    t->addWidget(m_total);

    // Which address is trading. The tab follows the selected account, and orders, balances and the
    // redemption payout all belong to that one - so it says which, rather than leaving it to be
    // inferred from whichever row is selected over on Receive.
    m_tradingAs = new QLabel(ticket);
    // One line, elided if the column is narrow: it is a reminder of which account this is, and it
    // should not cost the ticket a second line to be one.
    m_tradingAs->setWordWrap(false);
    m_tradingAs->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_tradingAs->setStyleSheet(
        QStringLiteral("color:%1; font-size:11px;").arg(QString::fromLatin1(kMuted)));
    t->addWidget(m_tradingAs);

    m_placeBtn = new QPushButton(tr("Buy XMR1"), ticket);
    m_placeBtn->setCursor(Qt::PointingHandCursor);
    m_placeBtn->setMinimumHeight(30);
    t->addWidget(m_placeBtn);

    // --- How much can actually be traded, and what it costs ---
    // The book shows the best price; it does not answer the two questions anyone actually has, which
    // are how much XMR1 is there to buy or sell at all, and what a given size would come to once it
    // has eaten through several levels. Both are read off the live book here and restated in plain
    // words, because deriving them from the shape of the depth bars is a skill, not a design.
    // Sizes across the columns and the two directions down the rows, rather than the other way
    // round. It is two lines instead of five, and the figure you want to compare - the same size
    // bought against sold - ends up in one column instead of at opposite ends of a wide row.
    m_liquidity = makeTable(bookBox, {QString()}, true);
    m_liquidity->setSelectionMode(QAbstractItemView::NoSelection);
    m_liquidity->setFocusPolicy(Qt::NoFocus);
    m_liquidity->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_liquidity->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_liquidity->header()->setSectionResizeMode(QHeaderView::Stretch);
    QFont liqFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    liqFont.setPointSizeF(m_liquidity->font().pointSizeF());
    m_liquidity->setFont(liqFont);

    m_hSplit = new QSplitter(Qt::Horizontal, content);
    m_hSplit->setChildrenCollapsible(false);
    // The ticket hugs its fields instead of stretching to the height of the book beside it. Stretched,
    // a tall window opened a blank half-frame between the amount and the Buy button that reads as
    // something failing to load.
    auto *ticketPane = new QWidget(content);
    auto *ticketCol = new QVBoxLayout(ticketPane);
    ticketCol->setContentsMargins(0, 0, 0, 0);
    ticketCol->addWidget(ticket);
    ticketCol->addStretch(1);

    m_hSplit->addWidget(leftPane);
    m_hSplit->addWidget(ticketPane);
    m_hSplit->setStretchFactor(0, 3);
    m_hSplit->setStretchFactor(1, 2);

    // --- Open orders / fills ---
    m_tabs = new QTabWidget(content);
    m_orders = makeTable(m_tabs, {tr("Side"), tr("Price"), tr("Size"), tr("Placed"), tr("Order")},
                         true);
    m_fills = makeTable(m_tabs, {tr("Side"), tr("Price"), tr("Size"), tr("Fee"), tr("When")}, true);
    m_fills->setSelectionMode(QAbstractItemView::NoSelection);

    auto *ordersPage = new QWidget(m_tabs);
    auto *ov = new QVBoxLayout(ordersPage);
    ov->setContentsMargins(0, 0, 0, 0);
    ov->addWidget(m_orders, 1);
    m_cancelBtn = new QPushButton(tr("Cancel selected order"), ordersPage);
    m_cancelBtn->setEnabled(false);
    m_cancelBtn->setCursor(Qt::PointingHandCursor);
    auto *ocRow = new QHBoxLayout();
    ocRow->addStretch(1);
    ocRow->addWidget(m_cancelBtn);
    ov->addLayout(ocRow);
    connect(m_orders, &QTreeWidget::itemSelectionChanged, this, [this]() {
        m_cancelBtn->setEnabled(!m_inFlight && !m_orders->selectedItems().isEmpty());
    });
    connect(m_cancelBtn, &QPushButton::clicked, this, &XmrTradeTab::cancelSelected);

    // The cost ladder lives here rather than under the book. This strip sits outside the scrolling
    // area, so whatever is in it is on screen at any window height, and what a trade would cost is
    // worth that more than a fourth and fifth level of the book was. It leads, because it is the
    // question you have before you have any orders to look at.
    auto *liqPage = new QWidget(m_tabs);
    auto *lv = new QVBoxLayout(liqPage);
    lv->setContentsMargins(0, 0, 0, 0);
    lv->addWidget(m_liquidity);
    lv->addStretch(1);
    m_liquidity->setParent(liqPage);

    m_tabs->addTab(liqPage, tr("What a trade costs"));
    m_tabs->addTab(ordersPage, tr("Open orders"));
    m_tabs->addTab(m_fills, tr("Recent fills"));
    // No height cap any more: the splitter below decides how this is divided against the book, and
    // capping it here would silently override a division the user had dragged for themselves. The
    // floor is the tab bar plus the ladder's three rows, so the tab that leads is never half shown.
    m_tabs->setMinimumHeight(104);

    root->addWidget(m_hSplit, 1);

    m_scroll = new QScrollArea(this);
    QScrollArea *scroll = m_scroll;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setWidget(content);
    scroll->setMinimumHeight(160);

    // What is resting on the exchange sits outside the scrolling area, so it is on screen whether or
    // not the window is tall enough for everything above it. An open order you have forgotten about
    // is the one that fills at a price you would not choose now, and it should never be something
    // you have to go looking for.
    m_vSplit = new QSplitter(Qt::Vertical, this);
    m_vSplit->setChildrenCollapsible(false);
    m_vSplit->addWidget(scroll);
    m_vSplit->addWidget(m_tabs);
    m_vSplit->setStretchFactor(0, 3);
    m_vSplit->setStretchFactor(1, 1);
    // Start with the order list at about its minimum and everything else to the book and the ticket.
    // On a short window that is the difference between the Buy button being on screen or under the
    // fold, and an empty order list is not worth that.
    m_vSplit->setSizes({10000, 80});

    // --- Status + funding, pinned at the bottom like the Swap tab's confirm bar ---
    auto *bar = new QWidget(this);
    auto *barLayout = new QVBoxLayout(bar);
    barLayout->setContentsMargins(12, 6, 12, 8);
    barLayout->setSpacing(6);
    m_status = new QLabel(bar);
    m_status->setWordWrap(true);

    // Status and funding share one row. This bar is pinned, so every line it takes is a line the
    // book above it does not get, and at Aero's default window height that is a real trade.
    auto *fundRow = new QHBoxLayout();
    fundRow->addWidget(m_status, 1);
    m_depositBtn = new QPushButton(tr("Deposit USDC…"), bar);
    m_withdrawBtn = new QPushButton(tr("Withdraw USDC…"), bar);
    m_redeemBtn = new QPushButton(tr("Withdraw XMR…"), bar);
    for (auto *b : {m_depositBtn, m_withdrawBtn, m_redeemBtn})
        b->setCursor(Qt::PointingHandCursor);
    fundRow->addSpacing(8);
    fundRow->addWidget(m_depositBtn);
    fundRow->addWidget(m_withdrawBtn);
    fundRow->addWidget(m_redeemBtn);
    barLayout->addLayout(fundRow);

    auto *page = new QVBoxLayout(this);
    page->setContentsMargins(0, 0, 0, 0);
    page->setSpacing(0);
    page->addWidget(m_vSplit, 1);
    page->addWidget(bar);
    connect(m_depositBtn, &QPushButton::clicked, this, &XmrTradeTab::deposit);
    connect(m_withdrawBtn, &QPushButton::clicked, this, &XmrTradeTab::withdraw);
    connect(m_redeemBtn, &QPushButton::clicked, this, &XmrTradeTab::redeem);

    connect(m_placeBtn, &QPushButton::clicked, this, &XmrTradeTab::placeOrder);
    connect(m_price, &QLineEdit::textChanged, this, &XmrTradeTab::updateTotals);
    connect(m_size, &QLineEdit::textChanged, this, &XmrTradeTab::updateTotals);
    connect(m_maxBtn, &QPushButton::clicked, this, [this]() {
        const bool isBuy = m_side->currentIndex() == 0;
        const double avail = available(isBuy);
        if (isBuy && m_type->currentIndex() == 1) {
            // Buying at the market: spend down the balance level by level. Dividing it by a single
            // price would overstate what it buys, because a size past the first level is filled at
            // worse prices than the first level quotes. The haircut leaves room for the taker fee
            // and for the book moving between here and the fill.
            double budget = avail * kMaxBuyCommit;
            double bought = 0.0;
            for (const Level &lvl : m_rawAsks) {
                if (budget <= 0.0)
                    break;
                const double take = qMin(lvl.sz, budget / lvl.px);
                bought += take;
                budget -= take * lvl.px;
            }
            m_size->setText(truncNum(bought, m_szDecimals));
        } else if (isBuy) {
            // Buying at a limit: the price is known, so this is just division, with the same
            // haircut for the fee.
            const double px = m_price->text().toDouble();
            if (px > 0.0)
                m_size->setText(truncNum(avail / px * kMaxBuyCommit, m_szDecimals));
        } else {
            // Selling: the balance is the thing being sold, so it is exact - but it must be rounded
            // down to a tick, since rounding up would ask for more XMR1 than the account holds.
            m_size->setText(truncNum(avail, m_szDecimals));
        }
    });
    connect(m_side, &QComboBox::currentIndexChanged, this, [this](int i) {
        m_placeBtn->setText(i == 0 ? tr("Buy XMR1") : tr("Sell XMR1"));
        updateTotals();
    });
    connect(m_type, &QComboBox::currentIndexChanged, this, [this](int i) {
        const bool market = i == 1;
        m_price->setEnabled(!market);
        m_price->setPlaceholderText(market ? tr("at the market") : tr("USDC per XMR1"));
        m_postOnly->setVisible(!market); // add-liquidity-only is meaningless on a market order
        updateTotals();
    });
}

void XmrTradeTab::refresh(bool force) {
    if (!m_wallet)
        return;
    // Skip a scheduled poll while the previous one is still out. Over Tor a request can easily take
    // longer than the poll interval, and without this the requests overlap: each one costs a circuit
    // and the replies can arrive out of order, so an older book can land after a newer one and the
    // screen goes backwards. The elapsed check means a request that never returns unwedges polling
    // instead of stopping it for good.
    if (!force && m_refreshInFlight && m_refreshStarted.isValid()
        && m_refreshStarted.msecsTo(QDateTime::currentDateTime()) < kRequestTimeoutMs)
        return;

    m_refreshInFlight = true;
    m_refreshStarted = QDateTime::currentDateTime();
    m_wallet->hlOverview(m_account);
}

// Where the user dragged the dividers, kept per install like the rest of Aero's window state. A
// layout you have to set up again on every launch is barely worth being able to set up at all.
void XmrTradeTab::saveLayout() const {
    if (!m_vSplit)
        return;
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    s.setValue(QStringLiteral("xmr/splitVertical"), m_vSplit->saveState());
    s.setValue(QStringLiteral("xmr/splitHorizontal"), m_hSplit->saveState());
}

void XmrTradeTab::restoreLayout() {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    const auto v = s.value(QStringLiteral("xmr/splitVertical")).toByteArray();
    const auto h = s.value(QStringLiteral("xmr/splitHorizontal")).toByteArray();
    if (!v.isEmpty())
        m_vSplit->restoreState(v);
    if (!h.isEmpty())
        m_hSplit->restoreState(h);
}

void XmrTradeTab::updateFreshness() {
    if (!m_lastUpdate.isValid()) {
        m_live->setText(m_wallet ? tr("connecting…") : QString());
        m_live->setStyleSheet(
            QStringLiteral("color:%1; font-size:11px;").arg(QString::fromLatin1(kMuted)));
        return;
    }
    const qint64 age = m_lastUpdate.secsTo(QDateTime::currentDateTime());
    // Two missed polls is the point where the prices on screen stop being worth trusting, so that is
    // where the label stops being quiet grey and says so.
    const bool stale = age > (kPollMs / 1000) * 2;
    m_live->setText(age < 2 ? tr("live") : tr("updated %1s ago").arg(age));
    m_live->setStyleSheet(QStringLiteral("color:%1; font-size:11px;")
                              .arg(QString::fromLatin1(stale ? kDown : kMuted)));
}

void XmrTradeTab::setBusy(bool busy) {
    m_inFlight = busy;
    m_placeBtn->setEnabled(!busy && m_agentReady);
    m_enableBtn->setEnabled(!busy);
    m_cancelBtn->setEnabled(!busy && !m_orders->selectedItems().isEmpty());
    m_depositBtn->setEnabled(!busy);
    m_withdrawBtn->setEnabled(!busy);
    // Redeeming is signed by the account key, not the trading agent, so it stays available on an
    // account that has never enabled trading - someone who only wants their XMR out should not have
    // to authorise trading first.
    m_redeemBtn->setEnabled(!busy && m_xmr1 > 0.0);
    if (m_toSpotBtn)
        m_toSpotBtn->setEnabled(!busy);
    // The perp row carries its own move button, so it has to follow the busy state too: hidden while
    // a transfer is in flight, back once it settles.
    updatePerpNote();
}

double XmrTradeTab::available(bool isBuy) const {
    return isBuy ? m_usdc : m_xmr1;
}

double XmrTradeTab::marketCap(bool isBuy, double size) const {
    // A market order here is an IOC limit, so this price is the whole of what it will and won't do:
    // it must reach far enough through the book to fill the size asked for, and no further.
    //
    // Pricing it off the top of the book alone was wrong on exactly the orders that matter. This
    // book holds a few units a level, so any size past the first level needs a price past the first
    // level too - and an IOC that only reaches the first level fills that much and cancels the rest,
    // which reads as the order having half worked for no stated reason. So the reach is measured
    // against the levels the size actually consumes, and the allowance is added beyond that to
    // absorb whatever moves between this snapshot and the fill.
    const QVector<Level> &side = isBuy ? m_rawAsks : m_rawBids;
    const double best = isBuy ? m_bestAsk : m_bestBid;
    if (best <= 0.0)
        return 0.0;
    const Walk w = walk(side, size);
    const double reach = w.worst > 0.0 ? w.worst : best;
    return isBuy ? reach * (1.0 + kMarketSlippage) : reach * (1.0 - kMarketSlippage);
}

double XmrTradeTab::wirePrice(double price, bool isBuy) const {
    // Mirrors core/src/hyperliquid.rs::format_price, but rounds in the user's favour instead of to
    // nearest: a buy limit is floored so it never rests above the price typed, and a sell limit is
    // ceiled so it never rests below it. Because this lands on the exact tick the exchange accepts,
    // the core's round-to-nearest is then a no-op, so the string it sends matches this value.
    if (price <= 0.0)
        return 0.0;
    const int magnitude = static_cast<int>(std::floor(std::log10(price)));
    const int sigDecimals = std::max(0, 4 - magnitude); // at most five significant figures
    const int decimals = std::min(sigDecimals, m_pxDecimals);
    const double factor = std::pow(10.0, decimals);
    const double scaled = price * factor;
    // A price already on the tick must stay put: the epsilon keeps binary error (164.57 held as
    // 164.5699999) from being floored a whole tick down, or ceiled one up.
    const double eps = 1e-9 * std::max(1.0, std::abs(scaled));
    const double stepped = isBuy ? std::floor(scaled + eps) : std::ceil(scaled - eps);
    return stepped / factor;
}

void XmrTradeTab::onAgentReady(bool ready, const QString &error) {
    m_agentReady = ready && error.isEmpty();
    m_agentRow->setVisible(!m_agentReady);
    if (!m_agentReady) {
        m_agentBanner->setText(
            error.isEmpty()
                ? tr("Trading isn't enabled for this account yet. Aero signs orders with a key that "
                     "can trade but cannot withdraw. Authorise it once to start.")
                : tr("Couldn't check whether trading is enabled: %1").arg(error));
    }
    m_placeBtn->setEnabled(m_agentReady && !m_inFlight);
}

void XmrTradeTab::onAgentApproved(const QString &error) {
    setBusy(false);
    if (!error.isEmpty()) {
        m_status->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                              .arg(QString::fromLatin1(kDown), error.toHtmlEscaped()));
        return;
    }
    m_status->setText(tr("Trading enabled."));
    m_wallet->hlAgentReady(m_account);
}

void XmrTradeTab::onOverview(quint32 account, const QString &json, const QString &error) {
    if (account != m_account)
        return; // the previous account's request, still in flight when the account changed
    m_refreshInFlight = false;
    if (!error.isEmpty()) {
        updateFreshness(); // a failed poll ages the data on screen; say so rather than look live
        // Reported without wiping the book: a failed poll means these prices are stale, not gone,
        // and blanking the screen every time a request times out is worse than saying so.
        m_status->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                              .arg(QString::fromLatin1(kDown),
                                   tr("Couldn't reach the exchange: %1").arg(error).toHtmlEscaped()));
        return;
    }
    const QJsonObject data = QJsonDocument::fromJson(json.toUtf8()).object();
    m_lastOverview = data; // so changing the grouping can redraw without another round trip
    m_lastUpdate = QDateTime::currentDateTime();
    updateFreshness();
    m_szDecimals = data.value(QStringLiteral("sz_decimals")).toInt(2);
    m_pxDecimals = data.value(QStringLiteral("px_decimals")).toInt(6);

    const QJsonObject xmr1 = data.value(QStringLiteral("xmr1")).toObject();
    const QJsonObject usdc = data.value(QStringLiteral("usdc")).toObject();
    // What can actually be spent: resting orders hold part of the balance.
    m_xmr1 = xmr1.value(QStringLiteral("total")).toString().toDouble()
             - xmr1.value(QStringLiteral("hold")).toString().toDouble();
    m_usdc = usdc.value(QStringLiteral("total")).toString().toDouble()
             - usdc.value(QStringLiteral("hold")).toString().toDouble();
    // USDC still in the perp wallet - a deposit that has credited but is not yet tradable.
    m_usdcPerp = data.value(QStringLiteral("usdc_perp")).toString().toDouble();
    // On-chain USDC on Arbitrum - what a deposit would move onto the exchange. Empty (and
    // m_onArbitrum false) when the wallet is on another chain, where there is nothing to deposit.
    m_onArbitrum = data.value(QStringLiteral("on_arbitrum")).toBool();
    m_usdcArb = data.value(QStringLiteral("usdc_arb")).toString().toDouble();

    m_balances->setText(tr("<b>%1</b> XMR1 &nbsp;&nbsp; <b>%2</b> USDC "
                           "<span style='color:%3'>available to trade</span>")
                            .arg(money(m_xmr1, 4), money(m_usdc, 2),
                                 QString::fromLatin1(kMuted)));

    updatePerpNote();
    updateWalletUsdc();
    maybeSweepDeposit();

    fillBook(data);
    fillOrders(data);
    fillFills(data);
    updateTotals();
    setBusy(m_inFlight); // the balance just moved, and redeeming depends on it
}

void XmrTradeTab::updatePerpNote() {
    if (!m_perpNote || !m_toSpotBtn)
        return;
    // A little dust can linger in perp from rounding; below a cent there is nothing worth moving and
    // the row would just nag. The exchange also will not transfer a zero.
    if (m_usdcPerp < 0.01 || m_inFlight) {
        m_perpNote->hide();
        m_toSpotBtn->hide();
        return;
    }
    m_perpNote->setText(tr("<span style='color:%1'><b>%2</b> USDC arrived in your perps balance. "
                           "Move it to spot to trade or withdraw it.</span>")
                            .arg(QString::fromLatin1(kDown), money(m_usdcPerp, 2)));
    m_perpNote->show();
    m_toSpotBtn->show();
}

void XmrTradeTab::updateWalletUsdc() {
    if (!m_walletUsdc)
        return;
    // Off Arbitrum there is nothing here to deposit from, so rather than show a misleading zero the
    // row says what has to change and offers to change it. The link fires switchToArbitrumRequested,
    // which the main window turns into a chain switch.
    if (!m_onArbitrum) {
        m_walletUsdc->setText(tr("<span style='color:%1'>To deposit USDC, "
                                 "<a href='#'>switch this wallet to Arbitrum One</a>.</span>")
                                  .arg(QString::fromLatin1(kMuted)));
        m_walletUsdc->show();
        return;
    }
    // On Arbitrum: show the wallet's USDC, which is exactly what the deposit button can move onto the
    // exchange. Shown even at zero so "nothing to deposit" is explicit rather than a blank.
    m_walletUsdc->setText(tr("<span style='color:%1'><b>%2</b> USDC in your wallet on Arbitrum, "
                             "available to deposit.</span>")
                              .arg(QString::fromLatin1(kMuted), money(m_usdcArb, 2)));
    m_walletUsdc->show();
}

void XmrTradeTab::maybeSweepDeposit() {
    if (!m_awaitingDepositCredit || m_inFlight)
        return;
    // Give up waiting after a few minutes: the credit either never came (a deposit below the
    // bridge's minimum, say) or the user has already moved it by hand. The perp row still offers the
    // move, so nothing is stranded - this only stops the automatic sweep from firing forever.
    if (m_depositCreditDeadline.isValid()
        && QDateTime::currentDateTime() > m_depositCreditDeadline) {
        m_awaitingDepositCredit = false;
        return;
    }
    // The deposit has landed once perp USDC climbs past where it was when the deposit was sent. Sweep
    // the whole perp balance into spot in one move - in this wallet USDC only ever belongs in spot,
    // where XMR1 trades.
    if (m_usdcPerp > m_perpBeforeDeposit + 0.01) {
        m_awaitingDepositCredit = false;
        m_status->setText(tr("Deposit credited. Moving it to your spot balance to trade…"));
        setBusy(true);
        m_wallet->hlClassTransfer(m_account, truncNum(m_usdcPerp, 6), false);
    }
}

void XmrTradeTab::moveToSpot() {
    if (!m_wallet || m_usdcPerp < 0.01)
        return;
    m_awaitingDepositCredit = false; // a manual move settles what the sweep was waiting for
    setBusy(true);
    m_status->setText(tr("Moving %1 USDC to your spot balance…").arg(money(m_usdcPerp, 2)));
    m_wallet->hlClassTransfer(m_account, truncNum(m_usdcPerp, 6), false);
}

void XmrTradeTab::onClassTransferred(const QString &error) {
    setBusy(false);
    if (!error.isEmpty()) {
        m_status->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                              .arg(QString::fromLatin1(kDown), error.toHtmlEscaped()));
    } else {
        m_status->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                              .arg(QString::fromLatin1(kUp),
                                   tr("USDC moved to spot. You can trade it now.")));
    }
    refresh(true);
}

double XmrTradeTab::groupStep() const {
    const double step = m_group ? m_group->currentData().toDouble() : 0.01;
    return step > 0.0 ? step : 0.01;
}

XmrTradeTab::Walk XmrTradeTab::walk(const QVector<Level> &side, double size) {
    Walk w;
    if (size <= 0.0)
        return w;
    double remaining = size;
    for (const Level &lvl : side) {
        if (remaining <= 0.0)
            break;
        const double take = qMin(remaining, lvl.sz);
        w.filled += take;
        w.cost += take * lvl.px;
        w.worst = lvl.px; // the levels arrive best first, so the last one touched is the worst
        remaining -= take;
    }
    w.complete = remaining <= 1e-12;
    if (w.filled > 0.0)
        w.avg = w.cost / w.filled;
    return w;
}

QVector<XmrTradeTab::Level> XmrTradeTab::levelsWithin(const QVector<Level> &side, double limit,
                                                      bool isBuy) {
    QVector<Level> out;
    for (const Level &lvl : side) {
        if (isBuy ? lvl.px > limit : lvl.px < limit)
            break; // best first, so everything after this is further beyond the limit
        out.push_back(lvl);
    }
    return out;
}

bool XmrTradeTab::crosses(bool isBuy, double price) const {
    const double touch = isBuy ? m_bestAsk : m_bestBid;
    if (touch <= 0.0 || price <= 0.0)
        return false;
    return isBuy ? price >= touch : price <= touch;
}

void XmrTradeTab::fillBook(const QJsonObject &data) {
    const QJsonArray bids = data.value(QStringLiteral("bids")).toArray();
    const QJsonArray asks = data.value(QStringLiteral("asks")).toArray();

    auto parse = [](const QJsonArray &side) {
        QVector<Level> out;
        out.reserve(side.size());
        for (const QJsonValue &v : side) {
            const QJsonObject o = v.toObject();
            Level lvl;
            lvl.px = o.value(QStringLiteral("px")).toString().toDouble();
            lvl.sz = o.value(QStringLiteral("sz")).toString().toDouble();
            if (lvl.px > 0.0 && lvl.sz > 0.0)
                out.append(lvl);
        }
        return out;
    };
    m_rawBids = parse(bids);
    m_rawAsks = parse(asks);
    m_bestBid = m_rawBids.isEmpty() ? 0.0 : m_rawBids.first().px;
    m_bestAsk = m_rawAsks.isEmpty() ? 0.0 : m_rawAsks.first().px;

    // Bucket the levels into the chosen price step for display. Bids round down and asks round up,
    // so a bucket is always a price you could actually deal at: every order inside an ask bucket is
    // at or below its label, and every order inside a bid bucket at or above.
    const double step = groupStep();
    auto group = [step](const QVector<Level> &side, bool ask) {
        QVector<Level> out;
        for (const Level &lvl : side) {
            const double bucket =
                ask ? std::ceil(lvl.px / step - 1e-9) * step : std::floor(lvl.px / step + 1e-9) * step;
            if (!out.isEmpty() && std::abs(out.last().px - bucket) < step / 2.0)
                out.last().sz += lvl.sz; // same bucket as the level before it
            else
                out.append(Level{bucket, lvl.sz});
        }
        return out;
    };
    const QVector<Level> groupedAsks = group(m_rawAsks, true);
    const QVector<Level> groupedBids = group(m_rawBids, false);

    // Show as many levels per side as the box can hold, so the whole book fits without scrolling and
    // the spread sits in the middle by construction.
    const int rowHeight = qMax(1, m_book->fontMetrics().height() + 6);
    // A book that has been squeezed until only one side of it shows is worse than one that scrolls:
    // it reads as a market with no bids. Three levels a side plus the mid row is the floor, and the
    // widget is held to that height so the rows exist to be scrolled to if it comes to that.
    const int minRows = kMinBookLevels * 2 + 1;
    m_book->setMinimumHeight(rowHeight * minRows + m_book->header()->height() + 4);
    const int rowsThatFit = qMax(minRows, m_book->viewport()->height() / rowHeight);
    m_bookRows = rowsThatFit;
    // Clamped rather than qBound'ed: with an empty book the upper limit is below the lower one, and
    // qBound is undefined that way round.
    // One row of the budget goes to the mid row between the two sides, and the rest is split evenly.
    const int levels = qMax(0, qMin(qMin((rowsThatFit - 1) / 2, kBookLevels),
                                    qMax(groupedBids.size(), groupedAsks.size())));

    // Each side is shaded against its own deepest level rather than a shared scale. The two sides of
    // this book routinely differ several-fold, and on a shared scale the thinner one collapses into
    // slivers that show nothing - which defeats the point, since the bars exist to make the shape of
    // each side readable at a glance. The imbalance between sides is still there to read in the
    // totals column.
    auto deepest = [&](const QVector<Level> &side) {
        double run = 0.0;
        for (int i = 0; i < qMin(levels, side.size()); ++i)
            run += side.at(i).sz;
        return run > 0.0 ? run : 1.0;
    };
    const double maxAsk = deepest(groupedAsks);
    const double maxBid = deepest(groupedBids);

    m_book->clear();
    QList<QTreeWidgetItem *> rows;

    auto put = [&](const Level &lvl, double cumulative, bool ask) {
        const double px = lvl.px;
        const double sz = lvl.sz;

        auto *item = new QTreeWidgetItem();
        item->setText(0, money(px, m_pxDecimals > 2 ? 2 : m_pxDecimals));
        item->setData(0, Qt::UserRole, px);
        item->setForeground(0, QColor(ask ? kDown : kUp));
        item->setText(1, money(sz, m_szDecimals));
        item->setText(2, money(cumulative, m_szDecimals));
        for (int c = 0; c < 3; ++c)
            item->setTextAlignment(c, Qt::AlignRight | Qt::AlignVCenter);
        item->setSizeHint(0, QSize(0, rowHeight));

        // A depth bar: the shaded part of the row is this level's share of its side's deepest
        // total, so the shape of the book reads at a glance.
        //
        // A background gradient is painted per cell, and each cell's gradient runs 0..1 across its
        // own width - so the bar is split into the slice of the row each column occupies, and the
        // three pieces line up into one continuous bar instead of restarting in every column.
        const double frac = qBound(0.0, cumulative / (ask ? maxAsk : maxBid), 1.0);
        const QColor tint = ask ? QColor(231, 76, 60, 55) : QColor(39, 174, 96, 55);
        const int columns = 3;
        for (int c = 0; c < columns; ++c) {
            const double from = double(c) / columns;
            const double local = qBound(0.0, (frac - from) * columns, 1.0);
            if (local <= 0.0)
                continue; // the bar does not reach this column
            QLinearGradient g(0, 0, 1, 0);
            g.setCoordinateMode(QGradient::ObjectBoundingMode);
            g.setColorAt(0.0, tint);
            if (local >= 1.0) {
                g.setColorAt(1.0, tint);
            } else {
                g.setColorAt(local, tint);
                g.setColorAt(qMin(1.0, local + 0.0001), Qt::transparent);
                g.setColorAt(1.0, Qt::transparent);
            }
            item->setBackground(c, QBrush(g));
        }
        rows.append(item);
    };

    // Asks descend towards the spread, so the cheapest offer sits just above the mid - the way a
    // book is read everywhere.
    QVector<QPair<Level, double>> askRows;
    double cum = 0.0;
    for (int i = 0; i < qMin(levels, groupedAsks.size()); ++i) {
        cum += groupedAsks.at(i).sz;
        askRows.append({groupedAsks.at(i), cum});
    }
    for (int i = askRows.size() - 1; i >= 0; --i)
        put(askRows[i].first, askRows[i].second, true);

    // The mid sits in the book between the two sides rather than on a line underneath it. That is
    // where every exchange puts it, and it is the number the eye goes to first - the two halves of
    // the book only mean anything relative to it.
    auto *midRow = new QTreeWidgetItem();
    if (m_bestBid > 0.0 && m_bestAsk > 0.0) {
        const double mid = (m_bestBid + m_bestAsk) / 2.0;
        const double spread = m_bestAsk - m_bestBid;
        midRow->setText(0, tr("%1    spread %2  (%3%)")
                               .arg(money(mid, 2), money(spread, 2),
                                    QString::number(spread / mid * 100.0, 'f', 2)));
    } else {
        midRow->setText(0, tr("one side of the book is empty"));
    }
    midRow->setTextAlignment(0, Qt::AlignCenter);
    QFont midFont = m_book->font();
    midFont.setBold(true);
    midRow->setFont(0, midFont);
    midRow->setSizeHint(0, QSize(0, rowHeight + 6));
    // Enabled but not selectable, so it can't be picked as a price; the click handler ignores it
    // anyway because it carries no price in UserRole.
    midRow->setFlags(Qt::ItemIsEnabled);
    rows.append(midRow);

    cum = 0.0;
    for (int i = 0; i < qMin(levels, groupedBids.size()); ++i) {
        cum += groupedBids.at(i).sz;
        put(groupedBids.at(i), cum, false);
    }
    m_book->addTopLevelItems(rows);
    midRow->setFirstColumnSpanned(true); // only takes effect once the item is in the tree

    // A blank price field on first load is unhelpful; seed it with the price a buy would pay.
    if (m_price->text().isEmpty() && m_bestAsk > 0.0)
        m_price->setText(trimNum(m_bestAsk, m_pxDecimals));
}

void XmrTradeTab::updateLiquidity() {
    // How much there is to trade at all, before any question of price. Every level the exchange
    // publishes counts towards this, not just the few the book has room to draw.
    auto total = [](const QVector<Level> &side) {
        double sz = 0.0;
        for (const Level &lvl : side)
            sz += lvl.sz;
        return sz;
    };
    const double canBuy = total(m_rawAsks);
    const double canSell = total(m_rawBids);
    if (canBuy <= 0.0 && canSell <= 0.0) {
        m_depth->setText(tr("Waiting for the book."));
    } else {
        // Said as what you can do rather than as "ask depth" and "bid depth". The worst price each
        // side reaches is the other half of the answer: buying all of it is not buying it at the top
        // of the book, and the gap between the two numbers is the whole story of a thin market.
        const QString buyPart =
            canBuy > 0.0 ? tr("Buy up to <b style='color:%1'>%2 XMR1</b>")
                               .arg(QString::fromLatin1(kDown), trimNum(canBuy, 2))
                         : tr("Nothing offered for sale");
        const QString sellPart = canSell > 0.0 ? tr("sell up to <b style='color:%1'>%2 XMR1</b>")
                                                     .arg(QString::fromLatin1(kUp),
                                                          trimNum(canSell, 2))
                                               : tr("nobody bidding");
        m_depth->setText(buyPart + QStringLiteral(", ") + sellPart);
        // The worst price each side reaches is the other half of the answer, but it is detail: the
        // headline is how much there is, and buying all of it is plainly not buying it at the top of
        // the book.
        m_depth->setToolTip(
            tr("Offers run out at %1 USDC and bids at %2 USDC. Counts every price level the exchange "
               "publishes, which is the twenty nearest the spread on each side.")
                .arg(canBuy > 0.0 ? money(m_rawAsks.last().px, 2) : tr("no price"),
                     canSell > 0.0 ? money(m_rawBids.last().px, 2) : tr("no price")));
    }

    // A ladder of sizes, plus whatever is in the ticket so the size you care about is always one of
    // the columns.
    QVector<double> sizes{0.1, 0.5, 1.0, 5.0};
    const double typed = m_size->text().toDouble();
    if (typed > 0.0 && std::none_of(sizes.cbegin(), sizes.cend(), [typed](double s) {
            return std::abs(s - typed) < 1e-9;
        }))
        sizes.append(typed);
    std::sort(sizes.begin(), sizes.end());

    m_liquidity->clear();
    QStringList headers{QString()};
    for (double size : sizes)
        headers << tr("%1 XMR1").arg(trimNum(size, 4));
    m_liquidity->setColumnCount(headers.size());
    m_liquidity->setHeaderLabels(headers);
    // The row labels take the width of the words and no more; the figures share what is left, so
    // every size column is the same width and the amounts line up down the page.
    m_liquidity->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    for (int c = 1; c < headers.size(); ++c) {
        m_liquidity->header()->setSectionResizeMode(c, QHeaderView::Stretch);
        m_liquidity->headerItem()->setTextAlignment(c, Qt::AlignRight | Qt::AlignVCenter);
        if (std::abs(sizes.at(c - 1) - typed) < 1e-9) {
            QFont bold = m_liquidity->headerItem()->font(c);
            bold.setBold(true);
            m_liquidity->headerItem()->setFont(c, bold); // the size in the ticket, marked out
        }
    }

    auto *payRow = new QTreeWidgetItem(m_liquidity);
    payRow->setText(0, tr("You pay"));
    auto *getRow = new QTreeWidgetItem(m_liquidity);
    getRow->setText(0, tr("You receive"));

    for (int i = 0; i < sizes.size(); ++i) {
        const double size = sizes.at(i);
        const Walk buy = walk(m_rawAsks, size);  // buying lifts the offers
        const Walk sell = walk(m_rawBids, size); // selling hits the bids
        const int c = i + 1;

        // An incomplete walk means the book does not hold that much at any price. The cell says so
        // plainly rather than quoting a total for a trade that would only partly happen.
        auto put = [&](QTreeWidgetItem *row, const Walk &w, const char *colour) {
            if (w.complete) {
                row->setText(c, money(w.cost, 2));
                row->setForeground(c, QColor(colour));
                row->setToolTip(c, tr("Averages %1 USDC per XMR1.").arg(money(w.avg, 2)));
            } else {
                row->setText(c, tr("not there"));
                row->setForeground(c, QColor(kMuted));
                row->setToolTip(c, tr("Only %1 XMR1 is available at any price.")
                                       .arg(trimNum(w.filled, m_szDecimals)));
            }
            row->setTextAlignment(c, Qt::AlignRight | Qt::AlignVCenter);
        };
        put(payRow, buy, kDown);
        put(getRow, sell, kUp);
    }

    // Sized to its contents, so it never leaves an empty strip below the last row and every pixel of
    // spare height in this column goes to the book above it.
    const int rowHeight = qMax(1, m_liquidity->fontMetrics().height() + 6);
    m_liquidity->setFixedHeight(rowHeight * 3 + 8);
}

void XmrTradeTab::fillOrders(const QJsonObject &data) {
    const QJsonArray orders = data.value(QStringLiteral("open_orders")).toArray();
    // Keep the selection across refreshes, or cancelling becomes a race against the timer.
    const auto selected = m_orders->selectedItems();
    const qint64 selectedOid =
        selected.isEmpty() ? -1 : selected.first()->data(4, Qt::UserRole).toLongLong();

    m_orders->clear();
    QTreeWidgetItem *restore = nullptr;
    for (const QJsonValue &v : orders) {
        const QJsonObject o = v.toObject();
        const bool isBuy = o.value(QStringLiteral("is_buy")).toBool();
        const qint64 oid = static_cast<qint64>(o.value(QStringLiteral("oid")).toDouble());
        const QDateTime when = QDateTime::fromMSecsSinceEpoch(
            static_cast<qint64>(o.value(QStringLiteral("timestamp")).toDouble()));

        auto *item = new QTreeWidgetItem(m_orders);
        item->setText(0, isBuy ? tr("Buy") : tr("Sell"));
        item->setForeground(0, QColor(isBuy ? kUp : kDown));
        item->setText(1, o.value(QStringLiteral("px")).toString());
        item->setText(2, o.value(QStringLiteral("sz")).toString());
        item->setText(3, when.toString(QStringLiteral("MMM d hh:mm")));
        item->setText(4, QString::number(oid));
        item->setData(4, Qt::UserRole, oid);
        if (oid == selectedOid)
            restore = item;
    }
    if (restore)
        restore->setSelected(true);
    m_tabs->setTabText(1, orders.isEmpty() ? tr("Open orders")
                                           : tr("Open orders (%1)").arg(orders.size()));
}

void XmrTradeTab::fillFills(const QJsonObject &data) {
    const QJsonArray fills = data.value(QStringLiteral("fills")).toArray();
    m_fills->clear();
    for (const QJsonValue &v : fills) {
        const QJsonObject f = v.toObject();
        const bool isBuy = f.value(QStringLiteral("is_buy")).toBool();
        const QDateTime when = QDateTime::fromMSecsSinceEpoch(
            static_cast<qint64>(f.value(QStringLiteral("time")).toDouble()));

        auto *item = new QTreeWidgetItem(m_fills);
        item->setText(0, isBuy ? tr("Bought") : tr("Sold"));
        item->setForeground(0, QColor(isBuy ? kUp : kDown));
        item->setText(1, f.value(QStringLiteral("px")).toString());
        item->setText(2, f.value(QStringLiteral("sz")).toString());
        item->setText(3, f.value(QStringLiteral("fee")).toString());
        item->setText(4, when.toString(QStringLiteral("MMM d hh:mm")));
    }
}

void XmrTradeTab::updateTotals() {
    const bool isBuy = m_side->currentIndex() == 0;
    const bool market = m_type->currentIndex() == 1;
    const double size = m_size->text().toDouble();

    updateLiquidity();

    // Both order types are priced by walking the book rather than off the best price: any size past
    // the top level fills at a worse average, and quoting the touch would understate the cost of
    // exactly the orders where it matters most. A limit order that is already through the book is
    // walked the same way, but only across the levels it is willing to pay for.
    const QVector<Level> &side = isBuy ? m_rawAsks : m_rawBids;
    const double limit = market ? 0.0 : wirePrice(m_price->text().toDouble(), isBuy);
    const bool crossing = !market && crosses(isBuy, limit);
    const Walk w = market      ? walk(side, size)
                   : crossing  ? walk(levelsWithin(side, limit, isBuy), size)
                               : Walk{};
    const double px = market ? w.avg : limit;
    // What the order really commits. A limit order priced through the book takes the levels it can
    // and rests the remainder at its own limit, so the bill is the part it sweeps plus the part it
    // leaves behind; one that does not cross has swept nothing, which reduces to size times price. A
    // market order commits only what it fills, because the rest is cancelled rather than left.
    const double cost = market ? w.cost : w.cost + (size - w.filled) * px;

    if (size <= 0.0 || px <= 0.0) {
        m_total->setText(QString());
        return;
    }
    QString text = isBuy ? tr("Costs about <b>%1 USDC</b>").arg(money(cost, 2))
                         : tr("Receives about <b>%1 USDC</b>").arg(money(cost, 2));
    if (market) {
        text += tr("<br><span style='color:%1'>Fills at about %2 USDC each on the book as it "
                   "stands, and %3 %4 USDC (%5% past the last level it needs). Anything it can't "
                   "fill is cancelled.</span>")
                    .arg(QString::fromLatin1(kMuted), money(px, 2),
                         isBuy ? tr("pays at most") : tr("accepts as little as"),
                         money(marketCap(isBuy, size), 2),
                         QString::number(kMarketSlippage * 100.0, 'f', 0));
        if (!w.complete)
            text += QStringLiteral("<br><span style='color:%1'>%2</span>")
                        .arg(QString::fromLatin1(kDown),
                             tr("The book only holds %1 XMR1 at any price. The rest would be "
                                "cancelled.")
                                 .arg(trimNum(w.filled, m_szDecimals)));
    } else if (crossing) {
        // Saying nothing here let a price typed through the book look like an order that would sit
        // and wait, when it is a trade that happens the moment it is sent.
        text += QStringLiteral("<br><span style='color:%1'>%2</span>")
                    .arg(QString::fromLatin1(kMuted),
                         isBuy ? tr("This price is above the best ask, so %1 XMR1 of it trades "
                                    "immediately at about %2 USDC each rather than resting.")
                                     .arg(trimNum(w.filled, m_szDecimals), money(w.avg, 2))
                               : tr("This price is below the best bid, so %1 XMR1 of it trades "
                                    "immediately at about %2 USDC each rather than resting.")
                                     .arg(trimNum(w.filled, m_szDecimals), money(w.avg, 2)));
    }
    if (size * px < kMinOrderUsdc)
        text += QStringLiteral("<br><span style='color:%1'>%2</span>")
                    .arg(QString::fromLatin1(kDown),
                         tr("Hyperliquid takes no order worth less than %1 USDC.")
                             .arg(money(kMinOrderUsdc, 0)));
    if (isBuy && cost > available(true))
        text += QStringLiteral("<br><span style='color:%1'>%2</span>")
                    .arg(QString::fromLatin1(kDown), tr("More USDC than this account holds."));
    if (!isBuy && size > available(false))
        text += QStringLiteral("<br><span style='color:%1'>%2</span>")
                    .arg(QString::fromLatin1(kDown), tr("More XMR1 than this account holds."));
    m_total->setText(text);
}

void XmrTradeTab::placeOrder() {
    if (!m_wallet)
        return;
    // The Buy button is disabled while an order is with the exchange, but that is one widget's
    // state, not the rule. Anything else that reaches this function - a keyboard shortcut, a click
    // delivered while the confirmation was up - would send a second order nobody asked for, and this
    // wallet has sent a payment twice before for want of exactly this line.
    if (m_inFlight)
        return;
    if (!m_agentReady) {
        m_status->setText(tr("Enable trading first."));
        return;
    }
    const bool isBuy = m_side->currentIndex() == 0;
    const bool market = m_type->currentIndex() == 1;

    // Work in the size that will actually be sent. The market trades in fixed steps and the wire
    // format truncates anything finer, so a ticket for 1.239 becomes an order for 1.23 - and every
    // figure confirmed below would otherwise have described an order that was never placed. It is
    // written back to the field too, so the ticket and the order say the same thing.
    const double typed = m_size->text().toDouble();
    const double size = truncTo(typed, m_szDecimals);
    if (size <= 0.0) {
        m_status->setText(typed > 0.0
                              ? tr("This market trades in steps of %1 XMR1, and that rounds to "
                                   "nothing.")
                                    .arg(trimNum(std::pow(10.0, -m_szDecimals), m_szDecimals))
                              : tr("Enter how much XMR1 to trade."));
        return;
    }
    m_size->setText(trimNum(size, m_szDecimals));

    const double price = market ? marketCap(isBuy, size) : wirePrice(m_price->text().toDouble(), isBuy);
    if (price <= 0.0) {
        m_status->setText(market ? tr("The book is empty, so there is nothing to trade against.")
                                 : tr("Enter a price."));
        return;
    }
    // Show the exact price the order will carry. The field accepts more precision than the exchange
    // does, so a typed 164.567 rests at 164.56 on a buy; writing it back keeps the ticket, the
    // confirmation below, and the order itself all saying the same number.
    if (!market)
        m_price->setText(trimNum(price, m_pxDecimals));

    // A market order is nothing but a price read off the book, so it is only as good as the book it
    // was read from. If the last poll failed or is still out, every figure in the confirmation below
    // describes a market that may have moved, so it is better to wait for one good refresh than to
    // send an order priced from a snapshot of unknown age.
    const qint64 age = m_lastUpdate.isValid() ? m_lastUpdate.msecsTo(QDateTime::currentDateTime())
                                              : -1;
    if (market && (age < 0 || age > kRequestTimeoutMs)) {
        m_status->setText(tr("The book hasn't refreshed recently, so a market order can't be priced "
                             "from it. Wait for the next update, or place a limit order."));
        refresh(true);
        return;
    }

    // What this order is really expected to cost, as against what it is allowed to cost. A market
    // order is priced with an allowance beyond the levels it needs, and a limit order priced through
    // the book pays the levels it crosses rather than its own limit, so in both cases the limit
    // overstates the bill. The balance is checked against the expectation and the worst case is
    // stated in the confirmation.
    const QVector<Level> &side = isBuy ? m_rawAsks : m_rawBids;
    const bool crossing = !market && crosses(isBuy, price);
    const bool postOnly = !market && m_postOnly->isChecked();

    // A post-only order is rejected by the exchange the moment it would cross, so catch it here where
    // it can be explained rather than sending it to bounce. The price is already through the book, so
    // the fix is a price that rests: at or below the ask for a buy, at or above the bid for a sell.
    if (postOnly && crossing) {
        const double touch = isBuy ? m_bestAsk : m_bestBid;
        m_status->setText(
            isBuy ? tr("Post-only won't cross the book. Set the price at or below the best ask "
                       "(%1 USDC) so it rests, or clear post-only to take the offer.")
                        .arg(money(touch, 2))
                  : tr("Post-only won't cross the book. Set the price at or above the best bid "
                       "(%1 USDC) so it rests, or clear post-only to hit the bid.")
                        .arg(money(touch, 2)));
        return;
    }
    const Walk w = market      ? walk(side, size)
                   : crossing  ? walk(levelsWithin(side, price, isBuy), size)
                               : Walk{};
    // A crossing order pays the levels it sweeps and rests the remainder at its own limit; one that
    // does not cross has swept nothing, so this reduces to size times price. A market order commits
    // only what it fills, since the rest is cancelled.
    const double expected = market ? w.cost : w.cost + (size - w.filled) * price;
    const double worstCase = size * price;

    // Hyperliquid refuses anything under ten dollars, so refuse it here where it can be explained,
    // rather than sending it and reporting back whatever the exchange says.
    if (worstCase < kMinOrderUsdc) {
        m_status->setText(tr("Hyperliquid takes no order worth less than %1 USDC, and this one is "
                             "about %2.")
                              .arg(money(kMinOrderUsdc, 0), money(worstCase, 2)));
        return;
    }

    // Refuse an order the balance cannot cover rather than sending it to be refused. The red note
    // under the ticket already says so, but nothing stopped the button, so the only feedback was an
    // exchange error a few seconds later.
    if (isBuy && expected > m_usdc) {
        m_status->setText(tr("That would cost about %1 USDC and this account has %2.")
                              .arg(money(expected, 2), money(m_usdc, 2)));
        return;
    }
    if (!isBuy && size > m_xmr1) {
        m_status->setText(tr("That is %1 XMR1 and this account has %2 available.")
                              .arg(trimNum(size, m_szDecimals), trimNum(m_xmr1, m_szDecimals)));
        return;
    }

    // Confirm before sending, and describe what the order will actually do. A market order is priced
    // through the book, so the worst case is stated rather than implied: on a buy the cap is a
    // ceiling on what is paid, on a sell it is a floor under what is received, and saying "up to"
    // for both would describe a sell backwards. A limit order priced past the touch does not rest
    // either - it trades on arrival - and calling that "rests on the book" was simply untrue.
    QString body;
    if (market) {
        body = isBuy ? tr("Buy %1 XMR1 at the market?\n\nOn the book as it stands it fills at about "
                          "%2 USDC each, %3 USDC in total. It pays at most %4 USDC each and cancels "
                          "whatever it can't fill.")
                           .arg(trimNum(size, m_szDecimals), money(w.avg, 2), money(w.cost, 2),
                                money(price, 2))
                     : tr("Sell %1 XMR1 at the market?\n\nOn the book as it stands it fetches about "
                          "%2 USDC each, %3 USDC in total. It accepts as little as %4 USDC each and "
                          "cancels whatever it can't fill.")
                           .arg(trimNum(size, m_szDecimals), money(w.avg, 2), money(w.cost, 2),
                                money(price, 2));
        if (!w.complete)
            body += tr("\n\nThe book only holds %1 XMR1 at any price, so the rest is cancelled.")
                        .arg(trimNum(w.filled, m_szDecimals));
    } else if (crossing) {
        body = tr("%1 %2 XMR1 at %3 USDC each?\n\nThis price is already through the book, so %4 "
                  "XMR1 of it trades immediately at about %5 USDC each rather than resting. That "
                  "is about %6 USDC in all, counting anything left to rest at %3.")
                   .arg(isBuy ? tr("Buy") : tr("Sell"), trimNum(size, m_szDecimals),
                        money(price, 2), trimNum(w.filled, m_szDecimals), money(w.avg, 2),
                        money(expected, 2));
    } else {
        body = tr("%1 %2 XMR1 at %3 USDC each?\n\nThat is %4 USDC in total. The order rests on the "
                  "book until it fills or you cancel it.")
                   .arg(isBuy ? tr("Buy") : tr("Sell"), trimNum(size, m_szDecimals),
                        money(price, 2), money(worstCase, 2));
    }

    // Post-only is only reachable here on an order that rests (the crossing case returned earlier),
    // so the note explains the one way it differs from a plain limit: it is dropped rather than
    // filled if the market moves onto it before it lands.
    if (postOnly)
        body += tr("\n\nPost-only: if the market moves so this would trade on arrival, it is "
                   "rejected rather than filled, so it only ever pays the maker fee.");

    // A limit price far through the book is a mistyped one far more often than it is a deliberate
    // sweep, and on a book this thin it is not an order that can be cancelled - it is a trade that
    // has already taken every level up to it. So that case gets a warning, not a question, and it
    // defaults to Cancel rather than to the button that spends the money.
    const double touch = isBuy ? m_bestAsk : m_bestBid;
    const bool wild = crossing && touch > 0.0
                      && (isBuy ? price > touch * (1.0 + kFatFinger)
                                : price < touch * (1.0 - kFatFinger));
    if (wild)
        body += tr("\n\nThat price is %1% %2 the best %3 of %4 USDC. Check it before continuing.")
                    .arg(QString::number(std::abs(price - touch) / touch * 100.0, 'f', 0),
                         isBuy ? tr("above") : tr("below"), isBuy ? tr("ask") : tr("bid"),
                         money(touch, 2));

    const QString title = isBuy ? tr("Buy XMR1") : tr("Sell XMR1");
    const QMessageBox::StandardButton answer =
        wild ? QMessageBox::warning(this, title, body, QMessageBox::Ok | QMessageBox::Cancel,
                                    QMessageBox::Cancel)
             : QMessageBox::question(this, title, body, QMessageBox::Ok | QMessageBox::Cancel,
                                     QMessageBox::Ok);
    if (answer != QMessageBox::Ok) {
        m_status->setText(tr("Cancelled."));
        return;
    }
    // The guard is re-checked: the confirmation runs its own event loop, so anything could have
    // happened while it was open, including another order going out.
    if (m_inFlight)
        return;

    setBusy(true);
    m_status->setText(tr("Sending the order…"));
    m_wallet->hlPlaceOrder(m_account, isBuy, price, size, market, postOnly);
}

void XmrTradeTab::onOrderPlaced(const QString &json, const QString &error) {
    setBusy(false);
    if (!error.isEmpty()) {
        m_status->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                              .arg(QString::fromLatin1(kDown), error.toHtmlEscaped()));
        return;
    }
    const QJsonObject r = QJsonDocument::fromJson(json.toUtf8()).object();
    const QString state = r.value(QStringLiteral("state")).toString();
    if (state == QLatin1String("filled")) {
        m_status->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                              .arg(QString::fromLatin1(kUp),
                                   tr("Filled %1 XMR1 at %2 USDC.")
                                       .arg(r.value(QStringLiteral("size")).toString(),
                                            r.value(QStringLiteral("price")).toString())));
        m_size->clear();
    } else if (state == QLatin1String("resting")) {
        m_status->setText(tr("Order resting on the book."));
        m_size->clear();
    } else if (state == QLatin1String("none")) {
        // An IOC that crossed nothing is cancelled rather than rejected - no error, but no trade.
        m_status->setText(tr("Nothing filled at that price, so the order was cancelled."));
    } else {
        // The exchange took the order but answered in a shape this build does not recognise. Saying
        // "nothing filled" would invite a second order on top of one that may be live, so point the
        // user at the lists below, which are about to refresh with the truth.
        m_status->setText(
            QStringLiteral("<span style='color:%1'>%2</span>")
                .arg(QString::fromLatin1(kDown),
                     tr("The exchange accepted the order but did not say what happened to it. "
                        "Check Open orders and Fills below before placing it again.")));
    }
    refresh(true);
    // And once more shortly after. The exchange acknowledges an order before it necessarily shows up
    // in the open-orders query, so the immediate refresh can come back without it and leave the list
    // looking wrong until the next poll.
    QTimer::singleShot(900, this, [this]() { refresh(true); });
}

void XmrTradeTab::cancelSelected() {
    const auto selected = m_orders->selectedItems();
    if (selected.isEmpty() || !m_wallet)
        return;
    const qint64 oid = selected.first()->data(4, Qt::UserRole).toLongLong();
    setBusy(true);
    m_status->setText(tr("Cancelling…"));
    m_wallet->hlCancelOrder(m_account, static_cast<quint64>(oid));
}

void XmrTradeTab::onOrderCancelled(const QString &error) {
    setBusy(false);
    m_status->setText(error.isEmpty() ? tr("Order cancelled.")
                                      : QStringLiteral("<span style='color:%1'>%2</span>")
                                            .arg(QString::fromLatin1(kDown), error.toHtmlEscaped()));
    refresh(true);
    QTimer::singleShot(900, this, [this]() { refresh(true); }); // as above: the list lags the ack
}

void XmrTradeTab::deposit() {
    if (!m_wallet)
        return;
    // The bridge only accepts USDC on Arbitrum One, so a deposit from any other chain cannot work.
    // Offer to switch rather than let the user type an amount that the core will only then reject.
    if (!m_onArbitrum) {
        if (QMessageBox::question(
                this, tr("Deposit USDC"),
                tr("Depositing USDC uses Hyperliquid's bridge on Arbitrum One, but this wallet is on "
                   "another network.\n\nSwitch to Arbitrum One now?"),
                QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Ok)
            == QMessageBox::Ok)
            emit switchToArbitrumRequested();
        return;
    }
    bool ok = false;
    const QString amount = QInputDialog::getText(
        this, tr("Deposit USDC"),
        tr("How much USDC to move from Arbitrum One onto the exchange?\n\n"
           "It is sent from this wallet to Hyperliquid's bridge and credits to the same "
           "address a minute or so later. Aero then moves it into your spot balance so it can "
           "buy XMR1. The minimum is 5 USDC; anything less is lost.\n\n"
           "Available: %1 USDC")
            .arg(money(m_usdcArb, 2)),
        QLineEdit::Normal, QString(), &ok);
    if (!ok || amount.trimmed().isEmpty())
        return;
    // Answer an obvious over-spend here instead of after a round trip that estimates gas and fails.
    const double want = amount.trimmed().toDouble();
    if (want <= 0.0) {
        m_status->setText(tr("Enter how much USDC to deposit."));
        return;
    }
    if (want > m_usdcArb + 1e-9 && m_usdcArb > 0.0) {
        m_status->setText(tr("That is %1 USDC and your wallet holds %2 on Arbitrum.")
                              .arg(money(want, 2), money(m_usdcArb, 2)));
        return;
    }
    if (QMessageBox::question(
            this, tr("Deposit USDC"),
            tr("Send %1 USDC to Hyperliquid's bridge on Arbitrum One?\n\n"
               "The wallet must be on Arbitrum One and hold native USDC. Bridged USDC.e is a "
               "different token and would be lost.")
                .arg(amount.trimmed()),
            QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Ok)
        != QMessageBox::Ok)
        return;
    // Locked until the transfer comes back. A deposit is a real on-chain transfer that can take
    // several seconds to estimate gas and broadcast, and with the button live that silence invites a
    // second click - which is a second transfer, not a retry of the first.
    setBusy(true);
    m_status->setText(tr("Sending the deposit…"));
    m_wallet->hlDeposit(m_account, amount.trimmed());
}

void XmrTradeTab::onDeposited(const QString &txHash, const QString &error) {
    setBusy(false);
    if (!error.isEmpty()) {
        m_status->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                              .arg(QString::fromLatin1(kDown), error.toHtmlEscaped()));
        return;
    }
    // The bridge credits the perp wallet, not spot, so once it lands the balance has to be moved
    // before it can buy XMR1. Remember where perp stood so the next rise is recognised as this
    // deposit arriving, and sweep it into spot automatically when it does.
    m_awaitingDepositCredit = true;
    m_perpBeforeDeposit = m_usdcPerp;
    m_depositCreditDeadline = QDateTime::currentDateTime().addSecs(5 * 60);
    m_status->setText(tr("Deposit sent (%1). It credits in about a minute, then Aero moves it to "
                         "your spot balance so you can trade.")
                          .arg(txHash.left(10) + QStringLiteral("…")));
    // The regular five-second poll will catch the credit, but nudge it sooner so the wait feels
    // like the "about a minute" it is rather than being rounded up by the poll interval.
    QTimer::singleShot(20000, this, [this]() { refresh(true); });
    QTimer::singleShot(45000, this, [this]() { refresh(true); });
}

void XmrTradeTab::withdraw() {
    if (!m_wallet)
        return;
    // A withdrawal is paid out of the perp wallet, and the core moves spot USDC across as needed, so
    // everything on the exchange is available - not just what happens to be in spot right now.
    const double onExchange = m_usdc + m_usdcPerp;
    bool ok = false;
    const QString amount = QInputDialog::getText(
        this, tr("Withdraw USDC"),
        tr("How much USDC to send back to Arbitrum One?\n\n"
           "It arrives at this same address, minus the exchange's 1 USDC fee, after a few minutes.\n\n"
           "Available: %1 USDC")
            .arg(money(onExchange, 2)),
        QLineEdit::Normal, QString(), &ok);
    if (!ok || amount.trimmed().isEmpty())
        return;

    // Checked here as well as in the core, so an obvious mistake is answered immediately instead of
    // after a round trip to the exchange.
    const double want = amount.trimmed().toDouble();
    if (want <= 0.0) {
        m_status->setText(tr("Enter how much USDC to withdraw."));
        return;
    }
    if (want > onExchange) {
        m_status->setText(tr("That is %1 USDC and this account has %2 available.")
                              .arg(money(want, 2), money(onExchange, 2)));
        return;
    }
    if (QMessageBox::question(
            this, tr("Withdraw USDC"),
            tr("Send %1 USDC from the exchange to %2 on Arbitrum One?\n\n"
               "The exchange takes a 1 USDC fee, so about %3 USDC will arrive.")
                .arg(money(want, 2), m_address, money(want - 1.0, 2)),
            QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Ok)
        != QMessageBox::Ok)
        return;

    setBusy(true);
    m_status->setText(tr("Requesting the withdrawal…"));
    m_wallet->hlWithdraw(m_account, amount.trimmed());
}

void XmrTradeTab::onWithdrawn(const QString &error) {
    setBusy(false);
    m_status->setText(error.isEmpty()
                          ? tr("Withdrawal requested. It arrives on Arbitrum in a few minutes.")
                          : QStringLiteral("<span style='color:%1'>%2</span>")
                                .arg(QString::fromLatin1(kDown), error.toHtmlEscaped()));
    refresh(true);
}

void XmrTradeTab::redeem() {
    if (!m_wallet)
        return;
    if (m_xmr1 <= 0.0) {
        QMessageBox::information(this, tr("Withdraw XMR"),
                                 tr("This account holds no XMR1 to withdraw. Buy some first, or "
                                    "deposit USDC and buy it here."));
        return;
    }

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Withdraw XMR"));
    dlg.setMinimumWidth(520);
    auto *form = new QVBoxLayout(&dlg);
    form->setSpacing(10);

    auto *intro = new QLabel(
        tr("This hands your XMR1 back to Wagyu, which pays out real Monero to the address below and "
           "keeps its fee from the amount. <b>Monero payments cannot be reversed or recovered</b>, "
           "so check the address carefully. It is the one thing here that nobody can fix "
           "afterwards."),
        &dlg);
    intro->setWordWrap(true);
    form->addWidget(intro);

    form->addWidget(new QLabel(tr("Monero address to be paid"), &dlg));
    auto *addr = new QLineEdit(&dlg);
    addr->setPlaceholderText(QStringLiteral("4… or 8…"));
    form->addWidget(addr);

    form->addWidget(new QLabel(tr("How much to withdraw (you have %1 XMR1)").arg(money(m_xmr1, 8)),
                               &dlg));
    auto *amountRow = new QHBoxLayout();
    auto *amount = new QLineEdit(&dlg);
    auto *maxBtn = new QPushButton(tr("Max"), &dlg);
    amountRow->addWidget(amount, 1);
    amountRow->addWidget(maxBtn);
    form->addLayout(amountRow);

    auto *quoteLbl = new QLabel(tr("Checking Wagyu's current fee…"), &dlg);
    quoteLbl->setWordWrap(true);
    form->addWidget(quoteLbl);

    auto *buttons = new QHBoxLayout();
    auto *cancelBtn = new QPushButton(tr("Cancel"), &dlg);
    auto *goBtn = new QPushButton(tr("Withdraw"), &dlg);
    goBtn->setEnabled(false);
    buttons->addStretch(1);
    buttons->addWidget(cancelBtn);
    buttons->addWidget(goBtn);
    form->addLayout(buttons);
    connect(cancelBtn, &QPushButton::clicked, &dlg, &QDialog::reject);
    connect(goBtn, &QPushButton::clicked, &dlg, &QDialog::accept);

    // The fee and minimum are Wagyu's to state, and it can vary them per sender, so they are read
    // once here rather than assumed. Everything after that is arithmetic and needs no round trip.
    double feePercent = 0.0;
    double minimum = 0.0;
    bool haveTerms = false;
    auto recompute = [&]() {
        const double want = amount->text().trimmed().toDouble();
        const QString payTo = addr->text().trimmed();
        // The same structural test the core applies before it opens an order, run here as the
        // address is typed. The core is what actually guards the funds; this only means the
        // commonest mistake - pasting an Ethereum address into a Monero field - is answered on the
        // spot rather than after the confirmation prompt.
        if (!payTo.isEmpty() && !looksLikeMoneroAddress(payTo)) {
            quoteLbl->setText(
                QStringLiteral("<span style='color:%1'>%2</span>")
                    .arg(QString::fromLatin1(kDown),
                         tr("That is not a Monero address. They begin with 4 or 8 and are 95 "
                            "characters long (106 for an integrated address).")));
            goBtn->setEnabled(false);
            return;
        }
        if (!haveTerms) {
            goBtn->setEnabled(false);
            return;
        }
        if (want <= 0.0) {
            quoteLbl->setText(tr("Wagyu takes %1% and will not redeem less than %2 XMR.")
                                  .arg(feePercent, 0, 'f', 2)
                                  .arg(minimum));
            goBtn->setEnabled(false);
            return;
        }
        if (want < minimum) {
            quoteLbl->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                                  .arg(QString::fromLatin1(kDown),
                                       tr("Wagyu will not redeem less than %1 XMR.").arg(minimum)));
            goBtn->setEnabled(false);
            return;
        }
        if (want > m_xmr1) {
            quoteLbl->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                                  .arg(QString::fromLatin1(kDown),
                                       tr("This account holds only %1 XMR1.")
                                           .arg(m_xmr1, 0, 'f', 8)));
            goBtn->setEnabled(false);
            return;
        }
        const double fee = want * feePercent / 100.0;
        quoteLbl->setText(tr("You receive <b>%1 XMR</b>: %2 less Wagyu's %3% fee of %4 XMR.")
                              .arg(want - fee, 0, 'f', 8)
                              .arg(want, 0, 'f', 8)
                              .arg(feePercent, 0, 'f', 2)
                              .arg(fee, 0, 'f', 8));
        goBtn->setEnabled(!payTo.isEmpty());
    };
    connect(amount, &QLineEdit::textChanged, &dlg, recompute);
    connect(addr, &QLineEdit::textChanged, &dlg, recompute);
    // Truncated, not rounded. QString::number rounds, so a balance of 1.234567895 became
    // 1.23456790 - fractionally more than is held, which the transfer then refuses after the Wagyu
    // order has already been created.
    connect(maxBtn, &QPushButton::clicked, &dlg,
            [&]() { amount->setText(truncNum(m_xmr1, 8)); });
    connect(m_wallet, &Wallet::xmrRedeemQuoted, &dlg,
            [&](const QJsonObject &quote, const QString &error) {
                if (!error.isEmpty()) {
                    quoteLbl->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                                          .arg(QString::fromLatin1(kDown), error.toHtmlEscaped()));
                    return;
                }
                feePercent = quote.value(QStringLiteral("fee_percent")).toDouble();
                minimum = quote.value(QStringLiteral("minimum")).toDouble();
                haveTerms = true;
                recompute();
            });
    m_wallet->xmrRedeemQuote(m_account, QStringLiteral("1"));

    if (dlg.exec() != QDialog::Accepted)
        return;

    const QString moneroAddress = addr->text().trimmed();
    const QString wanted = amount->text().trimmed();
    const double want = wanted.toDouble();
    const double net = want - want * feePercent / 100.0;

    // The address is shown back in full, because a transposed character is invisible in a field and
    // final once the Monero is sent.
    if (QMessageBox::question(
            this, tr("Withdraw XMR"),
            tr("Send %1 XMR1 to Wagyu and receive about %2 XMR at:\n\n%3\n\n"
               "Monero payments cannot be reversed. If this address is wrong or is not yours, the "
               "money is gone.")
                .arg(wanted)
                .arg(net, 0, 'f', 8)
                .arg(moneroAddress),
            QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel)
        != QMessageBox::Ok)
        return;

    setBusy(true);
    m_status->setText(tr("Opening the redemption and sending the XMR1…"));
    m_wallet->xmrRedeem(m_account, moneroAddress, wanted);
}

void XmrTradeTab::onRedeemed(const QJsonObject &order, const QString &error) {
    setBusy(false);
    if (!error.isEmpty()) {
        m_status->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                              .arg(QString::fromLatin1(kDown), error.toHtmlEscaped()));
        return;
    }

    m_redeemOrderId = order.value(QStringLiteral("order_id")).toString();
    m_redeemSessionId = order.value(QStringLiteral("session_id")).toString();
    m_redeemDestination = order.value(QStringLiteral("destination")).toString();
    // Write it down before anything else can go wrong. The XMR1 has left by now.
    rememberRedemption();
    m_status->setText(tr("Redemption %1 sent. About %2 XMR is on its way, and redemptions usually "
                         "settle in under two minutes.")
                          .arg(m_redeemOrderId)
                          .arg(order.value(QStringLiteral("expected")).toDouble(), 0, 'f', 8));

    startRedeemPoll();
    refresh(true);
}

// Keep asking after the money has left, since from here the order id is the only handle the user has
// on it. Runs regardless of which tab is showing, unlike the book poll.
void XmrTradeTab::startRedeemPoll() {
    if (m_redeemOrderId.isEmpty())
        return;
    if (!m_redeemPoll) {
        m_redeemPoll = new QTimer(this);
        m_redeemPoll->setInterval(10000);
        connect(m_redeemPoll, &QTimer::timeout, this, [this]() {
            if (!m_redeemOrderId.isEmpty() && m_wallet)
                m_wallet->xmrRedeemStatus(m_redeemOrderId, m_redeemSessionId);
        });
    }
    m_redeemPoll->start();
    if (m_wallet)
        m_wallet->xmrRedeemStatus(m_redeemOrderId, m_redeemSessionId);
}

void XmrTradeTab::rememberRedemption() {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    s.setValue(QStringLiteral("xmr/redeem/orderId"), m_redeemOrderId);
    s.setValue(QStringLiteral("xmr/redeem/sessionId"), m_redeemSessionId);
    s.setValue(QStringLiteral("xmr/redeem/destination"), m_redeemDestination);
    s.setValue(QStringLiteral("xmr/redeem/startedAt"),
               QDateTime::currentDateTime().toString(Qt::ISODate));
}

void XmrTradeTab::forgetRedemption() {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    s.remove(QStringLiteral("xmr/redeem"));
}

// Pick a redemption back up after a restart, so a user who closed Aero (or crashed) while Monero was
// in flight still has the order id, the session id, and a live status rather than nothing at all.
void XmrTradeTab::restoreRedemption() {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    const QString id = s.value(QStringLiteral("xmr/redeem/orderId")).toString();
    if (id.isEmpty())
        return;
    // Wagyu's orders do not stay queryable forever; stop carrying one around after a day.
    const QDateTime started =
        QDateTime::fromString(s.value(QStringLiteral("xmr/redeem/startedAt")).toString(),
                              Qt::ISODate);
    if (started.isValid() && started.daysTo(QDateTime::currentDateTime()) >= 1) {
        forgetRedemption();
        return;
    }
    m_redeemOrderId = id;
    m_redeemSessionId = s.value(QStringLiteral("xmr/redeem/sessionId")).toString();
    m_redeemDestination = s.value(QStringLiteral("xmr/redeem/destination")).toString();
    m_status->setText(tr("Picking up redemption %1 from your last session…").arg(m_redeemOrderId));
    startRedeemPoll();
}

void XmrTradeTab::onRedeemStatus(const QJsonObject &status, const QString &error) {
    if (!error.isEmpty() || m_redeemOrderId.isEmpty())
        return;
    const QString state = status.value(QStringLiteral("status")).toString();
    if (state.isEmpty())
        return;

    if (state == QLatin1String("completed")) {
        m_redeemPoll->stop();
        m_status->setText(QStringLiteral("<span style='color:%1'>%2</span>")
                              .arg(QString::fromLatin1(kUp),
                                   tr("Redemption %1 completed. The Monero has been sent.")
                                       .arg(m_redeemOrderId)));
        m_redeemOrderId.clear();
        m_redeemSessionId.clear();
        m_redeemDestination.clear();
        forgetRedemption();
        return;
    }
    if (state == QLatin1String("failed") || state == QLatin1String("expired")) {
        m_redeemPoll->stop();
        // Deliberately kept on disk: the XMR1 has already been sent, so these two ids are what any
        // conversation with Wagyu about recovering it will need, and they must survive a restart.
        m_status->setText(
            QStringLiteral("<span style='color:%1'>%2</span>")
                .arg(QString::fromLatin1(kDown),
                     tr("Redemption %1 %2. Contact Wagyu quoting that order id and session id %3. "
                        "Aero has saved both and will still have them if you close it.")
                         .arg(m_redeemOrderId, state, m_redeemSessionId)));
        return;
    }
    m_status->setText(tr("Redemption %1: %2…").arg(m_redeemOrderId, state));
}
