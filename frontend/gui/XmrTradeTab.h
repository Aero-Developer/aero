// SPDX-License-Identifier: BSD-3-Clause
// Buying and selling XMR1 - Wagyu's synthetic Monero - on Hyperliquid's order book.
//
// A tab rather than a window, and built from the same pieces as the rest of Aero: this is a place
// you keep an eye on while the book moves, not something you open, do once and dismiss.
//
// It shows the book, takes limit and market orders, lists what is resting and what has filled, moves
// USDC on and off the exchange over Arbitrum, and redeems XMR1 for real Monero through Wagyu.
#ifndef AERO_XMR_TRADE_TAB_H
#define AERO_XMR_TRADE_TAB_H

#include <QDateTime>
#include <QJsonObject>
#include <QWidget>

class Wallet;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QScrollArea;
class QSplitter;
class QTabWidget;
class QTimer;
class QTreeWidget;

class XmrTradeTab : public QWidget
{
    Q_OBJECT
public:
    explicit XmrTradeTab(QWidget *parent = nullptr);
    ~XmrTradeTab() override;

    // Bind the tab to an open wallet and the account it trades as. The account is fixed while bound:
    // orders, balances and withdrawals all belong to one address, and letting it change underneath
    // would attribute them to the wrong one.
    void setWallet(Wallet *wallet, quint32 account, const QString &address);

protected:
    // Polling follows visibility. The exchange is only worth asking while someone is looking, and
    // over Tor an idle five-second poll is a real cost for nothing.
    void showEvent(QShowEvent *event) override;
    void hideEvent(QHideEvent *event) override;
    // Watches the book for height changes so dragging a divider adds or removes levels as you drag,
    // instead of leaving a gap until the next poll five seconds later.
    bool eventFilter(QObject *watched, QEvent *event) override;

private slots:
    void onOverview(quint32 account, const QString &json, const QString &error);
    void onAgentReady(bool ready, const QString &error);
    void onAgentApproved(const QString &error);
    void onOrderPlaced(const QString &json, const QString &error);
    void onOrderCancelled(const QString &error);
    void onWithdrawn(const QString &error);
    void onDeposited(const QString &txHash, const QString &error);
    void onRedeemed(const QJsonObject &order, const QString &error);
    void onRedeemStatus(const QJsonObject &status, const QString &error);

private:
    // One price level of the raw book, as the exchange sent it. Kept unaggregated because the
    // grouping below is a display choice, while everything priced off the book - market orders, the
    // cost table - has to walk the levels that actually exist.
    struct Level {
        double px = 0.0;
        double sz = 0.0;
    };

    // What filling `size` against one side of the book would come to.
    struct Walk {
        double filled = 0.0;  // how much the book could actually supply
        double cost = 0.0;    // USDC paid or received for that much
        double avg = 0.0;     // cost / filled - the price the trade really happens at
        double worst = 0.0;   // price of the deepest level the size reaches into
        bool complete = false; // false when the book ran out before the size was met
    };
    static Walk walk(const QVector<Level> &side, double size);
    // The levels of `side` a limit order at `limit` may trade against. Levels arrive best first, so
    // this is the leading run of them; the rest are priced beyond what the order will accept.
    static QVector<Level> levelsWithin(const QVector<Level> &side, double limit, bool isBuy);
    // Whether a limit order at `price` would trade immediately instead of resting on the book.
    bool crosses(bool isBuy, double price) const;

    void buildUi();
    // `force` bypasses the in-flight guard. Timer polls are skipped while a request is still out, so
    // a slow link cannot queue up overlapping requests that then land out of order; an action the
    // user just took always refreshes regardless.
    void refresh(bool force = false);
    void startPolling();
    void updateFreshness();
    void saveLayout() const;
    void restoreLayout();
    void placeOrder();
    void cancelSelected();
    void deposit();
    void withdraw();
    void redeem();
    void fillBook(const QJsonObject &data);
    void fillOrders(const QJsonObject &data);
    void fillFills(const QJsonObject &data);
    void updateLiquidity();
    void updateTotals();
    double groupStep() const; // price increment the book is bucketed into for display
    void setBusy(bool busy);
    // The price a market order should be capped at: through the book by `slippage`, so it fills but
    // never at an arbitrary price if the book is thin.
    // Worst price a market order of `size` may take, which is what an IOC order is priced at: far
    // enough through the book to fill that size, plus an allowance for movement.
    double marketCap(bool isBuy, double size) const;
    double available(bool isBuy) const;

    Wallet *m_wallet = nullptr;
    quint32 m_account = 0;
    QString m_address;

    QTimer *m_poll = nullptr;
    QTimer *m_ageTick = nullptr;      // ticks the "updated N seconds ago" text
    bool m_refreshInFlight = false;   // a book/balance request is out
    QDateTime m_refreshStarted;       // when, so a lost request cannot wedge polling forever
    QDateTime m_lastUpdate;           // when the screen last showed live data
    bool m_inFlight = false;   // an order/cancel/withdrawal is with the exchange
    bool m_agentReady = false; // this account has authorised Aero's trading key
    double m_bestBid = 0.0;
    double m_bestAsk = 0.0;
    QVector<Level> m_rawBids; // best first
    QVector<Level> m_rawAsks; // best first
    QJsonObject m_lastOverview; // last snapshot, so regrouping needs no round trip
    double m_xmr1 = 0.0;
    double m_usdc = 0.0;
    int m_szDecimals = 2;
    int m_pxDecimals = 6;

    QLabel *m_warning = nullptr;
    QWidget *m_agentRow = nullptr;
    QLabel *m_agentBanner = nullptr;
    QPushButton *m_enableBtn = nullptr;
    QTreeWidget *m_book = nullptr;
    QComboBox *m_group = nullptr;
    QLabel *m_live = nullptr; // "updated N seconds ago", so staleness is visible rather than assumed
    QLabel *m_depth = nullptr; // how much XMR1 there is to buy and to sell, right now
    QScrollArea *m_scroll = nullptr;
    int m_bookRows = 0;               // rows the book last fitted, to spot a real height change
    QSplitter *m_vSplit = nullptr; // book and ticket above, open orders below
    QSplitter *m_hSplit = nullptr; // book and costs beside the order form
    QTreeWidget *m_liquidity = nullptr;
    QLabel *m_balances = nullptr;
    QComboBox *m_side = nullptr;
    QComboBox *m_type = nullptr;
    QLineEdit *m_price = nullptr;
    QLineEdit *m_size = nullptr;
    QLabel *m_total = nullptr;
    QLabel *m_tradingAs = nullptr;
    QPushButton *m_maxBtn = nullptr;
    QPushButton *m_placeBtn = nullptr;
    QLabel *m_status = nullptr;
    QTabWidget *m_tabs = nullptr;
    QTreeWidget *m_orders = nullptr;
    QTreeWidget *m_fills = nullptr;
    QPushButton *m_cancelBtn = nullptr;
    QPushButton *m_depositBtn = nullptr;
    QPushButton *m_withdrawBtn = nullptr;
    QPushButton *m_redeemBtn = nullptr;

    // The redemption being tracked, if any. Held so the tab can keep reporting progress after the
    // XMR1 has left - at that point the order is the only record the user has of where it went.
    QString m_redeemOrderId;
    QString m_redeemSessionId;
    QTimer *m_redeemPoll = nullptr;
};

#endif // AERO_XMR_TRADE_TAB_H
