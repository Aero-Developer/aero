// SPDX-License-Identifier: BSD-3-Clause
// Backs HistoryWidget with ERC20 transfer history (reconstructed from logs) plus any
// locally-originated ETH sends the app has broadcast this session.

#ifndef AERO_HISTORYMODEL_H
#define AERO_HISTORYMODEL_H

#include <QAbstractTableModel>
#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVector>

#include "Wallet.h"

class QTimer;

class HistoryModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        Column_Date = 0,
        Column_Account, // which of the wallet's accounts this went through, by its Receive label
        Column_Direction,
        Column_Amount,
        Column_Value, // USD value of the transfer
        Column_Counterparty,
        Column_TxHash,
        Column_COUNT,
    };

    // Role carrying a typed sort key (used by the view's sort proxy) so Date sorts chronologically
    // and Amount sorts by value rather than as text.
    static constexpr int SortRole = Qt::UserRole + 100;

    // The HistoryItem backing a given row (for opening a transaction dialog).
    HistoryItem itemAt(int row) const {
        return (row >= 0 && row < m_items.size()) ? m_items.at(row) : HistoryItem{};
    }
    bool isSuspicious(int row) const; // likely address-poisoning / failed tx

    explicit HistoryModel(QObject *parent = nullptr) : QAbstractTableModel(parent) {}

    int rowCount(const QModelIndex &parent = QModelIndex()) const override {
        return parent.isValid() ? 0 : m_items.size();
    }
    int columnCount(const QModelIndex &parent = QModelIndex()) const override {
        return parent.isValid() ? 0 : Column_COUNT;
    }

    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    // Sort the full result set (not just the current page) by a column; the view drives this via
    // header clicks. Resets to the first page. Kept in the model (rather than a proxy) so only the
    // 500-row page window is ever materialised, no matter how large the full history is.
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

    // --- Pagination (500 rows per page) -----------------------------------------------------
    int pageSize() const { return m_pageSize; }
    int currentPage() const { return m_page; }               // 0-based
    int pageCount() const {                                   // >= 1
        const int total = m_filtered.size();
        return qMax(1, (total + m_pageSize - 1) / m_pageSize);
    }
    int totalRows() const { return m_filtered.size(); }       // rows across ALL pages (post-filter)

    // Distinct ERC-20 contract addresses (lower-case) present in history that aren't currently
    // trusted and aren't obvious homoglyph/ETH impersonators - candidates for a liquidity check.
    QStringList untrackedTokenAddresses() const;

    // What the filter needs to know about a row, worked out once when the row arrives rather than on
    // every pass. The filter runs on every search keystroke, price tick and settings change; at tens
    // of thousands of rows, re-lowercasing each row's token and counterparty, upper-casing its symbol
    // and re-parsing its amount every time was most of what that pass cost. None of these depend on
    // anything but the row itself.
    struct RowFacts {
        QString tokenLower;        // for the trusted-token lookup
        QString counterpartyLower; // for the look-alike index and search
        QString hashLower;         // for search (shares the original when it is already lower-case)
        QString sig;               // look-alike signature of the counterparty; empty if not an address
        QString symbolUpper;       // for the price lookup
        double amount = 0.0;       // `formatted`, parsed
        bool evm = false;          // the counterparty is an 0x address
        bool poisoning = false;    // zero-value poisoning shape
        bool homoglyph = false;    // non-ASCII symbol
    };

    // A chain's cached history made ready to show, on a worker thread: the rows, their dedup index,
    // their filter facts and the look-alike index. Adopting one is a swap. Loading the rows directly
    // did all of that on the UI thread in the middle of a chain switch - most of what made switching
    // on a large wallet stall.
    // The look-alike index: addresses known to be real, and their first4+last4 hex signatures.
    // `addrs` holds the wallet's own addresses and the counterparty of every genuine transfer of
    // value, either way. `sentAddrs` holds only the own addresses and those the wallet has sent value
    // to - the ones poisoning imitates, and ones an outsider cannot add, where anyone can put an
    // address in `addrs` by sending the wallet a little of a real token.
    struct PoisonRefs {
        QSet<QString> addrs, sigs;
        QSet<QString> sentAddrs, sentSigs;
    };
    struct Prepared {
        // Two copies, each owned outright (not sharing storage with the cache it came from), with
        // room to grow. Shared storage is copied on first write, and the first write is the next
        // batch to arrive - which then duplicated the whole history on the UI thread.
        QVector<HistoryItem> rows;    // becomes the fetched set
        QVector<HistoryItem> allRows; // becomes the full row list
        QHash<QString, int> fetchedAt;
        QVector<RowFacts> facts;
        PoisonRefs refs;
        QSet<QString> ownAddresses, knownTokens; // what the look-alike index was built against
    };
    // Thread-safe: reads nothing of any model. Pass the model's current ownAddresses()/knownTokens().
    static Prepared prepare(QVector<HistoryItem> rows, QSet<QString> own, QSet<QString> known);
    QSet<QString> ownAddresses() const { return m_ownAddresses; }
    QSet<QString> knownTokens() const { return m_knownTokens; }
    // Show a prepared history. Rows fetched while it was being prepared are kept, merged on top.
    void adoptPrepared(Prepared p);

public slots:
    // Connect to Wallet::historyRefreshed (single-account / one-shot path).
    void onHistoryRefreshed(const QVector<HistoryItem> &items);

    // Drop optimistic pending sends/swaps (e.g. on a chain switch) so a pending row from one chain
    // never leaks into another chain's history.
    void clearLocal();

    // Incremental all-account refresh: clear + reset dedup, then append per-account batches so a
    // huge multi-account history fills in progressively (each append is a small beginInsertRows,
    // not a full model reset). The sorting proxy orders rows for display.
    void beginFullRefresh();
    void appendBatch(const QVector<HistoryItem> &items);
    // Distinct fetched rows held, so a caller can tell whether a batch brought anything new.
    int fetchedCount() const { return m_fetched.size(); }

    // Persisted history (per-chain wallet cache): export the fetched set, and load it back on open so
    // a restart shows history instantly with zero network requests (Electrum/Feather model).
    QVector<HistoryItem> fetchedItems() const { return m_fetched; }
    void loadCachedHistory(const QVector<HistoryItem> &items);

    // Optimistically prepend a locally-broadcast send so it shows immediately. `token` is the ERC-20
    // contract ("" for a native-coin send) so the pending row shows the correct asset icon.
    void addLocalSend(const QString &txHash, const QString &to, const QString &amountFormatted,
                      const QString &symbol, const QString &token = QString());

    // Settle an optimistic local send the moment its receipt arrives, instead of waiting for the
    // explorer to index the mined row (which can lag minutes). Flips the matching pending row off
    // "pending" so the Date column stops saying "pending" and a revert shows as "Failed"; the row is
    // still reconciled away when the real fetched copy lands. No-op if no local send matches.
    void confirmLocalSend(const QString &txHash, bool failed);

    // Same, for an optimistic on-chain (router) swap: settle it the moment its receipt arrives rather
    // than waiting for the explorer to index both legs. The row already holds both symbols, so this
    // just flips "pending" to "done"/"failed"; the fetched swap row still reconciles it away. No-op if
    // no local swap matches (e.g. a CoW order, which settles via its own poll, not a tx receipt).
    void confirmLocalSwap(const QString &txHash, bool failed);

    // Flip any local optimistic swap still "pending" past `maxAgeSecs` to "failed", so a row can't
    // display "pending" forever if the CoW API never returns the order (unreachable / not indexed).
    void expireStalePendingSwaps(qint64 maxAgeSecs);

    // Optimistically show a just-placed swap as "pending" immediately (on any network, incl. on-chain
    // router swaps that only reach the explorer once mined). It's reconciled away when the real row
    // (CoW order by uid, or the mined tx) appears in fetched history.
    void addLocalSwap(const HistoryItem &h);

    // True if ANY swap (an optimistic local row OR a fetched order still open on CoW) is showing as
    // "pending". Drives the background poll: reconciliation moves a still-open order from the local
    // list into the fetched list (status still pending), so checking only m_localSwaps would stop
    // the poll prematurely and the row would never flip to filled/failed.
    bool hasPendingSwaps() const {
        for (const HistoryItem &h : m_allItems)
            if (h.kind == QLatin1String("swap") && h.status == QLatin1String("pending"))
                return true;
        return false;
    }

    // Accounts holding a swap that is still open. An off-chain order can only be asked about through
    // the address that placed it, so polling the account that happens to be on screen would leave a
    // swap made from any other one waiting forever.
    QList<quint32> pendingSwapAccounts() const;

    // Jump to a page (0-based; clamped to a valid range). Only re-slices the already-filtered list.
    void setPage(int page);

    // Case-insensitive search across the visible columns; filters the full set then paginates.
    void setSearchText(const QString &text);

    // Contract addresses (lower-case) of tokens the user actually tracks. Incoming transfers of any
    // *other* ERC-20 are treated as unsolicited spam/airdrops and hidden.
    void setKnownTokens(const QSet<QString> &tokens);

    // The wallet's own receive addresses (lower-case). Used to detect vanity/look-alike
    // address-poisoning: an attacker crafts an address sharing the same first/last hex characters as
    // one of these (or of a real counterparty) so it blends into history and gets copy-pasted later.
    void setOwnAddresses(const QSet<QString> &addrs);

    // When true (default), address-poisoning and spam-token transfers are removed from the list
    // entirely rather than shown; toggled from the History options menu.
    void setHideSpam(bool hide);
    bool hideSpam() const { return m_hideSpam; }

    // Hide incoming transfers worth less than this many USD (0 = disabled) as dust/spam. Requires
    // per-symbol prices (setPrices) to value each transfer.
    void setDustThreshold(double usd);
    void setPrices(const QHash<QString, double> &pricesBySymbol); // symbol (upper) -> USD
    // What to call each account in the Account column, keyed by account index: the label the user
    // typed on Receive, or "Account #N" where they have not named one. Pushed in from the window,
    // which owns the labels; the model only has an index to go on.
    void setAccountNames(const QHash<quint32, QString> &names);

    // The name shown for a row's account, or empty for a row old enough not to record one.
    QString accountName(const HistoryItem &h) const;

    // Per-transaction notes (Electrum-style), keyed by lower-case tx hash. When a row has a note it's
    // shown in the Counterparty column (the address moves to the tooltip).
    void setTxNotes(const QHash<QString, QString> &notes);
    void setTxNote(const QString &txHash, const QString &note);
    QString txNote(const QString &txHash) const { return m_txNotes.value(txHash.toLower()); }
    void setFiat(double rate, const QString &symbol);             // USD -> display fiat for Value column
    // Historical unit price for the Value column, keyed "SYMBOL|YYYY-MM-DD" (UTC). When present for a
    // transfer's asset+date it's used instead of the current price, so Value shows the fiat worth at
    // the time of the transaction.
    void setHistoricalUnitPrice(const QString &key, double usd);
    // Bulk form, for restoring a session's worth of saved prices at open. The single-key setter
    // repaints the whole Value column each time, so replaying hundreds of them one by one asked the
    // view to redraw hundreds of times before the window had even finished opening.
    void setHistoricalUnitPrices(const QHash<QString, double> &pricesByKey);

    // Unit price to value a transfer: the historical price for its date if known, else current.
    double unitPriceFor(const HistoryItem &h) const;

signals:
    // Emitted after any re-slice so the UI can update its pager (1-based page shown to the user is
    // page+1). `total` is the post-filter row count across all pages.
    void pageChanged(int page, int pageCount, int total);

    // A genuinely new incoming transfer that the spam filter did NOT hide. Notifications hang off
    // this instead of raw balance increases, so nothing that History hides (dust, zero-value or
    // look-alike poisoning) can ever pop a "Payment received" toast. Not fired while an account's
    // existing history is first being seeded (startup / first fetch), only for later arrivals.
    void incomingPayment(quint32 account, const QString &formatted, const QString &symbol);

private:
    static QString dedupKey(const HistoryItem &h); // stable per-row key for m_fetchedAt
    // Whether a freshly fetched copy of a row we already hold says something new. A swap is fetched
    // over and over precisely because its outcome changes, so "already seen" must not mean "ignore".
    static bool supersedes(const HistoryItem &prev, const HistoryItem &next);
    // Folds a coin and its wrapped token onto one name, so a swap of the chain's own coin recognises
    // its settled copy (see the eth-flow note in appendBatch).
    static QString assetKey(const QString &symbol);
    static bool samePair(const HistoryItem &a, const HistoryItem &b);
    void reindexFetched();                     // rebuild m_fetchedAt after a wholesale replacement
    int fetchedIndex(const QString &key) const; // position in m_fetched, or -1

    static RowFacts factsFor(const HistoryItem &h);
    // The spam-token rule against a given trusted set, so a worker preparing a history applies the
    // same rule the model does.
    static bool spamTokenIn(const HistoryItem &h, const RowFacts &f, const QSet<QString> &known);
    // Fold one row into a look-alike index if it is a genuine transfer of value (shared by the
    // model's incremental index and by prepare()).
    static void addPoisonRef(const HistoryItem &h, const RowFacts &f, const QSet<QString> &known,
                             PoisonRefs &refs);
    static void addOwnRef(PoisonRefs &refs, const QString &addrLower);
    bool isSpamToken(const HistoryItem &h, const RowFacts &f) const;
    bool isSpamToken(const HistoryItem &h) const;
    bool isHiddenSpam(const HistoryItem &h, const RowFacts &f) const;
    bool isHiddenSpam(const HistoryItem &h) const; // rows removed when m_hideSpam is on

    // The derived data below describes a PREFIX of m_allItems. Appending rows leaves it valid and
    // only the new tail is computed; anything that removes, replaces or reorders rows calls
    // invalidateDerived() and it is rebuilt on next use. Keeping it a prefix is what makes a stale
    // entry impossible: an earlier version indexed a search table that appends did not extend, and
    // read past its end.
    void invalidateDerived();
    void ensureFacts();
    void ensurePoisonRefs(); // the look-alike index over own addresses + genuine counterparties
    // Whether a row matches the search box, against the fields as shown. Matched in place rather than
    // through a pre-built per-row search text: building that text for every row cost the first
    // keystroke of a search most of a tenth of a second on a long history, and held ~10 MB.
    bool matchesSearch(const HistoryItem &h, const RowFacts &f) const;
    // "yyyy-MM-dd" for a timestamp's UTC day, cached per day. unitPriceFor looks up historical prices
    // by this key, and the value sort asks it twice per comparison - formatting a date for each was
    // what made sorting by value take the better part of a second.
    QString utcDayKey(quint64 ts) const;
    QString dayText(qint64 daysSinceEpoch) const; // "yyyy-MM-dd", cached
    // The Date column's "yyyy-MM-dd HH:mm" in local time, without a local-time conversion per row.
    // The search text needs it for every row, and converting each timestamp to local time was most
    // of what the first keystroke of a search cost.
    QString localMinuteText(quint64 ts) const;
    // Emit incomingPayment() for any new, non-hidden incoming transfer in `items`, seeding (silently)
    // each account's backlog on its first delivery so startup/first-fetch never bursts notifications.
    void noteIncoming(const QVector<HistoryItem> &items);
    bool lessThan(const HistoryItem &a, const HistoryItem &b) const; // cheap sort columns only
    void rebuildVisible();      // filter m_allItems -> m_filtered, sort, then re-slice the page
    void reslice();             // materialise only the current page window into m_items
    void sortFiltered();        // sort m_filtered by the current column/order
    void scheduleRebuild(int delayMs = 150); // debounce rebuildVisible
    // While account batches stream in during a history load, a rebuild of the whole table after each
    // one kept the UI thread about a seventh busy for the length of the load. During a burst the
    // table refreshes at this slower cadence instead; a single arrival still shows at the normal one.
    static constexpr int kBurstRebuildMs = 450;
    qint64 m_lastBatchMs = 0; // when the previous batch arrived, to recognise a burst
    void rebuildAll();          // compose m_allItems = pending swaps + fetched

    QVector<HistoryItem> m_fetched;    // last fetched (on-chain + CoW) history
    QVector<HistoryItem> m_localSwaps; // optimistic pending swaps until they appear in m_fetched
    QVector<HistoryItem> m_localSends; // optimistic pending sends until they appear in m_fetched
    QVector<HistoryItem> m_allItems; // full unfiltered history (+ local sends)
    // Dedup key -> where that row lives in m_fetched. A set would only answer "have we got this
    // one", which is the wrong question for a swap: the interesting fetch is the second one, the
    // one that says the order finally filled.
    QHash<QString, int> m_fetchedAt;
    // The filtered + sorted result (all pages), as positions in m_allItems. Positions rather than
    // copies: a filter pass used to copy every surviving row - fifteen strings each - and the sort
    // then shuffled those whole rows around, which was the floor under every rebuild.
    QVector<int> m_filtered;
    QVector<HistoryItem> m_items;    // the CURRENT PAGE slice of m_filtered (what the view renders)
    QVector<bool> m_itemSpam;        // per m_items row: shown only because spam is not being hidden
    QSet<QString> m_knownTokens;
    QSet<QString> m_ownAddresses;   // wallet's own addresses (lower-case) - poisoning targets
    PoisonRefs m_poisonRefs;        // the look-alike index (see PoisonRefs), lower-case
    QVector<RowFacts> m_facts;      // per row of m_allItems (a prefix; see invalidateDerived)
    // Per search: which accounts' names contain the text (a wallet has a few hundred accounts, and
    // naming one means building a string, so each is decided once, not once per row).
    mutable QHash<quint32, bool> m_searchAccountHit;
    bool m_searchLooksLikeDate = false; // only digits and date punctuation: worth matching dates
    // Bumped by every change that affects which rows pass the filter or their order, other than the
    // search text. If it has not moved since the last pass and the user has only typed more of the
    // same search, the next pass narrows the previous result instead of re-filtering everything.
    quint64 m_filterInputs = 0;
    quint64 m_filteredInputs = ~quint64(0); // m_filterInputs as of the last full pass
    QString m_filteredSearch;               // the search that pass was for
    // How many leading rows of m_allItems the look-alike index includes; -1 = rebuild from scratch.
    // The index depends on the rows, the wallet's own addresses and which tokens are trusted, so a
    // change to either set resets it too.
    int m_poisonRows = -1;
    mutable QHash<qint64, QString> m_dayKeys; // day number -> "yyyy-MM-dd"
    // UTC day number -> the local UTC offset in force all that day, or INT_MIN on a day the clocks
    // change (those rows are converted exactly).
    mutable QHash<qint64, int> m_localOffsets;
    QSet<QString> m_seenIncoming;      // dedup keys of incoming transfers already accounted for
    QSet<quint32> m_notifyInitialized; // accounts whose backlog has been seeded (so it stays silent)
    bool m_hideSpam = true;
    double m_dustUsd = 0.0;              // hide incoming worth less than this many USD (0 = off)
    QHash<QString, double> m_prices;     // symbol (upper) -> USD, for dust valuation
    QHash<QString, QString> m_txNotes;   // lower-case tx hash -> user note
    QHash<quint32, QString> m_accountNames; // account index -> its Receive label
    QHash<QString, double> m_histUnitPrice; // "SYMBOL|YYYY-MM-DD" -> USD, historical valuation
    double m_fiatRate = 1.0;             // USD -> display fiat multiplier for the Value column
    QString m_fiatSymbol = QStringLiteral("$");

    int m_pageSize = 500;                        // rows per page
    int m_page = 0;                              // current 0-based page
    QString m_search;                            // lower-case search text ("" = no filter)
    int m_sortColumn = Column_Date;              // default sort: newest first
    Qt::SortOrder m_sortOrder = Qt::DescendingOrder;
    QTimer *m_coalesceTimer = nullptr;           // coalesces appendBatch bursts into one rebuild
};

#endif // AERO_HISTORYMODEL_H
