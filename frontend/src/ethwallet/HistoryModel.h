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
    // trusted and aren't obvious homoglyph/ETH impersonators — candidates for a liquidity check.
    QStringList untrackedTokenAddresses() const;

public slots:
    // Connect to Wallet::historyRefreshed (single-account / one-shot path).
    void onHistoryRefreshed(const QVector<HistoryItem> &items);

    // Incremental all-account refresh: clear + reset dedup, then append per-account batches so a
    // huge multi-account history fills in progressively (each append is a small beginInsertRows,
    // not a full model reset). The sorting proxy orders rows for display.
    void beginFullRefresh();
    void appendBatch(const QVector<HistoryItem> &items);

    // Optimistically prepend a locally-broadcast send so it shows immediately.
    void addLocalSend(const QString &txHash, const QString &to, const QString &amountFormatted,
                      const QString &symbol);

    // Optimistically show a just-placed swap as "pending" immediately (on any network, incl. on-chain
    // router swaps that only reach the explorer once mined). It's reconciled away when the real row
    // (CoW order by uid, or the mined tx) appears in fetched history.
    void addLocalSwap(const HistoryItem &h);

    // Jump to a page (0-based; clamped to a valid range). Only re-slices the already-filtered list.
    void setPage(int page);

    // Case-insensitive search across the visible columns; filters the full set then paginates.
    void setSearchText(const QString &text);

    // Contract addresses (lower-case) of tokens the user actually tracks. Incoming transfers of any
    // *other* ERC-20 are treated as unsolicited spam/airdrops and hidden.
    void setKnownTokens(const QSet<QString> &tokens);

    // When true (default), address-poisoning and spam-token transfers are removed from the list
    // entirely rather than shown; toggled from the History options menu.
    void setHideSpam(bool hide);
    bool hideSpam() const { return m_hideSpam; }

    // Hide incoming transfers worth less than this many USD (0 = disabled) as dust/spam. Requires
    // per-symbol prices (setPrices) to value each transfer.
    void setDustThreshold(double usd);
    void setPrices(const QHash<QString, double> &pricesBySymbol); // symbol (upper) -> USD
    void setFiat(double rate, const QString &symbol);             // USD -> display fiat for Value column
    // Historical unit price for the Value column, keyed "SYMBOL|YYYY-MM-DD" (UTC). When present for a
    // transfer's asset+date it's used instead of the current price, so Value shows the fiat worth at
    // the time of the transaction.
    void setHistoricalUnitPrice(const QString &key, double usd);

    // Unit price to value a transfer: the historical price for its date if known, else current.
    double unitPriceFor(const HistoryItem &h) const;

signals:
    // Emitted after any re-slice so the UI can update its pager (1-based page shown to the user is
    // page+1). `total` is the post-filter row count across all pages.
    void pageChanged(int page, int pageCount, int total);

private:
    bool isSpamToken(const HistoryItem &h) const;
    bool isHiddenSpam(const HistoryItem &h) const; // rows removed when m_hideSpam is on
    bool matchesSearch(const HistoryItem &h) const;
    bool lessThan(const HistoryItem &a, const HistoryItem &b) const; // by current sort column
    void rebuildVisible();      // filter m_allItems -> m_filtered, sort, then re-slice the page
    void reslice();             // materialise only the current page window into m_items
    void sortFiltered();        // sort m_filtered by the current column/order
    void scheduleRebuild();     // debounce rebuildVisible during incremental appendBatch bursts
    void rebuildAll();          // compose m_allItems = pending swaps + fetched

    QVector<HistoryItem> m_fetched;    // last fetched (on-chain + CoW) history
    QVector<HistoryItem> m_localSwaps; // optimistic pending swaps until they appear in m_fetched
    QVector<HistoryItem> m_allItems; // full unfiltered history (+ local sends)
    QSet<QString> m_seen;              // dedup keys for the incremental appendBatch path
    QVector<HistoryItem> m_filtered;   // full filtered + sorted result (all pages)
    QVector<HistoryItem> m_items;    // the CURRENT PAGE slice of m_filtered (what the view renders)
    QSet<QString> m_knownTokens;
    bool m_hideSpam = true;
    double m_dustUsd = 0.0;              // hide incoming worth less than this many USD (0 = off)
    QHash<QString, double> m_prices;     // symbol (upper) -> USD, for dust valuation
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
