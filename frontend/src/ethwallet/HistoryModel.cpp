// SPDX-License-Identifier: BSD-3-Clause
#include "HistoryModel.h"

#include <algorithm>

#include <QBrush>
#include <QColor>
#include <QDateTime>
#include <QFileInfo>
#include <QIcon>
#include <QTimer>

// A token symbol is an impersonation if it isn't plain ASCII. Scam tokens use Cyrillic/Greek
// look-alikes (e.g. "ЕТН"/"ΕΤΗ" for "ETH") to dodge naive symbol checks and fool the eye; every
// legitimate ERC-20 symbol is ASCII, so any non-ASCII symbol is treated as a homoglyph attack.
static bool hasHomoglyphSymbol(const QString &symbol) {
    for (const QChar &c : symbol)
        if (c.unicode() > 0x7F)
            return true;
    return false;
}

// True if this transfer is an ERC-20 the user doesn't track. Attackers emit fake `Transfer` events
// (address-poisoning) that appear in history as though *you* sent funds, so we cannot trust the
// direction OR the symbol — we trust only the official tracked contract-address allow-list. This
// covers both unsolicited incoming airdrops and spoofed "outgoing" transactions you never signed.
bool HistoryModel::isSpamToken(const HistoryItem &h) const {
    if (h.token.isEmpty())
        return false; // native ETH transfers cannot be spoofed
    if (hasHomoglyphSymbol(h.symbol))
        return true; // non-ASCII symbol => homoglyph impersonation
    if (h.symbol.compare(QLatin1String("ETH"), Qt::CaseInsensitive) == 0)
        return true; // an ERC-20 calling itself "ETH" is always fake
    return !m_knownTokens.contains(h.token.toLower());
}

// Cap a full-precision decimal string to a readable number of places (tokens routinely report 18
// decimals, e.g. "16.916374757470879836"). Shows up to 4 places (8 for sub-0.0001 dust) and trims
// trailing zeros so amounts read cleanly in the table.
static QString capAmount(const QString &raw) {
    bool ok = false;
    const double v = raw.toDouble(&ok);
    if (!ok)
        return raw;
    const double a = qAbs(v);
    const int dec = (a != 0.0 && a < 0.0001) ? 8 : 4;
    QString s = QString::number(v, 'f', dec);
    if (s.contains(QLatin1Char('.'))) {
        while (s.endsWith(QLatin1Char('0')))
            s.chop(1);
        if (s.endsWith(QLatin1Char('.')))
            s.chop(1);
    }
    return s;
}

// Zero-value incoming transfers are the classic address-poisoning pattern (dust/$0 from look-alike
// addresses). These are not real payments and are hidden along with spam tokens.
static bool isPoisoning(const HistoryItem &h) {
    return h.direction == QLatin1String("in") && (h.amount.isEmpty() || h.amount == QLatin1String("0"));
}

bool HistoryModel::isHiddenSpam(const HistoryItem &h) const {
    if (h.kind == QLatin1String("swap"))
        return false; // swaps are user-initiated, never spam
    if (isPoisoning(h) || isSpamToken(h))
        return true;
    // Dust filter: hide incoming transfers worth less than the configured USD threshold. Only
    // applied when we actually have a positive price for the asset, so legit transfers aren't
    // hidden just because prices haven't loaded yet.
    if (m_dustUsd > 0.0 && h.direction == QLatin1String("in")) {
        const double price = m_prices.value(h.symbol.toUpper(), -1.0);
        if (price > 0.0 && h.formatted.toDouble() * price < m_dustUsd)
            return true;
    }
    return false;
}

bool HistoryModel::isSuspicious(int row) const {
    if (row < 0 || row >= m_items.size())
        return false;
    // Once spam/poisoning are filtered out, the only de-emphasised rows left are failed txs.
    return m_items.at(row).failed;
}

// True if `text` (search box) matches this row on any visible column. m_search is pre-lowercased.
bool HistoryModel::matchesSearch(const HistoryItem &h) const {
    if (m_search.isEmpty())
        return true;
    if (h.counterparty.toLower().contains(m_search)) return true;
    if (h.txHash.toLower().contains(m_search)) return true;
    if (h.symbol.toLower().contains(m_search)) return true;
    if (h.buySymbol.toLower().contains(m_search)) return true;
    if (h.formatted.contains(m_search)) return true;
    if (h.buyFormatted.contains(m_search)) return true;
    // Direction words as shown in the table.
    const QString dir = (h.kind == QLatin1String("swap"))
                            ? QStringLiteral("swap")
                            : (h.failed ? QStringLiteral("failed")
                                        : (h.direction == QLatin1String("in") ? QStringLiteral("received")
                                                                              : QStringLiteral("sent")));
    if (dir.contains(m_search)) return true;
    if (h.timestamp) {
        const QString d = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(h.timestamp))
                              .toString(QStringLiteral("yyyy-MM-dd HH:mm"));
        if (d.contains(m_search)) return true;
    }
    return false;
}

// Order comparison for the current sort column (ascending sense; sortFiltered flips for descending).
bool HistoryModel::lessThan(const HistoryItem &a, const HistoryItem &b) const {
    switch (m_sortColumn) {
    case Column_Date:
        return (a.timestamp ? a.timestamp : a.block) < (b.timestamp ? b.timestamp : b.block);
    case Column_Amount:
    case Column_Value: {
        const double ap = unitPriceFor(a);
        const double bp = unitPriceFor(b);
        const double av = a.formatted.toDouble() * (ap > 0.0 ? ap : 1.0);
        const double bv = b.formatted.toDouble() * (bp > 0.0 ? bp : 1.0);
        return av < bv;
    }
    case Column_Direction: {
        const int ak = a.failed ? 2 : (a.direction == QLatin1String("in") ? 0 : 1);
        const int bk = b.failed ? 2 : (b.direction == QLatin1String("in") ? 0 : 1);
        return ak < bk;
    }
    case Column_Counterparty:
        return a.counterparty < b.counterparty;
    case Column_TxHash:
        return a.txHash < b.txHash;
    default:
        return false;
    }
}

void HistoryModel::sortFiltered() {
    std::stable_sort(m_filtered.begin(), m_filtered.end(),
                     [this](const HistoryItem &a, const HistoryItem &b) {
                         return m_sortOrder == Qt::AscendingOrder ? lessThan(a, b) : lessThan(b, a);
                     });
}

// Recompute the full filtered + sorted result set, then show only the current page.
void HistoryModel::rebuildVisible() {
    m_filtered.clear();
    m_filtered.reserve(m_allItems.size());
    for (const HistoryItem &h : m_allItems) {
        if (m_hideSpam && isHiddenSpam(h))
            continue;
        if (!matchesSearch(h))
            continue;
        m_filtered.append(h);
    }
    sortFiltered();
    reslice();
}

// Materialise ONLY the 500-row window for the current page into m_items (what the view renders), so
// display cost stays constant regardless of how large the full history is.
void HistoryModel::reslice() {
    const int total = m_filtered.size();
    const int pages = qMax(1, (total + m_pageSize - 1) / m_pageSize);
    m_page = qBound(0, m_page, pages - 1);
    beginResetModel();
    m_items.clear();
    const int start = m_page * m_pageSize;
    const int end = qMin(total, start + m_pageSize);
    m_items.reserve(qMax(0, end - start));
    for (int i = start; i < end; ++i)
        m_items.append(m_filtered.at(i));
    endResetModel();
    emit pageChanged(m_page, pages, total);
}

void HistoryModel::setPage(int page) {
    if (page == m_page)
        return;
    m_page = page;
    reslice();
}

void HistoryModel::setSearchText(const QString &text) {
    const QString t = text.trimmed().toLower();
    if (t == m_search)
        return;
    m_search = t;
    m_page = 0; // a new filter always starts at the first page
    rebuildVisible();
}

void HistoryModel::sort(int column, Qt::SortOrder order) {
    // No-op when nothing changed — this also breaks the recursion the view would otherwise cause by
    // re-issuing sort() after each model reset (we own the ordering, there is no proxy).
    if (column == m_sortColumn && order == m_sortOrder)
        return;
    m_sortColumn = column;
    m_sortOrder = order;
    m_page = 0;
    rebuildVisible();
}

// Coalesce a burst of appendBatch() calls (one per account during an all-account load) into a single
// filter+sort+re-slice, so we don't re-sort a growing list on every one of hundreds of batches.
void HistoryModel::scheduleRebuild() {
    if (!m_coalesceTimer) {
        m_coalesceTimer = new QTimer(this);
        m_coalesceTimer->setSingleShot(true);
        m_coalesceTimer->setInterval(150);
        connect(m_coalesceTimer, &QTimer::timeout, this, [this]() { rebuildVisible(); });
    }
    // Start only if not already pending, so a continuous burst still refreshes ~every 150ms (page 0
    // fills in visibly) instead of deferring the rebuild until the burst stops.
    if (!m_coalesceTimer->isActive())
        m_coalesceTimer->start();
}

void HistoryModel::setHideSpam(bool hide) {
    if (m_hideSpam == hide)
        return;
    m_hideSpam = hide;
    rebuildVisible();
}

void HistoryModel::setDustThreshold(double usd) {
    if (m_dustUsd == usd)
        return;
    m_dustUsd = usd;
    rebuildVisible();
}

void HistoryModel::setPrices(const QHash<QString, double> &pricesBySymbol) {
    m_prices = pricesBySymbol;
    if (!m_items.isEmpty()) // refresh the Value column
        emit dataChanged(index(0, Column_Value), index(m_items.size() - 1, Column_Value));
    if (m_dustUsd > 0.0) // prices also affect the dust filter
        rebuildVisible();
}

void HistoryModel::setFiat(double rate, const QString &symbol) {
    m_fiatRate = rate > 0.0 ? rate : 1.0;
    m_fiatSymbol = symbol;
    if (!m_items.isEmpty())
        emit dataChanged(index(0, Column_Value), index(m_items.size() - 1, Column_Value));
}

void HistoryModel::setHistoricalUnitPrice(const QString &key, double usd) {
    if (usd <= 0.0)
        return;
    m_histUnitPrice.insert(key, usd);
    if (!m_items.isEmpty())
        emit dataChanged(index(0, Column_Value), index(m_items.size() - 1, Column_Value));
}

double HistoryModel::unitPriceFor(const HistoryItem &h) const {
    if (h.timestamp > 0) {
        const QString date =
            QDateTime::fromSecsSinceEpoch(static_cast<qint64>(h.timestamp), Qt::UTC)
                .toString(QStringLiteral("yyyy-MM-dd"));
        const double hist = m_histUnitPrice.value(h.symbol.toUpper() + QLatin1Char('|') + date, 0.0);
        if (hist > 0.0)
            return hist; // fiat value at the time of the transaction
    }
    return m_prices.value(h.symbol.toUpper(), 0.0); // fall back to the current price
}

QStringList HistoryModel::untrackedTokenAddresses() const {
    QSet<QString> seen;
    QStringList out;
    for (const HistoryItem &h : m_allItems) {
        if (h.token.isEmpty())
            continue; // native ETH
        const QString addr = h.token.toLower();
        if (m_knownTokens.contains(addr) || seen.contains(addr))
            continue;
        if (hasHomoglyphSymbol(h.symbol) ||
            h.symbol.compare(QLatin1String("ETH"), Qt::CaseInsensitive) == 0)
            continue; // always-spam impersonators aren't worth a liquidity lookup
        seen.insert(addr);
        out << addr;
    }
    return out;
}

void HistoryModel::setKnownTokens(const QSet<QString> &tokens) {
    m_knownTokens.clear();
    for (const QString &t : tokens)
        m_knownTokens.insert(t.toLower());
    // Spam classification depends on the tracked-token set, so re-filter the visible rows.
    rebuildVisible();
}

QVariant HistoryModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= m_items.size())
        return {};

    const HistoryItem &h = m_items.at(index.row());

    // Show the asset's logo next to the amount. Only *native* ETH (empty token address) may use the
    // ETH logo — an ERC-20 that calls itself "ETH" is a scam and must not borrow it. Unknown tokens
    // get no logo (QIcon(path) is never null even when the resource is missing, so check existence).
    if (role == Qt::DecorationRole && index.column() == Column_Amount) {
        const QString sym = h.token.isEmpty() ? QStringLiteral("ETH") : h.symbol.toUpper();
        if (!h.token.isEmpty() && sym == QLatin1String("ETH"))
            return {}; // ERC-20 impersonating native ETH
        const QString path = QStringLiteral(":/assets/images/tokens/%1.png").arg(sym);
        if (!QFileInfo::exists(path))
            return {};
        return QIcon(path);
    }

    if (role == Qt::ForegroundRole) {
        if (h.failed)
            return QBrush(QColor(0x80, 0x80, 0x80)); // grey out failed (reverted) txs
        if (h.kind == QLatin1String("swap")) {
            // Pending swaps are muted; otherwise use the default text colour (no red/green).
            if (h.status == QLatin1String("pending"))
                return QBrush(QColor(0xE5, 0xA5, 0x2E)); // amber = awaiting fill
            return {};
        }
        // Feather-style: outgoing amounts in red, incoming in white.
        if (index.column() == Column_Amount || index.column() == Column_Value)
            return QBrush(h.direction == QLatin1String("out") ? QColor(0xE0, 0x6C, 0x75)
                                                              : QColor(0xE6, 0xE6, 0xE6));
        return {};
    }

    if (role == Qt::ToolTipRole) {
        if (h.failed)
            return tr("This transaction failed (reverted).");
        // Spam/poisoning rows are normally hidden; if visible (toggle off) label them clearly.
        if (isSpamToken(h))
            return tr("Unsolicited/spam token transfer. This is NOT native ETH and does not affect "
                      "your balance — likely a scam token impersonating a real asset. Do not "
                      "interact with it.");
        if (isPoisoning(h))
            return tr("Possible address-poisoning: zero-value transfer. Do not trust this address.");
        return h.txHash;
    }

    // Numeric/typed sort keys so header-click sorting on Date and Amount is chronological / by value
    // rather than lexicographic. Used as the proxy model's sort role.
    if (role == SortRole) {
        switch (index.column()) {
        case Column_Date:
            return static_cast<qlonglong>(h.timestamp ? h.timestamp : h.block);
        case Column_Amount:
        case Column_Value: {
            const double amt = h.formatted.toDouble();
            const double price = unitPriceFor(h);
            return price > 0.0 ? amt * price : amt; // sort by USD value when known, else raw amount
        }
        case Column_Direction:
            return h.failed ? 2 : (h.direction == QLatin1String("in") ? 0 : 1);
        case Column_Counterparty:
            return h.counterparty;
        case Column_TxHash:
            return h.txHash;
        default:
            return {};
        }
    }

    if (role != Qt::DisplayRole)
        return {};

    switch (index.column()) {
        case Column_Date:
            if (h.timestamp == 0)
                return h.block == 0 ? tr("pending") : QString::number(h.block);
            return QDateTime::fromSecsSinceEpoch(static_cast<qint64>(h.timestamp))
                .toString(QStringLiteral("yyyy-MM-dd HH:mm"));
        case Column_Direction:
            if (h.kind == QLatin1String("swap")) {
                if (h.status == QLatin1String("pending")) return tr("Swap · pending");
                if (h.status == QLatin1String("failed") || h.failed) return tr("Swap · failed");
                return tr("Swap");
            }
            return h.failed ? tr("Failed")
                            : (h.direction == "in" ? tr("Received") : tr("Sent"));
        case Column_Amount:
            if (h.kind == QLatin1String("swap"))
                return QStringLiteral("%1 %2 \u2192 %3 %4")
                    .arg(capAmount(h.formatted), h.symbol, capAmount(h.buyFormatted), h.buySymbol);
            return QStringLiteral("%1 %2").arg(capAmount(h.formatted), h.symbol);
        case Column_Value: {
            const double price = unitPriceFor(h);
            if (price <= 0.0)
                return QStringLiteral("—"); // price not known (yet) for this asset
            const double val = h.formatted.toDouble() * price * m_fiatRate;
            return QStringLiteral("%1%2").arg(m_fiatSymbol, QString::number(val, 'f', 2));
        }
        case Column_Counterparty: return h.counterparty;
        case Column_TxHash:       return h.txHash;
        default:                  return {};
    }
}

QVariant HistoryModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return {};
    switch (section) {
        case Column_Date:         return tr("Date");
        case Column_Direction:    return tr("Direction");
        case Column_Amount:       return tr("Amount");
        case Column_Value:        return tr("Value (USD)");
        case Column_Counterparty: return tr("Counterparty");
        case Column_TxHash:       return tr("Transaction");
        default:                  return {};
    }
}

void HistoryModel::onHistoryRefreshed(const QVector<HistoryItem> &items) {
    m_fetched = items;
    rebuildAll();
}

// Start of an incremental all-account refresh: clear fetched history + dedup, keep any optimistic
// local swaps on top, and reset to the first page.
void HistoryModel::beginFullRefresh() {
    m_fetched.clear();
    m_seen.clear();
    // Seed dedup with the pending local swaps (by uid) so their settled copies aren't re-added.
    for (const HistoryItem &h : m_localSwaps)
        if (!h.txHash.isEmpty())
            m_seen.insert(h.txHash.toLower());
    m_allItems = m_localSwaps;
    m_page = 0;
    rebuildVisible(); // filter + sort + slice page 0 (just the pending swaps at this point)
}

// Append one account's rows (deduped) to the full set, then schedule a debounced filter/sort/slice.
// Only the current 500-row page is ever materialised, so a huge multi-account history stays smooth.
void HistoryModel::appendBatch(const QVector<HistoryItem> &items) {
    QVector<HistoryItem> add;
    add.reserve(items.size());
    for (const HistoryItem &h : items) {
        // A settled swap whose pending local copy is already shown: skip (keep the local one).
        if (h.kind == QLatin1String("swap") && !h.txHash.isEmpty() &&
            m_seen.contains(h.txHash.toLower()))
            continue;
        const QString key = QStringLiteral("%1|%2|%3|%4")
                                .arg(h.txHash, h.token, h.direction, h.amount);
        if (m_seen.contains(key))
            continue;
        m_seen.insert(key);
        add.append(h);
    }
    if (add.isEmpty())
        return;
    m_fetched += add;
    m_allItems += add;
    scheduleRebuild();
}

// Compose the unfiltered list as [optimistic pending swaps] + [fetched history], dropping any
// pending swap that has since appeared in fetched data (matched by tx hash / CoW order uid).
void HistoryModel::rebuildAll() {
    if (!m_localSwaps.isEmpty()) {
        QSet<QString> fetchedIds;
        for (const HistoryItem &h : m_fetched)
            if (!h.txHash.isEmpty())
                fetchedIds.insert(h.txHash.toLower());
        m_localSwaps.erase(std::remove_if(m_localSwaps.begin(), m_localSwaps.end(),
                                          [&](const HistoryItem &h) {
                                              return fetchedIds.contains(h.txHash.toLower());
                                          }),
                           m_localSwaps.end());
    }
    m_allItems = m_localSwaps; // pending swaps on top
    m_allItems += m_fetched;
    rebuildVisible();
}

void HistoryModel::addLocalSwap(const HistoryItem &h) {
    // Replace an existing pending entry with the same id, else prepend a new one.
    for (HistoryItem &e : m_localSwaps)
        if (!h.txHash.isEmpty() && e.txHash == h.txHash) {
            e = h;
            rebuildAll();
            return;
        }
    m_localSwaps.prepend(h);
    rebuildAll();
}

void HistoryModel::addLocalSend(const QString &txHash, const QString &to,
                                const QString &amountFormatted, const QString &symbol) {
    HistoryItem h;
    h.direction = QStringLiteral("out");
    h.counterparty = to;
    h.formatted = amountFormatted;
    h.symbol = symbol;
    h.txHash = txHash;
    h.block = 0; // pending until confirmed / next log refresh
    m_allItems.prepend(h);
    rebuildVisible(); // outgoing sends are never spam, so this always becomes visible
}
