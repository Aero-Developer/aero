// SPDX-License-Identifier: BSD-3-Clause
#include "HistoryModel.h"

#include <algorithm>
#include <cctype>

#include <QBrush>
#include <QColor>
#include <QDateTime>
#include <QFileInfo>
#include <QIcon>
#include <QLocale>
#include <QTimer>

// Format a number with thousands separators (commas) at 2 decimals for USD or a given precision for
// token amounts. Uses a fixed en-US locale so grouping is always commas regardless of system locale.
static QString grouped2(double v, int decimals) {
    static const QLocale kUs(QLocale::English, QLocale::UnitedStates);
    return kUs.toString(v, 'f', decimals);
}

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
    QString s = grouped2(v, dec); // thousands separators so big amounts read cleanly
    if (s.contains(QLatin1Char('.'))) {
        while (s.endsWith(QLatin1Char('0')))
            s.chop(1);
        if (s.endsWith(QLatin1Char('.')))
            s.chop(1);
    }
    return s;
}

// Zero-value transfers are address-poisoning, not real activity. Two flavours:
//   * incoming $0/dust from a look-alike address (the classic pattern), and
//   * spoofed zero-value ERC-20 Transfer events of REAL tokens (DAI/USDT/EURC/…) where YOUR address
//     is spoofed as the sender, so they'd otherwise show as bogus "Sent 0 DAI" rows. You never
//     legitimately send 0 of a token, so any zero-value token transfer (either direction) is spam.
// A zero-value NATIVE transaction is kept — that's a genuine contract call (approve/swap/revoke).
static bool isPoisoning(const HistoryItem &h) {
    const bool zero = h.amount.isEmpty() || h.amount == QLatin1String("0");
    if (!zero)
        return false;
    if (h.direction == QLatin1String("in"))
        return true;
    return !h.token.isEmpty(); // zero-value token transfer in any direction => poisoning
}

// True if `s` looks like a 0x… EVM address (0x + 40 hex chars). Counterparties can also be a
// contract name / CoW label, which we skip for look-alike analysis.
static bool isEvmAddress(const QString &s) {
    if (s.size() != 42 || !s.startsWith(QLatin1String("0x"), Qt::CaseInsensitive))
        return false;
    for (int i = 2; i < 42; ++i)
        if (!std::isxdigit(static_cast<unsigned char>(s.at(i).toLatin1())))
            return false;
    return true;
}

// Look-alike signature of an address: its first 4 + last 4 hex characters (lower-case). Vanity
// address-poisoning brute-forces exactly this prefix/suffix so a spoof address renders identically
// to a real one in the truncated "0x1234…abcd" form shown in wallets/explorers.
static QString addrSignature(const QString &addrLower) {
    if (addrLower.size() != 42)
        return QString();
    return addrLower.mid(2, 4) + addrLower.right(4);
}

// Rebuild the reference index of legitimate addresses (the wallet's own addresses + counterparties of
// genuine, non-spam transfers of value). A transfer whose counterparty matches one of these
// signatures but ISN'T one of the real addresses is a vanity look-alike (poisoning). Recomputed per
// rebuild; O(N) over history.
void HistoryModel::rebuildPoisonRefs() {
    m_poisonRefAddrs.clear();
    m_poisonRefSigs.clear();
    const auto addRef = [this](const QString &addrLower) {
        if (!isEvmAddress(addrLower))
            return;
        m_poisonRefAddrs.insert(addrLower);
        const QString sig = addrSignature(addrLower);
        if (!sig.isEmpty())
            m_poisonRefSigs.insert(sig);
    };
    for (const QString &a : m_ownAddresses)
        addRef(a.toLower());
    for (const HistoryItem &h : m_allItems) {
        if (h.kind == QLatin1String("swap"))
            continue;
        const bool nonzero = !(h.amount.isEmpty() || h.amount == QLatin1String("0"));
        // Only trust a counterparty as "real" if it moved value and isn't itself a spam token — so a
        // poisoning entry can never seed its own look-alike reference.
        if (nonzero && !isSpamToken(h))
            addRef(h.counterparty.toLower());
    }
}

// True if this transfer's counterparty is a vanity look-alike of a known-legit address: same
// first4/last4 hex as a real address, but not that address. This is the defining signature of
// address-poisoning and catches spoofs that carry a nonzero/dust value (which the zero-value and
// unknown-token filters miss).
bool HistoryModel::isVanityLookalike(const HistoryItem &h) const {
    const QString a = h.counterparty.toLower();
    if (!isEvmAddress(a) || m_poisonRefAddrs.contains(a))
        return false; // not an address, or an exact legit address — not a look-alike
    return m_poisonRefSigs.contains(addrSignature(a));
}

bool HistoryModel::isHiddenSpam(const HistoryItem &h) const {
    if (h.kind == QLatin1String("swap"))
        return false; // swaps are user-initiated, never spam
    // Never hide the user's own just-broadcast (pending) send — it must appear in history instantly.
    if (h.status == QLatin1String("pending") && h.direction == QLatin1String("out"))
        return false;
    if (isPoisoning(h) || isSpamToken(h))
        return true;
    // Look-alike poisoning is an inbound attack (a spoof address sent to you). Only gate incoming
    // transfers so a genuine outgoing send to a coincidentally-similar address is never hidden.
    if (h.direction == QLatin1String("in") && isVanityLookalike(h))
        return true; // spoof address mimicking a real one (poisoning), any value
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
    case Column_Value: {
        // Strictly by USD worth; an asset with no known price ranks as 0 so a huge-count, low-value
        // token (e.g. an unpriced meme coin) can never sit above a genuinely high-value transfer.
        const double ap = unitPriceFor(a), bp = unitPriceFor(b);
        const double av = ap > 0.0 ? a.formatted.toDouble() * ap : 0.0;
        const double bv = bp > 0.0 ? b.formatted.toDouble() * bp : 0.0;
        return av < bv;
    }
    case Column_Amount: {
        // Rank by USD worth too (so $1.5M outranks $400 of a meme coin). Unpriced assets have no
        // comparable value and rank below all priced ones, ordered among themselves by quantity.
        const double ap = unitPriceFor(a), bp = unitPriceFor(b);
        const double av = ap > 0.0 ? a.formatted.toDouble() * ap : 0.0;
        const double bv = bp > 0.0 ? b.formatted.toDouble() * bp : 0.0;
        if (av != bv)
            return av < bv;
        return a.formatted.toDouble() < b.formatted.toDouble();
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
    rebuildPoisonRefs(); // refresh the legit-address index before filtering (look-alike detection)
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

void HistoryModel::setOwnAddresses(const QSet<QString> &addrs) {
    QSet<QString> lower;
    lower.reserve(addrs.size());
    for (const QString &a : addrs)
        lower.insert(a.toLower());
    if (lower == m_ownAddresses)
        return; // unchanged — avoid a needless re-filter
    m_ownAddresses = lower;
    rebuildVisible(); // look-alike detection references the wallet's own addresses
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
        // If a note is shown in place of the counterparty, reveal the real address on hover.
        if (index.column() == Column_Counterparty && !m_txNotes.value(h.txHash.toLower()).isEmpty())
            return h.counterparty;
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
            // Sort by USD value; unpriced assets rank as 0 so a huge unpriced token count can't
            // outrank a genuinely high-value transfer.
            return price > 0.0 ? amt * price : 0.0;
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
            // Unconfirmed rows show "pending" even though we stamp a sort timestamp so they float to
            // the top. Keyed on status (not block==0) because settled CoW orders also carry block 0
            // but have a real creation timestamp to display.
            if (h.status == QLatin1String("pending"))
                return tr("pending");
            if (h.timestamp != 0)
                return QDateTime::fromSecsSinceEpoch(static_cast<qint64>(h.timestamp))
                    .toString(QStringLiteral("yyyy-MM-dd HH:mm"));
            return h.block == 0 ? tr("pending") : QString::number(h.block);
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
            return QStringLiteral("%1%2").arg(m_fiatSymbol, grouped2(val, 2));
        }
        case Column_Counterparty: {
            const QString note = m_txNotes.value(h.txHash.toLower());
            return note.isEmpty() ? h.counterparty : note; // note replaces the address (see tooltip)
        }
        case Column_TxHash:       return h.txHash;
        default:                  return {};
    }
}

void HistoryModel::setTxNotes(const QHash<QString, QString> &notes) {
    m_txNotes.clear();
    for (auto it = notes.constBegin(); it != notes.constEnd(); ++it)
        if (!it.value().trimmed().isEmpty())
            m_txNotes.insert(it.key().toLower(), it.value());
    if (!m_items.isEmpty())
        emit dataChanged(index(0, Column_Counterparty),
                         index(m_items.size() - 1, Column_Counterparty));
}

void HistoryModel::setTxNote(const QString &txHash, const QString &note) {
    const QString k = txHash.toLower();
    if (note.trimmed().isEmpty())
        m_txNotes.remove(k);
    else
        m_txNotes.insert(k, note);
    if (!m_items.isEmpty())
        emit dataChanged(index(0, Column_Counterparty),
                         index(m_items.size() - 1, Column_Counterparty));
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

void HistoryModel::clearLocal() {
    m_localSwaps.clear();
    m_localSends.clear();
    rebuildAll();
}

// Stable dedup key for an item, shared by appendBatch (insertion) and loadCachedHistory (seeding) so
// a cached row is recognised as "already seen" and a later targeted fetch of the same tx dedups.
QString HistoryModel::dedupKey(const HistoryItem &h) {
    if (h.kind == QLatin1String("swap") && !h.txHash.isEmpty())
        return h.txHash.toLower();
    return QStringLiteral("%1|%2|%3|%4").arg(h.txHash, h.token, h.direction, h.amount);
}

// Seed the model from persisted (wallet-file) history without any network fetch, and pre-populate the
// dedup set so a later targeted appendBatch() of the same account merges/dedups correctly.
void HistoryModel::loadCachedHistory(const QVector<HistoryItem> &items) {
    m_fetched = items;
    m_seen.clear();
    for (const HistoryItem &h : items)
        m_seen.insert(dedupKey(h));
    rebuildAll();
}

// Start of an incremental all-account refresh: clear fetched history + dedup, keep any optimistic
// local swaps on top, and reset to the first page.
void HistoryModel::beginFullRefresh() {
    m_fetched.clear();
    m_seen.clear();
    // Show any optimistic pending swaps on top until the fetched (settled) copy arrives, which
    // appendBatch then reconciles. NOTE: we deliberately do NOT seed m_seen with local swap UIDs —
    // doing so made appendBatch skip the fetched settled order, so the pending row never flipped to
    // filled/failed (the "stuck on pending forever" bug).
    m_allItems = m_localSwaps;
    m_allItems += m_localSends; // keep optimistic pending sends visible across the refresh too
    m_page = 0;
    rebuildVisible(); // filter + sort + slice page 0 (just the pending rows at this point)
}

// Append one account's rows (deduped) to the full set, then schedule a debounced filter/sort/slice.
// Only the current 500-row page is ever materialised, so a huge multi-account history stays smooth.
void HistoryModel::appendBatch(const QVector<HistoryItem> &items) {
    QVector<HistoryItem> add;
    add.reserve(items.size());
    for (const HistoryItem &h : items) {
        if (h.kind == QLatin1String("swap") && !h.txHash.isEmpty()) {
            const QString uid = h.txHash.toLower();
            // Reconcile a fetched (settled/known) swap against a local optimistic pending row: drop
            // the pending copy so this real one (with its true status) replaces it. Match by id
            // first; if that fails, fall back to a content match. The fallback is essential for CoW
            // eth-flow (native-ETH) swaps: we place the pending row under the on-chain tx hash, but
            // the settled order comes back from cow_orders keyed by the CoW order UID, so the ids
            // never match — without this the successful swap would linger "pending" and then wrongly
            // flip to "failed".
            QString removedLocalHash;
            for (int i = 0; i < m_localSwaps.size(); ++i)
                if (m_localSwaps.at(i).txHash.toLower() == uid) {
                    removedLocalHash = m_localSwaps.at(i).txHash.toLower();
                    m_localSwaps.removeAt(i);
                    break;
                }
            if (removedLocalHash.isEmpty()) {
                for (int i = 0; i < m_localSwaps.size(); ++i) {
                    const HistoryItem &l = m_localSwaps.at(i);
                    // Same sell/buy assets, and the fetched order happened around/after we placed the
                    // local row (allowing a little clock skew). The window keeps an older settled
                    // order of the same pair from reconciling a freshly-placed pending row.
                    const qint64 dt =
                        static_cast<qint64>(h.timestamp) - static_cast<qint64>(l.timestamp);
                    if (l.symbol == h.symbol && l.buySymbol == h.buySymbol && h.timestamp > 0 &&
                        l.timestamp > 0 && dt >= -300 && dt <= 6 * 3600) {
                        removedLocalHash = l.txHash.toLower();
                        m_localSwaps.removeAt(i);
                        break;
                    }
                }
            }
            if (!removedLocalHash.isEmpty())
                m_allItems.erase(
                    std::remove_if(m_allItems.begin(), m_allItems.end(),
                                   [&](const HistoryItem &e) {
                                       return e.kind == QLatin1String("swap") &&
                                              (e.txHash.toLower() == uid ||
                                               e.txHash.toLower() == removedLocalHash);
                                   }),
                    m_allItems.end());
            if (m_seen.contains(uid)) // cross-account/page dedup of the fetched swap itself
                continue;
            m_seen.insert(uid);
            add.append(h);
            continue;
        }
        // Reconcile an optimistic pending SEND against its real mined row (same txHash): drop the
        // pending local copy so the confirmed row (with block/timestamp/fee) replaces it — no duplicate.
        if (!h.txHash.isEmpty()) {
            const QString hx = h.txHash.toLower();
            bool wasLocal = false;
            for (int i = 0; i < m_localSends.size(); ++i)
                if (m_localSends.at(i).txHash.toLower() == hx) {
                    m_localSends.removeAt(i);
                    wasLocal = true;
                    break;
                }
            if (wasLocal)
                m_allItems.erase(std::remove_if(m_allItems.begin(), m_allItems.end(),
                                                [&](const HistoryItem &e) {
                                                    return e.block == 0 &&
                                                           e.kind != QLatin1String("swap") &&
                                                           e.txHash.toLower() == hx;
                                                }),
                                 m_allItems.end());
        }
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
    if (!m_localSwaps.isEmpty() || !m_localSends.isEmpty()) {
        QSet<QString> fetchedIds;
        for (const HistoryItem &h : m_fetched)
            if (!h.txHash.isEmpty())
                fetchedIds.insert(h.txHash.toLower());
        const auto dropReconciled = [&](QVector<HistoryItem> &v) {
            v.erase(std::remove_if(v.begin(), v.end(),
                                   [&](const HistoryItem &h) {
                                       return fetchedIds.contains(h.txHash.toLower());
                                   }),
                    v.end());
        };
        dropReconciled(m_localSwaps);
        dropReconciled(m_localSends);
        // Content-match fallback for swaps whose ids differ from the fetched copy (CoW eth-flow — see
        // appendBatch), so a settled order also clears its optimistic pending row here.
        m_localSwaps.erase(
            std::remove_if(m_localSwaps.begin(), m_localSwaps.end(),
                           [&](const HistoryItem &l) {
                               for (const HistoryItem &f : m_fetched) {
                                   if (f.kind != QLatin1String("swap"))
                                       continue;
                                   const qint64 dt = static_cast<qint64>(f.timestamp) -
                                                     static_cast<qint64>(l.timestamp);
                                   if (l.symbol == f.symbol && l.buySymbol == f.buySymbol &&
                                       f.timestamp > 0 && l.timestamp > 0 && dt >= -300 &&
                                       dt <= 6 * 3600)
                                       return true;
                               }
                               return false;
                           }),
            m_localSwaps.end());
    }
    m_allItems = m_localSwaps; // pending swaps + sends on top until their mined rows arrive
    m_allItems += m_localSends;
    m_allItems += m_fetched;
    rebuildVisible();
}

void HistoryModel::expireStalePendingSwaps(qint64 maxAgeSecs) {
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    bool changed = false;
    for (HistoryItem &h : m_localSwaps) {
        if (h.status != QLatin1String("pending") || h.timestamp <= 0)
            continue;
        // Prefer the order's real expiry (validTo): a CoW order is legitimately open until then, so
        // don't force it to "failed" early. Only when we don't know the expiry do we fall back to a
        // generous age cutoff. The background cow_orders poll reconciles the true final status.
        const qint64 cutoff = h.expiry > 0 ? static_cast<qint64>(h.expiry)
                                           : (static_cast<qint64>(h.timestamp) + maxAgeSecs);
        if (now > cutoff) {
            h.status = QStringLiteral("failed");
            changed = true;
        }
    }
    if (changed)
        rebuildAll();
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
                                const QString &amountFormatted, const QString &symbol,
                                const QString &token) {
    HistoryItem h;
    h.direction = QStringLiteral("out");
    h.counterparty = to;
    h.formatted = amountFormatted;
    h.symbol = symbol;
    h.token = token; // "" == native; set so a pending token send shows its own icon (not ETH's)
    h.txHash = txHash;
    h.block = 0; // pending until confirmed
    // Stamp "now" so the pending row sorts to the TOP (newest-first) immediately; the Date column
    // still shows "pending" while block == 0. Without this it defaulted to timestamp 0 and sank to
    // the bottom of the list, so a just-sent tx looked like it wasn't detected.
    h.timestamp = static_cast<quint64>(QDateTime::currentSecsSinceEpoch());
    h.status = QStringLiteral("pending");
    // Track it like a local swap so it survives full refreshes and is reconciled away (not duplicated)
    // once the real mined row is fetched.
    m_localSends.append(h);
    rebuildAll();
}
