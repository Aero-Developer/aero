// SPDX-License-Identifier: BSD-3-Clause
#include "HistoryModel.h"
#include "StallWatch.h"

#include <algorithm>
#include <cctype>
#include <climits>
#include <numeric>

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
// direction OR the symbol - we trust only the official tracked contract-address allow-list. This
// covers both unsolicited incoming airdrops and spoofed "outgoing" transactions you never signed.
bool HistoryModel::spamTokenIn(const HistoryItem &h, const RowFacts &f,
                               const QSet<QString> &known) {
    if (h.token.isEmpty())
        return false; // native transfers cannot be spoofed
    if (f.homoglyph)
        return true; // non-ASCII symbol => homoglyph impersonation
    // The allow-list is the whole point of this function, so consult it before any rule about what
    // a symbol is allowed to be. It used to come last, which meant the "an ERC-20 calling itself
    // ETH is always fake" rule fired first - true on Ethereum, but on BNB Smart Chain the real,
    // curated, Binance-pegged ETH is an ERC-20 called ETH, so every genuine transfer of it was
    // hidden and no amount of tracking the token could bring it back.
    //
    // Anything not on the list is spam, including an untracked ERC-20 calling itself "ETH".
    return !known.contains(f.tokenLower);
}

bool HistoryModel::isSpamToken(const HistoryItem &h, const RowFacts &f) const {
    return spamTokenIn(h, f, m_knownTokens);
}

void HistoryModel::addPoisonRef(const HistoryItem &h, const RowFacts &f, const QSet<QString> &known,
                                PoisonRefs &refs) {
    if (h.kind == QLatin1String("swap") || !f.evm)
        return;
    const bool nonzero = !(h.amount.isEmpty() || h.amount == QLatin1String("0"));
    // Only trust a counterparty as "real" if it moved value and isn't itself a spam token - so a
    // poisoning entry can never seed its own look-alike reference.
    if (!nonzero || spamTokenIn(h, f, known))
        return;
    refs.addrs.insert(f.counterpartyLower);
    refs.sigs.insert(f.sig);
    // A send of a real token cannot be forged - moving the wallet's tokens takes its key - so this is
    // an address the wallet chose to pay.
    if (h.direction == QLatin1String("out")) {
        refs.sentAddrs.insert(f.counterpartyLower);
        refs.sentSigs.insert(f.sig);
    }
}

bool HistoryModel::isSpamToken(const HistoryItem &h) const {
    return isSpamToken(h, factsFor(h));
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
// A zero-value NATIVE transaction is kept - that's a genuine contract call (approve/swap/revoke).
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

HistoryModel::RowFacts HistoryModel::factsFor(const HistoryItem &h) {
    RowFacts f;
    f.tokenLower = h.token.toLower();
    f.counterpartyLower = h.counterparty.toLower();
    f.hashLower = h.txHash.toLower();
    f.evm = isEvmAddress(f.counterpartyLower);
    if (f.evm)
        f.sig = addrSignature(f.counterpartyLower);
    f.symbolUpper = h.symbol.toUpper();
    f.amount = h.formatted.toDouble();
    f.poisoning = isPoisoning(h);
    f.homoglyph = hasHomoglyphSymbol(h.symbol);
    return f;
}

void HistoryModel::invalidateDerived() {
    m_facts.clear();
    m_poisonRows = -1;
    ++m_filterInputs;
}

void HistoryModel::ensureFacts() {
    const int n = m_allItems.size();
    if (m_facts.size() > n)
        m_facts.clear(); // cannot happen through the mutators; never index past what these describe
    // Grown with headroom. Reserving exactly `n` reallocated - and moved every existing entry - on
    // each batch that arrived, which at tens of thousands of rows was most of the cost of adding one.
    if (m_facts.capacity() < n)
        m_facts.reserve(n + n / 2);
    for (int i = m_facts.size(); i < n; ++i)
        m_facts.append(factsFor(m_allItems.at(i)));
}

// The reference index of legitimate addresses: the wallet's own, plus the counterparty of every
// genuine, non-spam transfer of value. A transfer whose counterparty matches one of these signatures
// but ISN'T one of the real addresses is a vanity look-alike (poisoning). Rows are folded in as they
// arrive; a change to the rows' order, the own-address set or the trusted tokens starts it over.
void HistoryModel::ensurePoisonRefs() {
    ensureFacts();
    const int n = m_allItems.size();
    if (m_poisonRows < 0 || m_poisonRows > n) {
        m_poisonRefs = PoisonRefs{};
        for (const QString &a : m_ownAddresses)
            addOwnRef(m_poisonRefs, a.toLower());
        m_poisonRows = 0;
    }
    for (int i = m_poisonRows; i < n; ++i)
        addPoisonRef(m_allItems.at(i), m_facts.at(i), m_knownTokens, m_poisonRefs);
    m_poisonRows = n;
}

void HistoryModel::addOwnRef(PoisonRefs &refs, const QString &addrLower) {
    if (!isEvmAddress(addrLower))
        return;
    const QString sig = addrSignature(addrLower);
    refs.addrs.insert(addrLower);
    refs.sigs.insert(sig);
    refs.sentAddrs.insert(addrLower);
    refs.sentSigs.insert(sig);
}

HistoryModel::Prepared HistoryModel::prepare(QVector<HistoryItem> rows, QSet<QString> own,
                                             QSet<QString> known) {
    // A token send is one transaction, which the explorer lists twice: the call itself - zero ether
    // to the token contract - and the transfer it made. The core now folds the first into the second;
    // rows cached before it did still carry both, so restoring them would bring back a "Sent 0 ETH"
    // beside every token send.
    {
        QSet<QString> tokenSends;
        for (const HistoryItem &h : rows)
            if (h.kind.isEmpty() && !h.token.isEmpty() && h.direction == QLatin1String("out") &&
                !h.txHash.isEmpty())
                tokenSends.insert(h.txHash.toLower());
        if (!tokenSends.isEmpty())
            rows.erase(std::remove_if(rows.begin(), rows.end(),
                                      [&](const HistoryItem &h) {
                                          return h.kind.isEmpty() && h.token.isEmpty() &&
                                                 h.direction == QLatin1String("out") && !h.failed &&
                                                 (h.amount.isEmpty() || h.amount == QLatin1String("0")) &&
                                                 tokenSends.contains(h.txHash.toLower());
                                      }),
                       rows.end());
    }
    Prepared p;
    p.fetchedAt.reserve(rows.size());
    for (int i = 0; i < rows.size(); ++i)
        p.fetchedAt.insert(dedupKey(rows.at(i)), i);
    // Room to grow, as for the rows below: the first batch after the swap must not reallocate.
    p.facts.reserve(rows.size() + 2048);
    for (const HistoryItem &h : rows)
        p.facts.append(factsFor(h));
    for (const QString &a : own)
        addOwnRef(p.refs, a.toLower());
    for (int i = 0; i < rows.size(); ++i)
        addPoisonRef(rows.at(i), p.facts.at(i), known, p.refs);
    const auto owned = [&rows]() {
        QVector<HistoryItem> copy;
        copy.reserve(rows.size() + 2048); // a few accounts' worth of new rows before any regrowth
        for (const HistoryItem &h : rows)
            copy.append(h);
        return copy;
    };
    p.rows = owned();
    p.allRows = owned();
    p.ownAddresses = std::move(own);
    p.knownTokens = std::move(known);
    return p;
}

void HistoryModel::adoptPrepared(Prepared p) {
    StallWatch::Scope stallScope("HistoryModel::adoptPrepared");
    // Anything fetched while this was being prepared is newer than the cache; re-applied on top.
    const QVector<HistoryItem> arrived = m_fetched;
    m_fetched = std::move(p.rows);
    m_fetchedAt = std::move(p.fetchedAt);
    if (!m_localSwaps.isEmpty() || !m_localSends.isEmpty()) {
        // An optimistic row appeared in the moment this took; compose and derive the ordinary way,
        // which also reconciles it against what was just adopted.
        rebuildAll();
    } else {
        m_allItems = std::move(p.allRows);
        m_facts = std::move(p.facts);
        ++m_filterInputs;
        // The index is only valid for the sets it was built against, which may have moved since.
        if (p.ownAddresses == m_ownAddresses && p.knownTokens == m_knownTokens) {
            m_poisonRefs = std::move(p.refs);
            m_poisonRows = m_allItems.size();
        } else {
            m_poisonRows = -1;
        }
        rebuildVisible();
    }
    if (!arrived.isEmpty())
        appendBatch(arrived);
}

bool HistoryModel::isHiddenSpam(const HistoryItem &h, const RowFacts &f) const {
    if (h.kind == QLatin1String("swap"))
        return false; // swaps are user-initiated, never spam
    // Never hide the user's own just-broadcast (pending) send - it must appear in history instantly.
    if (h.status == QLatin1String("pending") && h.direction == QLatin1String("out"))
        return false;
    if (f.poisoning || isSpamToken(h, f))
        return true;
    // Look-alike poisoning is an inbound attack (a spoof address sent to you): same first4/last4 hex
    // as a real address, but not that address. Only incoming transfers are gated, so a genuine
    // outgoing send to a coincidentally similar address is never hidden. This catches spoofs that
    // carry a nonzero/dust value, which the zero-value and unknown-token rules miss.
    //
    // Checked first against the addresses the wallet itself has paid, which only its own sends can
    // put there. The wider set also trusts anyone who sent the wallet a real token - so a look-alike
    // that sends a cent of real USDC vouches for itself there, and only this check still sees it.
    if (h.direction == QLatin1String("in") && f.evm) {
        if (!m_poisonRefs.sentAddrs.contains(f.counterpartyLower) &&
            m_poisonRefs.sentSigs.contains(f.sig))
            return true;
        if (!m_poisonRefs.addrs.contains(f.counterpartyLower) && m_poisonRefs.sigs.contains(f.sig))
            return true;
    }
    // Dust filter: hide incoming transfers worth less than the configured USD threshold. Only
    // applied when we actually have a positive price for the asset, so legit transfers aren't
    // hidden just because prices haven't loaded yet.
    if (m_dustUsd > 0.0 && h.direction == QLatin1String("in")) {
        const double price = m_prices.value(f.symbolUpper, -1.0);
        if (price > 0.0 && f.amount * price < m_dustUsd)
            return true;
    }
    return false;
}

bool HistoryModel::isHiddenSpam(const HistoryItem &h) const {
    return isHiddenSpam(h, factsFor(h));
}

bool HistoryModel::isSuspicious(int row) const {
    if (row < 0 || row >= m_items.size())
        return false;
    return m_items.at(row).failed || m_itemSpam.value(row);
}

// True if this row matches the search box on any visible column. m_search is pre-lowercased, and so
// is the counterparty in the row's facts; everything else is compared case-insensitively in place,
// so no per-row string is built.
bool HistoryModel::matchesSearch(const HistoryItem &h, const RowFacts &f) const {
    if (f.counterpartyLower.contains(m_search) || f.hashLower.contains(m_search))
        return true;
    if (h.symbol.contains(m_search, Qt::CaseInsensitive) ||
        h.buySymbol.contains(m_search, Qt::CaseInsensitive))
        return true;
    if (h.formatted.contains(m_search) || h.buyFormatted.contains(m_search))
        return true;
    // Direction words as shown in the table.
    const QLatin1StringView dir = (h.kind == QLatin1String("swap"))
                                      ? QLatin1StringView("swap")
                                      : (h.failed ? QLatin1StringView("failed")
                                                  : (h.direction == QLatin1String("in")
                                                         ? QLatin1StringView("received")
                                                         : QLatin1StringView("sent")));
    if (dir.contains(m_search))
        return true;
    // So typing an account's name narrows history to that account without touching the filter combo.
    auto hit = m_searchAccountHit.constFind(h.account);
    if (hit == m_searchAccountHit.constEnd())
        hit = m_searchAccountHit.insert(h.account,
                                        accountName(h).contains(m_search, Qt::CaseInsensitive));
    if (hit.value())
        return true;
    // A date can only match a query made of digits and date punctuation, so the date text - which
    // takes building - is built only for queries like that.
    return m_searchLooksLikeDate && h.timestamp && localMinuteText(h.timestamp).contains(m_search);
}

QString HistoryModel::dayText(qint64 daysSinceEpoch) const {
    const auto hit = m_dayKeys.constFind(daysSinceEpoch);
    if (hit != m_dayKeys.constEnd())
        return hit.value();
    const QString text = QDate(1970, 1, 1).addDays(daysSinceEpoch).toString(Qt::ISODate);
    m_dayKeys.insert(daysSinceEpoch, text);
    return text;
}

QString HistoryModel::utcDayKey(quint64 ts) const {
    // Identical to formatting the UTC QDateTime as yyyy-MM-dd, without the per-call conversion.
    return dayText(static_cast<qint64>(ts / 86400));
}

QString HistoryModel::localMinuteText(quint64 ts) const {
    const qint64 utc = static_cast<qint64>(ts);
    const qint64 utcDay = utc / 86400;
    auto offset = m_localOffsets.constFind(utcDay);
    if (offset == m_localOffsets.constEnd()) {
        // If the offset is the same at both ends of the day, no clock change falls inside it.
        const int atStart = QDateTime::fromSecsSinceEpoch(utcDay * 86400).offsetFromUtc();
        const int atEnd = QDateTime::fromSecsSinceEpoch(utcDay * 86400 + 86399).offsetFromUtc();
        offset = m_localOffsets.insert(utcDay, atStart == atEnd ? atStart : INT_MIN);
    }
    if (offset.value() == INT_MIN)
        return QDateTime::fromSecsSinceEpoch(utc).toString(QStringLiteral("yyyy-MM-dd HH:mm"));
    const qint64 local = utc + offset.value();
    const qint64 localDay = local >= 0 ? local / 86400 : (local - 86399) / 86400;
    const int secs = static_cast<int>(local - localDay * 86400);
    const int hh = secs / 3600, mm = (secs % 3600) / 60;
    QString out = dayText(localDay);
    out.reserve(16);
    out += QLatin1Char(' ');
    out += QLatin1Char(char('0' + hh / 10));
    out += QLatin1Char(char('0' + hh % 10));
    out += QLatin1Char(':');
    out += QLatin1Char(char('0' + mm / 10));
    out += QLatin1Char(char('0' + mm % 10));
    return out;
}

// Order comparison for the sort columns whose keys are plain fields (ascending sense; sortFiltered
// flips for descending). Value, Amount and Account are keyed once per row in sortFiltered instead.
bool HistoryModel::lessThan(const HistoryItem &a, const HistoryItem &b) const {
    switch (m_sortColumn) {
    case Column_Date:
        return (a.timestamp ? a.timestamp : a.block) < (b.timestamp ? b.timestamp : b.block);
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

// Sort m_filtered by the current column. The columns whose key takes work to produce - a USD value
// needs a price lookup, an account needs its name and a locale-aware comparison - are keyed ONCE per
// row and the keys sorted, rather than re-deriving both sides of every comparison: a stable sort of
// thirty thousand rows makes over four hundred thousand comparisons.
void HistoryModel::sortFiltered() {
    const bool asc = m_sortOrder == Qt::AscendingOrder;
    const int n = m_filtered.size();
    const auto row = [this](int k) -> const HistoryItem & { return m_allItems.at(m_filtered.at(k)); };
    // Sort by keys computed once per row: `less` compares positions k in m_filtered through
    // arrays filled before the sort, so no comparison touches a row itself.
    const auto sortBy = [&](const auto &less) {
        QVector<int> order(n);
        std::iota(order.begin(), order.end(), 0);
        std::stable_sort(order.begin(), order.end(),
                         [&](int a, int b) { return asc ? less(a, b) : less(b, a); });
        QVector<int> sorted(n);
        for (int k = 0; k < n; ++k)
            sorted[k] = m_filtered.at(order.at(k));
        m_filtered.swap(sorted);
    };

    switch (m_sortColumn) {
    case Column_Date: {
        // The default order, so this runs on every rebuild.
        QVector<quint64> when(n);
        for (int k = 0; k < n; ++k) {
            const HistoryItem &h = row(k);
            when[k] = h.timestamp ? h.timestamp : h.block;
        }
        sortBy([&](int a, int b) { return when[a] < when[b]; });
        return;
    }
    case Column_Value:
    case Column_Amount: {
        // Both rank by USD worth, so $1.5M of anything outranks $400 of a meme coin, and an asset
        // with no known price ranks as 0 - a huge-count, low-value token can never sit above a
        // genuinely valuable transfer. Amount then orders the unpriced ones by quantity.
        QVector<double> usd(n), qty(n);
        for (int k = 0; k < n; ++k) {
            const HistoryItem &h = row(k);
            qty[k] = h.formatted.toDouble();
            const double price = unitPriceFor(h);
            usd[k] = price > 0.0 ? qty[k] * price : 0.0;
        }
        const bool byQuantityToo = m_sortColumn == Column_Amount;
        sortBy([&](int a, int b) {
            if (usd[a] != usd[b])
                return usd[a] < usd[b];
            return byQuantityToo && qty[a] < qty[b];
        });
        return;
    }
    case Column_Account: {
        // By the name on screen, not the account index: a user sorting this column is looking for
        // all the rows that say "Savings" next to each other. A wallet has at most a few hundred
        // distinct names, so they are ranked once and the rows sorted by rank.
        QVector<QString> names(n);
        QSet<QString> distinctSet;
        for (int k = 0; k < n; ++k) {
            names[k] = accountName(row(k));
            distinctSet.insert(names[k]);
        }
        QStringList distinct(distinctSet.begin(), distinctSet.end());
        std::sort(distinct.begin(), distinct.end(),
                  [](const QString &x, const QString &y) { return x.localeAwareCompare(y) < 0; });
        QHash<QString, int> rankOf;
        for (int r = 0; r < distinct.size(); ++r)
            rankOf.insert(distinct.at(r), r);
        QVector<int> rank(n);
        QVector<quint32> account(n);
        for (int k = 0; k < n; ++k) {
            rank[k] = rankOf.value(names.at(k));
            account[k] = row(k).account;
        }
        sortBy([&](int a, int b) {
            if (rank[a] != rank[b])
                return rank[a] < rank[b];
            return account[a] < account[b];
        });
        return;
    }
    default:
        std::stable_sort(m_filtered.begin(), m_filtered.end(), [&](int a, int b) {
            const HistoryItem &x = m_allItems.at(a), &y = m_allItems.at(b);
            return asc ? lessThan(x, y) : lessThan(y, x);
        });
    }
}

// Recompute the full filtered + sorted result set, then show only the current page.
void HistoryModel::rebuildVisible() {
    StallWatch::Scope stallScope("HistoryModel::rebuildVisible");
    // Typing more of the same search, with nothing else changed: every row that can match the longer
    // text matched the shorter one, and those rows are already filtered and in order.
    if (m_filteredInputs == m_filterInputs && !m_filteredSearch.isEmpty() &&
        m_search.size() > m_filteredSearch.size() && m_search.startsWith(m_filteredSearch) &&
        m_facts.size() == m_allItems.size()) {
        QVector<int> kept;
        kept.reserve(m_filtered.size());
        for (int i : m_filtered)
            if (i >= 0 && i < m_allItems.size() && matchesSearch(m_allItems.at(i), m_facts.at(i)))
                kept.append(i);
        m_filtered.swap(kept);
        m_filteredSearch = m_search;
        reslice();
        return;
    }
    ensureFacts();
    ensurePoisonRefs(); // the legit-address index, extended with any rows added since last time
    // Transactions that are the on-chain half of a swap we placed ourselves. The explorer reports
    // the leg that left the wallet as an ordinary transfer, and only later - once it has indexed the
    // internal transfer coming back - folds both legs into one swap. In between, showing our swap
    // row and that lone outgoing transfer would be the same action listed twice, the second time
    // looking like money that went out and never came back.
    QSet<QString> swapLegs;
    for (const HistoryItem &l : m_localSwaps)
        if (!l.txHash.isEmpty())
            swapLegs.insert(l.txHash.toLower());
    m_filtered.clear();
    m_filtered.reserve(m_allItems.size());
    for (int i = 0; i < m_allItems.size(); ++i) {
        const HistoryItem &h = m_allItems.at(i);
        if (!swapLegs.isEmpty() && h.kind != QLatin1String("swap") && !h.txHash.isEmpty() &&
            swapLegs.contains(m_facts.at(i).hashLower))
            continue;
        if (m_hideSpam && isHiddenSpam(h, m_facts.at(i)))
            continue;
        if (!m_search.isEmpty() && !matchesSearch(h, m_facts.at(i)))
            continue;
        m_filtered.append(i);
    }
    sortFiltered();
    m_filteredInputs = m_filterInputs;
    m_filteredSearch = m_search;
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
    m_itemSpam.clear();
    const int start = m_page * m_pageSize;
    const int end = qMin(total, start + m_pageSize);
    m_items.reserve(qMax(0, end - start));
    m_itemSpam.reserve(qMax(0, end - start));
    // Positions are checked because rows can be removed between a rebuild and a page change; a
    // stale position must drop out of the page rather than read past the end of the rows.
    for (int i = start; i < end; ++i) {
        const int at = m_filtered.at(i);
        if (at >= 0 && at < m_allItems.size()) {
            const HistoryItem &h = m_allItems.at(at);
            m_items.append(h);
            // On screen only because spam is not being hidden. Such a row is marked rather than drawn
            // like the rest: a poisoning transfer copies the amount of a real send, and the look-alike
            // address beside it is the one the attacker wants copied.
            m_itemSpam.append(!m_hideSpam && at < m_facts.size() && isHiddenSpam(h, m_facts.at(at)));
        }
    }
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
    m_searchAccountHit.clear();
    // Only digits and date punctuation. Deliberately without requiring a digit: every prefix of a
    // date-like query must itself be date-like, or typing "-" then "-1" would stop matching dates
    // part-way through and the narrowing in rebuildVisible would drop rows it should keep.
    m_searchLooksLikeDate = !t.isEmpty();
    for (const QChar c : t)
        if (!c.isDigit() && c != u'-' && c != u':' && c != u' ') {
            m_searchLooksLikeDate = false;
            break;
        }
    // Debounced: a filter pass walks the whole history, and running one per keystroke is what made
    // typing in the search box stutter on a wallet with a lot of it. The coalesce window still
    // refreshes while the user keeps typing, so results appear to keep up.
    scheduleRebuild();
}

void HistoryModel::sort(int column, Qt::SortOrder order) {
    // No-op when nothing changed - this also breaks the recursion the view would otherwise cause by
    // re-issuing sort() after each model reset (we own the ordering, there is no proxy).
    if (column == m_sortColumn && order == m_sortOrder)
        return;
    m_sortColumn = column;
    m_sortOrder = order;
    m_page = 0;
    ++m_filterInputs;
    rebuildVisible();
}

// Coalesce a burst of appendBatch() calls (one per account during an all-account load) into a single
// filter+sort+re-slice, so we don't re-sort a growing list on every one of hundreds of batches.
void HistoryModel::scheduleRebuild(int delayMs) {
    if (!m_coalesceTimer) {
        m_coalesceTimer = new QTimer(this);
        m_coalesceTimer->setSingleShot(true);
        connect(m_coalesceTimer, &QTimer::timeout, this, [this]() { rebuildVisible(); });
    }
    // Start only if not already pending, so a continuous burst still refreshes periodically (page 0
    // fills in visibly) instead of deferring the rebuild until the burst stops. A shorter request
    // pulls a pending longer one forward: a keystroke must not wait out a history load's cadence.
    if (!m_coalesceTimer->isActive() || m_coalesceTimer->remainingTime() > delayMs)
        m_coalesceTimer->start(delayMs);
}

void HistoryModel::setHideSpam(bool hide) {
    if (m_hideSpam == hide)
        return;
    m_hideSpam = hide;
    ++m_filterInputs;
    rebuildVisible();
}

void HistoryModel::setDustThreshold(double usd) {
    if (m_dustUsd == usd)
        return;
    m_dustUsd = usd;
    ++m_filterInputs;
    rebuildVisible();
}

void HistoryModel::setPrices(const QHash<QString, double> &pricesBySymbol) {
    m_prices = pricesBySymbol;
    ++m_filterInputs; // the dust filter and the value sort both read prices
    if (!m_items.isEmpty()) // refresh the Value column
        emit dataChanged(index(0, Column_Value), index(m_items.size() - 1, Column_Value));
    // Prices also decide what the dust filter hides, so the rows have to be re-tested. Coalesced:
    // this arrives on a timer while prices refresh, and the dust filter is on by default, so a
    // synchronous full re-filter here was a periodic hitch that grew with the history.
    if (m_dustUsd > 0.0)
        scheduleRebuild();
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
    ++m_filterInputs; // the value sort reads it
    if (!m_items.isEmpty())
        emit dataChanged(index(0, Column_Value), index(m_items.size() - 1, Column_Value));
}

void HistoryModel::setHistoricalUnitPrices(const QHash<QString, double> &pricesByKey) {
    bool any = false;
    for (auto it = pricesByKey.constBegin(); it != pricesByKey.constEnd(); ++it) {
        if (it.value() <= 0.0)
            continue;
        m_histUnitPrice.insert(it.key(), it.value());
        any = true;
    }
    if (any)
        ++m_filterInputs;
    if (any && !m_items.isEmpty())
        emit dataChanged(index(0, Column_Value), index(m_items.size() - 1, Column_Value));
}

double HistoryModel::unitPriceFor(const HistoryItem &h) const {
    const QString sym = h.symbol.toUpper();
    if (h.timestamp > 0 && !m_histUnitPrice.isEmpty()) {
        const double hist =
            m_histUnitPrice.value(sym + QLatin1Char('|') + utcDayKey(h.timestamp), 0.0);
        if (hist > 0.0)
            return hist; // fiat value at the time of the transaction
    }
    return m_prices.value(sym, 0.0); // fall back to the current price
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
    QSet<QString> lower;
    lower.reserve(tokens.size());
    for (const QString &t : tokens)
        lower.insert(t.toLower());
    // Unchanged is the common case: this is pushed again on every history refresh, every chain
    // switch and every liquidity verdict, and re-filtering the whole history each time - which on a
    // long history is a full pass over tens of thousands of rows - was work for no change on screen.
    if (lower == m_knownTokens)
        return;
    // Which tokens are trusted decides which counterparties seed the look-alike index. The usual
    // change is one token becoming trusted, which can only ADD genuine counterparties - so fold in
    // just the rows of the newly trusted tokens rather than rebuild the index from every row.
    // Anything else (a token no longer trusted) starts the index over.
    const bool onlyAdded = m_poisonRows >= 0 && m_poisonRows == m_allItems.size() &&
                           m_facts.size() == m_allItems.size() && lower.contains(m_knownTokens);
    if (onlyAdded) {
        const QSet<QString> added = lower - m_knownTokens;
        for (int i = 0; i < m_allItems.size(); ++i)
            if (added.contains(m_facts.at(i).tokenLower))
                addPoisonRef(m_allItems.at(i), m_facts.at(i), lower, m_poisonRefs);
    } else {
        m_poisonRows = -1;
    }
    m_knownTokens = std::move(lower);
    ++m_filterInputs;
    // Spam classification depends on the tracked-token set, so re-filter the visible rows. Coalesced
    // because verdicts arrive in bursts (up to fifteen liquidity lookups land per refresh).
    scheduleRebuild();
}

void HistoryModel::setOwnAddresses(const QSet<QString> &addrs) {
    QSet<QString> lower;
    lower.reserve(addrs.size());
    for (const QString &a : addrs)
        lower.insert(a.toLower());
    if (lower == m_ownAddresses)
        return; // unchanged - avoid a needless re-filter
    // A new account only adds an address to the look-alike index; add it rather than rebuilding the
    // index from every row. A removed address starts it over.
    if (m_poisonRows >= 0 && lower.contains(m_ownAddresses)) {
        for (const QString &a : lower - m_ownAddresses)
            addOwnRef(m_poisonRefs, a);
    } else {
        m_poisonRows = -1;
    }
    m_ownAddresses = lower;
    ++m_filterInputs;
    rebuildVisible(); // look-alike detection references the wallet's own addresses
}

QVariant HistoryModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= m_items.size())
        return {};

    const HistoryItem &h = m_items.at(index.row());

    // Show the asset's logo next to the amount. Only the *native* coin (empty token address) may use
    // the native logo - an ERC-20 that calls itself "ETH" is a scam and must not borrow it. Unknown
    // tokens get no logo (QIcon(path) is never null even when the resource is missing, so check
    // existence). The native row names its own coin, so read the symbol rather than assuming ether:
    // hardcoding "ETH" stamped the Ethereum logo on every POL, BNB, XDAI and AVAX transfer.
    if (role == Qt::DecorationRole && index.column() == Column_Amount) {
        const QString sym = h.token.isEmpty()
                                ? (h.symbol.isEmpty() ? QStringLiteral("ETH") : h.symbol.toUpper())
                                : h.symbol.toUpper();
        if (!h.token.isEmpty() && sym == QLatin1String("ETH"))
            return {}; // ERC-20 impersonating native ETH
        // Cached by symbol. The view asks for this role for every visible row on every repaint, and
        // building it meant a resource-existence check and a fresh QIcon each time - decoding the
        // same handful of PNGs over and over while the user scrolled.
        static QHash<QString, QIcon> iconBySymbol;
        const auto hit = iconBySymbol.constFind(sym);
        if (hit != iconBySymbol.constEnd())
            return hit.value().isNull() ? QVariant() : QVariant(hit.value());
        const QString path = QStringLiteral(":/assets/images/tokens/%1.png").arg(sym);
        const QIcon icon = QFileInfo::exists(path) ? QIcon(path) : QIcon();
        iconBySymbol.insert(sym, icon); // a missing logo is cached as null, so it is looked up once
        return icon.isNull() ? QVariant() : QVariant(icon);
    }

    if (role == Qt::ForegroundRole) {
        if (h.failed || m_itemSpam.value(index.row()))
            return QBrush(QColor(0x80, 0x80, 0x80)); // grey out failed (reverted) txs, and spam
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
                      "your balance - likely a scam token impersonating a real asset. Do not "
                      "interact with it.");
        if (isPoisoning(h))
            return tr("Possible address-poisoning: zero-value transfer. Do not trust this address.");
        if (m_itemSpam.value(index.row()))
            return tr("Hidden as spam: dust, or a transfer from an address made to look like one "
                      "you have used. Never copy an address from this row.");
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
        case Column_Account:
            return accountName(h);
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
        case Column_Account:      return accountName(h);
        case Column_Direction:
            if (h.kind == QLatin1String("swap")) {
                if (h.status == QLatin1String("pending")) return tr("Swap · pending");
                if (h.status == QLatin1String("failed") || h.failed) return tr("Swap · failed");
                return tr("Swap");
            }
            if (m_itemSpam.value(index.row()))
                return tr("Spam");
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
                return QStringLiteral("-"); // price not known (yet) for this asset
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

QString HistoryModel::accountName(const HistoryItem &h) const {
    // Rows cached before history recorded an account have nothing to name. Inventing "Account #0"
    // for them would be a guess, and a wrong one for anybody whose transaction came from elsewhere.
    if (h.account == HistoryItem::unknownAccount)
        return {};
    const QString named = m_accountNames.value(h.account);
    return named.isEmpty() ? tr("Account #%1").arg(h.account) : named;
}

void HistoryModel::setAccountNames(const QHash<quint32, QString> &names) {
    if (m_accountNames == names)
        return;
    m_accountNames = names;
    m_searchAccountHit.clear(); // decided against the old names
    ++m_filterInputs;           // a search for a name, or the Account sort, now answers differently
    // A name only decides which rows are shown when it is being searched for, and their order only
    // when the table is sorted by it. Otherwise the rows and their order are exactly as they were,
    // and re-filtering the whole history - which is what this used to do for every label edit -
    // bought nothing a repaint of the one column does not.
    if (!m_search.isEmpty() || m_sortColumn == Column_Account) {
        rebuildVisible();
        return;
    }
    if (!m_items.isEmpty())
        emit dataChanged(index(0, Column_Account), index(m_items.size() - 1, Column_Account));
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
        case Column_Account:      return tr("Account");
        case Column_Direction:    return tr("Direction");
        case Column_Amount:       return tr("Amount");
        case Column_Value:        return tr("Value (USD)");
        case Column_Counterparty: return tr("Counterparty");
        case Column_TxHash:       return tr("Transaction");
        default:                  return {};
    }
}

void HistoryModel::onHistoryRefreshed(const QVector<HistoryItem> &items) {
    noteIncoming(items);
    m_fetched = items;
    reindexFetched(); // the old positions describe a list that no longer exists
    rebuildAll();
}

// See the header: announce only genuinely new, non-hidden incoming transfers, and never the backlog.
void HistoryModel::noteIncoming(const QVector<HistoryItem> &items) {
    // Collect the accounts seeing their first delivery here, so an account's whole existing history
    // seeds silently even though the loop below runs row by row.
    QSet<quint32> firstTime;
    for (const HistoryItem &h : items)
        if (h.account != HistoryItem::unknownAccount && !m_notifyInitialized.contains(h.account))
            firstTime.insert(h.account);
    for (const HistoryItem &h : items) {
        if (h.direction != QLatin1String("in") || h.kind == QLatin1String("swap"))
            continue; // only unsolicited incoming transfers; a swap's buy leg isn't a "payment"
        if (isHiddenSpam(h))
            continue; // the whole point: never announce what History hides
        const QString key = dedupKey(h);
        const bool known = m_seenIncoming.contains(key);
        m_seenIncoming.insert(key);
        if (known)
            continue;
        // Silent while this account's backlog is being seeded (startup / its first fetch); announce
        // only arrivals that land after the account is known. An unknown-account row can't be named,
        // so it's seeded but never announced.
        if (m_notifyInitialized.contains(h.account) && !firstTime.contains(h.account))
            emit incomingPayment(h.account, h.formatted, h.symbol);
    }
    m_notifyInitialized.unite(firstTime);
}

// Where an already-held copy of `key` lives in m_fetched, or -1. Bounds-checked so a stale index
// can only cost us a duplicate row, never a read past the end of the list.
int HistoryModel::fetchedIndex(const QString &key) const {
    const auto at = m_fetchedAt.constFind(key);
    if (at == m_fetchedAt.constEnd())
        return -1;
    return (*at >= 0 && *at < m_fetched.size()) ? *at : -1;
}

// Rebuild the key -> position index after m_fetched has been replaced wholesale.
void HistoryModel::reindexFetched() {
    m_fetchedAt.clear();
    m_fetchedAt.reserve(m_fetched.size());
    for (int i = 0; i < m_fetched.size(); ++i)
        m_fetchedAt.insert(dedupKey(m_fetched.at(i)), i);
}

QList<quint32> HistoryModel::pendingSwapAccounts() const {
    QSet<quint32> out;
    const auto collect = [&out](const QVector<HistoryItem> &v) {
        for (const HistoryItem &h : v)
            if (h.kind == QLatin1String("swap") && h.status == QLatin1String("pending") &&
                h.account != HistoryItem::unknownAccount)
                out.insert(h.account);
    };
    collect(m_localSwaps);
    collect(m_fetched);
    return out.values();
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
    // "hash|token|direction|amount", built in one allocation: every row is keyed whenever a chain's
    // history is restored, and a format string per row showed up in that cost.
    const QChar bar(u'|');
    QString key;
    key.reserve(h.txHash.size() + h.token.size() + h.direction.size() + h.amount.size() + 3);
    key += h.txHash;
    key += bar;
    key += h.token;
    key += bar;
    key += h.direction;
    key += bar;
    key += h.amount;
    return key;
}

// How settled a row is. A later fetch may carry a row forward through these, never back: an order
// that has filled does not go back to resting, and a mined transaction does not un-mine. Without
// that floor, one stale reply mid-poll would flick a finished swap back to "pending".
static int settledRank(const HistoryItem &h) {
    if (h.status == QLatin1String("pending"))
        return 0;
    if (h.status == QLatin1String("done") || h.status == QLatin1String("failed"))
        return 2;
    return 1; // an ordinary transfer: the explorer only lists it once it is on chain
}

bool HistoryModel::supersedes(const HistoryItem &prev, const HistoryItem &next) {
    if (settledRank(next) < settledRank(prev))
        return false;
    if (next.status != prev.status)
        return true;
    if (prev.block == 0 && next.block != 0)     // gained its mined position
        return true;
    if (prev.timestamp == 0 && next.timestamp != 0)
        return true;
    if (prev.failed != next.failed)
        return true;
    // A filled order reports what was actually traded, which is rarely exactly what was quoted.
    return prev.status == QLatin1String("done") && next.status == QLatin1String("done") &&
           (prev.formatted != next.formatted || prev.buyFormatted != next.buyFormatted);
}

QString HistoryModel::assetKey(const QString &symbol) {
    // The two sides of one swap can arrive under different names. Our own optimistic row uses the
    // ticker shown in the Swap tab ("ETH"), while the settled order names what the protocol really
    // traded: the wrapped token ("WETH"), or the 0xEeee... sentinel that stands for the chain's coin
    // inside a field that otherwise holds a token address. Left unfolded, a native-coin swap never
    // recognises its own settled copy, so the pending row lingers next to it and is later marked
    // failed - a swap that worked, shown twice, one of them as a failure.
    static const QSet<QString> kCoin = {
        QStringLiteral("ETH"),   QStringLiteral("WETH"),  QStringLiteral("POL"),
        QStringLiteral("WPOL"),  QStringLiteral("MATIC"), QStringLiteral("WMATIC"),
        QStringLiteral("BNB"),   QStringLiteral("WBNB"),  QStringLiteral("AVAX"),
        QStringLiteral("WAVAX"), QStringLiteral("XDAI"),  QStringLiteral("WXDAI"),
    };
    const QString s = symbol.trimmed().toUpper();
    if (s.startsWith(QLatin1String("0XEEEE")) || kCoin.contains(s))
        return QStringLiteral("NATIVE");
    return s;
}

bool HistoryModel::samePair(const HistoryItem &a, const HistoryItem &b) {
    return assetKey(a.symbol) == assetKey(b.symbol) &&
           assetKey(a.buySymbol) == assetKey(b.buySymbol);
}

// Seed the model from persisted (wallet-file) history without any network fetch, and pre-populate the
// dedup index so a later targeted appendBatch() of the same account merges/dedups correctly.
void HistoryModel::loadCachedHistory(const QVector<HistoryItem> &items) {
    m_fetched = items;
    reindexFetched();
    rebuildAll();
}

// Start of an incremental all-account refresh: clear fetched history + dedup, keep any optimistic
// local swaps on top, and reset to the first page.
void HistoryModel::beginFullRefresh() {
    m_fetched.clear();
    m_fetchedAt.clear();
    // Show any optimistic pending swaps on top until the fetched (settled) copy arrives, which
    // appendBatch then reconciles. NOTE: we deliberately do NOT seed m_seen with local swap UIDs -
    // doing so made appendBatch skip the fetched settled order, so the pending row never flipped to
    // filled/failed (the "stuck on pending forever" bug).
    m_allItems = m_localSwaps;
    m_allItems += m_localSends; // keep optimistic pending sends visible across the refresh too
    invalidateDerived();
    m_page = 0;
    rebuildVisible(); // filter + sort + slice page 0 (just the pending rows at this point)
}

// Append one account's rows (deduped) to the full set, then schedule a debounced filter/sort/slice.
// Only the current 500-row page is ever materialised, so a huge multi-account history stays smooth.
void HistoryModel::appendBatch(const QVector<HistoryItem> &items) {
    StallWatch::Scope stallScope("HistoryModel::appendBatch");
    noteIncoming(items);
    QVector<HistoryItem> add;
    add.reserve(items.size());
    bool updated = false; // a row we already held has changed (an order filled, a tx mined)
    bool removed = false; // an optimistic row stood aside for its real copy
    for (const HistoryItem &h : items) {
        if (h.kind == QLatin1String("swap") && !h.txHash.isEmpty()) {
            const QString uid = h.txHash.toLower();
            // Reconcile a fetched (settled/known) swap against a local optimistic pending row: drop
            // the pending copy so this real one (with its true status) replaces it. Match by id
            // first; if that fails, fall back to a content match. The fallback is essential for CoW
            // eth-flow (native-ETH) swaps: we place the pending row under the on-chain tx hash, but
            // the settled order comes back from cow_orders keyed by the CoW order UID, so the ids
            // never match - without this the successful swap would linger "pending" and then wrongly
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
                    if (samePair(l, h) && h.timestamp > 0 && l.timestamp > 0 && dt >= -300 &&
                        dt <= 6 * 3600) {
                        removedLocalHash = l.txHash.toLower();
                        m_localSwaps.removeAt(i);
                        break;
                    }
                }
            }
            if (!removedLocalHash.isEmpty()) {
                m_allItems.erase(
                    std::remove_if(m_allItems.begin(), m_allItems.end(),
                                   [&](const HistoryItem &e) {
                                       return e.kind == QLatin1String("swap") &&
                                              (e.txHash.toLower() == uid ||
                                               e.txHash.toLower() == removedLocalHash);
                                   }),
                    m_allItems.end());
                // Rows moved up to close the gap, so the per-row tables no longer line up with
                // them. Left as they were, the filter matched each row against its neighbour's
                // search text, and read past the end of the table.
                invalidateDerived();
                removed = true;
            }
            // We may already hold this swap from an earlier poll. That is the normal case, not a
            // duplicate to throw away: an order is fetched again and again precisely because its
            // outcome is still being decided, and the reply that matters is the one saying it
            // filled. Discarding it here is what left a completed swap reading "pending" for the
            // rest of the session, and - because the status is cached - after the next restart too.
            const int at = fetchedIndex(uid);
            if (at >= 0) {
                if (supersedes(m_fetched.at(at), h)) {
                    m_fetched[at] = h;
                    updated = true;
                }
                continue;
            }
            m_fetchedAt.insert(uid, m_fetched.size() + add.size());
            add.append(h);
            continue;
        }
        // Reconcile an optimistic pending SEND against its real mined row (same txHash): drop the
        // pending local copy so the confirmed row (with block/timestamp/fee) replaces it - no duplicate.
        if (!h.txHash.isEmpty()) {
            const QString hx = h.txHash.toLower();
            // The same transaction may be the one our optimistic swap row is waiting on. A router
            // swap only becomes a swap row once the explorer has indexed both legs, and the leg paid
            // back to the user is often an internal transfer that lands hours later - until then the
            // wallet can see the transaction mined perfectly well and still be counting down to
            // calling it failed. Settle it on the evidence we have: the transaction is on chain, and
            // the receipt says whether it worked.
            if (h.block != 0) {
                for (HistoryItem &l : m_localSwaps)
                    if (l.txHash.toLower() == hx && l.status == QLatin1String("pending")) {
                        l.status = h.failed ? QStringLiteral("failed") : QStringLiteral("done");
                        l.failed = h.failed;
                        l.block = h.block;
                        if (h.timestamp)
                            l.timestamp = h.timestamp;
                        updated = true;
                        break;
                    }
            }
            bool wasLocal = false;
            for (int i = 0; i < m_localSends.size(); ++i)
                if (m_localSends.at(i).txHash.toLower() == hx) {
                    m_localSends.removeAt(i);
                    wasLocal = true;
                    break;
                }
            if (wasLocal) {
                m_allItems.erase(std::remove_if(m_allItems.begin(), m_allItems.end(),
                                                [&](const HistoryItem &e) {
                                                    return e.block == 0 &&
                                                           e.kind != QLatin1String("swap") &&
                                                           e.txHash.toLower() == hx;
                                                }),
                                 m_allItems.end());
                invalidateDerived(); // see the matching removal above
                removed = true;
            }
        }
        const QString key = dedupKey(h); // not a swap here, so the transfer form of the key
        const int at = fetchedIndex(key);
        if (at >= 0) {
            // A transfer keeps its key when it mines, so this is where a row picks up its block,
            // timestamp and fee - and where a transaction that reverted stops looking successful.
            if (supersedes(m_fetched.at(at), h)) {
                m_fetched[at] = h;
                updated = true;
            }
            continue;
        }
        m_fetchedAt.insert(key, m_fetched.size() + add.size());
        add.append(h);
    }
    if (!add.isEmpty())
        m_fetched += add;
    if (updated) {
        // m_allItems holds copies, so recompose it from m_fetched rather than trying to patch both
        // lists in step. This also re-runs the local reconciliation, which is what finally drops an
        // optimistic row once its real copy settles.
        rebuildAll();
        return;
    }
    if (add.isEmpty()) {
        // A removal with nothing to add still changed what is on screen; returning here left the
        // page showing rows that no longer existed until something unrelated rebuilt it.
        if (removed)
            scheduleRebuild();
        return;
    }
    m_allItems += add;
    ++m_filterInputs; // new rows the previous result never saw
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const bool burst = now - m_lastBatchMs < 1000;
    m_lastBatchMs = now;
    scheduleRebuild(burst ? kBurstRebuildMs : 150);
}

// Compose the unfiltered list as [optimistic pending swaps] + [fetched history], dropping any
// pending swap that has since appeared in fetched data (matched by tx hash / CoW order uid).
void HistoryModel::rebuildAll() {
    StallWatch::Scope stallScope("HistoryModel::rebuildAll");
    if (!m_localSwaps.isEmpty() || !m_localSends.isEmpty()) {
        QSet<QString> fetchedIds, fetchedSwapIds;
        for (const HistoryItem &h : m_fetched)
            if (!h.txHash.isEmpty()) {
                fetchedIds.insert(h.txHash.toLower());
                if (h.kind == QLatin1String("swap"))
                    fetchedSwapIds.insert(h.txHash.toLower());
            }
        const auto dropReconciled = [](QVector<HistoryItem> &v, const QSet<QString> &ids) {
            v.erase(std::remove_if(v.begin(), v.end(),
                                   [&](const HistoryItem &h) {
                                       return ids.contains(h.txHash.toLower());
                                   }),
                    v.end());
        };
        // A swap steps aside only for a fetched row that is itself a swap. Standing aside for any
        // row sharing its transaction meant the outgoing leg alone could take its place, and the
        // trade the user made would be listed as a payment to a router with nothing coming back.
        dropReconciled(m_localSwaps, fetchedSwapIds);
        dropReconciled(m_localSends, fetchedIds);
        // Content-match fallback for swaps whose ids differ from the fetched copy (CoW eth-flow - see
        // appendBatch), so a settled order also clears its optimistic pending row here.
        m_localSwaps.erase(
            std::remove_if(m_localSwaps.begin(), m_localSwaps.end(),
                           [&](const HistoryItem &l) {
                               for (const HistoryItem &f : m_fetched) {
                                   if (f.kind != QLatin1String("swap"))
                                       continue;
                                   const qint64 dt = static_cast<qint64>(f.timestamp) -
                                                     static_cast<qint64>(l.timestamp);
                                   if (samePair(l, f) && f.timestamp > 0 && l.timestamp > 0 &&
                                       dt >= -300 && dt <= 6 * 3600)
                                       return true;
                               }
                               return false;
                           }),
            m_localSwaps.end());
    }
    m_allItems = m_localSwaps; // pending swaps + sends on top until their mined rows arrive
    m_allItems += m_localSends;
    m_allItems += m_fetched;
    invalidateDerived(); // recomposed from scratch, so nothing derived from the old order holds
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
    // A fetched order can hang too. CoW returns the most recent 200 orders, so one that ages out of
    // that window stops being mentioned at all, and a row nobody will ever speak about again would
    // rest at "pending" forever, keeping the poll it depends on alive to ask about it every thirty
    // seconds for the life of the session. Only rows whose own deadline we know are called off, well
    // past it: an order with no stated deadline may genuinely still be open.
    const qint64 grace = 15 * 60;
    for (HistoryItem &h : m_fetched) {
        if (h.kind != QLatin1String("swap") || h.status != QLatin1String("pending"))
            continue;
        if (h.expiry == 0 || now <= static_cast<qint64>(h.expiry) + grace)
            continue;
        h.status = QStringLiteral("failed");
        h.failed = true;
        changed = true;
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

void HistoryModel::confirmLocalSend(const QString &txHash, bool failed) {
    if (txHash.isEmpty())
        return;
    const QString hx = txHash.toLower();
    bool changed = false;
    for (HistoryItem &h : m_localSends) {
        if (h.txHash.toLower() != hx || h.status != QLatin1String("pending"))
            continue;
        // The row already carries a "now" timestamp from addLocalSend, so clearing "pending" is
        // enough for the Date column to switch from "pending" to a real date - no block number
        // needed. The confirmed explorer row (with the true block/fee) still supersedes this later.
        h.status = failed ? QStringLiteral("failed") : QStringLiteral("done");
        h.failed = failed;
        changed = true;
        break;
    }
    if (changed)
        rebuildAll();
}

void HistoryModel::confirmLocalSwap(const QString &txHash, bool failed) {
    if (txHash.isEmpty())
        return;
    const QString hx = txHash.toLower();
    bool changed = false;
    for (HistoryItem &h : m_localSwaps) {
        if (h.txHash.toLower() != hx || h.status != QLatin1String("pending"))
            continue;
        // Mirror how appendBatch settles a swap on its mined row: the transaction is on chain and the
        // receipt says whether it worked, which is enough to stop the countdown to "failed".
        h.status = failed ? QStringLiteral("failed") : QStringLiteral("done");
        h.failed = failed;
        changed = true;
        break;
    }
    if (changed)
        rebuildAll();
}
