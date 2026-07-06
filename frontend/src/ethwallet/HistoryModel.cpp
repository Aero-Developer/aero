// SPDX-License-Identifier: BSD-3-Clause
#include "HistoryModel.h"

#include <QBrush>
#include <QColor>
#include <QDateTime>
#include <QFileInfo>
#include <QIcon>

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

// Zero-value incoming transfers are the classic address-poisoning pattern (dust/$0 from look-alike
// addresses). These are not real payments and are hidden along with spam tokens.
static bool isPoisoning(const HistoryItem &h) {
    return h.direction == QLatin1String("in") && (h.amount.isEmpty() || h.amount == QLatin1String("0"));
}

bool HistoryModel::isHiddenSpam(const HistoryItem &h) const {
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

void HistoryModel::rebuildVisible() {
    beginResetModel();
    if (!m_hideSpam) {
        m_items = m_allItems;
    } else {
        m_items.clear();
        m_items.reserve(m_allItems.size());
        for (const HistoryItem &h : m_allItems)
            if (!isHiddenSpam(h))
                m_items.append(h);
    }
    endResetModel();
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
            const double price = m_prices.value(h.symbol.toUpper(), 0.0);
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
        case Column_Direction:    return h.failed ? tr("Failed")
                                                  : (h.direction == "in" ? tr("Received") : tr("Sent"));
        case Column_Amount:       return QStringLiteral("%1 %2").arg(h.formatted, h.symbol);
        case Column_Value: {
            const double price = m_prices.value(h.symbol.toUpper(), 0.0);
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
    m_allItems = items;
    rebuildVisible();
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
