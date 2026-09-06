// SPDX-License-Identifier: BSD-3-Clause
#include "AddressModel.h"

#include <QBrush>
#include <QColor>
#include <QFont>

void AddressModel::setWallet(Wallet *wallet) {
    beginResetModel();
    m_wallet = wallet;
    m_labels.clear();
    m_balances.clear();
    m_used.clear();
    rebuildVisible();
    endResetModel();
}

void AddressModel::rebuildVisible() {
    m_visible.clear();
    if (!m_wallet)
        return;
    const quint32 n = m_wallet->numAccounts();
    if (m_fundedOnly) {
        for (quint32 i = 0; i < n; ++i)
            if (m_funded.contains(i))
                m_visible.append(i);
        if (!m_visible.isEmpty())
            return;
        // Fallback: nothing funded yet - show all so there's always an address to receive to.
    }
    for (quint32 i = 0; i < n; ++i)
        m_visible.append(i);
}

quint32 AddressModel::accountAt(int row) const {
    // Out-of-range rows (e.g. an empty/filtered model) return an INVALID sentinel rather than the raw
    // row index - otherwise callers would silently act on "account 0"/garbage. static_cast<int> of the
    // sentinel is -1, so the int-based guards in callers reject it.
    return (row >= 0 && row < m_visible.size()) ? m_visible.at(row) : 0xFFFFFFFFu;
}

int AddressModel::rowForAccount(quint32 index) const {
    return static_cast<int>(m_visible.indexOf(index));
}

void AddressModel::setFundedFilter(bool on, const QSet<quint32> &funded) {
    beginResetModel();
    m_fundedOnly = on;
    m_funded = funded;
    rebuildVisible();
    endResetModel();
}

int AddressModel::rowCount(const QModelIndex &parent) const {
    if (parent.isValid() || !m_wallet)
        return 0;
    return static_cast<int>(m_visible.size());
}

QVariant AddressModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || !m_wallet)
        return {};
    const quint32 acct = accountAt(index.row());

    if (role == Qt::DisplayRole || role == Qt::EditRole) {
        switch (index.column()) {
        case Column_Index:
            return QStringLiteral("#%1").arg(acct);
        case Column_Address:
            return m_wallet->address(acct);
        case Column_Label:
            // A user-set label always wins; otherwise imported accounts fall back to a default name
            // ("Imported #n") for display, but stay empty for editing so the field starts blank.
            if (const QString custom = m_labels.value(acct); !custom.isEmpty())
                return custom;
            return role == Qt::DisplayRole ? m_importedNames.value(acct) : QString();
        case Column_Balance:
            return m_balances.value(acct); // empty until the balance arrives
        default:
            return {};
        }
    }

    if (role == Qt::FontRole && index.column() == Column_Address) {
        QFont f;
        f.setFamily(QStringLiteral("monospace"));
        f.setStyleHint(QFont::TypeWriter);
        return f;
    }

    if (role == Qt::TextAlignmentRole && index.column() == Column_Index)
        return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);

    // Feather highlights used addresses (ones that have received/transacted) in red.
    if (role == Qt::BackgroundRole && m_used.contains(acct))
        return QBrush(QColor(0x6d, 0x2b, 0x2b));

    return {};
}

QVariant AddressModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return {};
    switch (section) {
    case Column_Index:   return QStringLiteral("#");
    case Column_Address: return QObject::tr("Address");
    case Column_Label:   return QObject::tr("Label");
    case Column_Balance: return QObject::tr("Balance");
    default:             return {};
    }
}

Qt::ItemFlags AddressModel::flags(const QModelIndex &index) const {
    Qt::ItemFlags f = QAbstractTableModel::flags(index);
    if (index.column() == Column_Label) // labels are user-editable, like Feather
        f |= Qt::ItemIsEditable;
    return f;
}

bool AddressModel::setData(const QModelIndex &index, const QVariant &value, int role) {
    if (!index.isValid() || role != Qt::EditRole || index.column() != Column_Label)
        return false;
    m_labels.insert(accountAt(index.row()), value.toString());
    emit dataChanged(index, index, {Qt::DisplayRole, Qt::EditRole});
    return true;
}

void AddressModel::refresh() {
    beginResetModel();
    rebuildVisible();
    endResetModel();
}

void AddressModel::setBalance(quint32 index, const QString &balance) {
    m_balances.insert(index, balance);
    const int row = rowForAccount(index);
    if (row >= 0) {
        const QModelIndex cell = this->index(row, Column_Balance);
        emit dataChanged(cell, cell, {Qt::DisplayRole});
    }
}

void AddressModel::setLabel(quint32 index, const QString &label) {
    m_labels.insert(index, label);
    const int row = rowForAccount(index);
    if (row >= 0) {
        const QModelIndex cell = this->index(row, Column_Label);
        emit dataChanged(cell, cell, {Qt::DisplayRole, Qt::EditRole});
    }
}

void AddressModel::setImportedNames(const QHash<quint32, QString> &names) {
    m_importedNames = names;
    if (!m_visible.isEmpty())
        emit dataChanged(index(0, Column_Label),
                         index(static_cast<int>(m_visible.size()) - 1, Column_Label),
                         {Qt::DisplayRole});
}

void AddressModel::setUsed(quint32 index, bool used) {
    if (used == m_used.contains(index))
        return;
    if (used)
        m_used.insert(index);
    else
        m_used.remove(index);
    const int row = rowForAccount(index);
    if (row >= 0)
        emit dataChanged(this->index(row, 0), this->index(row, Column_COUNT - 1),
                         {Qt::BackgroundRole});
}
