// SPDX-License-Identifier: BSD-3-Clause
// Backs the Receive tab's address list (Feather's SubaddressModel equivalent). Each row is one
// HD-derived receive address (m/44'/60'/0'/0/index); columns mirror Feather: #, Address, Label,
// plus a Balance column so each address shows its own ETH balance.

#ifndef AERO_ADDRESSMODEL_H
#define AERO_ADDRESSMODEL_H

#include <QAbstractTableModel>
#include <QHash>
#include <QSet>

#include "Wallet.h"

class AddressModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        Column_Index = 0,
        Column_Address,
        Column_Label,
        Column_Balance,
        Column_COUNT,
    };

    explicit AddressModel(QObject *parent = nullptr) : QAbstractTableModel(parent) {}

    void setWallet(Wallet *wallet);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override {
        return parent.isValid() ? 0 : Column_COUNT;
    }
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    bool setData(const QModelIndex &index, const QVariant &value, int role) override;

    QString labelAt(quint32 index) const { return m_labels.value(index); }
    // Set a label programmatically (e.g. when loading persisted labels).
    void setLabel(quint32 index, const QString &label);

    // Show only funded addresses (indices in `funded`) when `on`; otherwise show all derived
    // addresses. If `on` but nothing is funded yet, all addresses are shown as a fallback.
    void setFundedFilter(bool on, const QSet<quint32> &funded);

    // Map between a visible view row and the underlying account index (they differ once filtered).
    quint32 accountAt(int row) const;
    int rowForAccount(quint32 index) const;

public slots:
    // Re-read the address count from the wallet (after creating / importing an address).
    void refresh();
    // Update one address's cached balance string (e.g. "1.2345 ETH").
    void setBalance(quint32 index, const QString &balance);
    // Mark an address as "used" (has funds / has transacted) so it's shown in red, like Feather.
    void setUsed(quint32 index, bool used);

private:
    void rebuildVisible(); // recompute the visible row -> account-index mapping

    Wallet *m_wallet = nullptr;
    QHash<quint32, QString> m_labels;   // keyed by account index (stable across filtering)
    QHash<quint32, QString> m_balances; // keyed by account index
    QSet<quint32> m_used;               // account indices marked "used"
    QList<quint32> m_visible;           // row -> account index
    QSet<quint32> m_funded;             // account indices with a balance
    bool m_fundedOnly = false;
};

#endif // AERO_ADDRESSMODEL_H
