// SPDX-License-Identifier: BSD-3-Clause
// Stand-in for Feather's HistoryView (a QTreeView showing transaction history).
#ifndef AERO_HISTORYVIEW_H
#define AERO_HISTORYVIEW_H

#include <QTreeView>

class HistoryView : public QTreeView
{
    Q_OBJECT
public:
    explicit HistoryView(QWidget *parent = nullptr) : QTreeView(parent) {}
};

#endif // AERO_HISTORYVIEW_H
