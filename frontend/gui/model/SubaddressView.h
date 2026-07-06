// SPDX-License-Identifier: BSD-3-Clause
// Stand-in for Feather's SubaddressView (a QTreeView listing receive addresses).
#ifndef AERO_SUBADDRESSVIEW_H
#define AERO_SUBADDRESSVIEW_H

#include <QTreeView>

class SubaddressView : public QTreeView
{
    Q_OBJECT
public:
    explicit SubaddressView(QWidget *parent = nullptr) : QTreeView(parent) {}
};

#endif // AERO_SUBADDRESSVIEW_H
