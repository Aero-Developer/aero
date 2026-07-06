// SPDX-License-Identifier: BSD-3-Clause
// Stand-in for Feather's PayToEdit (a QPlainTextEdit used as the recipient field).
#ifndef AERO_PAYTOEDIT_H
#define AERO_PAYTOEDIT_H

#include <QPlainTextEdit>

class PayToEdit : public QPlainTextEdit
{
    Q_OBJECT
public:
    explicit PayToEdit(QWidget *parent = nullptr) : QPlainTextEdit(parent) {
        setTabChangesFocus(true);
    }

    QString text() const { return toPlainText().trimmed(); }
    void setText(const QString &t) { setPlainText(t); }
};

#endif // AERO_PAYTOEDIT_H
