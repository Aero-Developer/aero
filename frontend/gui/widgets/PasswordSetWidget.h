// SPDX-License-Identifier: BSD-3-Clause
// Feather's PasswordSetWidget (password + confirm, with a live "Passwords do not match" hint).
#ifndef AERO_PASSWORDSETWIDGET_H
#define AERO_PASSWORDSETWIDGET_H

#include <QWidget>

namespace Ui { class PasswordSetWidget; }

class PasswordSetWidget : public QWidget
{
    Q_OBJECT
public:
    explicit PasswordSetWidget(QWidget *parent = nullptr);
    ~PasswordSetWidget() override;

    QString password() const;
    bool passwordsMatch() const;
    void resetFields();

signals:
    void passwordEntryChanged();

private:
    void onChanged();
    Ui::PasswordSetWidget *ui;
};

#endif // AERO_PASSWORDSETWIDGET_H
