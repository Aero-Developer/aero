// SPDX-License-Identifier: BSD-3-Clause
#include "widgets/PasswordSetWidget.h"
#include "ui_PasswordSetWidget.h"

PasswordSetWidget::PasswordSetWidget(QWidget *parent)
    : QWidget(parent), ui(new Ui::PasswordSetWidget) {
    ui->setupUi(this);
    ui->label_match->setVisible(false);

    connect(ui->line_password, &QLineEdit::textChanged, this, &PasswordSetWidget::onChanged);
    connect(ui->line_confirmPassword, &QLineEdit::textChanged, this, &PasswordSetWidget::onChanged);
}

PasswordSetWidget::~PasswordSetWidget() {
    delete ui;
}

void PasswordSetWidget::onChanged() {
    const bool bothFilled = !ui->line_password->text().isEmpty()
                            && !ui->line_confirmPassword->text().isEmpty();
    ui->label_match->setVisible(bothFilled && !passwordsMatch());
    emit passwordEntryChanged();
}

QString PasswordSetWidget::password() const {
    return ui->line_password->text();
}

bool PasswordSetWidget::passwordsMatch() const {
    return ui->line_password->text() == ui->line_confirmPassword->text();
}

void PasswordSetWidget::resetFields() {
    ui->line_password->clear();
    ui->line_confirmPassword->clear();
    ui->label_match->setVisible(false);
}
