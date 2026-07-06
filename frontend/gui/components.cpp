// SPDX-License-Identifier: BSD-3-Clause
// InfoFrame implementation, matching Feather's src/components.cpp.
#include "components.h"

#include <QHBoxLayout>
#include <QPushButton>
#include <QSpacerItem>

InfoFrame::InfoFrame(QWidget *parent) : QFrame(parent) {
    auto *layout = new QHBoxLayout(this);

    m_icon = new QPushButton(this);
    m_icon->setFlat(true);
    m_icon->setIconSize(QSize(32, 32));
    m_icon->setMaximumSize(32, 32);
    m_icon->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);
    m_icon->setFocusPolicy(Qt::NoFocus);
    m_icon->setAttribute(Qt::WA_TransparentForMouseEvents);
    layout->addWidget(m_icon);

    layout->addSpacerItem(new QSpacerItem(5, 0, QSizePolicy::Fixed, QSizePolicy::Minimum));

    m_infoLabel = new QLabel(this);
    m_infoLabel->setWordWrap(true);
    layout->addWidget(m_infoLabel);
}

void InfoFrame::setInfo(const QIcon &icon, const QString &text) {
    m_icon->setIcon(icon);
    m_infoLabel->setText(text);
    setFrameShape(QFrame::StyledPanel);
}

void InfoFrame::setText(const QString &text) {
    m_infoLabel->setText(text);
}
