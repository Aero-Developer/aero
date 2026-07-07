// SPDX-License-Identifier: BSD-3-Clause
// InfoFrame implementation, matching Feather's src/components.cpp.
#include "components.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QPushButton>
#include <QSpacerItem>
#include <QStandardPaths>

bool aeroIsPortable() {
    // Computed once: launched with --portable, or a marker file sits next to the executable.
    static const bool portable = []() {
        if (QCoreApplication::arguments().contains(QStringLiteral("--portable")))
            return true;
        const QDir dir(QCoreApplication::applicationDirPath());
        return QFileInfo::exists(dir.filePath(QStringLiteral("portable")))
            || QFileInfo::exists(dir.filePath(QStringLiteral("portable.dat")));
    }();
    return portable;
}

QString aeroDataRoot() {
    if (aeroIsPortable())
        return QCoreApplication::applicationDirPath();
    return QDir(QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation))
        .filePath(QStringLiteral("Aero"));
}

QString aeroWalletsRoot() {
    return QDir(aeroDataRoot()).filePath(QStringLiteral("wallets"));
}

QString aeroLegacyRoot() {
    if (aeroIsPortable())
        return QCoreApplication::applicationDirPath();
    return QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
}

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
