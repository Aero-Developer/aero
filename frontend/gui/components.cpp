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
    // Computed once. Portable when:
    //   * launched with --portable (and never with --no-portable), or
    //   * a `portable`/`portable.dat` marker file sits next to the executable, or
    //   * a `wallets` or `config` folder already lives next to the executable (i.e. we've been
    //     running portably from here before — keeps it sticky even if a marker gets deleted).
    static const bool portable = []() {
        const QStringList args = QCoreApplication::arguments();
        if (args.contains(QStringLiteral("--no-portable")))
            return false;
        if (args.contains(QStringLiteral("--portable")))
            return true;
        const QDir dir(QCoreApplication::applicationDirPath());
        return QFileInfo::exists(dir.filePath(QStringLiteral("portable")))
            || QFileInfo::exists(dir.filePath(QStringLiteral("portable.dat")))
            || QFileInfo(dir.filePath(QStringLiteral("wallets"))).isDir()
            || QFileInfo(dir.filePath(QStringLiteral("config"))).isDir();
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
