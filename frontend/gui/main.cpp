// SPDX-License-Identifier: BSD-3-Clause
// Aero GUI entry point. Applies the Feather-style dark theme, runs a small create/restore/open
// startup flow, then shows the Feather 1:1 main window wired to the Ethereum backend.

#include <QApplication>
#include <QGuiApplication>
#include <QFont>
#include <QScreen>
#include <QFile>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QDialog>
#include <QVBoxLayout>
#include <QLabel>
#include <QSettings>
#include <QDir>

#include "AeroMainWindow.h"
#include "WalletWizard.h"
#include "components.h"
#include "ethwallet/WalletManager.h"

// Apply the selected theme app-wide. "dark" (default) uses the bundled qdarkstyle sheet; "light"
// clears it so the native platform (light) style is used. Shared by startup + the Settings dialog.
void aeroApplyTheme() {
    const QString theme = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                              .value(QStringLiteral("appearance/theme"), QStringLiteral("dark"))
                              .toString();
    if (theme == QLatin1String("light")) {
        qApp->setStyleSheet(QString());
        return;
    }
    QFile qss(QStringLiteral(":/qdarkstyle/style.qss"));
    if (qss.open(QIODevice::ReadOnly | QIODevice::Text))
        qApp->setStyleSheet(QString::fromUtf8(qss.readAll()));
}

int main(int argc, char *argv[]) {
    // Match Feather's font handling (src/main.cpp): use the system font, one point larger.
    QApplication::setDesktopSettingsAware(true);
    QApplication app(argc, argv);
    QApplication::setApplicationName("Aero");
    QApplication::setOrganizationName("Aero");

    // Portable mode (Electrum-style): keep settings next to the executable instead of the Windows
    // registry / user config dir, so an unzipped build is fully self-contained and leaves no trace.
    // Wallets are likewise stored under <exe dir>/wallets (see aeroWalletsRoot()). Must run before
    // any QSettings("Aero","Aero") is constructed.
    if (aeroIsPortable()) {
        QSettings::setDefaultFormat(QSettings::IniFormat);
        const QString cfg = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("config"));
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, cfg);
        QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, cfg);
    }

#if defined(Q_OS_MAC)
    // Feather only bumps the font size on macOS; on Windows/Linux it uses the plain system font.
    QFont fontDef = QApplication::font();
    fontDef.setPointSize(fontDef.pointSize() + 1);
    QApplication::setFont(fontDef);
#endif

    aeroApplyTheme();

    WalletWizard wizard;
    if (wizard.exec() != QDialog::Accepted)
        return 0;
    Wallet *wallet = wizard.takeWallet();
    if (!wallet)
        return 0;

    AeroMainWindow window;
    window.setWallet(wallet);
    // Match Feather's default window size (from MainWindow.ui), then center on screen.
    window.resize(977, 499);
    if (QScreen *screen = QGuiApplication::primaryScreen()) {
        const QRect avail = screen->availableGeometry();
        window.move(avail.center() - window.rect().center());
    }
    window.show();

    return app.exec();
}
