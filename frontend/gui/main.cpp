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

#include "AeroMainWindow.h"
#include "WalletWizard.h"
#include "ethwallet/WalletManager.h"

static void applyTheme(QApplication &app) {
    // Feather does not force a QStyle; it relies on the platform style + the qdarkstyle sheet.
    QFile qss(":/qdarkstyle/style.qss");
    if (qss.open(QIODevice::ReadOnly | QIODevice::Text)) {
        app.setStyleSheet(QString::fromUtf8(qss.readAll()));
    }
}

int main(int argc, char *argv[]) {
    // Match Feather's font handling (src/main.cpp): use the system font, one point larger.
    QApplication::setDesktopSettingsAware(true);
    QApplication app(argc, argv);
    QApplication::setApplicationName("Aero");
    QApplication::setOrganizationName("Aero");

#if defined(Q_OS_MAC)
    // Feather only bumps the font size on macOS; on Windows/Linux it uses the plain system font.
    QFont fontDef = QApplication::font();
    fontDef.setPointSize(fontDef.pointSize() + 1);
    QApplication::setFont(fontDef);
#endif

    applyTheme(app);

    Wallet *wallet = nullptr;
    // Demo shortcut: skip the setup wizard and show the main window with a throwaway wallet.
    if (!qEnvironmentVariableIsEmpty("AERO_DEMO")) {
        wallet = WalletManager::instance()->createWallet(12);
    } else {
        WalletWizard wizard;
        if (wizard.exec() != QDialog::Accepted) return 0;
        wallet = wizard.takeWallet();
    }
    if (!wallet) return 0;

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
