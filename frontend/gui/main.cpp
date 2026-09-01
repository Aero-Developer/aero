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

#include <QLineEdit>
#include <QThread>

#include "AeroMainWindow.h"
#include "WalletWizard.h"
#include "components.h"
#include "ethwallet/WalletManager.h"
#include "ethwallet/aero_core.h"

// Ask the user for the 6-digit code a Trezor Safe 5/7 shows while pairing.
//
// This runs "backwards" compared with the rest of the FFI: the Rust core calls it in the middle of
// a blocking operation, from whichever worker thread is driving the device. Qt dialogs may only be
// touched from the GUI thread, so the call is marshalled there and the worker blocks until the user
// answers. The thread check matters - a blocking-queued call issued from the GUI thread to itself
// would deadlock, which is exactly what happens on the connect path that runs without a worker.
static int aeroPairingCodePrompt(void *ctx, char *out, int outLen) {
    Q_UNUSED(ctx);
    if (!out || outLen <= 0)
        return -1;

    QString code;
    bool accepted = false;
    auto ask = [&code, &accepted]() {
        code = QInputDialog::getText(
            nullptr, QObject::tr("Pair your Trezor"),
            QObject::tr("Your Trezor is displaying a 6-digit pairing code.\n\n"
                        "Type it here to pair the device with Aero. You only need to do this once."),
            QLineEdit::Normal, QString(), &accepted);
    };

    if (QThread::currentThread() == qApp->thread())
        ask();
    else
        QMetaObject::invokeMethod(qApp, ask, Qt::BlockingQueuedConnection);

    if (!accepted)
        return -1;
    const QByteArray utf8 = code.trimmed().toUtf8();
    if (utf8.size() >= outLen)
        return -1;
    memcpy(out, utf8.constData(), static_cast<size_t>(utf8.size()));
    out[utf8.size()] = '\0';
    return 0;
}

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

    // 2025+ Trezor models (Safe 5/7) must be paired before they will talk to us, and the credential
    // that records the pairing lives alongside the wallets so portable installs stay self-contained.
    // It is deliberately app-level rather than per-wallet: the pairing identifies this copy of Aero
    // to the device, so pairing once covers every wallet.
    {
        const QString thpCredentials =
            QDir(aeroDataRoot()).filePath(QStringLiteral("thp-pairing.txt"));
        aero_thp_configure(thpCredentials.toUtf8().constData(), aeroPairingCodePrompt, nullptr);
    }

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
