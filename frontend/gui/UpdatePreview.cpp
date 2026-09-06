// SPDX-License-Identifier: BSD-3-Clause
// Shows the "new update" dialog on its own and saves a screenshot of it.
//
// A development tool. The real dialog only appears when a signed manifest has verified against the
// pinned release key and names a newer version, which is not something that can be arranged while
// working on the wording. This drives the same `Updater::offerUpdate` with a made-up status, under
// the same stylesheet the wallet applies, so what is captured is the dialog users get.
//
// Nothing is downloaded: the preview quits at the capture, before any button is pressed.
//
// Build with -DAERO_BUILD_UPDATE_PREVIEW=ON, run with an optional output path.

#include "Updater.h"

#include <QApplication>
#include <QFile>
#include <QPixmap>
#include <QTimer>
#include <QWidget>

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    const QString out =
        argc > 1 ? QString::fromLocal8Bit(argv[1]) : QStringLiteral("update-preview.png");

    QFile qss(QStringLiteral(":/qdarkstyle/style.qss"));
    if (qss.open(QIODevice::ReadOnly | QIODevice::Text))
        app.setStyleSheet(QString::fromUtf8(qss.readAll()));

    // A parent window, because the dialog is window-modal to the wallet and centres itself on it.
    auto *host = new QWidget();
    host->setWindowTitle(QStringLiteral("Aero"));
    host->resize(977, 499);
    host->show();

    auto *updater = new Updater(host);

    // The shape `aero_update_check` returns, with the release notes of an actual release so the text
    // is a realistic length rather than a single tidy line.
    const QString status = QStringLiteral(R"({
        "available": true,
        "latest": "0.1.29",
        "current": "0.1.28",
        "file": "Aero-0.1.29-Windows-x64-portable.zip",
        "sha256": "284731a91e66f38db2ca6b80b126191e7bce3fbabea8aeef505cdbe2fa9ae62d",
        "size": 38634954,
        "notes": "Signed automatic updates: Aero now checks for, verifies and installs releases signed with the Aero release key, over Tor. Wallets, settings and Trezor pairing are never touched.",
        "signed_by": "FD06 516B 6C76 2BB8 B016 16DE 80D5 05C2 5B02 54B3",
        "signed_at": 1757116800
    })");

    // Fires inside the dialog's own event loop, so it captures the dialog rather than the window
    // behind it. Quitting from here also means no button is ever pressed.
    QTimer::singleShot(1200, &app, [out]() {
        QWidget *dialog = QApplication::activeModalWidget();
        if (!dialog) {
            qWarning("no dialog on screen");
            QCoreApplication::exit(1);
            return;
        }
        const QPixmap shot = dialog->grab();
        if (!shot.save(out))
            qWarning("could not save %s", qPrintable(out));
        QCoreApplication::quit();
    });

    QTimer::singleShot(0, updater, [updater, status]() { updater->offerUpdate(status); });
    return app.exec();
}
