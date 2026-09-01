// SPDX-License-Identifier: BSD-3-Clause
// Opens the XMR1 trading tab on its own, against a watch-only wallet, and saves a screenshot.
//
// A development tool: the tab is otherwise reachable only through the wizard and an unlocked wallet,
// which makes it awkward to look at while working on it. Watch-only means nothing here can sign, so
// the screen can be driven against the live book with no possibility of placing an order.
//
// The tab is put inside a QTabWidget with the same stylesheet the wallet applies, because that is
// where it lives - previewing it as a bare window showed it in a frame it never actually has.
//
// Build with -DAERO_BUILD_XMR_PREVIEW=ON, run with an optional output path.

#include "XmrTradeTab.h"
#include "ethwallet/Wallet.h"
#include "ethwallet/aero_core.h"

#include <QApplication>
#include <QFile>
#include <QIcon>
#include <QPixmap>
#include <QTabWidget>
#include <QTimer>

int main(int argc, char **argv) {
    // A GUI-subsystem binary has no console, so anything logged while working on the tab would go
    // nowhere. Mirror it into a file next to the screenshot instead.
    qInstallMessageHandler([](QtMsgType, const QMessageLogContext &, const QString &msg) {
        QFile log(QStringLiteral("xmr-preview.log"));
        if (log.open(QIODevice::Append | QIODevice::Text))
            log.write(msg.toUtf8() + '\n');
    });
    QApplication app(argc, argv);
    const QString out = argc > 1 ? QString::fromLocal8Bit(argv[1])
                                 : QStringLiteral("xmr-preview.png");

    // An address that actually trades XMR1, so the balances, orders and fills panels have something
    // real in them rather than rendering as empty tables.
    const QString address = QStringLiteral("0x207700bd207df757825f9193ef9c648c1c65e06a");
    AeroWallet *core = aero_wallet_watch_only(
        QStringLiteral("[\"%1\"]").arg(address).toUtf8().constData());
    if (!core) {
        qWarning("could not create the watch-only wallet");
        return 1;
    }

    QFile qss(QStringLiteral(":/qdarkstyle/style.qss"));
    if (qss.open(QIODevice::ReadOnly | QIODevice::Text))
        app.setStyleSheet(QString::fromUtf8(qss.readAll()));

    auto *wallet = new Wallet(core, &app);
    wallet->setProvider(42161, {QStringLiteral("https://arb1.arbitrum.io/rpc")}, QString());

    auto *host = new QTabWidget();
    host->setWindowTitle(QStringLiteral("Aero - Buy XMR (preview)"));
    auto *tab = new XmrTradeTab();
    host->addTab(tab, QIcon(QStringLiteral(":/assets/images/tab_swap.png")),
                 QStringLiteral("Buy XMR"));
    // Defaults to Aero's own default window size, so the preview shows the tightest layout a user
    // actually gets rather than a generously sized one that hides any squeeze. Pass WxH to check a
    // larger window.
    int w = 977, h = 499;
    if (argc > 3) {
        w = QString::fromLocal8Bit(argv[2]).toInt();
        h = QString::fromLocal8Bit(argv[3]).toInt();
    }
    host->resize(w, h);
    host->show();
    tab->setWallet(wallet, 0, address);

    // Growing the window exercises the same path dragging a divider does: the book is told it has
    // more height and has to fit more levels into it without waiting for the next poll. Pass
    // --grow to check that, since a preview cannot drag anything itself.
    if (app.arguments().contains(QStringLiteral("--grow")))
        QTimer::singleShot(12000, host, [host, w, h]() { host->resize(w, h + 260); });

    // An earlier capture as well, so the pair shows the screen actually moving between polls rather
    // than only that it rendered once.
    QTimer::singleShot(8000, &app, [host, out]() {
        QString early = out;
        early.replace(QStringLiteral(".png"), QStringLiteral("-t1.png"));
        if (host->grab().save(early))
            qInfo("saved %s", qPrintable(early));
    });

    // Long enough for a poll or two to land, so the capture shows a populated book.
    QTimer::singleShot(20000, &app, [host, out]() {
        const QPixmap shot = host->grab();
        if (shot.save(out))
            qInfo("saved %s (%dx%d)", qPrintable(out), shot.width(), shot.height());
        else
            qWarning("could not save %s", qPrintable(out));
        QCoreApplication::quit();
    });

    return app.exec();
}
