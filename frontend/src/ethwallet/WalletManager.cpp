// SPDX-License-Identifier: BSD-3-Clause
#include "WalletManager.h"
#include "Wallet.h"

#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QThread>

#include "aero_core.h"

WalletManager *WalletManager::instance() {
    static WalletManager *self = new WalletManager();
    return self;
}

static QString takeError() {
    char *e = aero_last_error();
    if (!e) return QString();
    QString s = QString::fromUtf8(e);
    aero_string_free(e);
    return s;
}

// Create a Wallet and anchor it to the GUI (main) thread. The wizard opens/creates wallets on a
// worker thread (runBusy → QtConcurrent), so a Wallet born there would have its thread affinity set
// to that worker thread. Its queued signals - notably providerConnected(), emitted from the network
// pool via QMetaObject::invokeMethod(this, …, QueuedConnection) - are delivered on the object's
// thread's event loop, which for a finished worker thread doesn't exist. The result was the UI never
// leaving "Connecting to Tor…" even though the connect succeeded. Moving it to the main thread (which
// has the running event loop) makes those signals reach the UI slots.
static Wallet *anchoredWallet(AeroWallet *core) {
    Wallet *w = new Wallet(core);
    QThread *guiThread = QCoreApplication::instance() ? QCoreApplication::instance()->thread() : nullptr;
    if (guiThread && w->thread() != guiThread)
        w->moveToThread(guiThread);
    return w;
}

Wallet *WalletManager::createWallet(quint32 wordCount, const QString &passphrase) {
    AeroWallet *core = passphrase.isEmpty()
        ? aero_wallet_create_new(wordCount)
        : aero_wallet_create_new_with_passphrase(wordCount, passphrase.toUtf8().constData());
    if (!core) {
        m_errorString = takeError();
        return nullptr;
    }
    return anchoredWallet(core);
}

Wallet *WalletManager::recoveryWallet(const QString &mnemonic, const QString &passphrase) {
    AeroWallet *core = passphrase.isEmpty()
        ? aero_wallet_restore(mnemonic.toUtf8().constData())
        : aero_wallet_restore_with_passphrase(mnemonic.toUtf8().constData(),
                                               passphrase.toUtf8().constData());
    if (!core) {
        m_errorString = takeError();
        return nullptr;
    }
    return anchoredWallet(core);
}

Wallet *WalletManager::createWatchOnly(const QStringList &addresses) {
    QJsonArray arr;
    for (const QString &a : addresses) {
        const QString t = a.trimmed();
        if (!t.isEmpty())
            arr.append(t);
    }
    const QByteArray json = QJsonDocument(arr).toJson(QJsonDocument::Compact);
    AeroWallet *core = aero_wallet_watch_only(json.constData());
    if (!core) {
        m_errorString = takeError();
        return nullptr;
    }
    return anchoredWallet(core);
}

Wallet *WalletManager::openWallet(const QString &path, const QString &password) {
    AeroWallet *core = aero_wallet_open(path.toUtf8().constData(), password.toUtf8().constData());
    if (!core) {
        m_errorString = takeError();
        return nullptr;
    }
    Wallet *w = anchoredWallet(core);
    w->setWalletPath(path);
    w->setPassword(password); // retain so later changes can be re-saved
    return w;
}

QStringList WalletManager::listHwDevices(const QString &kind) {
    QStringList out;
    char *j = aero_wallet_hw_list_devices(kind.toUtf8().constData());
    if (j) {
        const QByteArray json = QByteArray(j);
        aero_string_free(j);
        const QJsonArray arr = QJsonDocument::fromJson(json).array();
        for (const QJsonValue &v : arr)
            out << v.toString();
    } else {
        m_errorString = takeError();
    }
    return out;
}

Wallet *WalletManager::createHardwareWallet(const QString &kind, const QString &passphrase,
                                            quint32 numAccounts) {
    AeroWallet *core = aero_wallet_create_hardware(
        kind.toUtf8().constData(), passphrase.toUtf8().constData(), numAccounts);
    if (!core) {
        m_errorString = takeError();
        return nullptr;
    }
    return anchoredWallet(core); // GUI-thread affinity, so queued signals reach the UI (see comment)
}

Wallet *WalletManager::openHardwareWallet(const QString &path, const QString &password,
                                          const QString &passphrase) {
    AeroWallet *core = aero_wallet_open_hardware(
        path.toUtf8().constData(), password.toUtf8().constData(), passphrase.toUtf8().constData());
    if (!core) {
        m_errorString = takeError();
        return nullptr;
    }
    Wallet *w = anchoredWallet(core); // GUI-thread affinity (may be created from a runBusy worker)
    w->setWalletPath(path);
    w->setPassword(password);
    return w;
}

int WalletManager::fileIsHardware(const QString &path, const QString &password) {
    return aero_wallet_file_is_hardware(path.toUtf8().constData(), password.toUtf8().constData());
}

QString WalletManager::coreVersion() {
    char *v = aero_version();
    if (!v) return QString();
    QString s = QString::fromUtf8(v);
    aero_string_free(v);
    return s;
}
