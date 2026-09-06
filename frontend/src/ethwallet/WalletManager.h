// SPDX-License-Identifier: BSD-3-Clause
// Aero - replaces Feather's Monero WalletManager. Constructs Wallet objects from the
// aero_core C ABI (create new / restore from mnemonic / open encrypted file).

#ifndef AERO_WALLETMANAGER_H
#define AERO_WALLETMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>

class Wallet;

class WalletManager : public QObject
{
    Q_OBJECT

public:
    static WalletManager *instance();

    // Create a brand-new wallet with a fresh mnemonic (wordCount = 12 or 24). An optional BIP39
    // passphrase ("extension word") derives a distinct set of addresses; empty = none.
    // The wallet is not yet persisted; call Wallet::store() after the user sets a password.
    Wallet *createWallet(quint32 wordCount = 12, const QString &passphrase = QString());

    // Restore from an existing BIP39 mnemonic, with an optional BIP39 passphrase (empty = none).
    Wallet *recoveryWallet(const QString &mnemonic, const QString &passphrase = QString());

    // Open an encrypted wallet file.
    Wallet *openWallet(const QString &path, const QString &password);

    // Create an address-only watch wallet from one or more 0x addresses (no keys; view-only).
    // Not yet persisted; the wizard saves it via Wallet::store() after the name/password pages.
    Wallet *createWatchOnly(const QStringList &addresses);

    // ##### Hardware wallets (Ledger / Trezor) #####
    // Connected device names of `kind` ("ledger"/"trezor"); empty if none/unreachable.
    QStringList listHwDevices(const QString &kind);
    // Create a watch-only wallet from a connected device (keys stay on the device). `passphrase` is
    // the host-entered BIP39 passphrase for Trezor (ignored by Ledger, which enters it on-device).
    Wallet *createHardwareWallet(const QString &kind, const QString &passphrase,
                                 bool passphraseOnDevice, quint32 numAccounts);
    // Open a hardware wallet file; requires the device (+ Trezor passphrase). Fails if absent.
    Wallet *openHardwareWallet(const QString &path, const QString &password, const QString &passphrase);
    // Inspect a file without a device: 1 = hardware, 0 = software, -1 = can't decrypt (bad password).
    int fileIsHardware(const QString &path, const QString &password);

    QString errorString() const { return m_errorString; }

    // aero_core library version string.
    static QString coreVersion();

private:
    explicit WalletManager(QObject *parent = nullptr) : QObject(parent) {}
    QString m_errorString;
};

#endif // AERO_WALLETMANAGER_H
