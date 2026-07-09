// SPDX-License-Identifier: BSD-3-Clause
// Feather-style wallet setup wizard for Ethereum. Uses Feather's actual wizard page layouts
// (PageMenu / PageWalletFile / PageWalletSeed / PageSetPassword .ui) with the Ethereum banner
// as the ModernStyle watermark, so it is 1:1 with Feather's setup flow.
#ifndef AERO_WALLETWIZARD_H
#define AERO_WALLETWIZARD_H

#include <QWizard>
#include <QWizardPage>

namespace Ui {
class PageMenu;
class PageWalletFile;
class PageWalletSeed;
class PageSetPassword;
class PageOpenWallet;
}

class Wallet;
class QPlainTextEdit;
class QLineEdit;
class QStandardItemModel;
class QRadioButton;
class QLabel;
class QCheckBox;
class QCompleter;
class TextEdit;

class WalletWizard : public QWizard
{
    Q_OBJECT
public:
    enum Page { Page_Menu, Page_File, Page_Seed, Page_RestoreSeed, Page_Password, Page_Open, Page_Hardware, Page_Watch };
    enum Mode { Create, Restore, Open, Hardware, Watch };

    explicit WalletWizard(QWidget *parent = nullptr);
    ~WalletWizard() override;

    Wallet *takeWallet();

    // Shared state across pages.
    Mode mode = Create;
    Wallet *wallet = nullptr;
    QString walletName = "wallet";
    QString walletDir;
    QString walletPath;

private:
    QString m_defaultNextText; // pristine "Next >" text, restored per-page so labels don't bleed
};

// ---- pages ----

class MenuPage : public QWizardPage
{
    Q_OBJECT
public:
    explicit MenuPage(WalletWizard *w);
    ~MenuPage() override;
    int nextId() const override;
    bool validatePage() override;

private:
    WalletWizard *m_w;
    Ui::PageMenu *ui;
};

class FilePage : public QWizardPage
{
    Q_OBJECT
public:
    explicit FilePage(WalletWizard *w);
    ~FilePage() override;
    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

private:
    WalletWizard *m_w;
    Ui::PageWalletFile *ui;
};

class SeedPage : public QWizardPage
{
    Q_OBJECT
public:
    explicit SeedPage(WalletWizard *w);
    ~SeedPage() override;
    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

private:
    void regenerate();
    void showSeedWords(const QString &mnemonic);
    WalletWizard *m_w;
    Ui::PageWalletSeed *ui;
    QCheckBox *m_usePass = nullptr;      // reveal the optional BIP39 passphrase fields
    QLineEdit *m_passphrase = nullptr;   // optional BIP39 passphrase ("extension word")
    QLineEdit *m_passConfirm = nullptr;  // confirm (a typo permanently changes the wallet)
    QLabel *m_passError = nullptr;
    bool m_seedVerified = false;         // user confirmed backup words (create flow); reset on regen
};

class RestoreSeedPage : public QWizardPage
{
    Q_OBJECT
public:
    explicit RestoreSeedPage(WalletWizard *w);
    bool validatePage() override;
    int nextId() const override;

private:
    int expectedWordCount() const;
    void updatePlaceholder();
    WalletWizard *m_w;
    TextEdit *m_seed;
    QRadioButton *m_r12;
    QRadioButton *m_r24;
    QLabel *m_error;
    QCompleter *m_completer;
    QStringList m_words;
    QCheckBox *m_usePass = nullptr;      // reveal the optional BIP39 passphrase field
    QLineEdit *m_passphrase = nullptr;   // optional BIP39 passphrase used during restore
};

class PasswordPage : public QWizardPage
{
    Q_OBJECT
public:
    explicit PasswordPage(WalletWizard *w);
    ~PasswordPage() override;
    void initializePage() override;
    bool isComplete() const override;
    bool validatePage() override;
    int nextId() const override;

private:
    WalletWizard *m_w;
    Ui::PageSetPassword *ui;
};

// Connect a Ledger/Trezor: pick the device type, detect it, optionally enter a passphrase
// (Trezor Suite style), then derive a watch-only wallet whose keys stay on the device.
class HardwarePage : public QWizardPage
{
    Q_OBJECT
public:
    explicit HardwarePage(WalletWizard *w);
    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

private:
    void refreshDevices();
    WalletWizard *m_w;
    QRadioButton *m_ledger = nullptr;
    QRadioButton *m_trezor = nullptr;
    QLabel *m_status = nullptr;
    QCheckBox *m_usePass = nullptr;
    QLineEdit *m_passphrase = nullptr;
    QLabel *m_error = nullptr;
};

// Watch-only: enter one or more 0x addresses to track without keys (view balances/history, no
// spending). The created wallet is still saved as an encrypted .keys file (name + password pages).
class WatchPage : public QWizardPage
{
    Q_OBJECT
public:
    explicit WatchPage(WalletWizard *w);
    bool validatePage() override;
    int nextId() const override;

private:
    WalletWizard *m_w;
    QPlainTextEdit *m_addresses = nullptr;
    QLabel *m_error = nullptr;
};

class OpenPage : public QWizardPage
{
    Q_OBJECT
public:
    explicit OpenPage(WalletWizard *w);
    ~OpenPage() override;
    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

private:
    void refreshList();
    void updatePath();
    void finishNow();
    WalletWizard *m_w;
    Ui::PageOpenWallet *ui;
    QStandardItemModel *m_model;
    QString m_walletFile;
};

#endif // AERO_WALLETWIZARD_H
