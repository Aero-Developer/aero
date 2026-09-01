// SPDX-License-Identifier: BSD-3-Clause
#include "WalletWizard.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QCompleter>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QMenu>
#include <QRandomGenerator>
#include <QLabel>
#include <QLineEdit>
#include <QStandardItemModel>
#include <algorithm>
#include <QEventLoop>
#include <QFutureWatcher>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QProgressDialog>
#include <QPushButton>
#include <QTimer>
#include <QtConcurrent/QtConcurrent>
#include <QRadioButton>
#include <QSettings>
#include <QStandardPaths>
#include <QVBoxLayout>

#include "components.h"
#include "widgets/TextEdit.h"

namespace {
// Run a slow blocking operation (Argon2id encrypt/decrypt + disk I/O) off the UI thread while a
// modal, indeterminate "please wait" dialog keeps the wizard painting - so it never shows as
// "Not responding". Returns the operation's bool result.
template <typename Fn>
bool runBusy(QWidget *parent, const QString &label, Fn fn) {
    QProgressDialog dlg(label, QString(), 0, 0, parent); // indeterminate, no cancel button
    dlg.setWindowTitle(QObject::tr("Please wait"));
    dlg.setWindowModality(Qt::WindowModal);
    dlg.setMinimumDuration(0);
    dlg.setAutoClose(false);
    dlg.setAutoReset(false);
    QFutureWatcher<bool> watcher;
    QEventLoop loop;
    bool result = false;
    QObject::connect(&watcher, &QFutureWatcher<bool>::finished, &loop, [&]() {
        result = watcher.future().result();
        loop.quit();
    });
    watcher.setFuture(QtConcurrent::run(std::move(fn)));
    dlg.show();
    loop.exec();
    dlg.close();
    return result;
}
} // namespace

#include <QDateTime>
#include <QFileInfo>
#include <QHeaderView>
#include <QPushButton>
#include <QStandardItemModel>
#include <QTreeView>

#include "ui_PageMenu.h"
#include "ui_PageWalletFile.h"
#include "ui_PageWalletSeed.h"
#include "ui_PageSetPassword.h"
#include "ui_PageOpenWallet.h"
#include "widgets/PasswordSetWidget.h"

#include "ethwallet/Wallet.h"
#include "ethwallet/WalletManager.h"

namespace {
const QString kLockIcon = ":/assets/images/lock.svg";
const QString kInfoIcon = ":/assets/images/info2.svg";
const QString kWarnIcon = ":/assets/images/warning.png";

// Feather-style wallet root. Each wallet lives in its own subfolder as <name>/<name>.keys, so a
// wallet's files are grouped together. In portable mode this is <exe dir>/wallets (next to the
// unzipped build, Electrum-style); otherwise <Documents>/Aero/wallets.
QString walletsRoot() {
    return aeroWalletsRoot();
}

// Full path of a wallet's key file for a given name: <root>/<name>/<name>.keys.
QString walletKeyPath(const QString &root, const QString &name) {
    return QDir(root).filePath(QStringLiteral("%1/%1.keys").arg(name));
}

// Like Feather: pick the first wallet name whose subfolder/key file doesn't already exist, so
// creating a new wallet never silently overwrites an existing one ("wallet", "wallet_2", ...).
QString uniqueWalletName(const QString &root, const QString &base = QStringLiteral("wallet")) {
    if (!QFileInfo::exists(walletKeyPath(root, base)))
        return base;
    for (int i = 2; i < 100000; ++i) {
        const QString candidate = QStringLiteral("%1_%2").arg(base).arg(i);
        if (!QFileInfo::exists(walletKeyPath(root, candidate)))
            return candidate;
    }
    return base; // unreachable in practice
}
}

// ================= WalletWizard =================

WalletWizard::WalletWizard(QWidget *parent) : QWizard(parent) {
    walletDir = walletsRoot();
    QDir().mkpath(walletDir);

    setWindowTitle(tr("Welcome to Aero"));
    setWindowIcon(QIcon(":/assets/images/appicons/64x64.png"));

    // Capture the pristine Next label before any page overrides it, so we can restore it per-page.
    m_defaultNextText = buttonText(QWizard::NextButton);

    setPage(Page_Menu, new MenuPage(this));
    setPage(Page_File, new FilePage(this));
    setPage(Page_Seed, new SeedPage(this));
    setPage(Page_RestoreSeed, new RestoreSeedPage(this));
    setPage(Page_Password, new PasswordPage(this));
    setPage(Page_Open, new OpenPage(this));
    setPage(Page_Hardware, new HardwarePage(this));
    setPage(Page_Watch, new WatchPage(this));
    setStartId(Page_Menu);

    // Mirror Feather's WalletWizard setup 1:1: ModernStyle with the banner as the full-height
    // left watermark (native, no scaling), and the Help / Settings button bar.
    setButtonText(QWizard::CancelButton, tr("Close"));
    setPixmap(QWizard::WatermarkPixmap, QPixmap(":/assets/images/banners/eth.png"));
    setWizardStyle(QWizard::ModernStyle);
    setOption(QWizard::NoBackButtonOnStartPage);
    setOption(QWizard::HaveHelpButton, true);
    setOption(QWizard::HaveCustomButton1, true);

    QList<QWizard::WizardButton> buttonLayout;
    buttonLayout << QWizard::HelpButton << QWizard::CustomButton1 << QWizard::Stretch
                 << QWizard::BackButton << QWizard::NextButton << QWizard::FinishButton
                 << QWizard::CommitButton;
    setButtonLayout(buttonLayout);

    auto *settingsButton = new QPushButton(tr("Settings"), this);
    setButton(QWizard::CustomButton1, settingsButton);
    settingsButton->setVisible(false);
    connect(this, &QWizard::currentIdChanged, this, [this, settingsButton](int id) {
        settingsButton->setVisible(id == WalletWizard::Page_Menu);
        // Keep the Next / Finish labels correct per-page - setButtonText is global, so without this
        // one page's custom label ("Connect", "Open wallet") bleeds onto later pages.
        setButtonText(QWizard::NextButton,
                      id == Page_Hardware ? tr("Connect") : m_defaultNextText);
        setButtonText(QWizard::FinishButton,
                      id == Page_Open ? tr("Open wallet") : tr("Create/Open wallet"));
    });
    // Auto-sizes like Feather; we only pin the minimum width to Feather's exact wizard width
    // (client ~562 -> 575px window incl. border) so the layout matches Feather 1:1. This is a
    // logical-pixel value, so it scales correctly on any display/DPI.
    setMinimumWidth(562);
}

WalletWizard::~WalletWizard() {
    delete wallet;
}

Wallet *WalletWizard::takeWallet() {
    Wallet *w = wallet;
    wallet = nullptr;
    return w;
}

// ================= MenuPage =================

MenuPage::MenuPage(WalletWizard *w) : m_w(w), ui(new Ui::PageMenu) {
    ui->setupUi(this);
    // Feather's menu page has no title/subtitle header - the banner runs full-height from the top.

    // Repurpose Feather's "view-only" option as an Ethereum address-only watch wallet.
    ui->radioViewOnly->setText(tr("Watch-only wallet (track an address)"));
    ui->radioCreateFromDevice->setText(tr("Connect hardware wallet (Ledger / Trezor)"));
    ui->frame_seedBump->setVisible(false);
    ui->label_version->setText(tr("Aero - Ethereum wallet"));

    // Default to the last action used; fall back to "Open wallet file" so returning users land
    // straight on their existing wallet.
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    const QString last = s.value(QStringLiteral("wizard/lastMode")).toString();
    if (last == QLatin1String("create"))
        ui->radioCreate->setChecked(true);
    else if (last == QLatin1String("restore"))
        ui->radioSeed->setChecked(true);
    else if (last == QLatin1String("hardware"))
        ui->radioCreateFromDevice->setChecked(true);
    else if (last == QLatin1String("watch"))
        ui->radioViewOnly->setChecked(true);
    else
        ui->radioOpen->setChecked(true);
}

MenuPage::~MenuPage() { delete ui; }

int MenuPage::nextId() const {
    if (ui->radioOpen->isChecked()) return WalletWizard::Page_Open;
    if (ui->radioCreateFromDevice->isChecked()) return WalletWizard::Page_Hardware;
    if (ui->radioViewOnly->isChecked()) return WalletWizard::Page_Watch;
    return WalletWizard::Page_File;
}

bool MenuPage::validatePage() {
    QString mode;
    const WalletWizard::Mode previous = m_w->mode;
    if (ui->radioOpen->isChecked()) { m_w->mode = WalletWizard::Open; mode = QStringLiteral("open"); }
    else if (ui->radioCreateFromDevice->isChecked()) { m_w->mode = WalletWizard::Hardware; mode = QStringLiteral("hardware"); }
    else if (ui->radioViewOnly->isChecked()) { m_w->mode = WalletWizard::Watch; mode = QStringLiteral("watch"); }
    else if (ui->radioSeed->isChecked()) { m_w->mode = WalletWizard::Restore; mode = QStringLiteral("restore"); }
    else { m_w->mode = WalletWizard::Create; mode = QStringLiteral("create"); }

    // Coming back here and picking a different path must not carry the half-finished wallet from
    // the previous one. A hardware wallet left behind this way used to surface on the seed page as
    // twelve blank words, because it has no seed to show.
    if (m_w->mode != previous) {
        delete m_w->wallet;
        m_w->wallet = nullptr;
    }
    QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
        .setValue(QStringLiteral("wizard/lastMode"), mode);
    return true;
}

// ================= FilePage =================

FilePage::FilePage(WalletWizard *w) : m_w(w), ui(new Ui::PageWalletFile) {
    ui->setupUi(this);
    setTitle(tr("Wallet name and location"));

    ui->frame_wallet->setInfo(QIcon(kInfoIcon),
                              aeroIsPortable()
                                  ? tr("Portable mode: your wallet is stored next to the app as an "
                                       "encrypted .keys file in the folder shown below. "
                                       "Choose a name and where to keep it.")
                                  : tr("Your wallet is stored in its own folder as an encrypted "
                                       ".keys file. Choose a name and where to keep it."));
    ui->line_walletName->setText(m_w->walletName);
    ui->line_walletDir->setText(m_w->walletDir);
    ui->check_defaultWalletDirectory->setVisible(false);

    connect(ui->btnChange, &QPushButton::clicked, this, [this]() {
        const QString d = QFileDialog::getExistingDirectory(this, tr("Wallet location"),
                                                            ui->line_walletDir->text());
        if (!d.isEmpty()) ui->line_walletDir->setText(d);
    });
}

FilePage::~FilePage() { delete ui; }

void FilePage::initializePage() {
    // Default to a name that doesn't collide with an existing wallet file (wallet, wallet_2, ...),
    // so a freshly-created wallet can never silently overwrite one you already have.
    m_w->walletName = uniqueWalletName(m_w->walletDir);
    ui->line_walletName->setText(m_w->walletName);
    ui->line_walletDir->setText(m_w->walletDir);
}

bool FilePage::validatePage() {
    const QString name = ui->line_walletName->text().trimmed();
    if (name.isEmpty()) {
        QMessageBox::warning(this, tr("Wallet"), tr("Please enter a wallet name."));
        return false;
    }
    const QString dir = ui->line_walletDir->text();
    // Never overwrite an existing wallet file (data loss / key-loss risk).
    if (QFileInfo::exists(walletKeyPath(dir, name))) {
        QMessageBox::warning(
            this, tr("Wallet already exists"),
            tr("A wallet named \"%1\" already exists in this folder.\n\n"
               "Choose a different name so you don't overwrite (and lose) your existing wallet.")
                .arg(name));
        return false;
    }
    m_w->walletName = name;
    m_w->walletDir = dir;
    return true;
}

int FilePage::nextId() const {
    if (m_w->mode == WalletWizard::Restore)
        return WalletWizard::Page_RestoreSeed;
    // Watch-only and hardware wallets were already built on their own page, and neither has a seed
    // to show or back up - the keys are on the device, or there are none. They go straight to
    // setting the file password.
    if (m_w->mode == WalletWizard::Watch || m_w->mode == WalletWizard::Hardware)
        return WalletWizard::Page_Password;
    return WalletWizard::Page_Seed;
}

// ================= SeedPage =================

SeedPage::SeedPage(WalletWizard *w) : m_w(w), ui(new Ui::PageWalletSeed) {
    ui->setupUi(this);
    setTitle(tr("Your recovery seed"));

    ui->frame_notice->setInfo(
        QIcon(kWarnIcon),
        tr("This is the only way to recover your wallet. Write these words down on paper, in "
           "order, and keep them somewhere safe. Anyone with your seed can steal your funds."));
    ui->frame_invalidSeed->setVisible(false);
    ui->btnOptions->setVisible(false);

    // Feather's grid has 16 slots; a BIP39 wallet here uses 12 words, so hide the last four.
    ui->frame_4->setVisible(false);   // word 13
    ui->frame_9->setVisible(false);   // word 14
    ui->frame_16->setVisible(false);  // word 15
    ui->frame_17->setVisible(false);  // word 16

    connect(ui->btnRoulette, &QPushButton::clicked, this, [this]() { regenerate(); });
    connect(ui->btnCopy, &QPushButton::clicked, this, [this]() {
        if (!m_w->wallet) return;
        const QString seed = m_w->wallet->getSeed();
        QApplication::clipboard()->setText(seed);
        // Auto-clear the seed from the clipboard after the configured timeout so it doesn't linger.
        const int secs = QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
                             .value(QStringLiteral("security/clipboardClearSecs"), 30).toInt();
        if (secs > 0)
            QTimer::singleShot(secs * 1000, qApp, [seed]() {
                if (QApplication::clipboard()->text() == seed)
                    QApplication::clipboard()->clear();
            });
    });

    // Optional BIP39 passphrase ("extension word" / "25th word"). It is NOT part of the seed words
    // above; it mixes into key derivation so it must be remembered separately, and a typo silently
    // produces a different wallet - hence a confirm field. Hidden behind a checkbox for normal users.
    m_usePass = new QCheckBox(tr("Add an optional passphrase (advanced)"), this);
    m_passphrase = new QLineEdit(this);
    m_passphrase->setEchoMode(QLineEdit::Password);
    m_passphrase->setPlaceholderText(tr("Passphrase"));
    m_passConfirm = new QLineEdit(this);
    m_passConfirm->setEchoMode(QLineEdit::Password);
    m_passConfirm->setPlaceholderText(tr("Confirm passphrase"));
    m_passError = new QLabel(this);
    m_passError->setStyleSheet(QStringLiteral("color: red;"));
    m_passError->setWordWrap(true);
    m_passError->hide();
    auto *passNote = new QLabel(
        tr("The passphrase is required together with your seed to recover this wallet. "
           "It is not written in the words above - store it separately. If you lose it, "
           "these funds are unrecoverable."),
        this);
    passNote->setWordWrap(true);
    passNote->setStyleSheet(QStringLiteral("color: gray;"));

    m_passphrase->setVisible(false);
    m_passConfirm->setVisible(false);
    passNote->setVisible(false);
    connect(m_usePass, &QCheckBox::toggled, this, [this, passNote](bool on) {
        m_passphrase->setVisible(on);
        m_passConfirm->setVisible(on);
        passNote->setVisible(on);
        if (!on) {
            m_passphrase->clear();
            m_passConfirm->clear();
            m_passError->hide();
        }
    });
    if (auto *lay = qobject_cast<QVBoxLayout *>(this->layout())) {
        lay->addWidget(m_usePass);
        lay->addWidget(m_passphrase);
        lay->addWidget(m_passConfirm);
        lay->addWidget(passNote);
        lay->addWidget(m_passError);
    }
}

SeedPage::~SeedPage() { delete ui; }

bool SeedPage::validatePage() {
    m_passError->hide();
    if (!m_w->wallet) {
        // Seed generation failed earlier - don't dead-end silently on a blank grid.
        m_passError->setText(tr("Couldn't generate a seed phrase. Go back a step and try again."));
        m_passError->show();
        return false;
    }
    // If the passphrase box is ticked it must actually be filled - otherwise we'd silently create a
    // NO-passphrase wallet, so the user's real addresses would differ from what they intended.
    const bool passChecked = m_usePass && m_usePass->isChecked();
    if (passChecked && m_passphrase->text().isEmpty()) {
        m_passError->setText(tr("You enabled a passphrase but left it blank. Enter one, or uncheck "
                                "the box to continue without a passphrase."));
        m_passError->show();
        return false;
    }
    const bool usePass = passChecked && !m_passphrase->text().isEmpty();
    if (usePass && m_passphrase->text() != m_passConfirm->text()) {
        m_passError->setText(tr("Passphrases don't match."));
        m_passError->show();
        return false;
    }
    // Seed-backup verification (create flow): make the user prove they wrote the words down by
    // confirming two random ones before continuing (Electrum/Feather both do this).
    if (m_w->mode == WalletWizard::Create && !m_seedVerified) {
        const QStringList sw = m_w->wallet->getSeed().split(QLatin1Char(' '), Qt::SkipEmptyParts);
        if (sw.size() >= 12) {
            int i1 = QRandomGenerator::global()->bounded(sw.size());
            int i2 = QRandomGenerator::global()->bounded(sw.size());
            while (i2 == i1)
                i2 = QRandomGenerator::global()->bounded(sw.size());
            const auto ask = [&](int idx) -> bool {
                bool ok = false;
                const QString ans =
                    QInputDialog::getText(this, tr("Confirm your backup"),
                                          tr("To confirm you wrote it down, enter word #%1 of your "
                                             "seed phrase:").arg(idx + 1),
                                          QLineEdit::Normal, QString(), &ok)
                        .trimmed();
                return ok && ans.compare(sw[idx], Qt::CaseInsensitive) == 0;
            };
            if (!ask(i1) || !ask(i2)) {
                m_passError->setText(
                    tr("That didn't match. Write down your seed phrase (in order) and try again."));
                m_passError->show();
                return false;
            }
            m_seedVerified = true;
        }
    }
    // Re-derive from the SAME seed words with the current passphrase state so the wallet always
    // reflects the checkbox (covers unchecking after a passphrase was set on a previous visit).
    const QString passphrase = usePass ? m_passphrase->text() : QString();
    const QString mnemonic = m_w->wallet->getSeed();
    Wallet *rebuilt = WalletManager::instance()->recoveryWallet(mnemonic, passphrase);
    if (!rebuilt) {
        m_passError->setText(WalletManager::instance()->errorString());
        m_passError->show();
        return false;
    }
    delete m_w->wallet;
    m_w->wallet = rebuilt;
    return true;
}

void SeedPage::initializePage() {
    // Regenerate whenever there is no seed to show, not merely when there is no wallet: a wallet
    // carried over from another path (hardware, watch-only) has no seed, and showing its emptiness
    // here would be both meaningless and alarming.
    const bool haveSeed = m_w->wallet && !m_w->wallet->getSeed().trimmed().isEmpty();
    if (m_w->mode == WalletWizard::Create && !haveSeed)
        regenerate();
    else if (haveSeed)
        showSeedWords(m_w->wallet->getSeed());
}

void SeedPage::regenerate() {
    delete m_w->wallet;
    m_w->wallet = WalletManager::instance()->createWallet(12);
    m_seedVerified = false; // a new seed must be re-confirmed
    if (!m_w->wallet) {
        m_passError->setText(tr("Couldn't generate a seed phrase: %1")
                                 .arg(WalletManager::instance()->errorString()));
        m_passError->show();
    }
    showSeedWords(m_w->wallet ? m_w->wallet->getSeed() : QString());
}

void SeedPage::showSeedWords(const QString &mnemonic) {
    const QStringList words = mnemonic.split(' ', Qt::SkipEmptyParts);
    QLabel *wordSlots[12] = {
        ui->seedWord1, ui->seedWord2, ui->seedWord3,  ui->seedWord4,
        ui->seedWord5, ui->seedWord6, ui->seedWord7,  ui->seedWord8,
        ui->seedWord9, ui->seedWord10, ui->seedWord11, ui->seedWord12,
    };
    for (int i = 0; i < 12; ++i)
        wordSlots[i]->setText(i < words.size() ? words[i] : QString());
}

int SeedPage::nextId() const {
    return WalletWizard::Page_Password;
}

// ================= RestoreSeedPage =================

// Restore from a BIP39 seed with word-by-word autocompletion, mirroring Feather's
// PageWalletRestoreSeed (seed-length radios + an autocompleting seed box).
RestoreSeedPage::RestoreSeedPage(WalletWizard *w) : m_w(w) {
    setTitle(tr("Restore wallet"));

    auto *info = new InfoFrame(this);
    info->setInfo(QIcon(kInfoIcon),
                  tr("Enter your seed. Words auto-complete as you type; press Enter or Tab to "
                     "accept. Your seed never leaves this device."));

    // Seed-length selector (BIP39 is 12 or 24 words).
    m_r12 = new QRadioButton(tr("12 words"), this);
    m_r24 = new QRadioButton(tr("24 words"), this);
    m_r12->setChecked(true);
    auto *radios = new QHBoxLayout();
    radios->addWidget(m_r12);
    radios->addWidget(m_r24);
    radios->addStretch();

    // Load the BIP39 English wordlist and build the completer.
    QFile wl(QStringLiteral(":/assets/bip39-english.txt"));
    if (wl.open(QIODevice::ReadOnly | QIODevice::Text)) {
        while (!wl.atEnd()) {
            const QString word = QString::fromUtf8(wl.readLine()).trimmed();
            if (!word.isEmpty()) m_words << word;
        }
    }
    m_completer = new QCompleter(m_words, this);

    m_seed = new TextEdit(this);
    m_seed->setAcceptRichText(false);
    m_seed->setMaximumHeight(120);
    m_seed->setCompleter(m_completer);

    m_error = new QLabel(this);
    m_error->setStyleSheet(QStringLiteral("color: red;"));
    m_error->hide();

    // Optional BIP39 passphrase used with the seed. Must match the one used when the wallet was
    // created, or a different (empty) wallet is restored.
    m_usePass = new QCheckBox(tr("My seed has a passphrase (advanced)"), this);
    m_passphrase = new QLineEdit(this);
    m_passphrase->setEchoMode(QLineEdit::Password);
    m_passphrase->setPlaceholderText(tr("Passphrase"));
    m_passphrase->setVisible(false);
    connect(m_usePass, &QCheckBox::toggled, this, [this](bool on) {
        m_passphrase->setVisible(on);
        if (!on) m_passphrase->clear();
    });

    auto *layout = new QVBoxLayout(this);
    layout->addWidget(info);
    layout->addLayout(radios);
    layout->addWidget(m_seed);
    layout->addWidget(m_usePass);
    layout->addWidget(m_passphrase);
    layout->addWidget(m_error);
    layout->addStretch();

    connect(m_r12, &QRadioButton::toggled, this, [this]() { updatePlaceholder(); });
    connect(m_r24, &QRadioButton::toggled, this, [this]() { updatePlaceholder(); });
    updatePlaceholder();
}

int RestoreSeedPage::expectedWordCount() const {
    return m_r24->isChecked() ? 24 : 12;
}

void RestoreSeedPage::updatePlaceholder() {
    // Any valid BIP39 length is accepted; the radios are just a hint for the common cases.
    m_seed->setPlaceholderText(tr("Enter your seed (12, 15, 18, 21, or 24 words)…"));
}

bool RestoreSeedPage::validatePage() {
    m_error->hide();
    QString phrase = m_seed->toPlainText().replace('\n', ' ').replace('\r', "").simplified();
    const QStringList seedWords = phrase.split(' ', Qt::SkipEmptyParts);

    // Accept every valid BIP39 length (12/15/18/21/24), not just 12 or 24 - an 18-word seed from
    // another wallet is perfectly valid. The core still verifies the checksum in recoveryWallet().
    const int n = seedWords.size();
    if (n != 12 && n != 15 && n != 18 && n != 21 && n != 24) {
        m_error->setText(tr("A BIP39 seed is 12, 15, 18, 21, or 24 words (got %1).").arg(n));
        m_error->show();
        return false;
    }
    for (const QString &word : seedWords) {
        if (!m_words.contains(word.toLower())) {
            m_error->setText(tr("Seed contains an unknown word: %1").arg(word));
            m_error->show();
            return false;
        }
    }

    const QString passphrase =
        (m_usePass && m_usePass->isChecked()) ? m_passphrase->text() : QString();
    Wallet *wallet = WalletManager::instance()->recoveryWallet(phrase.toLower(), passphrase);
    if (!wallet) {
        m_error->setText(WalletManager::instance()->errorString());
        m_error->show();
        return false;
    }
    delete m_w->wallet;
    m_w->wallet = wallet;
    return true;
}

int RestoreSeedPage::nextId() const {
    return WalletWizard::Page_Password;
}

// ================= PasswordPage =================

PasswordPage::PasswordPage(WalletWizard *w) : m_w(w), ui(new Ui::PageSetPassword) {
    ui->setupUi(this);
    setFinalPage(true);

    // The Electrum-style "encrypted with a password" banner: lock icon + message.
    ui->frame_password->setInfo(QIcon(kLockIcon),
                                tr("Choose a password to encrypt your wallet keys."));
    setButtonText(QWizard::FinishButton, tr("Create/Open wallet"));

    connect(ui->widget_password, &PasswordSetWidget::passwordEntryChanged, this,
            &PasswordPage::completeChanged);
}

PasswordPage::~PasswordPage() { delete ui; }

void PasswordPage::initializePage() {
    setTitle(m_w->mode == WalletWizard::Restore ? tr("Restore wallet") : tr("Create wallet"));
    ui->widget_password->resetFields();
}

bool PasswordPage::isComplete() const {
    return ui->widget_password->passwordsMatch();
}

bool PasswordPage::validatePage() {
    if (!m_w->wallet) {
        QMessageBox::warning(this, tr("Error"), tr("No wallet to save."));
        return false;
    }
    // Feather-style: each wallet gets its own subfolder <walletDir>/<name>/, holding <name>.keys.
    QDir dir(QDir(m_w->walletDir).filePath(m_w->walletName));
    if (!dir.exists()) dir.mkpath(".");
    const QString path = dir.filePath(m_w->walletName + QStringLiteral(".keys"));
    // Encrypting the wallet runs Argon2id (64 MiB / 3 passes) + a synced write - slow enough to
    // freeze the wizard. Run it off-thread behind a busy dialog so the UI stays responsive.
    Wallet *w = m_w->wallet;
    const QString pw = ui->widget_password->password();
    // An empty password means the keys are effectively unprotected on disk - allow it (some users
    // want it) but make them confirm, so it's never a silent accident.
    if (pw.isEmpty()) {
        const auto r = QMessageBox::warning(
            this, tr("Create without a password?"),
            tr("You didn't set a password. Anyone with access to this computer will be able to open "
               "this wallet and spend its funds.\n\nCreate the wallet without a password?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (r != QMessageBox::Yes)
            return false;
    }
    const bool ok = runBusy(this, tr("Creating wallet…"), [w, path, pw]() { return w->store(path, pw); });
    if (!ok) {
        QMessageBox::warning(this, tr("Error"), m_w->wallet->errorString());
        return false;
    }
    m_w->walletPath = path;
    return true;
}

int PasswordPage::nextId() const {
    return -1;
}

// ================= HardwarePage =================

HardwarePage::HardwarePage(WalletWizard *w) : m_w(w) {
    setTitle(tr("Connect hardware wallet"));

    auto *info = new InfoFrame(this);
    info->setInfo(QIcon(kInfoIcon),
                  tr("Your keys stay on the device. Connect and unlock it - on a Ledger, open the "
                     "Ethereum app as well. The wallet only opens while the device is connected."));

    // Only shown when both a Ledger and a Trezor are plugged in, since that is the only time the
    // device type cannot simply be detected.
    m_ledger = new QRadioButton(tr("Ledger"), this);
    m_trezor = new QRadioButton(tr("Trezor"), this);
    m_ledger->setChecked(true);
    m_choiceRow = new QWidget(this);
    auto *devs = new QHBoxLayout(m_choiceRow);
    devs->setContentsMargins(0, 0, 0, 0);
    devs->addWidget(new QLabel(tr("Two devices are connected. Use:"), m_choiceRow));
    devs->addWidget(m_ledger);
    devs->addWidget(m_trezor);
    devs->addStretch();
    m_choiceRow->setVisible(false);

    m_status = new QLabel(this);
    m_status->setStyleSheet(QStringLiteral("color: gray;"));

    auto *refresh = new QPushButton(tr("Detect device"), this);
    connect(refresh, &QPushButton::clicked, this, [this]() { refreshDevices(); });

    // Optional host-entered BIP39 passphrase (Trezor). Ledger enters its passphrase on-device.
    m_usePass = new QCheckBox(tr("Use a BIP39 passphrase"), this);
    m_passphrase = new QLineEdit(this);
    m_passphrase->setEchoMode(QLineEdit::Password);
    m_passphrase->setPlaceholderText(tr("Passphrase"));
    m_passphrase->setVisible(false);
    auto *passNote = new QLabel(
        tr("On a Trezor the passphrase is entered here. On a Ledger it is entered on the device, "
           "so this field is ignored."),
        this);
    passNote->setWordWrap(true);
    passNote->setStyleSheet(QStringLiteral("color: gray;"));
    passNote->setVisible(false);
    connect(m_usePass, &QCheckBox::toggled, this, [this, passNote](bool on) {
        m_passphrase->setVisible(on);
        passNote->setVisible(on);
        if (!on) m_passphrase->clear();
    });

    m_error = new QLabel(this);
    m_error->setStyleSheet(QStringLiteral("color: red;"));
    m_error->setWordWrap(true);
    m_error->hide();

    auto *layout = new QVBoxLayout(this);
    layout->addWidget(info);
    layout->addWidget(m_choiceRow);
    layout->addWidget(refresh);
    layout->addWidget(m_status);
    layout->addWidget(m_usePass);
    layout->addWidget(m_passphrase);
    layout->addWidget(passNote);
    layout->addWidget(m_error);
    layout->addStretch();
}

void HardwarePage::initializePage() {
    setButtonText(QWizard::NextButton, tr("Connect"));
    refreshDevices();
}

QString HardwarePage::detectedKind() const {
    if (m_found == QLatin1String("both"))
        return m_ledger->isChecked() ? QStringLiteral("ledger") : QStringLiteral("trezor");
    if (!m_found.isEmpty())
        return m_found;
    // Nothing was detected. Try Trezor anyway so the attempt produces a real device error rather
    // than a flat refusal - detection is a convenience, not a gate.
    return QStringLiteral("trezor");
}

void HardwarePage::refreshDevices() {
    if (!m_status) return;
    m_status->setText(tr("Looking for a device…"));
    // Enumerate off the UI thread so a slow/blocking USB probe can never freeze the wizard. Both
    // families are probed so the user does not have to tell us what they plugged in.
    QPointer<HardwarePage> self(this);
    QtConcurrent::run([]() {
        auto *wm = WalletManager::instance();
        return QPair<QStringList, QStringList>(wm->listHwDevices(QStringLiteral("ledger")),
                                               wm->listHwDevices(QStringLiteral("trezor")));
    }).then(this, [self](const QPair<QStringList, QStringList> &found) {
        if (!self || !self->m_status) return;
        const QStringList &ledger = found.first;
        const QStringList &trezor = found.second;

        if (!ledger.isEmpty() && !trezor.isEmpty()) {
            self->m_found = QStringLiteral("both");
            self->m_choiceRow->setVisible(true);
            self->m_status->setText(QObject::tr("Found a Ledger and a Trezor."));
        } else if (!ledger.isEmpty()) {
            self->m_found = QStringLiteral("ledger");
            self->m_choiceRow->setVisible(false);
            self->m_status->setText(
                QObject::tr("Found: %1").arg(ledger.join(QStringLiteral(", "))));
        } else if (!trezor.isEmpty()) {
            self->m_found = QStringLiteral("trezor");
            self->m_choiceRow->setVisible(false);
            self->m_status->setText(
                QObject::tr("Found: %1").arg(trezor.join(QStringLiteral(", "))));
        } else {
            self->m_found.clear();
            self->m_choiceRow->setVisible(false);
            self->m_status->setText(QObject::tr(
                "No device detected. Connect and unlock it, then press Detect device."));
        }
    });
}

bool HardwarePage::validatePage() {
    m_error->hide();
    const QString kind = detectedKind();
    const QString passphrase =
        (m_usePass && m_usePass->isChecked() && kind == QLatin1String("trezor"))
            ? m_passphrase->text()
            : QString();

    QApplication::setOverrideCursor(Qt::WaitCursor);
    // Derive the first few accounts from the device (watch-only; keys never leave it).
    Wallet *wallet = WalletManager::instance()->createHardwareWallet(kind, passphrase, 5);
    QApplication::restoreOverrideCursor();
    if (!wallet) {
        m_error->setText(tr("Couldn't connect: %1").arg(WalletManager::instance()->errorString()));
        m_error->show();
        return false;
    }
    delete m_w->wallet;
    m_w->wallet = wallet;
    return true;
}

int HardwarePage::nextId() const {
    return WalletWizard::Page_File; // choose a file name + set a password (encrypts the watch-only data)
}

// ================= WatchPage =================

WatchPage::WatchPage(WalletWizard *w) : m_w(w) {
    setTitle(tr("Watch-only wallet"));
    auto *v = new QVBoxLayout(this);
    auto *info = new QLabel(
        tr("Enter one or more Ethereum addresses to watch (one per line). A watch-only wallet "
           "tracks balances and history but cannot sign or send - it holds no private keys."),
        this);
    info->setWordWrap(true);
    v->addWidget(info);
    m_addresses = new QPlainTextEdit(this);
    m_addresses->setPlaceholderText(QStringLiteral("0x…\n0x…"));
    m_addresses->setMinimumHeight(110);
    v->addWidget(m_addresses);
    m_error = new QLabel(this);
    m_error->setStyleSheet(QStringLiteral("color:#e74c3c;"));
    m_error->setWordWrap(true);
    v->addWidget(m_error);
}

bool WatchPage::validatePage() {
    m_error->clear();
    QStringList addrs;
    for (const QString &line :
         m_addresses->toPlainText().split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        const QString t = line.trimmed();
        if (!t.isEmpty())
            addrs << t;
    }
    if (addrs.isEmpty()) {
        m_error->setText(tr("Enter at least one address."));
        return false;
    }
    Wallet *w = WalletManager::instance()->createWatchOnly(addrs);
    if (!w) {
        m_error->setText(
            tr("Could not create watch wallet: %1").arg(WalletManager::instance()->errorString()));
        return false;
    }
    delete m_w->wallet; // replace any wallet from a previous pass through this page
    m_w->wallet = w;
    return true;
}

int WatchPage::nextId() const { return WalletWizard::Page_File; }

// ================= OpenPage =================

// Mirrors Feather's PageOpenWallet: a list of wallet files in the wallet directory + Browse,
// with the password prompted when opening. (Ethereum wallets are single ".aero" files.)
OpenPage::OpenPage(WalletWizard *w) : m_w(w), ui(new Ui::PageOpenWallet) {
    ui->setupUi(this);
    setTitle(tr("Open wallet file"));
    setButtonText(QWizard::FinishButton, tr("Open wallet"));
    setFinalPage(true);

    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({tr("Name"), tr("Modified"), tr("Path")});
    ui->walletTable->setModel(m_model);
    ui->walletTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->walletTable->hideColumn(2); // Path column (kept for data only)
    ui->walletTable->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    ui->openOnStartup->hide(); // not implemented for Aero yet

    connect(ui->walletTable->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](const QModelIndex &, const QModelIndex &) { updatePath(); });
    connect(ui->walletTable, &QTreeView::doubleClicked, this, [this]() { finishNow(); });
    // Right-click to pin a wallet to the top of the list (favorites).
    ui->walletTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->walletTable, &QWidget::customContextMenuRequested, this, &OpenPage::showListMenu);
    connect(ui->btnBrowse, &QPushButton::clicked, this, [this]() {
        const QString start = QDir(walletsRoot()).exists() ? walletsRoot() : aeroLegacyRoot();
        const QString f = QFileDialog::getOpenFileName(this, tr("Select your wallet file"), start,
                                                       tr("Aero wallet (*.keys *.aero *.plume)"));
        if (f.isEmpty()) return;
        m_walletFile = f;
        finishNow();
    });
}

OpenPage::~OpenPage() { delete ui; }

void OpenPage::initializePage() {
    refreshList();
    const QModelIndex first = ui->walletTable->model()->index(0, 0);
    if (first.isValid())
        ui->walletTable->setCurrentIndex(first);
    updatePath();
}

void OpenPage::refreshList() {
    m_model->removeRows(0, m_model->rowCount());
    QFileInfoList files;
    // Layout: <walletsRoot>/<name>/<name>.keys (each wallet in its own subfolder). walletsRoot() is
    // next to the executable in portable mode, else <Documents>/Aero/wallets.
    const QString root = walletsRoot();
    for (const QFileInfo &sub : QDir(root).entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Time)) {
        files += QDir(sub.absoluteFilePath())
                     .entryInfoList({QStringLiteral("*.keys")}, QDir::Files, QDir::Time);
    }
    // Also list legacy flat wallets (openable for backward compatibility): Documents for a normal
    // install, or next to the executable in portable mode.
    const QString legacy = aeroLegacyRoot();
    files += QDir(legacy).entryInfoList({QStringLiteral("*.aero"), QStringLiteral("*.plume")},
                                        QDir::Files, QDir::Time);
    // Pinned wallets float to the top (see the right-click menu); each group keeps its existing
    // most-recent-first order.
    std::stable_sort(files.begin(), files.end(), [this](const QFileInfo &a, const QFileInfo &b) {
        return isPinned(a.absoluteFilePath()) && !isPinned(b.absoluteFilePath());
    });
    for (const QFileInfo &fi : files) {
        const bool pinned = isPinned(fi.absoluteFilePath());
        auto *name = new QStandardItem(
            (pinned ? QStringLiteral("\U0001F4CC  ") : QString()) + fi.completeBaseName());
        name->setEditable(false);
        auto *modified = new QStandardItem(fi.lastModified().toString(QStringLiteral("yyyy-MM-dd HH:mm")));
        modified->setEditable(false);
        auto *path = new QStandardItem(fi.absoluteFilePath());
        m_model->appendRow({name, modified, path});
    }
}

bool OpenPage::isPinned(const QString &path) const {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    return s.value(QStringLiteral("wallet/pinned")).toStringList().contains(path, Qt::CaseInsensitive);
}

void OpenPage::setPinned(const QString &path, bool pinned) {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    QStringList list = s.value(QStringLiteral("wallet/pinned")).toStringList();
    for (int i = list.size() - 1; i >= 0; --i)
        if (list.at(i).compare(path, Qt::CaseInsensitive) == 0)
            list.removeAt(i);
    if (pinned)
        list.prepend(path); // newest pin first
    s.setValue(QStringLiteral("wallet/pinned"), list);
}

void OpenPage::showListMenu(const QPoint &pos) {
    const QModelIndex idx = ui->walletTable->indexAt(pos);
    if (!idx.isValid())
        return;
    const QString path = m_model->item(idx.row(), 2)->text();
    const bool pinned = isPinned(path);
    QMenu menu(this);
    QAction *toggle = menu.addAction(pinned ? tr("Unpin from top") : tr("Pin to top"));
    if (menu.exec(ui->walletTable->viewport()->mapToGlobal(pos)) != toggle)
        return;
    setPinned(path, !pinned);
    refreshList();
    // Keep the same wallet selected after the list reorders.
    for (int r = 0; r < m_model->rowCount(); ++r)
        if (m_model->item(r, 2)->text() == path) {
            ui->walletTable->setCurrentIndex(m_model->index(r, 0));
            break;
        }
    updatePath();
}

void OpenPage::updatePath() {
    const QModelIndex idx = ui->walletTable->currentIndex();
    if (!idx.isValid()) {
        ui->linePath->clear();
        m_walletFile.clear();
        return;
    }
    m_walletFile = m_model->item(idx.row(), 2)->text();
    ui->linePath->setText(m_walletFile);
}

void OpenPage::finishNow() {
    if (auto *wiz = wizard())
        wiz->button(QWizard::FinishButton)->click();
}

bool OpenPage::validatePage() {
    if (m_walletFile.isEmpty()) {
        QMessageBox::warning(this, tr("Can't open wallet"), tr("No wallet file selected."));
        return false;
    }
    if (!QFileInfo(m_walletFile).isReadable()) {
        QMessageBox::warning(this, tr("Can't open wallet"), tr("No permission to read wallet file."));
        return false;
    }

    auto *wm = WalletManager::instance();

    // Determine the file password (empty first, then prompt). fileIsHardware also validates it:
    // -1 = can't decrypt (wrong password), 0 = software, 1 = hardware.
    QString password;
    int kind = -1;
    // fileIsHardware() decrypts the file (Argon2id) - run it off the UI thread so it never freezes.
    runBusy(this, tr("Opening wallet…"),
            [&]() { kind = wm->fileIsHardware(m_walletFile, password); return true; });
    if (kind == -1) {
        bool ok = false;
        password = QInputDialog::getText(
            this, tr("Open wallet"),
            tr("Password for %1:").arg(QFileInfo(m_walletFile).fileName()),
            QLineEdit::Password, QString(), &ok);
        if (!ok) return false;
        runBusy(this, tr("Opening wallet…"),
                [&]() { kind = wm->fileIsHardware(m_walletFile, password); return true; });
        if (kind == -1) {
            QMessageBox::warning(this, tr("Open failed"), tr("Incorrect password."));
            return false;
        }
    }

    Wallet *wallet = nullptr;
    if (kind == 1) {
        // Hardware wallet: the device must be present. Prompt for the passphrase (Trezor) if wanted.
        bool ok = false;
        const QString passphrase = QInputDialog::getText(
            this, tr("Hardware wallet"),
            tr("Connect and unlock your device. If your seed uses a passphrase (Trezor), enter it "
               "here; otherwise leave blank:"),
            QLineEdit::Password, QString(), &ok);
        if (!ok) return false;
        QApplication::setOverrideCursor(Qt::WaitCursor);
        wallet = wm->openHardwareWallet(m_walletFile, password, passphrase);
        QApplication::restoreOverrideCursor();
        if (!wallet) {
            QMessageBox::warning(this, tr("Can't open"),
                                 tr("Device not connected or passphrase mismatch.\n\n%1")
                                     .arg(wm->errorString()));
            return false;
        }
    } else {
        // Decrypting runs Argon2id (64 MiB / 3 passes) - run it off-thread behind a busy dialog so
        // the wizard doesn't hang while the wallet opens.
        const QString file = m_walletFile, pw = password;
        Wallet *opened = nullptr;
        const bool ok = runBusy(this, tr("Opening wallet…"), [wm, file, pw, &opened]() {
            opened = wm->openWallet(file, pw);
            return opened != nullptr;
        });
        if (!ok) {
            QMessageBox::warning(this, tr("Open failed"), wm->errorString());
            return false;
        }
        wallet = opened;
    }
    delete m_w->wallet;
    m_w->wallet = wallet;
    m_w->walletPath = m_walletFile;
    return true;
}

int OpenPage::nextId() const {
    return -1;
}
