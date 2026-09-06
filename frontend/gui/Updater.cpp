// SPDX-License-Identifier: BSD-3-Clause
#include "Updater.h"

#include "components.h"

#include <QApplication>
#include <QCheckBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFutureWatcher>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QMessageBox>
#include <QProcess>
#include <QProgressDialog>
#include <QPushButton>
#include <QSettings>
#include <QTimer>
#include <QtConcurrent/QtConcurrent>

#include "ethwallet/aero_core.h"

#ifndef AERO_APP_VERSION
// Only reachable if someone builds this file outside the project's CMake. A version of 0.0.0 makes
// every published release look newer, which would be the wrong way for this to fail, so refuse to
// guess instead.
#error "AERO_APP_VERSION must be defined by the build (see frontend/gui/CMakeLists.txt)"
#endif

namespace {

// Take ownership of a char* from the core and hand back a QString, as the rest of the app does.
QString takeCoreString(char *s) {
    if (!s) return QString();
    const QString out = QString::fromUtf8(s);
    aero_string_free(s);
    return out;
}

QString lastCoreError() {
    const QString e = takeCoreString(aero_last_error());
    return e.isEmpty() ? QObject::tr("unknown error") : e;
}

// The folder holding the application's own files - the one an update replaces.
QString applicationFolder() {
    return QCoreApplication::applicationDirPath();
}

QString humanSize(qint64 bytes) {
    return QLocale().formattedDataSize(bytes, 1, QLocale::DataSizeTraditionalFormat);
}

// Set when an installed update is waiting for the process to exit before the new one is started.
bool s_restartRequested = false;

} // namespace

Updater::Updater(QWidget *parent) : QObject(parent), m_parent(parent) {}

void Updater::launchInstalledVersion() {
    if (!s_restartRequested)
        return;
    s_restartRequested = false;
    // applicationFilePath() is where the new executable now sits: the running one was renamed aside
    // rather than overwritten, so this path is the update.
    QProcess::startDetached(QCoreApplication::applicationFilePath(), QStringList(),
                            applicationFolder());
}

QString Updater::currentVersion() {
    return QStringLiteral(AERO_APP_VERSION);
}

QString Updater::signingKeyFingerprint() {
    return takeCoreString(aero_update_key_fingerprint());
}

void Updater::sweepPreviousUpdate() {
    const QByteArray dir = applicationFolder().toUtf8();
    aero_update_sweep(dir.constData());
}

bool Updater::automaticChecksEnabled() {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    return s.value(QStringLiteral("updates/automatic"), true).toBool();
}

void Updater::setAutomaticChecksEnabled(bool on) {
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    s.setValue(QStringLiteral("updates/automatic"), on);
}

void Updater::checkNow() {
    startCheck(true);
}

// The automatic check exists to get security fixes onto machines whose owner will never open a Help
// menu. It is also a request to a server, so it is rate limited to once a day and can be turned off:
// a wallet that phones home on every launch is telling anyone watching how often it is used.
void Updater::checkQuietly() {
    if (!automaticChecksEnabled())
        return;
    QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
    const qint64 last = s.value(QStringLiteral("updates/lastCheck"), 0).toLongLong();
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    // A clock that has gone backwards (a fixed timezone, a restored machine) would otherwise park
    // the next automatic check somewhere in the future and never check again.
    if (last > now) {
        s.setValue(QStringLiteral("updates/lastCheck"), 0);
    } else if (last > 0 && now - last < 24 * 60 * 60) {
        return;
    }
    // Deliberately not stamped here. This runs a minute after Tor reports ready, which is exactly
    // when a check is most likely to fail for reasons that have nothing to do with the release
    // server; recording the attempt would then stand in for a successful check and hold the next one
    // off for a day. The stamp is written when a check actually answers.
    startCheck(false);
}

void Updater::startCheck(bool announce) {
    if (m_busy)
        return;
    m_busy = true;

    const QString version = currentVersion();
    const QString socks = m_socks;

    auto *watcher = new QFutureWatcher<QStringList>(this);
    connect(watcher, &QFutureWatcher<QStringList>::finished, this, [this, watcher, announce]() {
        const QStringList r = watcher->result();
        watcher->deleteLater();
        m_busy = false;
        onCheckFinished(r.value(0), r.value(1), announce);
    });
    // The check blocks on the core's Tokio runtime and can sit for a while behind Tor, so it runs
    // on a pool thread; the result comes back as plain strings for the UI thread to interpret.
    watcher->setFuture(QtConcurrent::run([version, socks]() -> QStringList {
        const QByteArray v = version.toUtf8();
        const QByteArray p = socks.toUtf8();
        char *json = aero_update_check(v.constData(), socks.isEmpty() ? nullptr : p.constData());
        if (!json)
            return QStringList{QString(), lastCoreError()};
        return QStringList{takeCoreString(json), QString()};
    }));
}

void Updater::onCheckFinished(const QString &statusJson, const QString &error, bool announce) {
    if (!statusJson.isEmpty()) {
        // A check that answered. This, not the attempt, is what the daily interval counts from: an
        // update Aero could not ask about is not an update Aero has checked for.
        QSettings(QStringLiteral("Aero"), QStringLiteral("Aero"))
            .setValue(QStringLiteral("updates/lastCheck"), QDateTime::currentSecsSinceEpoch());

        const QJsonObject o = QJsonDocument::fromJson(statusJson.toUtf8()).object();
        if (o.value(QStringLiteral("available")).toBool()) {
            // A version the user has already declined stays declined until a newer one appears.
            QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
            const QString skipped = s.value(QStringLiteral("updates/skipVersion")).toString();
            const QString latest = o.value(QStringLiteral("latest")).toString();
            if (!announce && skipped == latest)
                return;
            offerUpdate(statusJson);
            return;
        }
        if (announce) {
            QMessageBox::information(
                m_parent, tr("No update available"),
                tr("Aero %1 is the latest signed release.").arg(currentVersion()));
        }
        return;
    }

    // A failed check is not the same as being up to date, and must never be shown as though it
    // were: "no update" and "we could not find out" lead to very different decisions.
    if (announce) {
        QMessageBox::warning(m_parent, tr("Could not check for updates"),
                             tr("Aero could not confirm whether an update is available.\n\n%1\n\n"
                                "You can download releases yourself from\n"
                                "https://github.com/Aero-Developer/aero/releases")
                                 .arg(error));
    }
}

void Updater::offerUpdate(const QString &statusJson) {
    const QJsonObject o = QJsonDocument::fromJson(statusJson.toUtf8()).object();
    const QString latest = o.value(QStringLiteral("latest")).toString();
    const QString notes = o.value(QStringLiteral("notes")).toString().trimmed();
    const qint64 size = static_cast<qint64>(o.value(QStringLiteral("size")).toDouble());

    QMessageBox box(m_parent);
    box.setWindowTitle(tr("New update for Aero"));
    box.setIcon(QMessageBox::Question);
    box.setTextFormat(Qt::RichText);
    box.setText(tr("<b>There is a new update for Aero.</b><br><br>"
                   "Aero %1 is available. You are running %2.<br><br>"
                   "Do you want to update?")
                    .arg(latest.toHtmlEscaped(), currentVersion().toHtmlEscaped()));

    // Rich text throughout, so the breaks have to be markup: with Qt::RichText set, newlines in the
    // informative text collapse and the whole thing runs together as one paragraph.
    //
    // Everything here is deliberately on screen rather than behind a "Show Details" button. The
    // three things a person needs to answer this are what they are getting, who signed it, and what
    // it will not touch, and a detail button both hides those and plants itself in the middle of the
    // row of answers.
    QString informative = tr("Download size: %1").arg(humanSize(size));
    if (!notes.isEmpty())
        informative += QStringLiteral("<br><br>") + notes.toHtmlEscaped();
    informative += QStringLiteral("<br><br>") +
                   tr("Signed by the Aero release key<br><tt>%1</tt><br>"
                      "Your wallets, settings and Trezor pairing are not touched.")
                       .arg(signingKeyFingerprint().toHtmlEscaped());
    // "No" and "Ask me later" are not the same answer, and a dialog that does not say so is a
    // dialog people answer by guessing. Spell out which one stops the asking.
    informative += QStringLiteral("<br><br>") +
                   tr("Choose <b>No</b> and Aero will not offer this version again. Choose "
                      "<b>Ask me later</b> and it will bring this up at the next check.");
    box.setInformativeText(informative);

    QPushButton *yes = box.addButton(tr("Yes, update now"), QMessageBox::AcceptRole);
    // RejectRole is what closing the window and pressing Escape resolve to, so it holds the answer
    // that changes nothing: being asked again is recoverable, never being asked again is not.
    QPushButton *later = box.addButton(tr("Ask me later"), QMessageBox::RejectRole);
    QPushButton *no = box.addButton(tr("No"), QMessageBox::DestructiveRole);
    box.setDefaultButton(yes);
    box.setEscapeButton(later);
    box.exec();

    if (box.clickedButton() == no) {
        QSettings s(QStringLiteral("Aero"), QStringLiteral("Aero"));
        s.setValue(QStringLiteral("updates/skipVersion"), latest);
        return;
    }
    if (box.clickedButton() != yes)
        return;

    downloadAndInstall(statusJson);
}

void Updater::downloadAndInstall(const QString &statusJson) {
    if (m_busy)
        return;
    m_busy = true;
    m_installing = false;

    const QString socks = m_socks;
    const QString appDir = applicationFolder();

    m_progress = new QProgressDialog(tr("Downloading update..."), tr("Cancel"), 0, 100, m_parent);
    m_progress->setWindowTitle(tr("Updating Aero"));
    m_progress->setWindowModality(Qt::WindowModal);
    m_progress->setMinimumDuration(0);
    m_progress->setAutoClose(false);
    m_progress->setAutoReset(false);
    m_progress->setValue(0);
    // QProgressDialog's Cancel only hides the dialog by itself. Without this the download would run
    // on unseen and the update would install after the user asked it not to.
    connect(m_progress, &QProgressDialog::canceled, this, []() { aero_update_cancel(); });

    // Byte counters live in the core and are polled, the same way the funded-address scan reports
    // itself. A download over Tor is slow enough that a window with no sign of life reads as a hang.
    m_progressTimer = new QTimer(this);
    m_progressTimer->setInterval(250);
    connect(m_progressTimer, &QTimer::timeout, this, [this]() {
        const quint64 done = aero_update_downloaded();
        const quint64 total = aero_update_download_total();
        if (!m_progress || m_installing)
            return;
        if (total > 0) {
            m_progress->setValue(static_cast<int>(done * 100 / total));
            m_progress->setLabelText(tr("Downloading update... %1 of %2")
                                         .arg(humanSize(static_cast<qint64>(done)),
                                              humanSize(static_cast<qint64>(total))));
        }
    });
    m_progressTimer->start();

    auto *watcher = new QFutureWatcher<QStringList>(this);
    connect(watcher, &QFutureWatcher<QStringList>::finished, this, [this, watcher]() {
        const QStringList r = watcher->result();
        watcher->deleteLater();
        m_busy = false;
        if (m_progressTimer) {
            m_progressTimer->stop();
            m_progressTimer->deleteLater();
            m_progressTimer = nullptr;
        }
        if (m_progress) {
            m_progress->close();
            m_progress->deleteLater();
            m_progress = nullptr;
        }

        const QString error = r.value(1);
        if (!error.isEmpty()) {
            // Someone pressing Cancel is not a fault, and reporting it as one teaches people to
            // ignore the dialog that appears when something has genuinely gone wrong.
            const QByteArray e = error.toUtf8();
            if (aero_update_was_cancelled(e.constData()))
                return;
            QMessageBox::critical(m_parent, tr("Update failed"),
                                  tr("Aero did not install the update.\n\n%1\n\n"
                                     "Nothing was changed. Your wallets and settings are untouched.")
                                      .arg(error));
            return;
        }
        finishInstall();
    });

    watcher->setFuture(QtConcurrent::run([this, statusJson, socks, appDir]() -> QStringList {
        const QByteArray js = statusJson.toUtf8();
        const QByteArray dir = appDir.toUtf8();
        const QByteArray p = socks.toUtf8();

        char *archive = aero_update_download(js.constData(), dir.constData(),
                                             socks.isEmpty() ? nullptr : p.constData());
        if (!archive)
            return QStringList{QString(), lastCoreError()};
        const QString archivePath = takeCoreString(archive);

        // The download is the only interruptible part. From here files start moving, and stopping
        // half way through leaves a folder that is neither version - so the dialog is told to drop
        // its Cancel button rather than offer one that quietly does nothing.
        QMetaObject::invokeMethod(this, &Updater::enterInstallPhase, Qt::QueuedConnection);

        // Unpack to one side first. A bad archive is then found while it is still off to one side,
        // rather than halfway over the application.
        const QByteArray ap = archivePath.toUtf8();
        if (aero_update_stage(ap.constData(), dir.constData()) != 0)
            return QStringList{QString(), lastCoreError()};

        if (aero_update_apply(dir.constData()) < 0)
            return QStringList{QString(), lastCoreError()};

        return QStringList{archivePath, QString()};
    }));
}

void Updater::enterInstallPhase() {
    m_installing = true;
    if (!m_progress)
        return;
    // Unbounded range: the swap is a few dozen renames with no useful progress to report, and a bar
    // frozen at 100% for a second reads worse than one that is plainly just working.
    m_progress->setCancelButton(nullptr);
    m_progress->setRange(0, 0);
    m_progress->setLabelText(tr("Installing update..."));
}

void Updater::finishInstall() {
    QMessageBox box(m_parent);
    box.setWindowTitle(tr("Update installed"));
    box.setIcon(QMessageBox::Information);
    box.setText(tr("<b>Aero has been updated.</b><br>"
                   "Restart to start using the new version."));
    box.setInformativeText(tr("Your wallets, settings and Trezor pairing were left untouched."));
    QPushButton *restart = box.addButton(tr("Restart now"), QMessageBox::AcceptRole);
    box.addButton(tr("Later"), QMessageBox::RejectRole);
    box.setDefaultButton(restart);
    box.exec();

    if (box.clickedButton() != restart)
        return;

    // Go through the ordinary close, and take no for an answer.
    //
    // AeroMainWindow::closeEvent can refuse: if the final wallet save failed it asks whether to close
    // anyway, and the user may well say no. Quitting regardless would throw away the keys or
    // addresses they just chose to protect - and for a restart that could equally happen later. The
    // update is already installed either way; only the restart is in question.
    if (m_parent && !m_parent->close()) {
        QMessageBox::information(
            m_parent, tr("Update installed"),
            tr("Aero was not closed, so the update is not running yet.\n\n"
               "It will be in use the next time you start Aero."));
        return;
    }

    // Relaunching is left to main(), after the event loop has returned and the main window - and
    // with it the bundled Tor - has actually been torn down. Starting the new copy from here would
    // start it while this process is still alive: it would find the old Tor still holding the SOCKS
    // port, adopt it as an already-running one, and then lose it seconds later when this process
    // finally exits.
    s_restartRequested = true;
    QTimer::singleShot(0, qApp, &QCoreApplication::quit);
}
