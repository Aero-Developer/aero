// SPDX-License-Identifier: BSD-3-Clause
#ifndef AERO_UPDATER_H
#define AERO_UPDATER_H

#include <QObject>
#include <QString>

class QWidget;
class QTimer;
class QProgressDialog;

// Drives the signed-update flow and everything the user sees of it.
//
// All the deciding happens in the Rust core (`update.rs`): whether a manifest is genuinely signed by
// the Aero release key, whether its version is actually newer, whether the archive matches its hash,
// and which files an archive is allowed to touch. This class is the part that runs those steps off
// the UI thread, shows what they found, and asks before anything is installed.
//
// Two ways in:
//   * `checkQuietly()` - on a timer at startup. Says nothing unless there is an update, so a machine
//     that is offline, behind a broken Tor, or simply up to date never interrupts anyone.
//   * `checkNow()` - the Help menu item. Always answers, including "you are up to date".
class Updater : public QObject {
    Q_OBJECT

public:
    explicit Updater(QWidget *parent);

    // This build's version, from the CMake project version (see AERO_APP_VERSION).
    static QString currentVersion();

    // Fingerprint of the key an update must be signed with, for showing to the user.
    static QString signingKeyFingerprint();

    // Delete whatever the previous update displaced. Call once at startup, before anything else
    // touches the application folder.
    static void sweepPreviousUpdate();

    // Start the installed update, if one was installed and the user asked to restart into it.
    // Does nothing otherwise.
    //
    // Call from main() after the event loop has returned and the main window has been destroyed.
    // The relaunch cannot happen from inside the running window: the bundled Tor is one of its
    // children, and a new copy started too early adopts a SOCKS port that is about to close.
    static void launchInstalledVersion();

    // True when Aero may check on its own. Off means the user only ever checks from the menu.
    static bool automaticChecksEnabled();
    static void setAutomaticChecksEnabled(bool on);

    // The Tor proxy to fetch over, or empty to go direct.
    void setSocksProxy(const QString &socks) { m_socks = socks; }

public slots:
    void checkNow();     // user asked; always reports the outcome
    void checkQuietly(); // startup; speaks only when there is something to say

#ifdef AERO_UPDATE_PREVIEW
    // UpdatePreview.cpp shows this dialog without a release behind it, so it can be looked at while
    // being worked on. Only that build defines this; in the wallet, the only way to reach the offer
    // is through a manifest that verified against the pinned key.
public:
#else
private:
#endif
    void offerUpdate(const QString &statusJson);

private:
    void startCheck(bool announce);
    void onCheckFinished(const QString &statusJson, const QString &error, bool announce);
    void downloadAndInstall(const QString &statusJson);
    void enterInstallPhase(); // queued from the worker once the download is done
    void finishInstall();

    QWidget *m_parent = nullptr;
    QString m_socks;
    bool m_busy = false;
    bool m_installing = false;
    QProgressDialog *m_progress = nullptr;
    QTimer *m_progressTimer = nullptr;
};

#endif // AERO_UPDATER_H
