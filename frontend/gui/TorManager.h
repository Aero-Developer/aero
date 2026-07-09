// SPDX-License-Identifier: BSD-3-Clause
// Starts and supervises a bundled Tor process so the wallet is always routed through Tor with no
// clearnet fallback. We use a dedicated SOCKS port (not the common 9050) so the app never depends
// on — or accidentally routes through — some other SOCKS service; it runs its own Tor. If our own
// instance from a previous run is still listening on that port we reuse it, otherwise we launch the
// tor.exe shipped next to the app and wait for it to bootstrap to 100%.

#ifndef AERO_TORMANAGER_H
#define AERO_TORMANAGER_H

#include <QObject>
#include <QString>

class QProcess;
class QTimer;

class TorManager : public QObject
{
    Q_OBJECT

public:
    explicit TorManager(QObject *parent = nullptr);
    ~TorManager() override;

    // Detect an already-running Tor on the SOCKS port; otherwise launch the bundled tor.exe.
    void start();
    // Tear down and relaunch our bundled Tor to get a FRESH circuit (new guard/exit). Emits the
    // usual statusChanged/ready as it re-bootstraps. Used for "New Tor circuit" and auto-recovery.
    void restart();

    quint16 socksPort() const { return m_socksPort; }
    QString socksProxy() const { return QStringLiteral("socks5h://127.0.0.1:%1").arg(m_socksPort); }
    bool isReady() const { return m_ready; }
    bool isRunning() const;                 // our bundled Tor process is alive
    int bootstrapPercent() const { return m_pct; } // last "Bootstrapped X%" seen (0..100)

signals:
    void statusChanged(const QString &message); // human-readable progress
    void ready();                                // SOCKS proxy is usable
    void failed(const QString &error);           // Tor could not be started (no fallback)
    void ended();                                // Tor exited AFTER being ready (crash/kill) — recover

private:
    bool socksPortOpen() const;
    void launchBundled();
    void handleLine(const QString &line);

    QProcess *m_proc = nullptr;
    QTimer *m_timeout = nullptr;
    quint16 m_socksPort = 9055; // dedicated to Aero's own bundled Tor (not the common 9050)
    bool m_ready = false;
    bool m_restarting = false;  // a deliberate restart() is in progress (suppress ended()/failed())
    int m_pct = 0;              // last bootstrap percent
    QString m_lastError;        // last Tor [warn]/[err] line, for a useful failure message
};

#endif // AERO_TORMANAGER_H
