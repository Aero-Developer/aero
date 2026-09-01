// SPDX-License-Identifier: BSD-3-Clause
#include "TorManager.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QTcpSocket>
#include <QTimer>

TorManager::TorManager(QObject *parent) : QObject(parent) {}

TorManager::~TorManager() {
    if (m_proc) {
        m_proc->disconnect(this);
        m_proc->terminate();
        if (!m_proc->waitForFinished(3000))
            m_proc->kill();
    }
}

bool TorManager::socksPortOpen() const {
    // Don't just check that SOMETHING is listening - verify it speaks SOCKS5 before we route all
    // wallet traffic through it. A bare TCP connect would happily "adopt" a malicious/unrelated local
    // service squatting on our dedicated port; a SOCKS5 greeting/response rejects any non-SOCKS
    // squatter. (Full Tor-identity proof would need the control port; this closes the common case.)
    QTcpSocket probe;
    probe.connectToHost(QStringLiteral("127.0.0.1"), m_socksPort);
    if (!probe.waitForConnected(400))
        return false;
    // SOCKS5 client greeting: VER=5, 1 method, method=0x00 (no auth).
    const char greeting[3] = {0x05, 0x01, 0x00};
    probe.write(greeting, 3);
    if (!probe.waitForBytesWritten(300))
        return false;
    if (!probe.waitForReadyRead(600))
        return false;
    const QByteArray resp = probe.read(2);
    // A SOCKS5 server replies VER=5 and a selected method (0x00 no-auth, or 0xFF none acceptable).
    return resp.size() == 2 && static_cast<unsigned char>(resp[0]) == 0x05;
}

void TorManager::start() {
    // Reuse our own bundled Tor if it's still listening on the dedicated port from a previous run;
    // otherwise launch a fresh one. We never look at the common 9050 to avoid routing through some
    // unrelated SOCKS service.
    if (socksPortOpen()) {
        m_ready = true;
        m_pct = 100;
        emit statusChanged(tr("Connected to Tor"));
        emit ready();
        return;
    }
    launchBundled();
}

bool TorManager::isRunning() const {
    return m_proc && m_proc->state() != QProcess::NotRunning;
}

void TorManager::restart() {
    m_ready = false;
    m_pct = 0;
    if (m_proc) {
        // Kill the process we own and relaunch => a brand-new circuit. Disconnect first so the
        // deliberate termination doesn't fire failed()/ended().
        m_restarting = true;
        m_proc->disconnect(this);
        m_proc->terminate();
        if (!m_proc->waitForFinished(3000))
            m_proc->kill();
        m_proc->deleteLater();
        m_proc = nullptr;
        m_restarting = false;
        launchBundled();
    } else {
        // We were reusing an external Tor we don't own (nothing to kill); best-effort reconnect.
        start();
    }
}

void TorManager::launchBundled() {
    const QString base = QCoreApplication::applicationDirPath();
    // Bundled Tor binary: tor/tor.exe on Windows, tor/tor on macOS/Linux.
#ifdef Q_OS_WIN
    const QString torExe = QDir(base).filePath(QStringLiteral("tor/tor.exe"));
#else
    const QString torExe = QDir(base).filePath(QStringLiteral("tor/tor"));
#endif
    if (!QFileInfo::exists(torExe)) {
        emit failed(tr("Bundled Tor not found at %1").arg(QDir::toNativeSeparators(torExe)));
        return;
    }

    const QString torDir = QDir(base).filePath(QStringLiteral("tor"));
    const QString dataDir = QDir(torDir).filePath(QStringLiteral("data"));
    QDir().mkpath(dataDir);

    // We only get here when no Aero Tor is already listening on our port, so any leftover lock file
    // belongs to a previous Tor that crashed or was killed. Tor refuses to start (exits code 1 -
    // "Another process has locked the data directory") if a stale lock remains, so clear it.
    QFile::remove(QDir(dataDir).filePath(QStringLiteral("lock")));

    QStringList args;
    // IsolateSOCKSAuth (Tor default, made explicit): each distinct SOCKS username gets its OWN circuit
    // and exit. Aero uses this to spread bulk per-address fetches (block-explorer history) over many
    // circuits so they don't all share - and rate-limit against - one exit IP.
    args << QStringLiteral("--SocksPort")
         << QStringLiteral("%1 IsolateSOCKSAuth").arg(m_socksPort)
         << QStringLiteral("--DataDirectory") << dataDir
         << QStringLiteral("--GeoIPFile") << QDir(torDir).filePath(QStringLiteral("geoip"))
         << QStringLiteral("--GeoIPv6File") << QDir(torDir).filePath(QStringLiteral("geoip6"))
         << QStringLiteral("--ClientOnly") << QStringLiteral("1")
         << QStringLiteral("--AvoidDiskWrites") << QStringLiteral("1")
         << QStringLiteral("--Log") << QStringLiteral("notice stdout");

    m_proc = new QProcess(this);
    m_proc->setWorkingDirectory(torDir);
    m_proc->setProcessChannelMode(QProcess::MergedChannels);

    connect(m_proc, &QProcess::readyReadStandardOutput, this, [this]() {
        const QString out = QString::fromUtf8(m_proc->readAllStandardOutput());
        const QStringList lines = out.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        for (const QString &line : lines) {
            const QString t = line.trimmed();
            // Keep the last couple of notice/warn lines so a startup failure can be explained.
            if (t.contains(QLatin1String("[warn]")) || t.contains(QLatin1String("[err]")))
                m_lastError = t.section(QLatin1Char(']'), -1).trimmed();
            handleLine(t);
        }
    });
    connect(m_proc, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        if (!m_ready)
            emit failed(tr("Failed to launch Tor: %1").arg(m_proc->errorString()));
    });
    connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this](int code, QProcess::ExitStatus) {
                if (m_restarting)
                    return; // deliberate restart(); a fresh process is being launched
                if (!m_ready)
                    emit failed(m_lastError.isEmpty()
                                    ? tr("Tor exited unexpectedly (code %1)").arg(code)
                                    : tr("Tor failed: %1").arg(m_lastError));
                else {
                    m_ready = false; // Tor died after being up - let the app recover (auto-reconnect)
                    emit ended();
                }
            });

    // Give Tor up to 90s to bootstrap before giving up (no clearnet fallback).
    m_timeout = new QTimer(this);
    m_timeout->setSingleShot(true);
    m_timeout->setInterval(90000);
    connect(m_timeout, &QTimer::timeout, this, [this]() {
        if (!m_ready)
            emit failed(tr("Tor did not finish bootstrapping in time"));
    });
    m_timeout->start();

    emit statusChanged(tr("Starting Tor…"));
    m_proc->start(torExe, args);
}

void TorManager::handleLine(const QString &line) {
    static const QRegularExpression re(QStringLiteral("Bootstrapped (\\d+)%"));
    const QRegularExpressionMatch m = re.match(line);
    if (!m.hasMatch())
        return;
    const int pct = m.captured(1).toInt();
    m_pct = pct;
    emit statusChanged(tr("Starting Tor… %1%").arg(pct));
    if (pct >= 100 && !m_ready) {
        m_ready = true;
        if (m_timeout)
            m_timeout->stop();
        emit statusChanged(tr("Connected to Tor"));
        emit ready();
    }
}
