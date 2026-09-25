// SPDX-License-Identifier: BSD-3-Clause
#include "StallWatch.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QFile>
#include <QString>
#include <QTimer>

#include <chrono>
#include <thread>

namespace {

using Clock = std::chrono::steady_clock;

constexpr int kBeatMs = 40;          // how often the UI thread checks in
constexpr int kSampleMs = 20;        // how often the watchdog looks
constexpr qint64 kMaxLogBytes = 512 * 1024;

std::atomic<qint64> g_beatMs{0}; // steady-clock ms of the UI thread's most recent heartbeat
std::atomic<bool> g_running{false};
std::thread g_thread;

qint64 nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch())
        .count();
}

void appendLine(const QString &path, const QByteArray &line) {
    QFile f(path);
    // Kept small: once past the cap the log starts over, so it can never grow without bound.
    const bool fresh = f.size() > kMaxLogBytes;
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text |
                (fresh ? QIODevice::Truncate : QIODevice::Append)))
        return;
    f.write(line);
}

void watch(QString path, int thresholdMs) {
    bool stalled = false;
    qint64 lastBeatBefore = 0;
    int eventBefore = 0;
    const char *seen[4] = {};
    int seenCount = 0;
    while (g_running.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(kSampleMs));
        const qint64 beat = g_beatMs.load(std::memory_order_relaxed);
        const qint64 late = nowMs() - beat - kBeatMs;
        if (late > thresholdMs) {
            if (!stalled) {
                stalled = true;
                lastBeatBefore = beat;
                eventBefore = StallWatch::g_lastEvent.load(std::memory_order_relaxed);
                seenCount = 0;
            }
            // A long stall can pass through several labelled operations; keep the first few.
            const char *now = StallWatch::g_activity.load(std::memory_order_relaxed);
            bool known = false;
            for (int i = 0; i < seenCount; ++i)
                known = known || seen[i] == now;
            if (now && !known && seenCount < 4)
                seen[seenCount++] = now;
            continue;
        }
        if (!stalled || beat == lastBeatBefore)
            continue;
        stalled = false;
        const qint64 ms = beat - lastBeatBefore - kBeatMs;
        QByteArray where;
        for (int i = 0; i < seenCount; ++i) {
            if (i)
                where += " > ";
            where += seen[i];
        }
        if (where.isEmpty())
            where = "unlabelled, last event type " + QByteArray::number(eventBefore);
        const QByteArray line =
            QDateTime::currentDateTime().toString(Qt::ISODate).toUtf8() + "  stalled " +
            QByteArray::number(ms) + " ms  in: " + where + '\n';
        appendLine(path, line);
    }
}

} // namespace

void StallWatch::start(const QString &logPath, int thresholdMs) {
    if (g_running.exchange(true))
        return;
    g_beatMs.store(nowMs(), std::memory_order_relaxed);
    auto *beat = new QTimer(QCoreApplication::instance());
    beat->setTimerType(Qt::PreciseTimer);
    beat->setInterval(kBeatMs);
    QObject::connect(beat, &QTimer::timeout,
                     [] { g_beatMs.store(nowMs(), std::memory_order_relaxed); });
    beat->start();
    g_thread = std::thread(watch, logPath, thresholdMs);
}

void StallWatch::stop() {
    if (!g_running.exchange(false))
        return;
    if (g_thread.joinable())
        g_thread.join();
}
