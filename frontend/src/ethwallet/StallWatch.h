// SPDX-License-Identifier: BSD-3-Clause
// Notices when the UI thread stops responding, and writes down what it was doing at the time.
//
// Whether the window freezes depends on how long each piece of UI-thread work takes on the wallet
// actually open, which varies with its size in ways no review can predict. So Aero measures it: a
// watchdog thread expects a heartbeat from the UI thread every few tens of milliseconds, and when
// one is late by more than the threshold it records how long the gap lasted and which labelled
// operation the UI thread was inside. The log holds operation names and durations only - never an
// address, an amount or anything else about the wallet.
//
// Labels come from StallWatch::Scope, placed at the entry of the work that could plausibly run
// long. It is header-only so the history model, which is also built into the stand-alone checks,
// can carry labels without linking the watchdog.

#ifndef AERO_STALLWATCH_H
#define AERO_STALLWATCH_H

#include <atomic>

class QString;

namespace StallWatch {

// The operation the UI thread is in right now, or nullptr. Only ever a string literal, so the
// watchdog can read it from its own thread with nothing to copy or free.
inline std::atomic<const char *> g_activity{nullptr};
// The QEvent::Type the UI thread was last handed, for stalls that happen outside labelled code.
inline std::atomic<int> g_lastEvent{0};

// Labels a stretch of UI-thread work for the watchdog. Two relaxed atomic operations; cheap enough
// to sit on paths that run thousands of times per refresh.
class Scope {
public:
    explicit Scope(const char *what)
        : m_prev(g_activity.exchange(what, std::memory_order_relaxed)) {}
    ~Scope() { g_activity.store(m_prev, std::memory_order_relaxed); }
    Scope(const Scope &) = delete;
    Scope &operator=(const Scope &) = delete;

private:
    const char *m_prev;
};

// Watch the calling thread (which must be the UI thread, after the application object exists) and
// append a line to `logPath` for every stall longer than `thresholdMs`.
void start(const QString &logPath, int thresholdMs = 150);
void stop();

} // namespace StallWatch

#endif // AERO_STALLWATCH_H
