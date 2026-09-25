// SPDX-License-Identifier: BSD-3-Clause
// Times the work Aero does on its UI thread, at the size of a large real wallet.
//
// "Is it fast now" is not a question code review can answer: what freezes a window is how long one
// pass takes at the sizes people actually have, and that only shows up by running it. This builds a
// synthetic wallet the size of the biggest ones seen - hundreds of accounts, tens of thousands of
// history rows, spam and swaps mixed in - and times each operation the app performs on its UI
// thread, so a regression reads as a number rather than as a report that the app feels slow.
//
// Anything over one frame (16 ms) is a stutter; anything over 100 ms is a visible freeze. Build with
// -DAERO_BUILD_HISTORY_CHECK=ON and run perf_check. It needs no wallet, network or keys.

#include <QCoreApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QThread>

#include <algorithm>
#include <cstdio>

#include "HistoryModel.h"
#include "StallWatch.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

namespace {

int worstMs = 0;

// Work on the UI thread: what the user feels. Anything over a frame is a stutter.
void report(const char *what, qint64 ms) {
    const char *verdict = ms > 100 ? "FREEZE " : ms > 16 ? "stutter" : "ok     ";
    std::printf("%s %6lld ms  %s\n", verdict, static_cast<long long>(ms), what);
    worstMs = qMax(worstMs, static_cast<int>(ms));
}

// Work the app runs on a worker thread. Its cost is latency, not a frozen window, so it is shown
// for reference and kept out of the verdict.
void reportWorker(const char *what, qint64 ms) {
    std::printf("worker  %6lld ms  %s\n", static_cast<long long>(ms), what);
}

template <typename F>
qint64 timed(F &&f) {
    QElapsedTimer t;
    t.start();
    f();
    return t.elapsed();
}

// Run whatever the model's coalescing timer has queued, and time only the work, not the wait.
qint64 timedCoalesced() {
    QThread::msleep(480); // past the model's longest coalesce window (a burst of batches)
    return timed([] { QCoreApplication::processEvents(QEventLoop::AllEvents); });
}

QString hex(int chars) {
    static const char digits[] = "0123456789abcdef";
    QString s(chars, QLatin1Char('0'));
    for (int i = 0; i < chars; ++i)
        s[i] = QLatin1Char(digits[QRandomGenerator::global()->bounded(16)]);
    return s;
}

// A wallet's worth of rows, shaped like what the explorers return: native and token transfers both
// ways, a share of unsolicited spam tokens, and some swaps.
QVector<HistoryItem> makeHistory(int rows, int accounts, const QStringList &knownTokens) {
    QVector<HistoryItem> out;
    out.reserve(rows);
    const quint64 now = static_cast<quint64>(QDateTime::currentSecsSinceEpoch());
    auto *rng = QRandomGenerator::global();
    for (int i = 0; i < rows; ++i) {
        HistoryItem h;
        const int kind = rng->bounded(100);
        h.account = static_cast<quint32>(rng->bounded(accounts));
        h.txHash = QStringLiteral("0x") + hex(64);
        h.counterparty = QStringLiteral("0x") + hex(40);
        h.block = 18000000 + static_cast<quint64>(i);
        h.timestamp = now - static_cast<quint64>(rows - i) * 600;
        h.fee = QString::number(21000ull * 30000000000ull);
        h.direction = rng->bounded(2) ? QStringLiteral("in") : QStringLiteral("out");
        if (kind < 45) { // native
            h.symbol = QStringLiteral("ETH");
            h.formatted = QString::number(rng->bounded(1000) / 100.0, 'f', 4);
            h.amount = QStringLiteral("1000000000000000000");
        } else if (kind < 80) { // a known token
            h.token = knownTokens.at(rng->bounded(knownTokens.size()));
            h.symbol = QStringLiteral("USDC");
            h.formatted = QString::number(rng->bounded(100000) / 10.0, 'f', 2);
            h.amount = QStringLiteral("123450000");
        } else if (kind < 95) { // unsolicited spam token
            h.token = QStringLiteral("0x") + hex(40);
            h.symbol = QStringLiteral("CLAIM-REWARD");
            h.formatted = QStringLiteral("1000");
            h.amount = QStringLiteral("1000");
            h.direction = QStringLiteral("in");
        } else { // swap
            h.kind = QStringLiteral("swap");
            h.direction = QStringLiteral("swap");
            h.symbol = QStringLiteral("USDC");
            h.buySymbol = QStringLiteral("WETH");
            h.formatted = QStringLiteral("2500");
            h.buyFormatted = QStringLiteral("1");
            h.status = QStringLiteral("done");
        }
        out.append(h);
    }
    return out;
}

// The same terse encoding the wallet uses for its per-chain history cache.
QJsonObject toJson(const HistoryItem &h) {
    QJsonObject o;
    o[QStringLiteral("d")] = h.direction;
    o[QStringLiteral("c")] = h.counterparty;
    o[QStringLiteral("a")] = h.amount;
    o[QStringLiteral("f")] = h.formatted;
    o[QStringLiteral("h")] = h.txHash;
    o[QStringLiteral("b")] = static_cast<double>(h.block);
    o[QStringLiteral("t")] = h.token;
    o[QStringLiteral("s")] = h.symbol;
    o[QStringLiteral("ts")] = static_cast<double>(h.timestamp);
    if (!h.fee.isEmpty()) o[QStringLiteral("fee")] = h.fee;
    if (!h.kind.isEmpty()) o[QStringLiteral("k")] = h.kind;
    if (!h.buySymbol.isEmpty()) o[QStringLiteral("bs")] = h.buySymbol;
    if (!h.buyFormatted.isEmpty()) o[QStringLiteral("bf")] = h.buyFormatted;
    if (!h.status.isEmpty()) o[QStringLiteral("st")] = h.status;
    o[QStringLiteral("ac")] = static_cast<double>(h.account);
    return o;
}

HistoryItem fromJson(const QJsonObject &o) {
    HistoryItem h;
    h.direction = o.value(QStringLiteral("d")).toString();
    h.counterparty = o.value(QStringLiteral("c")).toString();
    h.amount = o.value(QStringLiteral("a")).toString();
    h.formatted = o.value(QStringLiteral("f")).toString();
    h.txHash = o.value(QStringLiteral("h")).toString();
    h.block = static_cast<quint64>(o.value(QStringLiteral("b")).toDouble());
    h.token = o.value(QStringLiteral("t")).toString();
    h.symbol = o.value(QStringLiteral("s")).toString();
    h.timestamp = static_cast<quint64>(o.value(QStringLiteral("ts")).toDouble());
    h.fee = o.value(QStringLiteral("fee")).toString();
    h.kind = o.value(QStringLiteral("k")).toString();
    h.buySymbol = o.value(QStringLiteral("bs")).toString();
    h.buyFormatted = o.value(QStringLiteral("bf")).toString();
    h.status = o.value(QStringLiteral("st")).toString();
    h.account = static_cast<quint32>(o.value(QStringLiteral("ac")).toDouble());
    return h;
}

} // namespace

int main(int argc, char **argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen"); // data() builds icons, which need a GUI application
    QGuiApplication app(argc, argv);

    const int kRows = 30000;   // the history cache's per-chain cap
    const int kAccounts = 300; // a large HD wallet
    const QStringList known = {QStringLiteral("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                               QStringLiteral("0xdac17f958d2ee523a2206206994597c13d831ec7"),
                               QStringLiteral("0x6b175474e89094c44da98b954eedeac495271d0f")};
    const QVector<HistoryItem> rows = makeHistory(kRows, kAccounts, known);
    std::printf("synthetic wallet: %d history rows across %d accounts\n\n", kRows, kAccounts);

    // --- History model: everything the History tab does on the UI thread ------------------------
    HistoryModel m;
    QSet<QString> knownSet(known.begin(), known.end());
    m.setKnownTokens(knownSet);
    QCoreApplication::processEvents();
    QSet<QString> own;
    for (int i = 0; i < kAccounts; ++i)
        own.insert(QStringLiteral("0x") + hex(40));
    m.setOwnAddresses(own);
    QHash<quint32, QString> names;
    for (int i = 0; i < kAccounts; ++i)
        names.insert(static_cast<quint32>(i), QStringLiteral("Account #%1").arg(i));
    m.setAccountNames(names);

    // A chain switch: the rows are prepared on a worker, then swapped into the model.
    HistoryModel::Prepared prepared;
    reportWorker("chain switch: prepare the chain's history",
                 timed([&] { prepared = HistoryModel::prepare(rows, m.ownAddresses(), m.knownTokens()); }));
    report("chain switch: show the prepared history",
           timed([&] { m.adoptPrepared(std::move(prepared)); }));
    report("filter pass (hide-spam toggle)", timed([&] {
               m.setHideSpam(false);
               m.setHideSpam(true);
           }) / 2);
    m.setSearchText(QStringLiteral("0xab"));
    report("search keystroke", timedCoalesced());
    m.setSearchText(QStringLiteral("0xabc"));
    report("next search keystroke", timedCoalesced());
    m.setSearchText(QString());
    timedCoalesced();
    report("sort by value", timed([&] { m.sort(HistoryModel::Column_Value, Qt::DescendingOrder); }));
    report("sort by date", timed([&] { m.sort(HistoryModel::Column_Date, Qt::DescendingOrder); }));
    names.insert(0, QStringLiteral("Savings"));
    report("rename an account", timed([&] { m.setAccountNames(names); }));
    own.insert(QStringLiteral("0x") + hex(40));
    report("own-address set changes (new account)", timed([&] { m.setOwnAddresses(own); }));
    knownSet.insert(QStringLiteral("0x") + hex(40));
    m.setKnownTokens(knownSet);
    report("trusted-token set changes", timedCoalesced());
    QHash<QString, double> prices{{QStringLiteral("ETH"), 3500.0}, {QStringLiteral("USDC"), 1.0}};
    m.setDustThreshold(0.005);
    m.setPrices(prices);
    report("price tick (dust filter on)", timedCoalesced());
    report("scan for untrusted tokens", timed([&] { (void)m.untrackedTokenAddresses(); }));
    report("pending-swap check (cow poll tick)", timed([&] { (void)m.hasPendingSwaps(); }));

    // One account's history arriving on top of a full model, as each funded account loads. Several
    // in a row: the first append after a chain switch also pays for un-sharing rows the model got
    // from the restore, which later ones do not.
    for (int b = 0; b < 3; ++b) {
        const QVector<HistoryItem> batch = makeHistory(b == 2 ? 100 : 500, kAccounts, known);
        char label[96];
        std::snprintf(label, sizeof label, "an account's batch arrives (%lld rows, #%d)",
                      static_cast<long long>(batch.size()), b + 1);
        report(label, timed([&] { m.appendBatch(batch); }));
        report("...and the rebuild it schedules", timedCoalesced());
    }

    // Where the post-batch rebuild's time goes: a forced full pass over the same rows, and the
    // per-row derivation for one batch on its own.
    report("  (diagnostic) full filter+sort pass after the batches", timed([&] {
               m.setHideSpam(false);
               m.setHideSpam(true);
           }) / 2);
    {
        const QVector<HistoryItem> batch = makeHistory(500, kAccounts, known);
        reportWorker("  (diagnostic) derive facts + index for a 500-row batch",
                     timed([&] { (void)HistoryModel::prepare(batch, own, knownSet); }));
        const QVector<HistoryItem> batch2 = makeHistory(500, kAccounts, known);
        m.appendBatch(batch2);
        report("  (diagnostic) the same rebuild, run synchronously right after an append",
               timed([&] {
                   m.setHideSpam(false); // forces the pass now, with the new rows' tails pending
               }));
        m.setHideSpam(true);
        report("  (diagnostic) ...and whatever the timer path adds on top", timedCoalesced());
    }

    // A full repaint of the visible page: every column, every role the view asks for.
    report("paint one page (500 rows x 7 columns)", timed([&] {
               for (int r = 0; r < m.rowCount(); ++r)
                   for (int c = 0; c < HistoryModel::Column_COUNT; ++c)
                       for (int role : {int(Qt::DisplayRole), int(Qt::DecorationRole),
                                        int(Qt::ForegroundRole), int(Qt::ToolTipRole)})
                           (void)m.data(m.index(r, c), role);
           }));

    // --- The per-chain history cache: persisted inside the wallet's metadata ---------------------
    // The fold (sort + encode) and the reverse conversion both run on worker threads in the app.
    QJsonArray arr;
    reportWorker("history -> JSON (saving the cache)", timed([&] {
                     for (const HistoryItem &h : rows)
                         arr.append(toJson(h));
                 }));
    QVector<HistoryItem> back;
    reportWorker("JSON -> history (first switch to a chain)", timed([&] {
                     back.reserve(arr.size());
                     for (const QJsonValue &v : arr)
                         back.append(fromJson(v.toObject()));
                 }));
    QVector<HistoryItem> sorted = rows;
    reportWorker("sort the cache for the 30k cap", timed([&] {
                     std::sort(sorted.begin(), sorted.end(),
                               [](const HistoryItem &a, const HistoryItem &b) {
                                   return a.timestamp > b.timestamp;
                               });
                 }));
    // What a save still costs the UI thread: taking shared copies to hand over, and putting the
    // finished snapshot back into the metadata.
    report("save: hand the history to the worker", timed([&] {
               const QVector<HistoryItem> fetched = m.fetchedItems();
               const QVector<HistoryItem> kept = rows;
               (void)fetched;
               (void)kept;
           }));

    // The whole metadata blob - history cache, balance cache, saved prices - which the wallet
    // serialises every time any part of it is saved.
    QJsonObject meta;
    {
        QJsonObject snap;
        snap[QStringLiteral("items")] = arr;
        QJsonObject hc;
        hc[QStringLiteral("1")] = snap;
        meta[QStringLiteral("histcache")] = hc;
        QJsonObject tok;
        for (int a = 0; a < kAccounts; ++a)
            for (const QString &t : known)
                tok[QStringLiteral("%1|%2").arg(a).arg(t)] = 12.5;
        QJsonObject bsnap;
        bsnap[QStringLiteral("tok")] = tok;
        QJsonObject bc;
        bc[QStringLiteral("1")] = bsnap;
        meta[QStringLiteral("balcache")] = bc;
        QJsonObject hp;
        for (int d = 0; d < 1500; ++d)
            hp[QStringLiteral("ETH|2024-%1").arg(d)] = 3000.0 + d;
        meta[QStringLiteral("histprices")] = hp;
    }
    report("save: put the folded snapshot into the metadata", timed([&] {
               QJsonObject snap;
               snap[QStringLiteral("items")] = arr;
               QJsonObject cache = meta.value(QStringLiteral("histcache")).toObject();
               cache[QStringLiteral("1")] = snap;
               meta[QStringLiteral("histcache")] = cache;
           }));
    QJsonObject snapshot;
    report("save: snapshot the metadata for the worker", timed([&] { snapshot = meta; }));
    QByteArray blob;
    reportWorker("serialise the whole metadata blob (any save)",
                 timed([&] { blob = QJsonDocument(snapshot).toJson(QJsonDocument::Compact); }));
    std::printf("                   (blob is %.1f MB)\n", blob.size() / 1048576.0);
    report("save: next edit to the metadata while the worker serialises",
           timed([&] { meta[QStringLiteral("notes")] = QStringLiteral("x"); }));
    report("parse the whole metadata blob (opening the wallet, once)",
           timed([&] { (void)QJsonDocument::fromJson(blob); }));

    std::printf("\nworst single UI-thread operation: %d ms\n", worstMs);

    // The stall log is how a freeze on a real wallet gets found, so check that it finds one: block
    // this (UI) thread inside a labelled operation and look for it in the log.
    {
        QTemporaryDir dir;
        const QString log = QDir(dir.path()).filePath(QStringLiteral("perflog.txt"));
        StallWatch::start(log, 100);
        QThread::msleep(80);
        QCoreApplication::processEvents(); // let the heartbeat start
        QThread::msleep(80);
        QCoreApplication::processEvents();
        {
            StallWatch::Scope scope("perf_check deliberate stall");
            QThread::msleep(400);
        }
        for (int i = 0; i < 10; ++i) { // heartbeats resume; the watchdog writes the line
            QCoreApplication::processEvents();
            QThread::msleep(30);
        }
        StallWatch::stop();
        QFile f(log);
        const QByteArray text = f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
        const int at = text.indexOf("stalled ");
        const int ms = at >= 0 ? text.mid(at + 8).split(' ').value(0).toInt() : 0;
        const bool ok = text.contains("perf_check deliberate stall") && ms >= 300 && ms <= 600;
        std::printf("%s stall log caught a 400 ms block: %s\n", ok ? "ok     " : "FAIL   ",
                    text.trimmed().isEmpty() ? "(nothing logged)" : text.trimmed().constData());
        if (!ok)
            return 1;
    }
    return 0;
}
