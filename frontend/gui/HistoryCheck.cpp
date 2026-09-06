// SPDX-License-Identifier: BSD-3-Clause
// Checks the part of HistoryModel that decides whether a swap looks finished.
//
// This is worth its own program because the failure it guards against is silent: the row is there,
// the amounts are right, and the only thing wrong is a word that says the trade is still happening
// when it finished twenty minutes ago. Nothing crashes, no log complains, and the person reading it
// has no way to tell the difference except by looking somewhere else.
//
// Build with -DAERO_BUILD_HISTORY_CHECK=ON and run it; it prints a line per case and exits non-zero
// if any of them fail. It needs no wallet, no network and no keys.

#include <QCoreApplication>
#include <QDeadlineTimer>
#include <QDateTime>

#include <cstdio>

#include "HistoryModel.h"

static int failures = 0;

static void check(bool ok, const char *what) {
    std::printf("%s  %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok)
        ++failures;
}

// Let the model's coalescing timer fire, the way it would between two frames in the app.
static void settle() {
    QDeadlineTimer deadline(300);
    while (!deadline.hasExpired())
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
}

static HistoryItem swapRow(const QString &id, const QString &status, const QString &sell,
                           const QString &buy, quint64 when, quint32 account = 0) {
    HistoryItem h;
    h.kind = QStringLiteral("swap");
    h.direction = QStringLiteral("swap");
    h.txHash = id;
    h.status = status;
    h.symbol = sell;
    h.buySymbol = buy;
    h.formatted = QStringLiteral("1");
    h.buyFormatted = QStringLiteral("2000");
    h.timestamp = when;
    h.account = account;
    return h;
}

// A plain native-coin transfer, which is never filtered as spam.
static HistoryItem transferRow(const QString &hash, const QString &direction, quint64 block,
                               quint64 when) {
    HistoryItem h;
    h.direction = direction;
    h.counterparty = QStringLiteral("0x000000000000000000000000000000000000dEaD");
    h.amount = QStringLiteral("1000000000000000000");
    h.formatted = QStringLiteral("1");
    h.symbol = QStringLiteral("ETH");
    h.txHash = hash;
    h.block = block;
    h.timestamp = when;
    return h;
}

static QString statusOf(const HistoryModel &m, const QString &id) {
    for (int r = 0; r < m.rowCount(); ++r) {
        const HistoryItem h = m.itemAt(r);
        if (h.txHash.compare(id, Qt::CaseInsensitive) == 0)
            return h.status;
    }
    return QStringLiteral("<no such row>");
}

static int swapRows(const HistoryModel &m) {
    int n = 0;
    for (int r = 0; r < m.rowCount(); ++r)
        if (m.itemAt(r).kind == QLatin1String("swap"))
            ++n;
    return n;
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    const quint64 now = static_cast<quint64>(QDateTime::currentSecsSinceEpoch());

    // The bug this whole file exists for. An order is fetched while it is still resting, and then
    // fetched again once it has filled. The second answer is the one that matters.
    {
        HistoryModel m;
        m.beginFullRefresh();
        m.appendBatch({swapRow("0xuid1", "pending", "USDC", "WETH", now - 60)});
        settle();
        check(statusOf(m, "0xuid1") == "pending", "a resting order reads as pending");
        m.appendBatch({swapRow("0xuid1", "done", "USDC", "WETH", now - 60)});
        settle();
        check(statusOf(m, "0xuid1") == "done", "the same order, once filled, reads as done");
        check(swapRows(m) == 1, "and it is still one row, not two");
        check(!m.hasPendingSwaps(), "so the poll that was watching it can stop");
    }

    // The opposite mistake: a late or stale reply must not walk a finished trade backwards.
    {
        HistoryModel m;
        m.beginFullRefresh();
        m.appendBatch({swapRow("0xuid2", "done", "USDC", "WETH", now - 600)});
        m.appendBatch({swapRow("0xuid2", "pending", "USDC", "WETH", now - 600)});
        settle();
        check(statusOf(m, "0xuid2") == "done", "a finished trade stays finished");
    }

    // A swap of the chain's own coin. We record it under the transaction hash we broadcast; the
    // settled order comes back under the protocol's own order id, naming the wrapped token. Nothing
    // links the two but the pair and the clock.
    {
        HistoryModel m;
        m.beginFullRefresh();
        m.addLocalSwap(swapRow("0xtxhash", "pending", "ETH", "USDC", now - 30));
        settle();
        check(swapRows(m) == 1, "a just-placed native swap shows immediately");
        m.appendBatch({swapRow("0xorderuid", "done", "WETH", "USDC", now - 25)});
        settle();
        check(swapRows(m) == 1, "and is replaced, not duplicated, by its settled copy");
        check(statusOf(m, "0xorderuid") == "done", "which reads as done");
    }

    // A router swap. The transaction mines, but the explorer has only indexed the leg that left the
    // wallet - the one coming back is an internal transfer it will get to later. Until then the
    // wallet used to sit and wait, and then call a swap that worked a failure.
    {
        HistoryModel m;
        m.beginFullRefresh();
        m.addLocalSwap(swapRow("0xmined", "pending", "USDC", "DAI", now - 120));
        m.appendBatch({transferRow("0xmined", "out", 21000000, now - 110)});
        settle();
        check(statusOf(m, "0xmined") == "done", "a mined router swap reads as done");
        m.expireStalePendingSwaps(1); // however long we wait, it is not pending any more
        settle();
        check(statusOf(m, "0xmined") == "done", "and is not later called a failure");
    }

    // A reverted swap is a failure, and says so.
    {
        HistoryModel m;
        m.beginFullRefresh();
        m.addLocalSwap(swapRow("0xreverted", "pending", "USDC", "DAI", now - 120));
        HistoryItem t = transferRow("0xreverted", "out", 21000001, now - 110);
        t.failed = true;
        m.appendBatch({t});
        settle();
        check(statusOf(m, "0xreverted") == "failed", "a reverted swap reads as failed");
    }

    // An order that has aged out of the exchange's window will never be mentioned again. Left alone
    // it rests at pending for good, and keeps a poll alive asking about it every thirty seconds.
    {
        HistoryModel m;
        m.beginFullRefresh();
        HistoryItem dead = swapRow("0xexpired", "pending", "USDC", "WETH", now - 4 * 3600);
        dead.expiry = now - 3 * 3600; // its own deadline, hours gone
        HistoryItem open = swapRow("0xopen", "pending", "USDC", "WETH", now - 60);
        open.expiry = now + 20 * 60;
        m.appendBatch({dead, open});
        settle();
        m.expireStalePendingSwaps(35 * 60);
        settle();
        check(statusOf(m, "0xexpired") == "failed", "an order past its deadline is called off");
        check(statusOf(m, "0xopen") == "pending", "one still inside it is left alone");
    }

    // The poll has to know which address to ask about, and it is not always the one on screen.
    {
        HistoryModel m;
        m.beginFullRefresh();
        m.appendBatch({swapRow("0xuid3", "pending", "USDC", "WETH", now - 60, /*account*/ 7)});
        settle();
        check(m.pendingSwapAccounts() == QList<quint32>{7},
              "an open order names the account that placed it");
    }

    // A wholesale replace (the single-account History view) must leave the model able to take
    // updates afterwards, rather than writing them over whichever row now sits at an old position.
    {
        HistoryModel m;
        m.beginFullRefresh();
        m.appendBatch({swapRow("0xuid4", "pending", "USDC", "WETH", now - 300),
                       swapRow("0xuid5", "pending", "DAI", "WETH", now - 200)});
        settle();
        m.onHistoryRefreshed({swapRow("0xuid5", "pending", "DAI", "WETH", now - 200)});
        m.appendBatch({swapRow("0xuid5", "done", "DAI", "WETH", now - 200)});
        settle();
        check(statusOf(m, "0xuid5") == "done", "an update after a full replace lands on the right row");
    }

    // History survives a restart, so a status frozen at the wrong value survives with it.
    {
        HistoryModel m;
        m.loadCachedHistory({swapRow("0xuid6", "pending", "USDC", "WETH", now - 3600, 2)});
        settle();
        check(m.hasPendingSwaps(), "a cached order is still open as far as we know");
        m.appendBatch({swapRow("0xuid6", "done", "USDC", "WETH", now - 3600, 2)});
        settle();
        check(statusOf(m, "0xuid6") == "done", "and the first fetch after opening settles it");
    }

    // The Account column. It reads an index the row carries and turns it into the name the user gave
    // that account on Receive.
    {
        HistoryModel m;
        m.setAccountNames({{0, QStringLiteral("Main")}, {2, QStringLiteral("Savings")}});
        m.beginFullRefresh();
        m.appendBatch({swapRow("0xacc1", "done", "USDC", "WETH", now - 100, 2),
                       swapRow("0xacc2", "done", "USDC", "WETH", now - 90, 5)});
        settle();

        auto nameOf = [&m](const QString &id) {
            for (int r = 0; r < m.rowCount(); ++r)
                if (m.itemAt(r).txHash.compare(id, Qt::CaseInsensitive) == 0)
                    return m.data(m.index(r, HistoryModel::Column_Account), Qt::DisplayRole).toString();
            return QStringLiteral("<no such row>");
        };
        check(nameOf("0xacc1") == "Savings", "a row shows the label of the account that made it");
        check(nameOf("0xacc2") == "Account #5", "an unnamed account falls back to its number");

        // Renaming on Receive has to reach rows already on screen.
        m.setAccountNames({{0, QStringLiteral("Main")}, {2, QStringLiteral("Cold storage")}});
        settle();
        check(nameOf("0xacc1") == "Cold storage", "renaming an account renames its history rows");

        // And searching by that name finds them, which is the point of showing it.
        m.setSearchText(QStringLiteral("cold"));
        settle();
        check(m.rowCount() == 1 && m.itemAt(0).txHash == "0xacc1", "history can be searched by account name");
        m.setSearchText(QString());
        settle();
    }

    // A row cached before history recorded an account has no account to name, and must not be
    // credited to account zero just because that is what an empty field looks like.
    {
        HistoryModel m;
        m.setAccountNames({{0, QStringLiteral("Main")}});
        HistoryItem old = swapRow("0xold", "done", "USDC", "WETH", now - 500);
        old.account = HistoryItem::unknownAccount;
        m.loadCachedHistory({old});
        settle();
        check(m.rowCount() == 1, "the old row is still shown");
        check(m.data(m.index(0, HistoryModel::Column_Account), Qt::DisplayRole).toString().isEmpty(),
              "but it is not attributed to an account it never named");
    }

    std::printf("\n%s\n", failures == 0 ? "all good" : "SOMETHING IS WRONG");
    return failures == 0 ? 0 : 1;
}
