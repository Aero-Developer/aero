// SPDX-License-Identifier: BSD-3-Clause
#include "Wallet.h"

#include <algorithm>

#include <QtConcurrent/QtConcurrent>
#include <QAtomicInt>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QReadLocker>
#include <QSet>
#include <QSharedPointer>
#include <QWriteLocker>

namespace {
// Wrap a aero_core char* result into a QString and free it.
QString takeString(char *s) {
    if (!s) return QString();
    QString out = QString::fromUtf8(s);
    aero_string_free(s);
    return out;
}

// Like takeString, but for SECRET material (mnemonic / private key): the core buffer is zeroized on
// free so the plaintext doesn't linger in freed heap. (The returned QString is still un-scrubbed Qt
// heap — the reveal dialogs clear it + auto-clear the clipboard — but this closes the Rust-side leak.)
QString takeSecretString(char *s) {
    if (!s) return QString();
    QString out = QString::fromUtf8(s);
    aero_secret_string_free(s);
    return out;
}

BalanceInfo parseBalance(const QString &json) {
    BalanceInfo b;
    const QJsonObject o = QJsonDocument::fromJson(json.toUtf8()).object();
    b.raw = o.value("raw").toString();
    b.formatted = o.value("formatted").toString();
    b.decimals = static_cast<quint8>(o.value("decimals").toInt(18));
    b.symbol = o.value("symbol").toString();
    return b;
}
} // namespace

Wallet::Wallet(AeroWallet *core, QObject *parent)
    : QObject(parent), m_core(core) {
    // Bound how many Tor requests run at once. Enough for all the essential refreshes (balances,
    // history, native price, market prices, fees, fiat, NFTs) to run together, while queuing the
    // non-essential burst (per-token liquidity checks, NFT/logo image fetches) right behind them —
    // so one SOCKS proxy isn't flooded with dozens of simultaneous circuits.
    m_netPool.setMaxThreadCount(8);
    // History gets its own small lane so its per-account fan-out can't monopolise the essentials'
    // threads (balances/prices/fees/block).
    m_historyPool.setMaxThreadCount(3);
}

Wallet::~Wallet() {
    // Drop queued tasks and wait for any running ones to finish BEFORE freeing the core, so no
    // worker thread touches m_core (or this object) after destruction. Tasks capture `this`, so
    // this must complete while the object is still valid.
    m_netPool.clear();
    m_netPool.waitForDone();
    m_historyPool.clear();
    m_historyPool.waitForDone();
    if (m_core) {
        QWriteLocker lock(&m_coreLock);
        aero_wallet_free(m_core);
        m_core = nullptr;
    }
    // Best-effort scrub of the retained password so the plaintext doesn't linger in freed heap
    // (QString doesn't zero on destruction). fill() overwrites this instance's buffer before clear().
    if (!m_password.isEmpty()) {
        m_password.fill(QChar(u'\0'));
        m_password.clear();
    }
}

QString Wallet::takeLastError() const {
    return takeString(aero_last_error());
}

QString Wallet::address(quint32 index) const {
    {
        QMutexLocker cl(&m_addrCacheMutex);
        auto it = m_addrCache.constFind(index);
        if (it != m_addrCache.constEnd())
            return it.value();
    }
    // Cache miss. NEVER block the (usually UI) caller on the core lock: a scan holds it exclusively
    // for minutes, and address() is called all over the UI — labels, the Receive QR, and especially
    // applyReceiveSearch() which derives EVERY visible row on each keystroke. A blocking read here
    // froze the whole window whenever any of those ran during a scan. Try to read without waiting; if
    // a writer holds the lock, return empty. Addresses are warmed off-thread (warmAddresses, which
    // may block on its worker), so the cache fills in and the UI refreshes on the next pass.
    if (!m_coreLock.tryLockForRead())
        return QString();
    const QString addr = takeString(aero_wallet_address(m_core, index));
    m_coreLock.unlock();
    if (!addr.isEmpty()) {
        QMutexLocker cl(&m_addrCacheMutex);
        m_addrCache.insert(index, addr);
    }
    return addr;
}

void Wallet::requestShutdown() {
    aero_request_shutdown();
}

bool Wallet::addressesCached(quint32 count) const {
    QMutexLocker cl(&m_addrCacheMutex);
    for (quint32 i = 0; i < count; ++i)
        if (!m_addrCache.contains(i))
            return false;
    return true;
}

void Wallet::invalidateAddressCache() {
    QMutexLocker cl(&m_addrCacheMutex);
    m_addrCache.clear();
}

void Wallet::invalidateMetaCache() {
    QMutexLocker c(&m_metaCacheMutex);
    ++m_metaGen; // signals any in-flight getter not to cache the value it's about to read
    m_numAccountsCache = -1;
    // NOTE: the TOKENS cache is intentionally NOT cleared here. Adding an HD account, importing a key,
    // and a funded scan all change the account COUNT but NOT the tracked-token list. Clearing the
    // tokens cache on those operations forced the next tokens() call to re-read under the core lock —
    // which BLOCKS the UI thread whenever a scan holds the write lock (a balance-update signal ->
    // showCachedBalance() -> tokens() froze the whole app for the entire multi-minute scan). Only
    // addToken()/removeToken() actually change tokens; they clear this cache explicitly.
}

void Wallet::invalidateTokensCache() {
    QMutexLocker c(&m_metaCacheMutex);
    ++m_metaGen;
    m_tokensCacheValid = false;
    m_tokensCache.clear();
}

quint32 Wallet::numAccounts() const {
    quint64 gen;
    {
        QMutexLocker c(&m_metaCacheMutex); // served from cache so UI reads never block on the core
        if (m_numAccountsCache >= 0)        // lock (e.g. while the funded scan holds it exclusively)
            return static_cast<quint32>(m_numAccountsCache);
        gen = m_metaGen;
    }
    // Cache miss. NEVER block the UI thread on the core lock: a scan holds it exclusively for minutes.
    // Try to read without waiting; if a writer holds the lock, return the last known count (stale by
    // at most the pending mutation) rather than freezing. The next call after the writer refreshes it.
    if (!m_coreLock.tryLockForRead()) {
        QMutexLocker c(&m_metaCacheMutex);
        return static_cast<quint32>(m_numAccountsLast);
    }
    const quint32 n = aero_wallet_account_count(m_core);
    m_coreLock.unlock();
    QMutexLocker c(&m_metaCacheMutex);
    m_numAccountsLast = static_cast<int>(n);
    if (m_metaGen == gen) // no mutation raced us — safe to cache
        m_numAccountsCache = static_cast<int>(n);
    return n;
}

quint32 Wallet::addAccount() {
    quint32 idx;
    {
        QWriteLocker lock(&m_coreLock); // mutates secrets.account_count
        idx = aero_wallet_add_account(m_core);
    }
    invalidateAddressCache();
    invalidateMetaCache();
    return idx;
}

void Wallet::addAccountAsync() {
    // Run on the GLOBAL pool, not m_netPool: deriving the next account is a quick local op and must
    // not queue behind the network tasks (e.g. a large history fan-out) sitting in m_netPool — that
    // would delay the new address. Any core-lock wait happens on this worker thread, never the UI.
    QtConcurrent::run([this]() {
        quint32 idx;
        {
            QWriteLocker lock(&m_coreLock);
            idx = aero_wallet_add_account(m_core);
        }
        // NOTE: do NOT clear the whole address cache here. Appending an HD account does not change
        // any existing index's address (derivation is deterministic per index), and clearing it made
        // the subsequent rebuildAccountCombos() re-derive ALL accounts synchronously on the UI thread
        // — a multi-second freeze once a wallet has hundreds of funded accounts. The new index simply
        // isn't cached yet and gets derived once on first access. Only the count cache must refresh.
        invalidateMetaCache();
        QMetaObject::invokeMethod(this, [this, idx]() { emit accountAdded(idx); },
                                  Qt::QueuedConnection);
    });
}

quint32 Wallet::importPrivateKey(const QString &hexKey) {
    QWriteLocker lock(&m_coreLock); // mutates secrets.imported_keys
    quint32 idx = aero_wallet_import_private_key(m_core, hexKey.toUtf8().constData());
    if (idx == 0xFFFFFFFFu) {
        m_status = Status_Error;
        m_errorString = takeLastError();
    }
    invalidateAddressCache();
    invalidateMetaCache();
    return idx;
}

QString Wallet::exportPrivateKey(quint32 index) const {
    QReadLocker lock(&m_coreLock);
    return takeSecretString(aero_wallet_export_private_key(m_core, index));
}

QString Wallet::signMessage(quint32 index, const QString &message) {
    QReadLocker lock(&m_coreLock); // reads the signer (&self)
    char *j = aero_wallet_sign_message(m_core, index, message.toUtf8().constData());
    if (!j) {
        m_errorString = takeLastError();
        return QString();
    }
    return takeString(j);
}

QString Wallet::resolveEns(const QString &name) {
    QReadLocker lock(&m_coreLock);
    return takeString(aero_wallet_resolve_ens(m_core, name.toUtf8().constData()));
}

QString Wallet::verifyMessage(const QString &message, const QString &signature) {
    // Pure recovery — doesn't touch the core wallet, so no lock needed.
    char *j = aero_wallet_verify_message(message.toUtf8().constData(),
                                         signature.toUtf8().constData());
    if (!j) {
        m_errorString = takeLastError();
        return QString();
    }
    return takeString(j);
}

bool Wallet::isHardware() const {
    {
        QMutexLocker c(&m_metaCacheMutex); // immutable for the wallet's lifetime; cache it so a UI
        if (m_hardwareCache >= 0)           // call during the scan's exclusive lock doesn't block
            return m_hardwareCache != 0;
    }
    int hw;
    {
        QReadLocker lock(&m_coreLock);
        hw = aero_wallet_is_hardware(m_core) != 0 ? 1 : 0;
    }
    QMutexLocker c(&m_metaCacheMutex);
    m_hardwareCache = hw;
    return hw != 0;
}

bool Wallet::isWatchOnly() const {
    {
        QMutexLocker c(&m_metaCacheMutex); // immutable for the wallet's lifetime; cache it so a UI
        if (m_watchOnlyCache >= 0)          // call during the scan's exclusive lock doesn't block
            return m_watchOnlyCache != 0;
    }
    int wo;
    {
        QReadLocker lock(&m_coreLock);
        wo = aero_wallet_is_watch_only(m_core) != 0 ? 1 : 0;
    }
    QMutexLocker c(&m_metaCacheMutex);
    m_watchOnlyCache = wo;
    return wo != 0;
}

QString Wallet::hwKind() const {
    {
        QMutexLocker c(&m_metaCacheMutex); // immutable for the wallet's lifetime; cache it
        if (m_hwKindCached)
            return m_hwKindCache;
    }
    QString kind;
    {
        QReadLocker lock(&m_coreLock);
        kind = takeString(aero_wallet_hw_kind(m_core));
    }
    QMutexLocker c(&m_metaCacheMutex);
    m_hwKindCache = kind;
    m_hwKindCached = true;
    return kind;
}

quint32 Wallet::addHardwareAccount() {
    QWriteLocker lock(&m_coreLock); // derives via the device + mutates the account list
    quint32 idx = aero_wallet_hw_add_account(m_core);
    if (idx == 0xFFFFFFFFu) {
        m_status = Status_Error;
        m_errorString = takeLastError();
    }
    return idx;
}

QString Wallet::getSeed() const {
    QReadLocker lock(&m_coreLock);
    return takeSecretString(aero_wallet_mnemonic(m_core));
}

bool Wallet::store(const QString &path, const QString &password) {
    QReadLocker lock(&m_coreLock); // save() serializes secrets (a read); mutations lock exclusively
    const QString p = path.isEmpty() ? m_path : path;
    int rc = aero_wallet_save(m_core, p.toUtf8().constData(), password.toUtf8().constData());
    if (rc != 0) {
        m_status = Status_Error;
        m_errorString = takeLastError();
        return false;
    }
    m_path = p;
    m_password = password; // retained so save() can re-encrypt after in-memory changes
    return true;
}

bool Wallet::save() {
    if (m_path.isEmpty())
        return false; // no file to save to (e.g. demo/throwaway wallet)
    QReadLocker lock(&m_coreLock);
    int rc = aero_wallet_save(m_core, m_path.toUtf8().constData(), m_password.toUtf8().constData());
    if (rc != 0) {
        m_status = Status_Error;
        m_errorString = takeLastError();
        return false;
    }
    return true;
}

bool Wallet::saveWithMetadata(const QString &metaJson) {
    if (m_path.isEmpty())
        return false; // nothing to persist (demo/throwaway wallet)
    {
        QWriteLocker lock(&m_coreLock);
        aero_wallet_set_metadata(m_core, metaJson.toUtf8().constData());
    }
    QReadLocker lock(&m_coreLock);
    int rc = aero_wallet_save(m_core, m_path.toUtf8().constData(), m_password.toUtf8().constData());
    if (rc != 0) {
        m_status = Status_Error;
        m_errorString = takeLastError();
        return false;
    }
    return true;
}

void Wallet::saveAsync() {
    if (m_path.isEmpty())
        return; // nothing to persist (demo/throwaway wallet)
    // If a save is already running, just mark that another is wanted; the running one will pick it
    // up when it finishes. This coalesces a burst of edits into a single trailing write and, with
    // testAndSetOrdered, guarantees only one encrypt/atomic-write is in flight at any time.
    if (!m_saveRunning.testAndSetOrdered(0, 1)) {
        m_saveQueued.storeRelease(1);
        return;
    }
    QtConcurrent::run(&m_netPool, [this]() {
        bool ok = true;
        do {
            m_saveQueued.storeRelease(0); // clear before saving so edits during the write re-queue
            // Apply any UI-queued metadata (labels/contacts/notes) off-thread, so the UI thread never
            // took the core write lock for it (which would freeze behind the funded scan).
            {
                QString meta;
                bool hasMeta = false;
                {
                    QMutexLocker m(&m_pendingMetaMutex);
                    if (m_hasPendingMetadata) {
                        meta = m_pendingMetadata;
                        hasMeta = true;
                        m_hasPendingMetadata = false;
                    }
                }
                if (hasMeta) {
                    QWriteLocker lock(&m_coreLock);
                    aero_wallet_set_metadata(m_core, meta.toUtf8().constData());
                }
            }
            {
                QReadLocker lock(&m_coreLock);
                int rc = aero_wallet_save(m_core, m_path.toUtf8().constData(),
                                          m_password.toUtf8().constData());
                if (rc != 0) {
                    m_status = Status_Error;
                    m_errorString = takeLastError();
                    ok = false;
                }
            }
            // Loop if another save was requested while this one ran.
        } while (m_saveQueued.loadAcquire() != 0);
        m_saveRunning.storeRelease(0);
        // A request that raced in right as we cleared m_saveRunning would have hit the fast path
        // above and set m_saveQueued; run one more pass so it isn't lost.
        if (m_saveQueued.loadAcquire() != 0)
            saveAsync();
        QMetaObject::invokeMethod(this, [this, ok]() { emit saved(ok); }, Qt::QueuedConnection);
    });
}

bool Wallet::setProvider(quint64 chainId, const QStringList &endpoints, const QString &socksProxy) {
    m_chainId = chainId;
    QJsonArray arr;
    for (const QString &e : endpoints) arr.append(e);
    const QByteArray endpointsJson = QJsonDocument(arr).toJson(QJsonDocument::Compact);
    const QByteArray proxy = socksProxy.toUtf8();
    QWriteLocker lock(&m_coreLock); // set_provider mutates the wallet's provider (&mut)
    int rc = aero_wallet_set_provider(
        m_core, chainId, endpointsJson.constData(),
        socksProxy.isEmpty() ? nullptr : proxy.constData(), socksProxy.isEmpty(), 60);
    if (rc != 0) {
        m_status = Status_Error;
        m_errorString = takeLastError();
        return false;
    }
    emit connectionStatusChanged(1);
    return true;
}

void Wallet::connectProvider(quint64 chainId, const QStringList &endpoints, const QString &socksProxy) {
    QtConcurrent::run(&m_netPool, [this, chainId, endpoints, socksProxy]() {
        QJsonArray arr;
        for (const QString &e : endpoints) arr.append(e);
        const QByteArray endpointsJson = QJsonDocument(arr).toJson(QJsonDocument::Compact);

        // Configure the given proxy ("" = direct) then probe connectivity with a real RPC call.
        // A direct connection must explicitly allow clearnet (the core refuses otherwise).
        //
        // set_provider is swapped under a brief EXCLUSIVE write lock (a single fast FFI call), but the
        // connectivity probe — which can block up to the RPC timeout when Tor is still bootstrapping /
        // unreachable — runs under a SHARED read lock. Reads on the UI thread (address(), tokens(),
        // balances) are also shared reads, so they no longer block behind a stuck connect: this was
        // the "Aero not responding" freeze whenever Tor was slow or down.
        auto tryMode = [&](const QString &proxy) -> bool {
            {
                QWriteLocker lock(&m_coreLock);
                const QByteArray p = proxy.toUtf8();
                // allow_clearnet is ALWAYS false: with no proxy the core permits ONLY local endpoints
                // (127.0.0.1 / localhost — your own node) and refuses remote ones, so blanking the
                // proxy while public RPCs are still configured can't silently leak the real IP.
                const int rc = aero_wallet_set_provider(m_core, chainId, endpointsJson.constData(),
                                                        proxy.isEmpty() ? nullptr : p.constData(),
                                                        false, 20);
                if (rc != 0)
                    return false;
            }
            QReadLocker lock(&m_coreLock);
            char *probe = aero_wallet_eth_balance(m_core, 0); // null => RPC unreachable
            if (!probe)
                return false;
            aero_string_free(probe);
            return true;
        };

        // Tor only — no clearnet fallback, so a failed Tor connection never silently leaks the IP.
        int mode = 0;
        QString message;
        if (!socksProxy.isEmpty() && tryMode(socksProxy)) {
            mode = 2;
            message = tr("Connected via Tor");
        } else if (socksProxy.isEmpty() && tryMode(QString())) {
            // The user explicitly disabled Tor (blank proxy) — typically to reach their own node
            // (e.g. http://127.0.0.1:8545). Connect directly. We only do this when the proxy was
            // deliberately left blank, never as a silent clearnet fallback for the default RPCs.
            mode = 1;
            message = tr("Connected (direct — own node)");
        } else {
            mode = 0;
            message = takeLastError();
            if (message.isEmpty())
                message = socksProxy.isEmpty() ? tr("Offline — node unreachable")
                                               : tr("Offline — no RPC reachable over Tor");
        }

        m_chainId = chainId;
        m_status = mode ? Status_Ok : Status_Error;
        QMetaObject::invokeMethod(this, [this, mode, message]() {
            emit connectionStatusChanged(mode);
            emit providerConnected(mode, message);
        }, Qt::QueuedConnection);
    });
}

void Wallet::fetchAvailable(quint32 index, const QString &token) {
    QtConcurrent::run(&m_netPool, [this, index, token]() {
        QReadLocker lock(&m_coreLock);
        BalanceInfo b;
        char *j = token.isEmpty()
                      ? aero_wallet_eth_balance(m_core, index)
                      : aero_wallet_erc20_balance(m_core, token.toUtf8().constData(), index);
        if (j)
            b = parseBalance(takeString(j));
        QMetaObject::invokeMethod(this, [this, index, token, b]() {
            emit availableBalance(index, token, b.formatted, b.symbol);
        }, Qt::QueuedConnection);
    });
}

void Wallet::refreshAllBalances(quint32 numAccounts, const QString &extraTokensJson) {
    if (numAccounts == 0) numAccounts = 1;
    QtConcurrent::run(&m_netPool, [this, numAccounts, extraTokensJson]() {
        QString json;
        {
            QReadLocker lock(&m_coreLock);
            char *j = aero_wallet_all_balances(m_core, numAccounts,
                                               extraTokensJson.toUtf8().constData());
            if (j) json = takeString(j);
        }
        QMetaObject::invokeMethod(this, [this, json]() {
            const QJsonObject root = QJsonDocument::fromJson(json.toUtf8()).object();
            const QJsonArray accts = root.value(QStringLiteral("accounts")).toArray();
            for (const QJsonValue &av : accts) {
                const QJsonObject a = av.toObject();
                const quint32 idx = static_cast<quint32>(a.value(QStringLiteral("index")).toDouble());
                const QString nativeSym = a.value(QStringLiteral("native_symbol")).toString();
                const QString nativeFmt = a.value(QStringLiteral("native_formatted")).toString();
                // Only propagate reads that actually succeeded. A failed RPC read (native_ok=false)
                // is skipped so the UI keeps its cached balance instead of flickering to 0 and
                // firing a spurious "payment received" on the next good read. (Default true keeps
                // back-compat with an older core.)
                if (a.value(QStringLiteral("native_ok")).toBool(true)) {
                    // Native balance: drives Home total, AddressModel, notifications, status bar...
                    emit accountBalanceUpdated(idx, nativeFmt, nativeSym);
                    // ...and the Send "available" label when the native asset is selected (token "").
                    emit availableBalance(idx, QString(), nativeFmt, nativeSym);
                }
                for (const QJsonValue &tv : a.value(QStringLiteral("tokens")).toArray()) {
                    const QJsonObject t = tv.toObject();
                    if (!t.value(QStringLiteral("ok")).toBool(true))
                        continue; // failed token read -> keep cached value
                    emit availableBalance(idx, t.value(QStringLiteral("address")).toString(),
                                          t.value(QStringLiteral("formatted")).toString(),
                                          t.value(QStringLiteral("symbol")).toString());
                }
            }
            emit allBalancesRefreshed();
        }, Qt::QueuedConnection);
    });
}

void Wallet::refresh(quint32 accountIndex) {
    // Network I/O runs off the UI thread; results are marshalled back via queued signals.
    QtConcurrent::run(&m_netPool, [this, accountIndex]() {
        QReadLocker lock(&m_coreLock);
        BalanceInfo eth;
        QVector<BalanceInfo> tokenBalances;
        QString err;

        char *ethJson = aero_wallet_eth_balance(m_core, accountIndex);
        if (ethJson) {
            eth = parseBalance(takeString(ethJson));
        } else {
            err = takeLastError();
        }

        for (const TokenInfo &t : tokens()) {
            char *tj = aero_wallet_erc20_balance(m_core, t.address.toUtf8().constData(), accountIndex);
            if (tj) tokenBalances.append(parseBalance(takeString(tj)));
        }

        QMetaObject::invokeMethod(this, [this, eth, tokenBalances, err]() {
            emit balanceUpdated(eth, tokenBalances);
            emit updated();
            emit refreshed(err.isEmpty(), err);
        }, Qt::QueuedConnection);
    });
}

void Wallet::refreshAccountBalance(quint32 accountIndex) {
    QtConcurrent::run(&m_netPool, [this, accountIndex]() {
        QReadLocker lock(&m_coreLock);
        BalanceInfo eth;
        char *ethJson = aero_wallet_eth_balance(m_core, accountIndex);
        if (ethJson)
            eth = parseBalance(takeString(ethJson));
        QMetaObject::invokeMethod(this, [this, accountIndex, eth]() {
            emit accountBalanceUpdated(accountIndex, eth.formatted, eth.symbol);
        }, Qt::QueuedConnection);
    });
}

void Wallet::refreshEthUsdPrice() {
    QtConcurrent::run(&m_netPool, [this]() {
        QReadLocker lock(&m_coreLock);
        char *j = aero_wallet_eth_usd_price(m_core);
        double price = 0.0;
        if (j) {
            bool ok = false;
            const double v = takeString(j).toDouble(&ok);
            if (ok) price = v;
        }
        QMetaObject::invokeMethod(this, [this, price]() { emit ethUsdPriceUpdated(price); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::refreshMarketPrices() {
    QtConcurrent::run(&m_netPool, [this]() {
        QReadLocker lock(&m_coreLock);
        double xmrUsd = 0, xmrChg = 0, ethUsd = 0, ethChg = 0;
        char *j = aero_wallet_market_prices(m_core);
        if (j) {
            const QJsonObject o = QJsonDocument::fromJson(takeString(j).toUtf8()).object();
            xmrUsd = o.value("xmr_usd").toDouble();
            xmrChg = o.value("xmr_chg").toDouble();
            ethUsd = o.value("eth_usd").toDouble();
            ethChg = o.value("eth_chg").toDouble();
        }
        QMetaObject::invokeMethod(this, [this, xmrUsd, xmrChg, ethUsd, ethChg]() {
            emit marketPricesUpdated(xmrUsd, xmrChg, ethUsd, ethChg);
        }, Qt::QueuedConnection);
    });
}

void Wallet::refreshBlockNumber() {
    QtConcurrent::run(&m_netPool, [this]() {
        QReadLocker lock(&m_coreLock);
        const quint64 n = aero_wallet_block_number(m_core);
        QMetaObject::invokeMethod(this, [this, n]() { emit blockNumberUpdated(n); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::txReceipt(const QString &txHash) {
    QtConcurrent::run(&m_netPool, [this, txHash]() {
        bool mined = false, success = false;
        {
            QReadLocker lock(&m_coreLock);
            char *j = aero_wallet_tx_receipt(m_core, txHash.toUtf8().constData());
            if (j) {
                const QJsonDocument doc = QJsonDocument::fromJson(takeString(j).toUtf8());
                if (doc.isObject()) {
                    const QJsonObject o = doc.object();
                    // A mined receipt carries a blockNumber; status "0x1" = success, "0x0" = reverted.
                    mined = o.contains(QStringLiteral("blockNumber")) &&
                            !o.value(QStringLiteral("blockNumber")).isNull();
                    success = o.value(QStringLiteral("status")).toString() == QLatin1String("0x1");
                }
            }
        }
        QMetaObject::invokeMethod(
            this, [this, txHash, mined, success]() { emit txReceiptReady(txHash, mined, success); },
            Qt::QueuedConnection);
    });
}

// Parse a aero_wallet_account_history JSON array (already ownership-taken) into HistoryItems.
static void parseHistoryArray(const QString &json, QVector<HistoryItem> &out) {
    const QJsonArray arr = QJsonDocument::fromJson(json.toUtf8()).array();
    for (const QJsonValue &v : arr) {
        const QJsonObject o = v.toObject();
        HistoryItem h;
        h.direction = o.value("direction").toString();
        h.counterparty = o.value("counterparty").toString();
        h.amount = o.value("amount").toString();
        h.formatted = o.value("formatted").toString();
        h.txHash = o.value("tx_hash").toString();
        h.block = static_cast<quint64>(o.value("block").toDouble());
        h.token = o.value("token").toString();
        h.symbol = o.value("symbol").toString();
        h.timestamp = static_cast<quint64>(o.value("timestamp").toDouble());
        h.fee = o.value("fee").toString();
        h.failed = o.value("failed").toBool();
        h.kind = o.value("kind").toString();
        h.buySymbol = o.value("buy_symbol").toString();
        h.buyFormatted = o.value("buy_formatted").toString();
        h.status = o.value("status").toString();
        out.append(h);
    }
}

void Wallet::refreshHistory(quint32 accountIndex, const QString &fromBlock) {
    Q_UNUSED(fromBlock);
    QtConcurrent::run(&m_netPool, [this, accountIndex]() {
        QReadLocker lock(&m_coreLock);
        const quint64 chain = m_chainId; // the chain this fetch is for (stable under the read lock)
        // Full native + token history from the block explorer (over Tor) in one call.
        QVector<HistoryItem> items;
        char *j = aero_wallet_account_history(m_core, accountIndex);
        if (j)
            parseHistoryArray(takeString(j), items);
        // Merge CoW Protocol swaps (pending + historical) for this account: they aren't on-chain
        // transfers, so the explorer never lists them.
        mergeCowOrders(accountIndex, items);
        std::sort(items.begin(), items.end(),
                  [](const HistoryItem &a, const HistoryItem &b) { return a.timestamp > b.timestamp; });
        QMetaObject::invokeMethod(this, [this, items, chain]() { emit historyRefreshed(items, chain); },
                                  Qt::QueuedConnection);
    });
}

// Fetch CoW Protocol orders for `accountIndex` and append de-duplicated swap rows to `items`.
// Must be called with m_coreLock held (read). Silently no-ops on non-CoW chains / errors.
void Wallet::mergeCowOrders(quint32 accountIndex, QVector<HistoryItem> &items) {
    char *c = aero_wallet_cow_orders(m_core, accountIndex);
    if (!c)
        return;
    QVector<HistoryItem> cow;
    parseHistoryArray(takeString(c), cow);
    QSet<QString> haveUid;
    for (const HistoryItem &h : items)
        if (h.kind == QLatin1String("swap"))
            haveUid.insert(h.txHash);
    for (const HistoryItem &h : cow) {
        if (haveUid.contains(h.txHash))
            continue;
        haveUid.insert(h.txHash);
        items.append(h);
    }
}

void Wallet::refreshHistoryAll(quint32 numAccounts, quint32 priorityIndex) {
    if (numAccounts == 0) numAccounts = 1;
    // Called on the UI thread: emit the start signal SYNCHRONOUSLY so the model is cleared + dedup
    // reset before any (out-of-order) batch can arrive. Then fan out the per-account fetches.
    emit historyRefreshStarted();
    // Fetch accounts with bounded parallelism (m_netPool caps concurrent tasks; the global RPC
    // semaphore caps concurrent Tor requests) instead of one-at-a-time. Order the work so the
    // currently-selected account is scheduled first, so its rows show up near-instantly. Each
    // account's fetch emits its own historyBatch as it completes; a shared atomic counts completions
    // so the model's begin/append/finish sequencing (done==1 .. done==total) still works even though
    // batches now arrive out of order.
    QVector<quint32> order;
    order.reserve(static_cast<int>(numAccounts));
    if (priorityIndex < numAccounts)
        order.append(priorityIndex);
    for (quint32 a = 0; a < numAccounts; ++a)
        if (a != priorityIndex)
            order.append(a);

    auto done = QSharedPointer<QAtomicInt>::create(0);
    const quint32 total = numAccounts;
    for (quint32 a : order) {
        // On the dedicated history pool so this N-task fan-out can't starve the single-task
        // balance/price/fee/block refreshes running on m_netPool.
        QtConcurrent::run(&m_historyPool, [this, a, total, done]() {
            QVector<HistoryItem> part;
            quint64 chain;
            {
                QReadLocker lock(&m_coreLock);
                chain = m_chainId;
                char *j = aero_wallet_account_history(m_core, a);
                if (j)
                    parseHistoryArray(takeString(j), part);
                mergeCowOrders(a, part); // CoW swaps for this account (off-chain; not the explorer)
            }
            const quint32 d = static_cast<quint32>(done->fetchAndAddOrdered(1)) + 1;
            QMetaObject::invokeMethod(
                this, [this, part, d, total, chain]() { emit historyBatch(part, d, total, chain); },
                Qt::QueuedConnection);
        });
    }
}

void Wallet::refreshAccountHistory(quint32 accountIndex) {
    // One account's full history, on the dedicated history pool (Background-gated in the core so it
    // yields the Tor circuit to interactive work). Appended by the caller — no model clear — so this
    // is the primitive for lazy/on-demand and status-gated refresh (Electrum's per-address model).
    QtConcurrent::run(&m_historyPool, [this, accountIndex]() {
        QVector<HistoryItem> part;
        quint64 chain;
        {
            QReadLocker lock(&m_coreLock);
            chain = m_chainId;
            char *j = aero_wallet_account_history(m_core, accountIndex);
            if (j)
                parseHistoryArray(takeString(j), part);
            mergeCowOrders(accountIndex, part);
        }
        QMetaObject::invokeMethod(
            this,
            [this, accountIndex, part, chain]() { emit accountHistoryReady(accountIndex, part, chain); },
            Qt::QueuedConnection);
    });
}

void Wallet::scanFunded(quint32 gapLimit) {
    QtConcurrent::run(&m_netPool, [this, gapLimit]() {
        QWriteLocker lock(&m_coreLock); // scan_funded mutates account_order (&mut)
        QList<quint32> indices;
        char *j = aero_wallet_scan_funded(m_core, gapLimit);
        if (j) {
            const QJsonArray arr = QJsonDocument::fromJson(takeString(j).toUtf8()).array();
            for (const QJsonValue &v : arr)
                indices.append(static_cast<quint32>(v.toDouble()));
        }
        invalidateAddressCache(); // account_order may have been reordered (contiguous backfill)
        invalidateMetaCache();    // account count changed
        QMetaObject::invokeMethod(this, [this, indices]() { emit fundedScanned(indices); },
                                  Qt::QueuedConnection);
    });
}

quint64 Wallet::scanProgress() const {
    // Lock-free: reads a core atomic that the scan (on another thread) updates. No m_coreLock.
    return aero_wallet_scan_progress();
}

quint64 Wallet::scanFound() const {
    return aero_wallet_scan_found();
}

void Wallet::warmAddresses(quint32 count) {
    QtConcurrent::run(&m_netPool, [this, count]() {
        // On a WORKER thread it's fine to block until any in-flight scan releases the write lock;
        // take the read lock ONCE for the whole warm and derive every not-yet-cached address, so the
        // (non-blocking) UI address() getter finds them all in the cache afterwards. This is what
        // keeps the UI from ever having to derive under the core lock itself.
        {
            QReadLocker lock(&m_coreLock);
            for (quint32 i = 0; i < count; ++i) {
                {
                    QMutexLocker cl(&m_addrCacheMutex);
                    if (m_addrCache.contains(i))
                        continue;
                }
                const QString a = takeString(aero_wallet_address(m_core, i));
                if (!a.isEmpty()) {
                    QMutexLocker cl(&m_addrCacheMutex);
                    m_addrCache.insert(i, a);
                }
            }
        }
        QMetaObject::invokeMethod(this, [this]() { emit addressesWarmed(); }, Qt::QueuedConnection);
    });
}

void Wallet::scanFundedMulti(const QString &configsJson, quint32 gapLimit) {
    QtConcurrent::run(&m_netPool, [this, configsJson, gapLimit]() {
        // Exclusive: the multi-chain scan mutates account_order AND swaps the provider per chain,
        // so no reader may run concurrently. Held for the whole (one-time) scan.
        QWriteLocker lock(&m_coreLock);
        QList<quint32> indices;
        char *j = aero_wallet_scan_funded_multi(m_core, configsJson.toUtf8().constData(), gapLimit);
        if (j) {
            const QJsonArray arr = QJsonDocument::fromJson(takeString(j).toUtf8()).array();
            for (const QJsonValue &v : arr)
                indices.append(static_cast<quint32>(v.toDouble()));
        }
        invalidateAddressCache(); // account_order was reordered by the contiguous backfill
        invalidateMetaCache();    // account count changed
        QMetaObject::invokeMethod(this, [this, indices]() { emit fundedScanned(indices); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::checkTokenLiquidity(const QString &tokenAddress) {
    QtConcurrent::run(&m_netPool, [this, tokenAddress]() {
        QReadLocker lock(&m_coreLock);
        double usd = 0.0;
        char *j = aero_wallet_token_liquidity_usd(m_core, tokenAddress.toUtf8().constData());
        if (j) {
            bool ok = false;
            const double v = takeString(j).toDouble(&ok);
            if (ok) usd = v;
        }
        QMetaObject::invokeMethod(
            this, [this, tokenAddress, usd]() { emit tokenLiquidity(tokenAddress, usd); },
            Qt::QueuedConnection);
    });
}

void Wallet::refreshNfts(quint32 accountIndex) {
    QtConcurrent::run(&m_netPool, [this, accountIndex]() {
        QReadLocker lock(&m_coreLock);
        QVector<NftCollection> out;
        char *j = aero_wallet_account_nfts(m_core, accountIndex);
        if (j) {
            const QJsonArray arr = QJsonDocument::fromJson(takeString(j).toUtf8()).array();
            for (const QJsonValue &v : arr) {
                const QJsonObject o = v.toObject();
                NftCollection n;
                n.name = o.value("name").toString();
                n.symbol = o.value("symbol").toString();
                n.address = o.value("address").toString();
                n.type = o.value("token_type").toString();
                n.reputation = o.value("reputation").toString();
                n.count = static_cast<quint64>(o.value("count").toDouble());
                n.imageUrl = o.value("image_url").toString();
                out.append(n);
            }
        }
        QMetaObject::invokeMethod(this, [this, out]() { emit nftsRefreshed(out); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::fetchImage(const QString &url) {
    QtConcurrent::run(&m_netPool, [this, url]() {
        QReadLocker lock(&m_coreLock);
        QByteArray data;
        char *j = aero_wallet_fetch_image(m_core, url.toUtf8().constData());
        if (j)
            data = QByteArray::fromHex(takeString(j).toLatin1());
        QMetaObject::invokeMethod(this, [this, url, data]() { emit imageReady(url, data); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::resolveTokenMeta(const QString &address) {
    QtConcurrent::run(&m_netPool, [this, address]() {
        QReadLocker lock(&m_coreLock);
        QString symbol;
        quint8 decimals = 18;
        char *j = aero_wallet_erc20_metadata(m_core, address.toUtf8().constData());
        if (j) {
            const QJsonObject o = QJsonDocument::fromJson(takeString(j).toUtf8()).object();
            symbol = o.value("symbol").toString();
            decimals = static_cast<quint8>(o.value("decimals").toInt(18));
        }
        QMetaObject::invokeMethod(
            this, [this, address, symbol, decimals]() { emit tokenMetaResolved(address, symbol, decimals); },
            Qt::QueuedConnection);
    });
}

void Wallet::refreshFiatRate(const QString &currency) {
    QtConcurrent::run(&m_netPool, [this, currency]() {
        QReadLocker lock(&m_coreLock);
        double rate = 1.0;
        char *j = aero_wallet_fiat_per_usd(m_core, currency.toUtf8().constData());
        if (j) {
            bool ok = false;
            const double v = takeString(j).toDouble(&ok);
            if (ok && v > 0.0) rate = v;
        }
        QMetaObject::invokeMethod(this, [this, currency, rate]() { emit fiatRate(currency, rate); },
                                  Qt::QueuedConnection);
    });
}

QString Wallet::metadata() const {
    QReadLocker lock(&m_coreLock);
    return takeString(aero_wallet_metadata(m_core));
}

void Wallet::setMetadata(const QString &json) {
    QWriteLocker lock(&m_coreLock); // mutates the in-memory secrets (persisted on save())
    aero_wallet_set_metadata(m_core, json.toUtf8().constData());
}

void Wallet::queueMetadata(const QString &json) {
    // Lock-free store only (no core lock): the UI thread must never block here, even while the
    // funded scan holds the core lock exclusively. saveAsync() applies it off-thread.
    QMutexLocker m(&m_pendingMetaMutex);
    m_pendingMetadata = json;
    m_hasPendingMetadata = true;
}

void Wallet::flushPendingMetadata() {
    QString json;
    {
        QMutexLocker m(&m_pendingMetaMutex);
        if (!m_hasPendingMetadata)
            return;
        json = m_pendingMetadata;
        m_hasPendingMetadata = false;
    }
    QWriteLocker lock(&m_coreLock);
    aero_wallet_set_metadata(m_core, json.toUtf8().constData());
}

void Wallet::addToken(const TokenInfo &t) {
    {
        QWriteLocker lock(&m_coreLock); // mutates secrets.tokens
        aero_wallet_add_token(m_core, t.address.toUtf8().constData(),
                               t.symbol.toUtf8().constData(), t.decimals);
    }
    invalidateTokensCache(); // the tracked-token list actually changed here
}

void Wallet::removeToken(const QString &address) {
    {
        QWriteLocker lock(&m_coreLock); // mutates secrets.tokens
        aero_wallet_remove_token(m_core, address.toUtf8().constData());
    }
    invalidateTokensCache(); // the tracked-token list actually changed here
}

QVector<TokenInfo> Wallet::tokens() const {
    quint64 gen;
    {
        QMutexLocker c(&m_metaCacheMutex); // cache so UI reads don't block on the core lock (scan)
        if (m_tokensCacheValid)
            return m_tokensCache;
        gen = m_metaGen;
    }
    // Cache miss. NEVER block the UI thread on the core lock (a scan holds it exclusively for minutes:
    // a balance-update signal -> showCachedBalance() -> tokens() would otherwise freeze the whole app).
    // Try to read without waiting; if a writer holds the lock, return the last-known tokens (stale is
    // fine — the tracked list rarely changes; the next call after the writer refreshes it).
    if (!m_coreLock.tryLockForRead()) {
        QMutexLocker c(&m_metaCacheMutex);
        return m_tokensCache;
    }
    QVector<TokenInfo> out;
    {
        const QString json = takeString(aero_wallet_tokens(m_core));
        const QJsonArray arr = QJsonDocument::fromJson(json.toUtf8()).array();
        for (const QJsonValue &v : arr) {
            const QJsonObject o = v.toObject();
            TokenInfo t;
            t.address = o.value("address").toString();
            t.symbol = o.value("symbol").toString();
            t.decimals = static_cast<quint8>(o.value("decimals").toInt(18));
            out.append(t);
        }
    }
    m_coreLock.unlock();
    {
        QMutexLocker c(&m_metaCacheMutex);
        if (m_metaGen == gen) { // no mutation raced us — safe to cache
            m_tokensCache = out;
            m_tokensCacheValid = true;
        }
    }
    return out;
}

void Wallet::refreshFees() {
    QtConcurrent::run(&m_netPool, [this]() {
        QReadLocker lock(&m_coreLock);
        QString base, tip;
        char *feeJson = aero_wallet_suggest_fees(m_core);
        if (feeJson) {
            const QJsonObject o = QJsonDocument::fromJson(takeString(feeJson).toUtf8()).object();
            base = o.value("base_fee").toString();
            tip = o.value("max_priority_fee").toString();
        }
        QMetaObject::invokeMethod(this, [this, base, tip]() { emit feesUpdated(base, tip); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::createTransaction(quint32 fromIndex, const QString &to, const QString &amount,
                               const QString &token, const QString &maxFeeWei,
                               const QString &maxPriorityWei, quint8 decimals) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, to, amount, token, maxFeeWei, maxPriorityWei, decimals]() {
        QReadLocker lock(&m_coreLock);
        PendingEthTx tx;
        tx.fromIndex = fromIndex;
        tx.to = to;
        tx.token = token;

        if (!maxFeeWei.isEmpty()) {
            // Caller chose an explicit fee (a tier or custom).
            tx.fee.maxFee = maxFeeWei;
            tx.fee.maxPriorityFee = maxPriorityWei;
        } else {
            // Otherwise fetch the node's automatic suggestion for display + sending.
            char *feeJson = aero_wallet_suggest_fees(m_core);
            if (feeJson) {
                const QJsonObject o = QJsonDocument::fromJson(takeString(feeJson).toUtf8()).object();
                tx.fee.baseFee = o.value("base_fee").toString();
                tx.fee.maxPriorityFee = o.value("max_priority_fee").toString();
                tx.fee.maxFee = o.value("max_fee").toString();
            }
        }

        if (token.isEmpty()) {
            tx.amountWei = parseUnits(amount, 18);
        } else {
            // Prefer the caller-supplied decimals (from the Send picker, which resolves arbitrary
            // tokens on-chain); 0xFF means "unknown" so fall back to tracked-token metadata, then
            // 18. (0 is a valid decimals value for some tokens, so it must NOT mean "unknown".)
            quint8 dec = decimals;
            if (dec == 0xFF) {
                dec = 18;
                for (const TokenInfo &t : tokens())
                    if (t.address.compare(token, Qt::CaseInsensitive) == 0) dec = t.decimals;
            }
            tx.amountUnits = parseUnits(amount, dec);
        }

        QMetaObject::invokeMethod(this, [this, tx]() { emit transactionCreated(tx); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::commitTransaction(const PendingEthTx &tx) {
    QtConcurrent::run(&m_netPool, [this, tx]() {
        QReadLocker lock(&m_coreLock);
        // Hardware wallets require an on-device confirmation before the (blocking) broadcast.
        if (aero_wallet_is_hardware(m_core) != 0)
            QMetaObject::invokeMethod(this, [this]() { emit signingOnDevice(); },
                                      Qt::QueuedConnection);
        const QByteArray maxFee = tx.fee.maxFee.toUtf8();       // "" => automatic
        const QByteArray maxPriority = tx.fee.maxPriorityFee.toUtf8();
        char *res;
        if (tx.token.isEmpty()) {
            res = aero_wallet_send_eth(m_core, tx.fromIndex, tx.to.toUtf8().constData(),
                                        tx.amountWei.toUtf8().constData(),
                                        maxFee.constData(), maxPriority.constData(), tx.nonce);
        } else {
            res = aero_wallet_send_erc20(m_core, tx.fromIndex, tx.token.toUtf8().constData(),
                                          tx.to.toUtf8().constData(),
                                          tx.amountUnits.toUtf8().constData(),
                                          maxFee.constData(), maxPriority.constData(), tx.nonce);
        }

        bool success = res != nullptr;
        QString txHash, err;
        quint64 nonce = ~Q_UINT64_C(0);
        if (success) {
            const QJsonObject o = QJsonDocument::fromJson(takeString(res).toUtf8()).object();
            txHash = o.value("tx_hash").toString();
            nonce = static_cast<quint64>(o.value("nonce").toDouble());
        } else {
            err = takeLastError();
        }

        PendingEthTx sent = tx;
        sent.nonce = nonce;
        QMetaObject::invokeMethod(this, [this, success, txHash, err, sent]() {
            if (success)
                emit transactionSent(sent, txHash); // record for speed-up/cancel (carries nonce)
            emit transactionCommitted(success, txHash, err);
        }, Qt::QueuedConnection);
    });
}

void Wallet::cancelTransaction(quint32 fromIndex, quint64 nonce, const QString &maxFeeWei,
                               const QString &maxPriorityWei) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, nonce, maxFeeWei, maxPriorityWei]() {
        QReadLocker lock(&m_coreLock);
        const QByteArray mf = maxFeeWei.toUtf8();
        const QByteArray mp = maxPriorityWei.toUtf8();
        char *res = aero_wallet_cancel_tx(m_core, fromIndex, nonce, mf.constData(), mp.constData());
        bool success = res != nullptr;
        QString txHash, err;
        if (success)
            txHash = QJsonDocument::fromJson(takeString(res).toUtf8()).object()
                         .value("tx_hash").toString();
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, success, txHash, err]() {
            emit transactionCommitted(success, txHash, err);
        }, Qt::QueuedConnection);
    });
}

void Wallet::replaceTx(quint32 fromIndex, const QString &txHash, const QString &maxFeeWei,
                       const QString &maxPriorityWei, bool cancel) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, txHash, maxFeeWei, maxPriorityWei, cancel]() {
        QReadLocker lock(&m_coreLock);
        const QByteArray mf = maxFeeWei.toUtf8();
        const QByteArray mp = maxPriorityWei.toUtf8();
        char *res = aero_wallet_replace_tx(m_core, fromIndex, txHash.toUtf8().constData(),
                                           mf.constData(), mp.constData(), cancel);
        bool success = res != nullptr;
        QString newHash, err;
        if (success)
            newHash = QJsonDocument::fromJson(takeString(res).toUtf8()).object()
                          .value("tx_hash").toString();
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, success, newHash, err]() {
            emit transactionCommitted(success, newHash, err);
        }, Qt::QueuedConnection);
    });
}

void Wallet::broadcastRaw(const QString &rawHex) {
    QtConcurrent::run(&m_netPool, [this, rawHex]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_broadcast_raw(m_core, rawHex.trimmed().toUtf8().constData());
        bool success = res != nullptr;
        QString txHash, err;
        if (success)
            txHash = QJsonDocument::fromJson(takeString(res).toUtf8()).object()
                         .value("tx_hash").toString();
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, success, txHash, err]() {
            emit transactionCommitted(success, txHash, err);
        }, Qt::QueuedConnection);
    });
}

void Wallet::historicalPrice(const QString &symbol, const QString &date) {
    QtConcurrent::run(&m_netPool, [this, symbol, date]() {
        QReadLocker lock(&m_coreLock);
        double p = 0.0;
        char *j = aero_wallet_price_on_date(m_core, symbol.toUtf8().constData(),
                                            date.toUtf8().constData());
        if (j) {
            bool ok = false;
            const double v = takeString(j).toDouble(&ok);
            if (ok) p = v;
        }
        QMetaObject::invokeMethod(this,
                                  [this, symbol, date, p]() { emit historicalPriceReady(symbol, date, p); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::sendMany(quint32 fromIndex, const QVector<QPair<QString, QString>> &recipients,
                      const QString &token, quint8 decimals, const QString &maxFeeWei,
                      const QString &maxPriorityWei) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, recipients, token, decimals, maxFeeWei,
                                   maxPriorityWei]() {
        QJsonArray arr;
        for (const QPair<QString, QString> &r : recipients) {
            QJsonArray pair;
            pair.append(r.first);
            pair.append(parseUnits(r.second, decimals)); // human -> base units
            arr.append(pair);
        }
        const QByteArray rj = QJsonDocument(arr).toJson(QJsonDocument::Compact);
        const int nRecipients = recipients.size();
        QReadLocker lock(&m_coreLock);
        const QByteArray mf = maxFeeWei.toUtf8();
        const QByteArray mp = maxPriorityWei.toUtf8();
        QString json, err;
        if (token.isEmpty()) {
            // Native: send to everyone ATOMICALLY in one Multicall3 tx (all-or-nothing, no stranded
            // nonces). Synthesize the same result shape the sequential path emits so the UI handler
            // is unchanged (one entry = one broadcast tx covering all recipients).
            char *res = aero_wallet_send_many_native(m_core, fromIndex, rj.constData(),
                                                     mf.constData(), mp.constData());
            if (res) {
                const QString hash = QJsonDocument::fromJson(takeString(res).toUtf8()).object()
                                         .value("tx_hash").toString();
                QJsonArray a;
                QJsonObject o;
                o["to"] = QStringLiteral("%1 recipients (atomic batch)").arg(nRecipients);
                o["tx_hash"] = hash;
                a.append(o);
                json = QString::fromUtf8(QJsonDocument(a).toJson(QJsonDocument::Compact));
            } else {
                err = takeLastError();
            }
        } else {
            // ERC-20: sequential (one transfer per recipient); Multicall can't move your tokens.
            char *res = aero_wallet_send_many(m_core, fromIndex, rj.constData(),
                                              token.toUtf8().constData(), mf.constData(),
                                              mp.constData());
            if (res)
                json = takeString(res);
            else
                err = takeLastError();
        }
        QMetaObject::invokeMethod(this, [this, json, err]() { emit manySent(json, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::buildUnsigned(const PendingEthTx &tx) {
    QtConcurrent::run(&m_netPool, [this, tx]() {
        QReadLocker lock(&m_coreLock);
        const QByteArray maxFee = tx.fee.maxFee.toUtf8();
        const QByteArray maxPriority = tx.fee.maxPriorityFee.toUtf8();
        char *res = aero_wallet_build_unsigned(
            m_core, tx.fromIndex, tx.to.toUtf8().constData(), tx.amountWei.toUtf8().constData(),
            tx.token.toUtf8().constData(), tx.amountUnits.toUtf8().constData(), maxFee.constData(),
            maxPriority.constData(), tx.nonce);
        QString json, err;
        if (res)
            json = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, json, err]() { emit unsignedTxReady(json, err); },
                                  Qt::QueuedConnection);
    });
}

QString Wallet::signUnsigned(const QString &json) {
    QReadLocker lock(&m_coreLock); // signing reads the key (&self); no network needed
    char *res = aero_wallet_sign_unsigned(m_core, json.toUtf8().constData());
    if (!res) {
        m_errorString = takeLastError();
        return QString();
    }
    return takeString(res);
}

QString Wallet::parseUnits(const QString &amount, quint8 decimals) {
    return takeString(aero_parse_units(amount.toUtf8().constData(), decimals));
}

// ---------------------------------------------------------------------------------------------
// CoW Protocol swaps. All run on the bounded net pool. The Rust methods borrow the wallet as
// `&self` (they sign with a borrowed key; no struct mutation), so a shared read lock is correct —
// same as commitTransaction.

void Wallet::swapQuote(quint32 fromIndex, const QString &sellToken, const QString &buyToken,
                       const QString &sellAmountWei, bool sellIsNative) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, sellToken, buyToken, sellAmountWei,
                                   sellIsNative]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_swap_quote(m_core, fromIndex, sellToken.toUtf8().constData(),
                                           buyToken.toUtf8().constData(),
                                           sellAmountWei.toUtf8().constData(), sellIsNative);
        QString json, err;
        if (res)
            json = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, json, err]() { emit swapQuoteReady(json, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::swapAllowance(quint32 fromIndex, const QString &token) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, token]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_swap_allowance(m_core, fromIndex, token.toUtf8().constData());
        QString wei, err;
        if (res)
            wei = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, token, wei, err]() {
            emit swapAllowanceReady(token, wei, err);
        }, Qt::QueuedConnection);
    });
}

void Wallet::swapApprove(quint32 fromIndex, const QString &token, const QString &amountWei) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, token, amountWei]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_swap_approve(m_core, fromIndex, token.toUtf8().constData(),
                                             amountWei.toUtf8().constData());
        QString txHash, err;
        if (res)
            txHash = QJsonDocument::fromJson(takeString(res).toUtf8()).object()
                         .value("tx_hash").toString();
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, txHash, err]() { emit swapApproved(txHash, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::swapSubmit(quint32 fromIndex, const QString &quoteJson, quint32 slippageBps) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, quoteJson, slippageBps]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_swap_submit(m_core, fromIndex, quoteJson.toUtf8().constData(),
                                            slippageBps);
        QString uid, err;
        if (res)
            uid = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, uid, err]() { emit swapSubmitted(uid, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::swapEthFlow(quint32 fromIndex, const QString &quoteJson, const QString &buyToken,
                         quint32 slippageBps) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, quoteJson, buyToken, slippageBps]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_swap_eth_flow(m_core, fromIndex, quoteJson.toUtf8().constData(),
                                              buyToken.toUtf8().constData(), slippageBps);
        QString txHash, err;
        if (res)
            txHash = QJsonDocument::fromJson(takeString(res).toUtf8()).object()
                         .value("tx_hash").toString();
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, txHash, err]() { emit swapEthFlowSent(txHash, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::tokenAllowances(quint32 fromIndex, const QString &tokensJson,
                             const QString &spendersJson) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, tokensJson, spendersJson]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_token_allowances(m_core, fromIndex, tokensJson.toUtf8().constData(),
                                                 spendersJson.toUtf8().constData());
        QString json, err;
        if (res)
            json = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, json, err]() { emit tokenAllowancesReady(json, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::revokeApproval(quint32 fromIndex, const QString &token, const QString &spender) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, token, spender]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_revoke_approval(m_core, fromIndex, token.toUtf8().constData(),
                                                spender.toUtf8().constData());
        QString txHash, err;
        if (res)
            txHash = QJsonDocument::fromJson(takeString(res).toUtf8()).object()
                         .value("tx_hash").toString();
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, token, spender, txHash, err]() {
            emit approvalRevoked(token, spender, txHash, err);
        }, Qt::QueuedConnection);
    });
}

void Wallet::defillamaPrices(const QString &coinsCsv) {
    QtConcurrent::run(&m_netPool, [this, coinsCsv]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_defillama_prices(m_core, coinsCsv.toUtf8().constData());
        QString json, err;
        if (res)
            json = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, json, err]() { emit defillamaPricesReady(json, err); },
                                  Qt::QueuedConnection);
    });
}

// ---------------------------------------------------------------------------------------------
// Multi-router swap aggregator. All borrow the wallet as &self (sign with a borrowed key), so a
// shared read lock is correct — same as commitTransaction.

void Wallet::swapQuotes(quint32 fromIndex, const QString &sell, const QString &buy,
                        const QString &sellAmountWei, bool sellIsNative, quint8 sellDecimals,
                        quint8 buyDecimals, quint32 slippageBps) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, sell, buy, sellAmountWei, sellIsNative,
                                   sellDecimals, buyDecimals, slippageBps]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_swap_quotes(m_core, fromIndex, sell.toUtf8().constData(),
                                            buy.toUtf8().constData(),
                                            sellAmountWei.toUtf8().constData(), sellIsNative,
                                            sellDecimals, buyDecimals, slippageBps);
        QString json, err;
        if (res)
            json = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, json, err]() { emit swapQuotesReady(json, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::routerBuild(const QString &routerId, quint32 fromIndex, const QString &sell,
                         const QString &buy, const QString &sellAmountWei, bool sellIsNative,
                         quint8 sellDecimals, quint8 buyDecimals, quint32 slippageBps) {
    QtConcurrent::run(&m_netPool, [this, routerId, fromIndex, sell, buy, sellAmountWei, sellIsNative,
                                   sellDecimals, buyDecimals, slippageBps]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_router_build(m_core, routerId.toUtf8().constData(), fromIndex,
                                             sell.toUtf8().constData(), buy.toUtf8().constData(),
                                             sellAmountWei.toUtf8().constData(), sellIsNative,
                                             sellDecimals, buyDecimals, slippageBps);
        QString json, err;
        if (res)
            json = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, json, err]() { emit routerBuilt(json, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::routerAllowance(quint32 fromIndex, const QString &token, const QString &spender) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, token, spender]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_router_allowance(m_core, fromIndex, token.toUtf8().constData(),
                                                 spender.toUtf8().constData());
        QString wei, err;
        if (res)
            wei = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, token, spender, wei, err]() {
            emit routerAllowanceReady(token, spender, wei, err);
        }, Qt::QueuedConnection);
    });
}

void Wallet::routerApprove(quint32 fromIndex, const QString &token, const QString &spender,
                           const QString &amountWei) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, token, spender, amountWei]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_router_approve(m_core, fromIndex, token.toUtf8().constData(),
                                               spender.toUtf8().constData(),
                                               amountWei.toUtf8().constData());
        QString txHash, err;
        if (res)
            txHash = QJsonDocument::fromJson(takeString(res).toUtf8()).object()
                         .value("tx_hash").toString();
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, txHash, err]() { emit routerApproved(txHash, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::routerSwap(quint32 fromIndex, const QString &to, const QString &valueWei,
                        const QString &dataHex) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, to, valueWei, dataHex]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_router_swap(m_core, fromIndex, to.toUtf8().constData(),
                                            valueWei.toUtf8().constData(),
                                            dataHex.toUtf8().constData());
        QString txHash, err;
        if (res)
            txHash = QJsonDocument::fromJson(takeString(res).toUtf8()).object()
                         .value("tx_hash").toString();
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, txHash, err]() { emit routerSwapSent(txHash, err); },
                                  Qt::QueuedConnection);
    });
}

// --- Across cross-chain bridge -------------------------------------------------------------------

void Wallet::acrossQuote(quint32 fromIndex, const QString &symbol, quint64 destChainId,
                         const QString &amountWei) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, symbol, destChainId, amountWei]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_across_quote(m_core, fromIndex, symbol.toUtf8().constData(),
                                             destChainId, amountWei.toUtf8().constData());
        QString json, err;
        if (res)
            json = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, json, err]() { emit acrossQuoteReady(json, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::acrossBuild(quint32 fromIndex, const QString &symbol, quint64 destChainId,
                         const QString &amountWei) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, symbol, destChainId, amountWei]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_across_build(m_core, fromIndex, symbol.toUtf8().constData(),
                                             destChainId, amountWei.toUtf8().constData());
        QString json, err;
        if (res)
            json = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, json, err]() { emit acrossBuilt(json, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::bridgeAllowance(quint32 fromIndex, const QString &token, const QString &spender) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, token, spender]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_router_allowance(m_core, fromIndex, token.toUtf8().constData(),
                                                 spender.toUtf8().constData());
        QString wei, err;
        if (res)
            wei = takeString(res);
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, token, spender, wei, err]() {
            emit bridgeAllowanceReady(token, spender, wei, err);
        }, Qt::QueuedConnection);
    });
}

void Wallet::bridgeApprove(quint32 fromIndex, const QString &token, const QString &spender,
                           const QString &amountWei) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, token, spender, amountWei]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_router_approve(m_core, fromIndex, token.toUtf8().constData(),
                                               spender.toUtf8().constData(),
                                               amountWei.toUtf8().constData());
        QString txHash, err;
        if (res)
            txHash = QJsonDocument::fromJson(takeString(res).toUtf8()).object()
                         .value("tx_hash").toString();
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, txHash, err]() { emit bridgeApproved(txHash, err); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::bridgeSend(quint32 fromIndex, const QString &to, const QString &valueWei,
                        const QString &dataHex) {
    QtConcurrent::run(&m_netPool, [this, fromIndex, to, valueWei, dataHex]() {
        QReadLocker lock(&m_coreLock);
        char *res = aero_wallet_router_swap(m_core, fromIndex, to.toUtf8().constData(),
                                            valueWei.toUtf8().constData(),
                                            dataHex.toUtf8().constData());
        QString txHash, err;
        if (res)
            txHash = QJsonDocument::fromJson(takeString(res).toUtf8()).object()
                         .value("tx_hash").toString();
        else
            err = takeLastError();
        QMetaObject::invokeMethod(this, [this, txHash, err]() { emit bridgeSent(txHash, err); },
                                  Qt::QueuedConnection);
    });
}
