// SPDX-License-Identifier: BSD-3-Clause
#include "Wallet.h"

#include <algorithm>

#include <QtConcurrent/QtConcurrent>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QReadLocker>
#include <QSet>
#include <QWriteLocker>

namespace {
// Wrap a aero_core char* result into a QString and free it.
QString takeString(char *s) {
    if (!s) return QString();
    QString out = QString::fromUtf8(s);
    aero_string_free(s);
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
    : QObject(parent), m_core(core) {}

Wallet::~Wallet() {
    if (m_core) {
        // Wait for any in-flight background task (all of which take m_coreLock while touching
        // m_core) to finish before freeing, so we never free the core out from under a worker
        // thread. New tasks aren't spawned during destruction (that only happens on this thread).
        QWriteLocker lock(&m_coreLock);
        aero_wallet_free(m_core);
        m_core = nullptr;
    }
}

QString Wallet::takeLastError() const {
    return takeString(aero_last_error());
}

QString Wallet::address(quint32 index) const {
    QReadLocker lock(&m_coreLock);
    return takeString(aero_wallet_address(m_core, index));
}

quint32 Wallet::numAccounts() const {
    QReadLocker lock(&m_coreLock);
    return aero_wallet_account_count(m_core);
}

quint32 Wallet::addAccount() {
    QWriteLocker lock(&m_coreLock); // mutates secrets.account_count
    return aero_wallet_add_account(m_core);
}

quint32 Wallet::importPrivateKey(const QString &hexKey) {
    QWriteLocker lock(&m_coreLock); // mutates secrets.imported_keys
    quint32 idx = aero_wallet_import_private_key(m_core, hexKey.toUtf8().constData());
    if (idx == 0xFFFFFFFFu) {
        m_status = Status_Error;
        m_errorString = takeLastError();
    }
    return idx;
}

QString Wallet::exportPrivateKey(quint32 index) const {
    QReadLocker lock(&m_coreLock);
    return takeString(aero_wallet_export_private_key(m_core, index));
}

bool Wallet::isHardware() const {
    QReadLocker lock(&m_coreLock);
    return aero_wallet_is_hardware(m_core) != 0;
}

QString Wallet::hwKind() const {
    QReadLocker lock(&m_coreLock);
    return takeString(aero_wallet_hw_kind(m_core));
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
    return takeString(aero_wallet_mnemonic(m_core));
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
    QtConcurrent::run([this, chainId, endpoints, socksProxy]() {
        QJsonArray arr;
        for (const QString &e : endpoints) arr.append(e);
        const QByteArray endpointsJson = QJsonDocument(arr).toJson(QJsonDocument::Compact);

        // Configure the given proxy ("" = direct) then probe connectivity with a real RPC call.
        // A direct connection must explicitly allow clearnet (the core refuses otherwise).
        // Hold the write lock across set_provider + probe so no read runs against a half-swapped
        // provider (this is the chain-switch data race).
        auto tryMode = [&](const QString &proxy) -> bool {
            QWriteLocker lock(&m_coreLock);
            const QByteArray p = proxy.toUtf8();
            int rc = aero_wallet_set_provider(m_core, chainId, endpointsJson.constData(),
                                               proxy.isEmpty() ? nullptr : p.constData(),
                                               proxy.isEmpty(), 30);
            if (rc != 0)
                return false;
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
        } else {
            mode = 0;
            message = takeLastError();
            if (message.isEmpty())
                message = tr("Offline — no RPC reachable over Tor");
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
    QtConcurrent::run([this, index, token]() {
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

void Wallet::refresh(quint32 accountIndex) {
    // Network I/O runs off the UI thread; results are marshalled back via queued signals.
    QtConcurrent::run([this, accountIndex]() {
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
    QtConcurrent::run([this, accountIndex]() {
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
    QtConcurrent::run([this]() {
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
    QtConcurrent::run([this]() {
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
    QtConcurrent::run([this]() {
        QReadLocker lock(&m_coreLock);
        const quint64 n = aero_wallet_block_number(m_core);
        QMetaObject::invokeMethod(this, [this, n]() { emit blockNumberUpdated(n); },
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
        out.append(h);
    }
}

void Wallet::refreshHistory(quint32 accountIndex, const QString &fromBlock) {
    Q_UNUSED(fromBlock);
    QtConcurrent::run([this, accountIndex]() {
        QReadLocker lock(&m_coreLock);
        // Full native + token history from the block explorer (over Tor) in one call.
        QVector<HistoryItem> items;
        char *j = aero_wallet_account_history(m_core, accountIndex);
        if (j)
            parseHistoryArray(takeString(j), items);
        QMetaObject::invokeMethod(this, [this, items]() { emit historyRefreshed(items); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::refreshHistoryAll(quint32 numAccounts) {
    QtConcurrent::run([this, numAccounts]() {
        QReadLocker lock(&m_coreLock);
        QVector<HistoryItem> items;
        QSet<QString> seen;
        for (quint32 a = 0; a < numAccounts; ++a) {
            char *j = aero_wallet_account_history(m_core, a);
            if (!j)
                continue;
            QVector<HistoryItem> part;
            parseHistoryArray(takeString(j), part);
            for (const HistoryItem &h : part) {
                // Dedup across accounts (e.g. an internal transfer between two of the user's own
                // addresses would otherwise appear once per side).
                const QString key = QStringLiteral("%1|%2|%3|%4")
                                        .arg(h.txHash, h.token, h.direction, h.amount);
                if (seen.contains(key))
                    continue;
                seen.insert(key);
                items.append(h);
            }
        }
        std::sort(items.begin(), items.end(),
                  [](const HistoryItem &a, const HistoryItem &b) { return a.block > b.block; });
        QMetaObject::invokeMethod(this, [this, items]() { emit historyRefreshed(items); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::scanFunded(quint32 gapLimit) {
    QtConcurrent::run([this, gapLimit]() {
        QReadLocker lock(&m_coreLock);
        QList<quint32> indices;
        char *j = aero_wallet_scan_funded(m_core, gapLimit);
        if (j) {
            const QJsonArray arr = QJsonDocument::fromJson(takeString(j).toUtf8()).array();
            for (const QJsonValue &v : arr)
                indices.append(static_cast<quint32>(v.toDouble()));
        }
        QMetaObject::invokeMethod(this, [this, indices]() { emit fundedScanned(indices); },
                                  Qt::QueuedConnection);
    });
}

void Wallet::checkTokenLiquidity(const QString &tokenAddress) {
    QtConcurrent::run([this, tokenAddress]() {
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
    QtConcurrent::run([this, accountIndex]() {
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
    QtConcurrent::run([this, url]() {
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
    QtConcurrent::run([this, address]() {
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
    QtConcurrent::run([this, currency]() {
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

void Wallet::addToken(const TokenInfo &t) {
    QWriteLocker lock(&m_coreLock); // mutates secrets.tokens
    aero_wallet_add_token(m_core, t.address.toUtf8().constData(),
                           t.symbol.toUtf8().constData(), t.decimals);
}

void Wallet::removeToken(const QString &address) {
    QWriteLocker lock(&m_coreLock); // mutates secrets.tokens
    aero_wallet_remove_token(m_core, address.toUtf8().constData());
}

QVector<TokenInfo> Wallet::tokens() const {
    QReadLocker lock(&m_coreLock);
    QVector<TokenInfo> out;
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
    return out;
}

void Wallet::refreshFees() {
    QtConcurrent::run([this]() {
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
    QtConcurrent::run([this, fromIndex, to, amount, token, maxFeeWei, maxPriorityWei, decimals]() {
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
    QtConcurrent::run([this, tx]() {
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
                                        maxFee.constData(), maxPriority.constData());
        } else {
            res = aero_wallet_send_erc20(m_core, tx.fromIndex, tx.token.toUtf8().constData(),
                                          tx.to.toUtf8().constData(),
                                          tx.amountUnits.toUtf8().constData(),
                                          maxFee.constData(), maxPriority.constData());
        }

        bool success = res != nullptr;
        QString txHash, err;
        if (success) {
            const QJsonObject o = QJsonDocument::fromJson(takeString(res).toUtf8()).object();
            txHash = o.value("tx_hash").toString();
        } else {
            err = takeLastError();
        }

        QMetaObject::invokeMethod(this, [this, success, txHash, err]() {
            emit transactionCommitted(success, txHash, err);
        }, Qt::QueuedConnection);
    });
}

QString Wallet::parseUnits(const QString &amount, quint8 decimals) {
    return takeString(aero_parse_units(amount.toUtf8().constData(), decimals));
}
