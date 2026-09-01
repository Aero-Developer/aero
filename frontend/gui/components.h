// SPDX-License-Identifier: BSD-3-Clause
// Stand-ins for Feather's promoted label widgets + the InfoFrame (icon + message banner),
// so the original Feather .ui files compile and look identical.
#ifndef AERO_COMPONENTS_H
#define AERO_COMPONENTS_H

#include <QFrame>
#include <QLabel>
#include <QMouseEvent>
#include <QString>

class QPushButton;

// ---- Portable-mode data locations (Electrum-style) -----------------------------------------
// When portable, Aero keeps ALL of its data (wallets + settings) next to the executable, so an
// unzipped build is fully self-contained and leaves nothing in Documents or the registry.
// Portable is enabled by launching with `--portable` or by shipping a `portable` marker file next
// to the executable (the portable release does the latter).
bool aeroIsPortable();

// Root data directory:  portable => <exe dir> ;  otherwise => <Documents>/Aero.
QString aeroDataRoot();

// Wallets directory:  <dataRoot>/wallets  (each wallet in its own <name>/<name>.keys subfolder).
QString aeroWalletsRoot();

// Where legacy flat *.aero/*.plume wallets are looked for (portable => exe dir, else Documents).
QString aeroLegacyRoot();

class ClickableLabel : public QLabel
{
    Q_OBJECT
public:
    explicit ClickableLabel(QWidget *parent = nullptr, Qt::WindowFlags f = Qt::WindowFlags())
        : QLabel(parent) { Q_UNUSED(f); }

signals:
    void clicked();

protected:
    void mousePressEvent(QMouseEvent *event) override {
        if (event->button() == Qt::LeftButton)
            emit clicked();
        QLabel::mousePressEvent(event);
    }
};

class HelpLabel : public QLabel
{
    Q_OBJECT
public:
    explicit HelpLabel(QWidget *parent = nullptr) : QLabel(parent) {}
};

// Feather's InfoFrame: a framed row with a 32px icon on the left and a wrapped message -
// used for the "encrypted with a password" (lock) banner, seed warning, etc.
class InfoFrame : public QFrame
{
    Q_OBJECT
public:
    explicit InfoFrame(QWidget *parent = nullptr);
    void setInfo(const QIcon &icon, const QString &text);
    void setText(const QString &text);

private:
    QPushButton *m_icon;
    QLabel *m_infoLabel;
};

#endif // AERO_COMPONENTS_H
