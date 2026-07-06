// SPDX-License-Identifier: BSD-3-Clause
// Stand-ins for Feather's promoted label widgets + the InfoFrame (icon + message banner),
// so the original Feather .ui files compile and look identical.
#ifndef AERO_COMPONENTS_H
#define AERO_COMPONENTS_H

#include <QFrame>
#include <QLabel>
#include <QMouseEvent>

class QPushButton;

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

// Feather's InfoFrame: a framed row with a 32px icon on the left and a wrapped message —
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
