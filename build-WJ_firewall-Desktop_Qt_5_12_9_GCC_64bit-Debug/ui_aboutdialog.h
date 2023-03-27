/********************************************************************************
** Form generated from reading UI file 'aboutdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.9
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_ABOUTDIALOG_H
#define UI_ABOUTDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>

QT_BEGIN_NAMESPACE

class Ui_aboutdialog
{
public:
    QPushButton *pushButton_ok;
    QLabel *label;

    void setupUi(QDialog *aboutdialog)
    {
        if (aboutdialog->objectName().isEmpty())
            aboutdialog->setObjectName(QString::fromUtf8("aboutdialog"));
        aboutdialog->resize(420, 300);
        pushButton_ok = new QPushButton(aboutdialog);
        pushButton_ok->setObjectName(QString::fromUtf8("pushButton_ok"));
        pushButton_ok->setGeometry(QRect(170, 250, 80, 30));
        pushButton_ok->setMinimumSize(QSize(80, 30));
        pushButton_ok->setMaximumSize(QSize(80, 30));
        label = new QLabel(aboutdialog);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(60, 30, 300, 201));
        label->setMinimumSize(QSize(300, 0));
        label->setMaximumSize(QSize(300, 16777215));

        retranslateUi(aboutdialog);

        QMetaObject::connectSlotsByName(aboutdialog);
    } // setupUi

    void retranslateUi(QDialog *aboutdialog)
    {
        aboutdialog->setWindowTitle(QApplication::translate("aboutdialog", "About", nullptr));
        pushButton_ok->setText(QApplication::translate("aboutdialog", "\347\241\256\345\256\232", nullptr));
        label->setText(QApplication::translate("aboutdialog", "TextLabel", nullptr));
    } // retranslateUi

};

namespace Ui {
    class aboutdialog: public Ui_aboutdialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_ABOUTDIALOG_H
