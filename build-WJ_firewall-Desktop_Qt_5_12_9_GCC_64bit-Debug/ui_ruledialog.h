/********************************************************************************
** Form generated from reading UI file 'ruledialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.9
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_RULEDIALOG_H
#define UI_RULEDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTimeEdit>

QT_BEGIN_NAMESPACE

class Ui_RuleDialog
{
public:
    QPushButton *pushButton_ok;
    QPushButton *pushButton_cancel;
    QLabel *label;
    QLabel *label_2;
    QLabel *label_3;
    QLabel *label_4;
    QLineEdit *lineEdit_src_ip;
    QLineEdit *lineEdit_src_port;
    QLineEdit *lineEdit_dst_port;
    QLineEdit *lineEdit_dst_ip;
    QComboBox *comboBox_time;
    QLabel *label_5;
    QLabel *label_6;
    QComboBox *comboBox_protocol;
    QLabel *label_7;
    QTimeEdit *timeEdit;
    QLabel *label_8;
    QTimeEdit *timeEdit_2;

    void setupUi(QDialog *RuleDialog)
    {
        if (RuleDialog->objectName().isEmpty())
            RuleDialog->setObjectName(QString::fromUtf8("RuleDialog"));
        RuleDialog->resize(600, 250);
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(RuleDialog->sizePolicy().hasHeightForWidth());
        RuleDialog->setSizePolicy(sizePolicy);
        RuleDialog->setMinimumSize(QSize(600, 250));
        RuleDialog->setMaximumSize(QSize(600, 250));
        pushButton_ok = new QPushButton(RuleDialog);
        pushButton_ok->setObjectName(QString::fromUtf8("pushButton_ok"));
        pushButton_ok->setGeometry(QRect(400, 200, 60, 25));
        pushButton_cancel = new QPushButton(RuleDialog);
        pushButton_cancel->setObjectName(QString::fromUtf8("pushButton_cancel"));
        pushButton_cancel->setGeometry(QRect(490, 200, 60, 25));
        label = new QLabel(RuleDialog);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(40, 20, 67, 25));
        label_2 = new QLabel(RuleDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setGeometry(QRect(40, 60, 67, 25));
        label_3 = new QLabel(RuleDialog);
        label_3->setObjectName(QString::fromUtf8("label_3"));
        label_3->setGeometry(QRect(320, 20, 71, 25));
        label_4 = new QLabel(RuleDialog);
        label_4->setObjectName(QString::fromUtf8("label_4"));
        label_4->setGeometry(QRect(320, 60, 71, 25));
        lineEdit_src_ip = new QLineEdit(RuleDialog);
        lineEdit_src_ip->setObjectName(QString::fromUtf8("lineEdit_src_ip"));
        lineEdit_src_ip->setGeometry(QRect(110, 20, 150, 25));
        lineEdit_src_port = new QLineEdit(RuleDialog);
        lineEdit_src_port->setObjectName(QString::fromUtf8("lineEdit_src_port"));
        lineEdit_src_port->setGeometry(QRect(110, 60, 150, 25));
        lineEdit_dst_port = new QLineEdit(RuleDialog);
        lineEdit_dst_port->setObjectName(QString::fromUtf8("lineEdit_dst_port"));
        lineEdit_dst_port->setGeometry(QRect(400, 60, 150, 25));
        lineEdit_dst_ip = new QLineEdit(RuleDialog);
        lineEdit_dst_ip->setObjectName(QString::fromUtf8("lineEdit_dst_ip"));
        lineEdit_dst_ip->setGeometry(QRect(399, 20, 151, 25));
        comboBox_time = new QComboBox(RuleDialog);
        comboBox_time->setObjectName(QString::fromUtf8("comboBox_time"));
        comboBox_time->setGeometry(QRect(110, 110, 150, 25));
        sizePolicy.setHeightForWidth(comboBox_time->sizePolicy().hasHeightForWidth());
        comboBox_time->setSizePolicy(sizePolicy);
        label_5 = new QLabel(RuleDialog);
        label_5->setObjectName(QString::fromUtf8("label_5"));
        label_5->setGeometry(QRect(40, 110, 67, 25));
        label_6 = new QLabel(RuleDialog);
        label_6->setObjectName(QString::fromUtf8("label_6"));
        label_6->setGeometry(QRect(320, 110, 67, 25));
        comboBox_protocol = new QComboBox(RuleDialog);
        comboBox_protocol->setObjectName(QString::fromUtf8("comboBox_protocol"));
        comboBox_protocol->setGeometry(QRect(400, 110, 150, 25));
        sizePolicy.setHeightForWidth(comboBox_protocol->sizePolicy().hasHeightForWidth());
        comboBox_protocol->setSizePolicy(sizePolicy);
        label_7 = new QLabel(RuleDialog);
        label_7->setObjectName(QString::fromUtf8("label_7"));
        label_7->setGeometry(QRect(40, 150, 80, 25));
        timeEdit = new QTimeEdit(RuleDialog);
        timeEdit->setObjectName(QString::fromUtf8("timeEdit"));
        timeEdit->setGeometry(QRect(130, 150, 130, 26));
        timeEdit->setAlignment(Qt::AlignCenter);
        label_8 = new QLabel(RuleDialog);
        label_8->setObjectName(QString::fromUtf8("label_8"));
        label_8->setGeometry(QRect(320, 150, 80, 25));
        timeEdit_2 = new QTimeEdit(RuleDialog);
        timeEdit_2->setObjectName(QString::fromUtf8("timeEdit_2"));
        timeEdit_2->setGeometry(QRect(420, 150, 130, 26));
        timeEdit_2->setAlignment(Qt::AlignCenter);

        retranslateUi(RuleDialog);

        QMetaObject::connectSlotsByName(RuleDialog);
    } // setupUi

    void retranslateUi(QDialog *RuleDialog)
    {
        RuleDialog->setWindowTitle(QApplication::translate("RuleDialog", "\346\267\273\345\212\240\350\247\204\345\210\231", nullptr));
        pushButton_ok->setText(QApplication::translate("RuleDialog", "\347\241\256\345\256\232", nullptr));
        pushButton_cancel->setText(QApplication::translate("RuleDialog", "\345\217\226\346\266\210", nullptr));
        label->setText(QApplication::translate("RuleDialog", "\346\272\220\345\234\260\345\235\200\357\274\232", nullptr));
        label_2->setText(QApplication::translate("RuleDialog", "\346\272\220\347\253\257\345\217\243\357\274\232", nullptr));
        label_3->setText(QApplication::translate("RuleDialog", "\347\233\256\347\232\204\345\234\260\345\235\200\357\274\232", nullptr));
        label_4->setText(QApplication::translate("RuleDialog", "\347\233\256\347\232\204\347\253\257\345\217\243\357\274\232", nullptr));
        lineEdit_src_ip->setText(QApplication::translate("RuleDialog", "any", nullptr));
        lineEdit_src_port->setText(QApplication::translate("RuleDialog", "any", nullptr));
        lineEdit_dst_port->setText(QApplication::translate("RuleDialog", "any", nullptr));
        lineEdit_dst_ip->setText(QApplication::translate("RuleDialog", "any", nullptr));
        label_5->setText(QApplication::translate("RuleDialog", "\346\227\266\351\227\264\357\274\232", nullptr));
        label_6->setText(QApplication::translate("RuleDialog", "\345\215\217\350\256\256\357\274\232", nullptr));
        label_7->setText(QApplication::translate("RuleDialog", "\345\274\200\345\247\213\346\227\266\351\227\264\357\274\232", nullptr));
        label_8->setText(QApplication::translate("RuleDialog", "\347\273\223\346\235\237\346\227\266\351\227\264\357\274\232", nullptr));
    } // retranslateUi

};

namespace Ui {
    class RuleDialog: public Ui_RuleDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_RULEDIALOG_H
