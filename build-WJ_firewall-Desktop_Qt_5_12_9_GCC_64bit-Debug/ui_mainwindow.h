/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.12.9
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QFrame>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QAction *action_importRules;
    QAction *action_exportRules;
    QAction *action_exitAPP;
    QAction *action_about;
    QWidget *centralWidget;
    QVBoxLayout *verticalLayout;
    QHBoxLayout *horizontalLayout_2;
    QPushButton *pushButton_addRule;
    QSpacerItem *horizontalSpacer;
    QPushButton *pushButton_modRule;
    QSpacerItem *horizontalSpacer_9;
    QPushButton *pushButton_delRule;
    QSpacerItem *horizontalSpacer_5;
    QFrame *line_3;
    QSpacerItem *horizontalSpacer_6;
    QPushButton *pushButton_addTrust;
    QSpacerItem *horizontalSpacer_10;
    QPushButton *pushButton_modTrust;
    QSpacerItem *horizontalSpacer_4;
    QPushButton *pushButton_delTrust;
    QFrame *line;
    QHBoxLayout *horizontalLayout;
    QTabWidget *tabWidget;
    QWidget *tab_1;
    QVBoxLayout *verticalLayout_2;
    QTableWidget *tableWidget;
    QWidget *tab;
    QVBoxLayout *verticalLayout_5;
    QTableWidget *tableWidget_trust;
    QWidget *tab_2;
    QVBoxLayout *verticalLayout_3;
    QPushButton *pushButton_logClean;
    QPlainTextEdit *plainTextEdit;
    QHBoxLayout *horizontalLayout_7;
    QSpacerItem *horizontalSpacer_3;
    QSpacerItem *horizontalSpacer_8;
    QSpacerItem *horizontalSpacer_12;
    QSpacerItem *horizontalSpacer_2;
    QPushButton *pushButton_fiterOn;
    QSpacerItem *horizontalSpacer_7;
    QPushButton *pushButton_fiterOff;
    QMenuBar *menuBar;
    QMenu *menu_file;
    QMenu *menu_help;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->resize(1000, 600);
        MainWindow->setMinimumSize(QSize(1000, 600));
        MainWindow->setMaximumSize(QSize(1000, 600));
        action_importRules = new QAction(MainWindow);
        action_importRules->setObjectName(QString::fromUtf8("action_importRules"));
        action_exportRules = new QAction(MainWindow);
        action_exportRules->setObjectName(QString::fromUtf8("action_exportRules"));
        action_exitAPP = new QAction(MainWindow);
        action_exitAPP->setObjectName(QString::fromUtf8("action_exitAPP"));
        action_about = new QAction(MainWindow);
        action_about->setObjectName(QString::fromUtf8("action_about"));
        centralWidget = new QWidget(MainWindow);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        verticalLayout = new QVBoxLayout(centralWidget);
        verticalLayout->setSpacing(6);
        verticalLayout->setContentsMargins(11, 11, 11, 11);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setSpacing(20);
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        pushButton_addRule = new QPushButton(centralWidget);
        pushButton_addRule->setObjectName(QString::fromUtf8("pushButton_addRule"));
        pushButton_addRule->setMinimumSize(QSize(100, 30));
        pushButton_addRule->setMaximumSize(QSize(100, 30));

        horizontalLayout_2->addWidget(pushButton_addRule);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);

        pushButton_modRule = new QPushButton(centralWidget);
        pushButton_modRule->setObjectName(QString::fromUtf8("pushButton_modRule"));
        pushButton_modRule->setMinimumSize(QSize(100, 30));
        pushButton_modRule->setMaximumSize(QSize(100, 30));

        horizontalLayout_2->addWidget(pushButton_modRule);

        horizontalSpacer_9 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_9);

        pushButton_delRule = new QPushButton(centralWidget);
        pushButton_delRule->setObjectName(QString::fromUtf8("pushButton_delRule"));
        pushButton_delRule->setMinimumSize(QSize(100, 30));
        pushButton_delRule->setMaximumSize(QSize(100, 30));

        horizontalLayout_2->addWidget(pushButton_delRule);

        horizontalSpacer_5 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_5);

        line_3 = new QFrame(centralWidget);
        line_3->setObjectName(QString::fromUtf8("line_3"));
        line_3->setFrameShape(QFrame::VLine);
        line_3->setFrameShadow(QFrame::Sunken);

        horizontalLayout_2->addWidget(line_3);

        horizontalSpacer_6 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_6);

        pushButton_addTrust = new QPushButton(centralWidget);
        pushButton_addTrust->setObjectName(QString::fromUtf8("pushButton_addTrust"));
        pushButton_addTrust->setMinimumSize(QSize(100, 30));
        pushButton_addTrust->setMaximumSize(QSize(100, 30));

        horizontalLayout_2->addWidget(pushButton_addTrust);

        horizontalSpacer_10 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_10);

        pushButton_modTrust = new QPushButton(centralWidget);
        pushButton_modTrust->setObjectName(QString::fromUtf8("pushButton_modTrust"));
        pushButton_modTrust->setMinimumSize(QSize(100, 30));
        pushButton_modTrust->setMaximumSize(QSize(100, 30));

        horizontalLayout_2->addWidget(pushButton_modTrust);

        horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_4);

        pushButton_delTrust = new QPushButton(centralWidget);
        pushButton_delTrust->setObjectName(QString::fromUtf8("pushButton_delTrust"));
        pushButton_delTrust->setMinimumSize(QSize(100, 30));
        pushButton_delTrust->setMaximumSize(QSize(100, 30));

        horizontalLayout_2->addWidget(pushButton_delTrust);


        verticalLayout->addLayout(horizontalLayout_2);

        line = new QFrame(centralWidget);
        line->setObjectName(QString::fromUtf8("line"));
        line->setFrameShape(QFrame::HLine);
        line->setFrameShadow(QFrame::Sunken);

        verticalLayout->addWidget(line);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setSpacing(6);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        tabWidget = new QTabWidget(centralWidget);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        tabWidget->setStyleSheet(QString::fromUtf8("QTabBar::tab:selected{background-color:  white;}\n"
"QTabBar::tab:!selected{background-color: rgb(239, 235, 231);}\n"
"QTabBar::tab{min-width:80px; min-height:28px; border: 1px solid rgb(188, 185, 181); margin-bottom:1px;}"));
        tab_1 = new QWidget();
        tab_1->setObjectName(QString::fromUtf8("tab_1"));
        tab_1->setFocusPolicy(Qt::NoFocus);
        tab_1->setStyleSheet(QString::fromUtf8(""));
        verticalLayout_2 = new QVBoxLayout(tab_1);
        verticalLayout_2->setSpacing(0);
        verticalLayout_2->setContentsMargins(11, 11, 11, 11);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        verticalLayout_2->setContentsMargins(0, 0, 0, 0);
        tableWidget = new QTableWidget(tab_1);
        if (tableWidget->columnCount() < 10)
            tableWidget->setColumnCount(10);
        QTableWidgetItem *__qtablewidgetitem = new QTableWidgetItem();
        __qtablewidgetitem->setTextAlignment(Qt::AlignCenter);
        tableWidget->setHorizontalHeaderItem(0, __qtablewidgetitem);
        QTableWidgetItem *__qtablewidgetitem1 = new QTableWidgetItem();
        __qtablewidgetitem1->setTextAlignment(Qt::AlignCenter);
        tableWidget->setHorizontalHeaderItem(1, __qtablewidgetitem1);
        QTableWidgetItem *__qtablewidgetitem2 = new QTableWidgetItem();
        __qtablewidgetitem2->setTextAlignment(Qt::AlignCenter);
        tableWidget->setHorizontalHeaderItem(2, __qtablewidgetitem2);
        QTableWidgetItem *__qtablewidgetitem3 = new QTableWidgetItem();
        __qtablewidgetitem3->setTextAlignment(Qt::AlignCenter);
        tableWidget->setHorizontalHeaderItem(3, __qtablewidgetitem3);
        QTableWidgetItem *__qtablewidgetitem4 = new QTableWidgetItem();
        __qtablewidgetitem4->setTextAlignment(Qt::AlignCenter);
        tableWidget->setHorizontalHeaderItem(4, __qtablewidgetitem4);
        QTableWidgetItem *__qtablewidgetitem5 = new QTableWidgetItem();
        __qtablewidgetitem5->setTextAlignment(Qt::AlignCenter);
        tableWidget->setHorizontalHeaderItem(5, __qtablewidgetitem5);
        QTableWidgetItem *__qtablewidgetitem6 = new QTableWidgetItem();
        __qtablewidgetitem6->setTextAlignment(Qt::AlignCenter);
        tableWidget->setHorizontalHeaderItem(6, __qtablewidgetitem6);
        QTableWidgetItem *__qtablewidgetitem7 = new QTableWidgetItem();
        __qtablewidgetitem7->setTextAlignment(Qt::AlignCenter);
        tableWidget->setHorizontalHeaderItem(7, __qtablewidgetitem7);
        QTableWidgetItem *__qtablewidgetitem8 = new QTableWidgetItem();
        __qtablewidgetitem8->setTextAlignment(Qt::AlignCenter);
        tableWidget->setHorizontalHeaderItem(8, __qtablewidgetitem8);
        QTableWidgetItem *__qtablewidgetitem9 = new QTableWidgetItem();
        __qtablewidgetitem9->setTextAlignment(Qt::AlignCenter);
        tableWidget->setHorizontalHeaderItem(9, __qtablewidgetitem9);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
        tableWidget->setStyleSheet(QString::fromUtf8("margin:-1px;"));
        tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableWidget->horizontalHeader()->setMinimumSectionSize(60);
        tableWidget->horizontalHeader()->setDefaultSectionSize(85);
        tableWidget->horizontalHeader()->setHighlightSections(false);
        tableWidget->horizontalHeader()->setStretchLastSection(true);
        tableWidget->verticalHeader()->setVisible(false);
        tableWidget->verticalHeader()->setMinimumSectionSize(30);
        tableWidget->verticalHeader()->setHighlightSections(false);

        verticalLayout_2->addWidget(tableWidget);

        tabWidget->addTab(tab_1, QString());
        tab = new QWidget();
        tab->setObjectName(QString::fromUtf8("tab"));
        verticalLayout_5 = new QVBoxLayout(tab);
        verticalLayout_5->setSpacing(0);
        verticalLayout_5->setContentsMargins(11, 11, 11, 11);
        verticalLayout_5->setObjectName(QString::fromUtf8("verticalLayout_5"));
        verticalLayout_5->setContentsMargins(0, 0, 0, 0);
        tableWidget_trust = new QTableWidget(tab);
        if (tableWidget_trust->columnCount() < 10)
            tableWidget_trust->setColumnCount(10);
        QTableWidgetItem *__qtablewidgetitem10 = new QTableWidgetItem();
        __qtablewidgetitem10->setTextAlignment(Qt::AlignCenter);
        tableWidget_trust->setHorizontalHeaderItem(0, __qtablewidgetitem10);
        QTableWidgetItem *__qtablewidgetitem11 = new QTableWidgetItem();
        __qtablewidgetitem11->setTextAlignment(Qt::AlignCenter);
        tableWidget_trust->setHorizontalHeaderItem(1, __qtablewidgetitem11);
        QTableWidgetItem *__qtablewidgetitem12 = new QTableWidgetItem();
        __qtablewidgetitem12->setTextAlignment(Qt::AlignCenter);
        tableWidget_trust->setHorizontalHeaderItem(2, __qtablewidgetitem12);
        QTableWidgetItem *__qtablewidgetitem13 = new QTableWidgetItem();
        __qtablewidgetitem13->setTextAlignment(Qt::AlignCenter);
        tableWidget_trust->setHorizontalHeaderItem(3, __qtablewidgetitem13);
        QTableWidgetItem *__qtablewidgetitem14 = new QTableWidgetItem();
        __qtablewidgetitem14->setTextAlignment(Qt::AlignCenter);
        tableWidget_trust->setHorizontalHeaderItem(4, __qtablewidgetitem14);
        QTableWidgetItem *__qtablewidgetitem15 = new QTableWidgetItem();
        __qtablewidgetitem15->setTextAlignment(Qt::AlignCenter);
        tableWidget_trust->setHorizontalHeaderItem(5, __qtablewidgetitem15);
        QTableWidgetItem *__qtablewidgetitem16 = new QTableWidgetItem();
        __qtablewidgetitem16->setTextAlignment(Qt::AlignCenter);
        tableWidget_trust->setHorizontalHeaderItem(6, __qtablewidgetitem16);
        QTableWidgetItem *__qtablewidgetitem17 = new QTableWidgetItem();
        __qtablewidgetitem17->setTextAlignment(Qt::AlignCenter);
        tableWidget_trust->setHorizontalHeaderItem(7, __qtablewidgetitem17);
        QTableWidgetItem *__qtablewidgetitem18 = new QTableWidgetItem();
        __qtablewidgetitem18->setTextAlignment(Qt::AlignCenter);
        tableWidget_trust->setHorizontalHeaderItem(8, __qtablewidgetitem18);
        QTableWidgetItem *__qtablewidgetitem19 = new QTableWidgetItem();
        __qtablewidgetitem19->setTextAlignment(Qt::AlignCenter);
        tableWidget_trust->setHorizontalHeaderItem(9, __qtablewidgetitem19);
        tableWidget_trust->setObjectName(QString::fromUtf8("tableWidget_trust"));
        tableWidget_trust->setStyleSheet(QString::fromUtf8("margin:-1px;"));
        tableWidget_trust->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableWidget_trust->setSelectionMode(QAbstractItemView::SingleSelection);
        tableWidget_trust->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableWidget_trust->horizontalHeader()->setMinimumSectionSize(60);
        tableWidget_trust->horizontalHeader()->setDefaultSectionSize(85);
        tableWidget_trust->horizontalHeader()->setHighlightSections(false);
        tableWidget_trust->horizontalHeader()->setStretchLastSection(true);
        tableWidget_trust->verticalHeader()->setVisible(false);
        tableWidget_trust->verticalHeader()->setMinimumSectionSize(30);
        tableWidget_trust->verticalHeader()->setHighlightSections(false);

        verticalLayout_5->addWidget(tableWidget_trust);

        tabWidget->addTab(tab, QString());
        tab_2 = new QWidget();
        tab_2->setObjectName(QString::fromUtf8("tab_2"));
        verticalLayout_3 = new QVBoxLayout(tab_2);
        verticalLayout_3->setSpacing(0);
        verticalLayout_3->setContentsMargins(11, 11, 11, 11);
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        verticalLayout_3->setContentsMargins(0, 0, 0, 0);
        pushButton_logClean = new QPushButton(tab_2);
        pushButton_logClean->setObjectName(QString::fromUtf8("pushButton_logClean"));

        verticalLayout_3->addWidget(pushButton_logClean);

        plainTextEdit = new QPlainTextEdit(tab_2);
        plainTextEdit->setObjectName(QString::fromUtf8("plainTextEdit"));
        plainTextEdit->setStyleSheet(QString::fromUtf8("margin:-1px;"));
        plainTextEdit->setReadOnly(true);

        verticalLayout_3->addWidget(plainTextEdit);

        tabWidget->addTab(tab_2, QString());

        horizontalLayout->addWidget(tabWidget);


        verticalLayout->addLayout(horizontalLayout);

        horizontalLayout_7 = new QHBoxLayout();
        horizontalLayout_7->setSpacing(6);
        horizontalLayout_7->setObjectName(QString::fromUtf8("horizontalLayout_7"));
        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_7->addItem(horizontalSpacer_3);

        horizontalSpacer_8 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_7->addItem(horizontalSpacer_8);

        horizontalSpacer_12 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_7->addItem(horizontalSpacer_12);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_7->addItem(horizontalSpacer_2);

        pushButton_fiterOn = new QPushButton(centralWidget);
        pushButton_fiterOn->setObjectName(QString::fromUtf8("pushButton_fiterOn"));
        pushButton_fiterOn->setMinimumSize(QSize(100, 30));
        pushButton_fiterOn->setMaximumSize(QSize(100, 30));

        horizontalLayout_7->addWidget(pushButton_fiterOn);

        horizontalSpacer_7 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_7->addItem(horizontalSpacer_7);

        pushButton_fiterOff = new QPushButton(centralWidget);
        pushButton_fiterOff->setObjectName(QString::fromUtf8("pushButton_fiterOff"));
        pushButton_fiterOff->setMinimumSize(QSize(100, 30));
        pushButton_fiterOff->setMaximumSize(QSize(100, 30));

        horizontalLayout_7->addWidget(pushButton_fiterOff);


        verticalLayout->addLayout(horizontalLayout_7);

        MainWindow->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(MainWindow);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 1000, 28));
        menu_file = new QMenu(menuBar);
        menu_file->setObjectName(QString::fromUtf8("menu_file"));
        menu_help = new QMenu(menuBar);
        menu_help->setObjectName(QString::fromUtf8("menu_help"));
        MainWindow->setMenuBar(menuBar);
        statusBar = new QStatusBar(MainWindow);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        statusBar->setStyleSheet(QString::fromUtf8("padding-left:20px;"));
        MainWindow->setStatusBar(statusBar);

        menuBar->addAction(menu_file->menuAction());
        menuBar->addAction(menu_help->menuAction());
        menu_file->addAction(action_importRules);
        menu_file->addAction(action_exportRules);
        menu_file->addAction(action_exitAPP);
        menu_help->addAction(action_about);

        retranslateUi(MainWindow);

        tabWidget->setCurrentIndex(1);


        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QApplication::translate("MainWindow", "WJ firewall", nullptr));
        action_importRules->setText(QApplication::translate("MainWindow", "\345\257\274\345\205\245\351\273\221\345\220\215\345\215\225\350\247\204\345\210\231", nullptr));
        action_exportRules->setText(QApplication::translate("MainWindow", "\345\257\274\345\207\272\351\273\221\345\220\215\345\215\225\350\247\204\345\210\231", nullptr));
        action_exitAPP->setText(QApplication::translate("MainWindow", "\351\200\200\345\207\272", nullptr));
        action_about->setText(QApplication::translate("MainWindow", "\345\205\263\344\272\216", nullptr));
        pushButton_addRule->setText(QApplication::translate("MainWindow", "\346\267\273\345\212\240\350\247\204\345\210\231", nullptr));
        pushButton_modRule->setText(QApplication::translate("MainWindow", "\344\277\256\346\224\271\350\247\204\345\210\231", nullptr));
        pushButton_delRule->setText(QApplication::translate("MainWindow", "\345\210\240\351\231\244\350\247\204\345\210\231", nullptr));
        pushButton_addTrust->setText(QApplication::translate("MainWindow", "\346\267\273\345\212\240\345\217\257\344\277\241", nullptr));
        pushButton_modTrust->setText(QApplication::translate("MainWindow", "\344\277\256\346\224\271\345\217\257\344\277\241", nullptr));
        pushButton_delTrust->setText(QApplication::translate("MainWindow", "\345\210\240\351\231\244\345\217\257\344\277\241", nullptr));
        QTableWidgetItem *___qtablewidgetitem = tableWidget->horizontalHeaderItem(0);
        ___qtablewidgetitem->setText(QApplication::translate("MainWindow", "NO", nullptr));
        QTableWidgetItem *___qtablewidgetitem1 = tableWidget->horizontalHeaderItem(1);
        ___qtablewidgetitem1->setText(QApplication::translate("MainWindow", "SADDR", nullptr));
        QTableWidgetItem *___qtablewidgetitem2 = tableWidget->horizontalHeaderItem(2);
        ___qtablewidgetitem2->setText(QApplication::translate("MainWindow", "SPORT", nullptr));
        QTableWidgetItem *___qtablewidgetitem3 = tableWidget->horizontalHeaderItem(3);
        ___qtablewidgetitem3->setText(QApplication::translate("MainWindow", "DADDR", nullptr));
        QTableWidgetItem *___qtablewidgetitem4 = tableWidget->horizontalHeaderItem(4);
        ___qtablewidgetitem4->setText(QApplication::translate("MainWindow", "DPORT", nullptr));
        QTableWidgetItem *___qtablewidgetitem5 = tableWidget->horizontalHeaderItem(5);
        ___qtablewidgetitem5->setText(QApplication::translate("MainWindow", "TIME_FLAG", nullptr));
        QTableWidgetItem *___qtablewidgetitem6 = tableWidget->horizontalHeaderItem(6);
        ___qtablewidgetitem6->setText(QApplication::translate("MainWindow", "TIME_BEG", nullptr));
        QTableWidgetItem *___qtablewidgetitem7 = tableWidget->horizontalHeaderItem(7);
        ___qtablewidgetitem7->setText(QApplication::translate("MainWindow", "TIME_END", nullptr));
        QTableWidgetItem *___qtablewidgetitem8 = tableWidget->horizontalHeaderItem(8);
        ___qtablewidgetitem8->setText(QApplication::translate("MainWindow", "PROTOCOL", nullptr));
        QTableWidgetItem *___qtablewidgetitem9 = tableWidget->horizontalHeaderItem(9);
        ___qtablewidgetitem9->setText(QApplication::translate("MainWindow", "ACTION", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_1), QApplication::translate("MainWindow", "\351\273\221\345\220\215\345\215\225\350\247\204\345\210\231", nullptr));
        QTableWidgetItem *___qtablewidgetitem10 = tableWidget_trust->horizontalHeaderItem(0);
        ___qtablewidgetitem10->setText(QApplication::translate("MainWindow", "NO", nullptr));
        QTableWidgetItem *___qtablewidgetitem11 = tableWidget_trust->horizontalHeaderItem(1);
        ___qtablewidgetitem11->setText(QApplication::translate("MainWindow", "SADDR", nullptr));
        QTableWidgetItem *___qtablewidgetitem12 = tableWidget_trust->horizontalHeaderItem(2);
        ___qtablewidgetitem12->setText(QApplication::translate("MainWindow", "SPORT", nullptr));
        QTableWidgetItem *___qtablewidgetitem13 = tableWidget_trust->horizontalHeaderItem(3);
        ___qtablewidgetitem13->setText(QApplication::translate("MainWindow", "DADDR", nullptr));
        QTableWidgetItem *___qtablewidgetitem14 = tableWidget_trust->horizontalHeaderItem(4);
        ___qtablewidgetitem14->setText(QApplication::translate("MainWindow", "DPORT", nullptr));
        QTableWidgetItem *___qtablewidgetitem15 = tableWidget_trust->horizontalHeaderItem(5);
        ___qtablewidgetitem15->setText(QApplication::translate("MainWindow", "TIME_FLAG", nullptr));
        QTableWidgetItem *___qtablewidgetitem16 = tableWidget_trust->horizontalHeaderItem(6);
        ___qtablewidgetitem16->setText(QApplication::translate("MainWindow", "TIME_BEG", nullptr));
        QTableWidgetItem *___qtablewidgetitem17 = tableWidget_trust->horizontalHeaderItem(7);
        ___qtablewidgetitem17->setText(QApplication::translate("MainWindow", "TIME_END", nullptr));
        QTableWidgetItem *___qtablewidgetitem18 = tableWidget_trust->horizontalHeaderItem(8);
        ___qtablewidgetitem18->setText(QApplication::translate("MainWindow", "PROTOCOL", nullptr));
        QTableWidgetItem *___qtablewidgetitem19 = tableWidget_trust->horizontalHeaderItem(9);
        ___qtablewidgetitem19->setText(QApplication::translate("MainWindow", "ACTION", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab), QApplication::translate("MainWindow", "\345\217\257\344\277\241IP\344\277\241\346\201\257", nullptr));
        pushButton_logClean->setText(QApplication::translate("MainWindow", "\346\270\205\351\231\244\346\227\245\345\277\227", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_2), QApplication::translate("MainWindow", "\346\227\245\345\277\227", nullptr));
        pushButton_fiterOn->setText(QApplication::translate("MainWindow", "\345\274\200\345\220\257\350\277\207\346\273\244", nullptr));
        pushButton_fiterOff->setText(QApplication::translate("MainWindow", "\345\201\234\346\255\242\350\277\207\346\273\244", nullptr));
        menu_file->setTitle(QApplication::translate("MainWindow", "\346\226\207\344\273\266", nullptr));
        menu_help->setTitle(QApplication::translate("MainWindow", "\345\270\256\345\212\251", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
