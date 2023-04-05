#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <iostream>
#include <QCoreApplication>
#include <QDebug>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "common.h"
#include "ruledialog.h"
#include "aboutdialog.h"
#include "messagedialog.h"
#include "ruledialog_m.h"

extern char controlinfo[64000];

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    QString runShell(QString cmd);
    bool isModLoaded();
    bool sendTrustRuleToFirewall();
    bool setRuleStringFile();
    bool getRuleStringFile();
    void updateRuleNo();

    bool setTrustStringFile();
    void updateTrustNo();
    bool sendTrustToFirewall();
    bool getTrustStringFile();

private slots:
    void on_pushButton_addRule_clicked();
    void on_pushButton_delRule_clicked();
    void on_pushButton_fiterOn_clicked();
    void on_pushButton_fiterOff_clicked();
    void addRuleString(rule_str_tp ruleString);
    void modRuleString(rule_str_tp ruleString);
    void delRuleString(bool action);
    void updateLog();
    void on_pushButton_logClean_clicked();
    void on_pushButton_modRule_clicked();

    void on_action_importRules_triggered();

    void on_action_exportRules_triggered();

    void on_action_exitAPP_triggered();

    void on_action_about_triggered();

    void on_pushButton_addTrust_clicked();
    void on_pushButton_modTrust_clicked();
    void on_pushButton_delTrust_clicked();
    void addTrustString(rule_str_tp trustString);
    void modTrustString(rule_str_tp ruleString);
    void delTrustString(bool action);

private:
    Ui::MainWindow *ui;
    QLabel *label_runStatus;
    RuleDialog *addRuleDialog;
    MessageDialog *delRuleDialog;
    aboutdialog *aboutDialog;
    ruledialog_m *modRuleDialog;
    QTableWidget *rulesTable;
    QList<rule_str_tp> ruleStringList;
    QTimer *logTimer;

    RuleDialog *addTrustDialog;
    ruledialog_m *modTrustDialog;

    MessageDialog *delTrustDialog;
    QList<rule_str_tp> trustStringList;
    QTableWidget *trustsTable;
};

#endif // MAINWINDOW_H
