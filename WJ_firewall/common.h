#ifndef COMMON_H
#define COMMON_H

#include <QButtonGroup>
#include <QDebug>
#include <QDesktopWidget>
#include <QDir>
#include <QFile>
#include <QLabel>
#include <QMessageBox>
#include <QMetaType>
#include <QProcess>
#include <QRadioButton>
#include <QString>
#include <QStringList>
#include <QTableWidget>
#include <QTextStream>
#include <QTimer>
#include <QTime>
#include <QTimeEdit>
#include <QVariant>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RULE_COUNT_MAX  1000  //最大规则数
#define LOG_UPDATE_TIME 100 //ms

struct rule_str_tp  //保存规则信息
{
    QString src_addr;  //0 4B
    QString dst_addr;  //1 4B
    QString src_port;  //2 4B
    QString dst_port;  //3 4B
    QString time_flag; //4 4B
    QString hour_begin;//5 4B
    QString min_begin; //6
    QString hour_end;  //7 4B
    QString min_end;   //8
    QString protocol;  //9 4B

    QString action;//新增 action 字段，区分黑名单规则与可信IP
};

bool ruleFromString_new(rule_str_tp ruleString, char *p_controlinfo);
bool ruleAddrCheck(QString addrString);
bool rulePortCheck(QString portString);

//===== new from here =====
//QString trustSeedGen(rule_str_tp trustString);// 生成 seed 的基底信息
//===== end =====

#endif // COMMON_H
