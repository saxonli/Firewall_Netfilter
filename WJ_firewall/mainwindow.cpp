#include "mainwindow.h"
#include "ui_mainwindow.h"

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


char controlinfo[64000]; // 规则条数这里有问题，以前是黑名单最多50条，现在加了可信表，二者变成了100条
int numa=0;

//===== 生成 seed 模块 =====
// 01 SHA256 hash
QString sha256(const QString &str)
{
    char buf[2];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    QByteArray tmp=str.toLatin1();
    char *cStr=tmp.data();
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, cStr, str.size());
    SHA256_Final(hash, &sha256);
    std::string newString = "";
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(buf,"%02x",hash[i]);
        newString = newString + buf;
    }
    return QString::fromStdString(newString);
}
// 02 RSA
QString rsaPriEncryptBase64(const QString &str)
{
    //私钥  长度为512  （使用自己生成的公秘钥）
    char private_key[] ="-----BEGIN PRIVATE KEY-----\n"\
            "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA0d8NA5dTs5J8ifcl\n"\
            "CPw6Or/NOqIx5+cqildADsALH6hobxWsyDCjmPpiAWwIRX6ThJo9gmzwddgD3gfL\n"\
            "ioxG0wIDAQABAkBnpzJWQ7cjSYYY3ed8uJZJzdEe1FyxnIp2KQGKR283AqDQGqFE\n"\
            "F8CaRPUn/1y4K8QSG/rxpvUo4BVoohwA7WcBAiEA89uCUiWfi6GE+OBFg1kegm/w\n"\
            "CGfKRWz38HgksMk+SCkCIQDcUlCHD/TmeL5OErBKBTzKW+i+bH6s7yUuyg0UqCym\n"\
            "mwIhANvZogOHkfCj/SsXnvQNS7lTS/d4A19WH6530rRjqrgJAiEAjlhIWtq+WWFN\n"\
            "YtfEOi6kFgHHn7AtL8Hafh5g0SXOo10CIQCIydQo0Se1PsxOcFfFnWJdPldk3GV/\n"\
            "61TSzPkZ/nG5Lw==\n"\
            "-----END PRIVATE KEY-----";

    //将字符串键加载到bio对象
    BIO* pKeyBio = BIO_new_mem_buf(private_key, strlen(private_key));
    if (pKeyBio == NULL){
        return "";
    }
    RSA* pRsa = RSA_new();
    pRsa = PEM_read_bio_RSAPrivateKey(pKeyBio, &pRsa, NULL, NULL);
    if ( pRsa == NULL ){
         BIO_free_all(pKeyBio);
         return "";
    }
    int nLen = RSA_size(pRsa);
    char* pEncryptBuf = new char[nLen];
    memset(pEncryptBuf, 0, nLen);
    QByteArray clearDataArry = str.toUtf8();
    int nClearDataLen = clearDataArry.length();
    uchar* pClearData = (uchar*)clearDataArry.data();
    int nSize = RSA_private_encrypt(nClearDataLen,
                                    pClearData,
                                    (uchar*)pEncryptBuf,
                                    pRsa,
                                    RSA_PKCS1_PADDING);

    QString strEncryptData = "";
    if ( nSize >= 0 ){
         QByteArray arry(pEncryptBuf, nSize);
         strEncryptData = arry.toBase64();
    }
    // 释放内存
    delete pEncryptBuf;
    BIO_free_all(pKeyBio);
    RSA_free(pRsa);
    return strEncryptData;
}


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    //主窗口初始化设置
    ui->setupUi(this);
    addRuleDialog = new RuleDialog(this);
    delRuleDialog = new MessageDialog(this);
    aboutDialog = new aboutdialog(this);
    delRuleDialog->setMessage("确定要删除吗？");
    label_runStatus = new QLabel();
    label_runStatus->setAlignment(Qt::AlignHCenter);
    label_runStatus->setMinimumHeight(25);
    ui->statusBar->addWidget(label_runStatus);
    rulesTable = ui->tableWidget;
    rulesTable->horizontalHeader()->setMinimumHeight(30);
    rulesTable->setColumnWidth(1, 150);
    rulesTable->setColumnWidth(3, 150);
    rulesTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    rulesTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);
    rulesTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    rulesTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Fixed);
    rulesTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    rulesTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    rulesTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    rulesTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);
    rulesTable->horizontalHeader()->setSectionResizeMode(8, QHeaderView::Stretch);
    rulesTable->horizontalHeader()->setSectionResizeMode(9, QHeaderView::Stretch);
    rulesTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    logTimer = new QTimer(this);

    //===== new from here =====
    addTrustDialog = new RuleDialog(this);
    delTrustDialog = new MessageDialog(this);
    delTrustDialog->setMessage("确定要删除吗？");

    trustsTable = ui->tableWidget_trust;
    trustsTable->horizontalHeader()->setMinimumHeight(30);
    trustsTable->setColumnWidth(1, 150);
    trustsTable->setColumnWidth(3, 150);
    trustsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    trustsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);
    trustsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    trustsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Fixed);
    trustsTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    trustsTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    trustsTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    trustsTable->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);
    trustsTable->horizontalHeader()->setSectionResizeMode(8, QHeaderView::Stretch);
    trustsTable->horizontalHeader()->setSectionResizeMode(9, QHeaderView::Stretch);
    trustsTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    //===== end =====

    // check mod，检查是否启动 “开启过滤” 按钮
    if (isModLoaded()){
        ui->pushButton_fiterOn->setEnabled(false);
        label_runStatus->setText("运行状态：已启动");
        logTimer->start(LOG_UPDATE_TIME); //every 100ms fresh the log
    }else{
        ui->pushButton_fiterOff->setEnabled(false);
        label_runStatus->setText("运行状态：未启动");
    }

    //connect
    connect(addRuleDialog, SIGNAL(addNewRuleSignal(rule_str_tp)),
            this, SLOT(addRuleString(rule_str_tp)));
    connect(delRuleDialog, SIGNAL(actionSignal(bool)),
            this, SLOT(delRuleString(bool)));

    connect(logTimer, SIGNAL(timeout()), this, SLOT(updateLog()));

    //===== new from here =====
    connect(addTrustDialog,SIGNAL(addNewRuleSignal(rule_str_tp)),
            this,SLOT(addTrustString(rule_str_tp)));
    connect(delTrustDialog,SIGNAL(actionSignal(bool)),
            this,SLOT(delTrustString(bool)));
    //===== end =====

    //set table
    getRuleStringFile();


    //===== new from here =====

    getTrustStringFile();

    //===== end =====
}

MainWindow::~MainWindow()
{
    delete ui;
}

// 执行shell命令，调用脚本
QString MainWindow::runShell(QString cmd)
{
    QProcess *shell = new QProcess(this);
    shell->start(cmd);
    shell->waitForFinished();
    return shell->readAll();
}

bool MainWindow::isModLoaded()
{
    return runShell("bash ../bin/main.sh ckmod") == "true";
}

bool MainWindow::sendTrustRuleToFirewall()
{
    //将 trustStringList + ruleStringList 发送给防火墙内核模块
    if (!isModLoaded()){
        return false;
    }

    int count = 0; //记录 rule + trust 数量

    // 这里是先写 trust 再写 rule ，方便后续防火墙内核的处理
    //===== new from here =====
    // trust 转化为字符串再发送
    foreach(rule_str_tp trustString,trustStringList){
        if(ruleFromString_new(trustString,(controlinfo+(count*32)))){
            count++;
        }
        if (count > RULE_COUNT_MAX){
            return false;
        }
    }
    //===== end =====

    // rule 转化为字符串再发送
    foreach(rule_str_tp ruleString, ruleStringList){
        if (ruleFromString_new(ruleString, (controlinfo+(count*32)))){
            count++;
        }
        if (count > RULE_COUNT_MAX){
            return false;
        }
    }

    int fp;
    fp =open("/dev/controlinfo",O_RDWR,S_IRUSR|S_IWUSR);
    if (fp > 0)
    {
        write(fp,controlinfo,count*32);
    }
    else {
        QMessageBox::critical(this, "错误", "无法打开controlinfo！");
        return false;
    }
    ::close(fp);

    return true;
}

bool MainWindow::setRuleStringFile()
{
    //将有改动的ruleStringList更新到rule.txt文档
    QDir dir("../data/");
    if (!dir.exists()){
        dir.mkdir("../data/");
    }
    QFile f("../data/rule.txt");
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)){
        QMessageBox::critical(this, "错误", "无法打开rule.txt！");
        return false;
    }
    QTextStream stream(&f);
    foreach (rule_str_tp ruleString, ruleStringList) {
        QString temp = ruleString.src_addr + "%"
                + ruleString.dst_addr + "%"
                + ruleString.src_port + "%"
                + ruleString.dst_port + "%"
                + ruleString.time_flag + "%"
                + ruleString.hour_begin + "%"
                + ruleString.min_begin + "%"
                + ruleString.hour_end + "%"
                + ruleString.min_end + "%"
                + ruleString.protocol + "%"
                + ruleString.action;
        stream << temp << endl;
    }
    f.close();
    return true;
}

bool MainWindow::getRuleStringFile()
{
    //打开规则文件
    QFile f("../data/rule.txt");
    if (!f.exists()){
        return false;
    }
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)){
        QMessageBox::critical(this, "错误", "无法打开rule.txt！");
        return false;
    }
    QTextStream stream(&f);

    //逐条取规则并显示，存储在ruleStringList
    while (!stream.atEnd()){
        QString lineStr = stream.readLine();
        QStringList lineSpilt = lineStr.split("%");

        //===== mod 11 =====
        if (lineSpilt.length() != 11){
            continue;
        }
        rule_str_tp ruleString;
        ruleString.src_addr = lineSpilt[0];
        ruleString.dst_addr = lineSpilt[1];
        ruleString.src_port = lineSpilt[2];
        ruleString.dst_port = lineSpilt[3];
        ruleString.time_flag = lineSpilt[4];
        ruleString.hour_begin = lineSpilt[5];
        ruleString.min_begin = lineSpilt[6];
        ruleString.hour_end = lineSpilt[7];
        ruleString.min_end = lineSpilt[8];
        ruleString.protocol = lineSpilt[9];
        ruleString.action = lineSpilt[10];

        if (ruleAddrCheck(ruleString.src_addr) &&ruleAddrCheck(ruleString.dst_addr) &&
            rulePortCheck(ruleString.src_port) &&rulePortCheck(ruleString.dst_port))
        {addRuleString(ruleString);}
    }
    return true;
}

void MainWindow::updateRuleNo()
{
    for (int i=0; i<rulesTable->rowCount(); i++){
        rulesTable->item(i, 0)->setText(QString::number(i+1));
    }
}

void MainWindow::on_pushButton_addRule_clicked()
{
    if (ruleStringList.length() >= 50){
        QMessageBox::information(this, "提示", "规则数量已达上限！");
        return;
    }
    addRuleDialog->exec();
    setRuleStringFile();
    sendTrustRuleToFirewall();
}

void MainWindow::on_pushButton_delRule_clicked()
{
    if (rulesTable->currentRow() < 0){
        QMessageBox::information(this, "提示", "请先选中要删除的规则！");
        return;
    }
    delRuleDialog->exec();
    setRuleStringFile();
    sendTrustRuleToFirewall();
}

void MainWindow::on_pushButton_fiterOn_clicked()
{
    QString ret = runShell("bash ../bin/main.sh insmod");
    if (ret == "pkexec"){
        QMessageBox::critical(this, "错误", "请先安装pkexec");
    }
    if (isModLoaded()){
        if (!logTimer->isActive()){
            logTimer->start(LOG_UPDATE_TIME);
        }
        label_runStatus->setText("运行状态：已启动");
        ui->pushButton_fiterOn->setEnabled(false);
        ui->pushButton_fiterOff->setEnabled(true);
    }
    sendTrustRuleToFirewall();
}

void MainWindow::on_pushButton_fiterOff_clicked()
{
    QString ret = runShell("bash ../bin/main.sh rmmod");
    if (ret == "pkexec"){
        QMessageBox::critical(this, "错误", "请先安装pkexec！");
    }
    if (!isModLoaded()){
        if (logTimer->isActive()){
            logTimer->stop();
        }
        ui->pushButton_fiterOn->setEnabled(true);
        ui->pushButton_fiterOff->setEnabled(false);
        label_runStatus->setText("运行状态：未启动");
    }
}

void MainWindow::addRuleString(rule_str_tp ruleString)
{
    //将单条规则添加至ruleStringList
    ruleString.action="reject";// action 字段
    ruleStringList.append(ruleString);
    int row = ruleStringList.length();
    rulesTable->setRowCount(row);
    rulesTable->setItem(row - 1, 0, new QTableWidgetItem(""));
    rulesTable->setItem(row - 1, 1, new QTableWidgetItem(ruleString.src_addr));
    rulesTable->setItem(row - 1, 2, new QTableWidgetItem(ruleString.src_port));
    rulesTable->setItem(row - 1, 3, new QTableWidgetItem(ruleString.dst_addr));
    rulesTable->setItem(row - 1, 4, new QTableWidgetItem(ruleString.dst_port));
    rulesTable->setItem(row - 1, 5, new QTableWidgetItem(ruleString.time_flag));
    rulesTable->setItem(row - 1, 6, new QTableWidgetItem(ruleString.hour_begin+':'+ruleString.min_begin));
    rulesTable->setItem(row - 1, 7, new QTableWidgetItem(ruleString.hour_end+':'+ruleString.min_end));
    rulesTable->setItem(row - 1, 8, new QTableWidgetItem(ruleString.protocol));
    rulesTable->setItem(row - 1, 9, new QTableWidgetItem(ruleString.action));
    for (int i=0; i<rulesTable->columnCount(); ++i){
        rulesTable->item(row - 1, i)->setTextAlignment(Qt::AlignCenter);
    }
    updateRuleNo();
}

void MainWindow::modRuleString(rule_str_tp ruleString)
{
    ruleStringList[numa]=ruleString;
    rulesTable->setItem(numa, 0, new QTableWidgetItem(""));
    rulesTable->setItem(numa, 1, new QTableWidgetItem(ruleString.src_addr));
    rulesTable->setItem(numa, 2, new QTableWidgetItem(ruleString.src_port));
    rulesTable->setItem(numa, 3, new QTableWidgetItem(ruleString.dst_addr));
    rulesTable->setItem(numa, 4, new QTableWidgetItem(ruleString.dst_port));
    rulesTable->setItem(numa, 5, new QTableWidgetItem(ruleString.time_flag));
    rulesTable->setItem(numa, 6, new QTableWidgetItem(ruleString.hour_begin+':'+ruleString.min_begin));
    rulesTable->setItem(numa, 7, new QTableWidgetItem(ruleString.hour_end+':'+ruleString.min_end));
    rulesTable->setItem(numa, 8, new QTableWidgetItem(ruleString.protocol));
    rulesTable->setItem(numa, 9, new QTableWidgetItem("reject"));
    for (int i=0; i<rulesTable->columnCount(); ++i){
        rulesTable->item(numa, i)->setTextAlignment(Qt::AlignCenter);
    }
    updateRuleNo();
}

void MainWindow::delRuleString(bool action)
{
    //从ruleStringList和rulesTable中删除规则
    if (action){
        int rowIndex = rulesTable->currentRow();
        if (rowIndex >= 0){
            rulesTable->removeRow(rowIndex);
            ruleStringList.removeAt(rowIndex);
        }
        rulesTable->setRowCount(ruleStringList.length());
    }
    updateRuleNo();
}

void MainWindow::updateLog()
{
    QStringList ret = runShell("bash ../bin/log.sh").split("\n");
    QDir dir("../data/");
    if (!dir.exists()){
        dir.mkdir("../data/");
    }
    QFile f("../data/log.txt");
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Append)){
        QMessageBox::critical(this, "错误", "无法打开log.txt！");
    }
    QTextStream stream(&f);
    foreach (QString line, ret) {
        if (line.split(">").length() < 2){
            continue;
        }
        ui->plainTextEdit->appendPlainText(line.split(">")[1] + "\n");
        stream << line.split(">")[1] << endl;
    }

    f.close();
}

void MainWindow::on_pushButton_logClean_clicked()
{
    ui->plainTextEdit->clear();
}

void MainWindow::on_pushButton_modRule_clicked()
{
    numa=rulesTable->currentRow();
    if (numa < 0){
        QMessageBox::information(this, "提示", "请先选中要修改的规则！");
        return;
    }

    modrule=ruleStringList[numa];
    modRuleDialog = new ruledialog_m(this);
    connect(modRuleDialog, SIGNAL(modRuleSignal(rule_str_tp)),
            this, SLOT(modRuleString(rule_str_tp)));
    modRuleDialog->exec();
    ruleStringList[numa].action="reject";
    setRuleStringFile();
    sendTrustRuleToFirewall();
}

// 导入新的rule集合，会覆盖原有的rule集合
void MainWindow::on_action_importRules_triggered()
{
    //---获取文件名
    QString fileName = QFileDialog :: getOpenFileName(this,tr("导入规则"),"/home","");
    if(fileName.isNull()) return;

        //---打开文件并读取文件内容
        QFile file(fileName);

        //--打开文件成功
        if (file.open(QIODevice ::ReadOnly | QIODevice ::Text))
        {
            QTextStream textStream(&file);
            QString line=textStream.readAll();
                //---写入防火墙rule.txt
                QFile f("../data/rule.txt");
                if (!f.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)){
                    QMessageBox::critical(this, "错误", "无法打开rule.txt！");
                    return;
                }
                QTextStream stream(&f);
                stream << line << endl;
                file.close();  //success ro XieRu
                f.close();

                //更新rulelist
                QFile fn("../data/rule.txt");
                if (!fn.open(QIODevice::ReadOnly | QIODevice::Text)){
                    QMessageBox::critical(this, "错误", "无法打开rule.txt！");
                    return;
                }
                QTextStream instream(&fn);
                QList<rule_str_tp> ruleStringList_tmp;

                rulesTable->setRowCount(0);
                rulesTable->clearContents();

                while (!instream.atEnd()){
                    QString lineStr = instream.readLine();
                    QStringList lineSpilt = lineStr.split("%");
                    if (lineSpilt.length() != 11){
                        continue;
                    }
                    rule_str_tp ruleString;
                    ruleString.src_addr = lineSpilt[0];
                    ruleString.dst_addr = lineSpilt[1];
                    ruleString.src_port = lineSpilt[2];
                    ruleString.dst_port = lineSpilt[3];
                    ruleString.time_flag = lineSpilt[4];
                    ruleString.hour_begin = lineSpilt[5];
                    ruleString.min_begin = lineSpilt[6];
                    ruleString.hour_end = lineSpilt[7];
                    ruleString.min_end = lineSpilt[8];
                    ruleString.protocol = lineSpilt[9];
                    ruleString.action = lineSpilt[10];

                    if (ruleAddrCheck(ruleString.src_addr) &&ruleAddrCheck(ruleString.dst_addr) &&
                        rulePortCheck(ruleString.src_port) &&rulePortCheck(ruleString.dst_port))
                    {
                        ruleStringList_tmp.append(ruleString);
                        int row = ruleStringList_tmp.length();
                        rulesTable->setRowCount(row);
                        rulesTable->setItem(row - 1, 0, new QTableWidgetItem(""));
                        rulesTable->setItem(row - 1, 1, new QTableWidgetItem(ruleString.src_addr));
                        rulesTable->setItem(row - 1, 2, new QTableWidgetItem(ruleString.src_port));
                        rulesTable->setItem(row - 1, 3, new QTableWidgetItem(ruleString.dst_addr));
                        rulesTable->setItem(row - 1, 4, new QTableWidgetItem(ruleString.dst_port));
                        rulesTable->setItem(row - 1, 5, new QTableWidgetItem(ruleString.time_flag));
                        rulesTable->setItem(row - 1, 6, new QTableWidgetItem(ruleString.hour_begin+':'+ruleString.min_begin));
                        rulesTable->setItem(row - 1, 7, new QTableWidgetItem(ruleString.hour_end+':'+ruleString.min_end));
                        rulesTable->setItem(row - 1, 8, new QTableWidgetItem(ruleString.protocol));
                        rulesTable->setItem(row - 1, 9, new QTableWidgetItem(ruleString.action));
                        for (int i=0; i<rulesTable->columnCount(); ++i){
                            rulesTable->item(row - 1, i)->setTextAlignment(Qt::AlignCenter);
                        }
                        updateRuleNo();
                    }
                } //rulelist和ruletable更新完成
                ruleStringList = ruleStringList_tmp;
                fn.close();

        }
        else	//---打开文件失败
        {
            QMessageBox ::information(NULL, NULL, "open file error");
        }
        sendTrustRuleToFirewall();

}

void MainWindow::on_action_exportRules_triggered()
{
    QFileDialog fileDialog;
       QString fileName = fileDialog.getSaveFileName(this,tr("导出规则"),"/home","");
       if(fileName.isNull()) return;
       if(fileName == "")
           return;
       QFile file(fileName);
       if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
       {
           QMessageBox::warning(this,tr("错误"),tr("打开文件失败"));
           return;
       }
       else
       {
           QTextStream textStream(&file);

           foreach (rule_str_tp ruleString, ruleStringList) {
                   QString temp = ruleString.src_addr + "%"
                           + ruleString.dst_addr + "%"
                           + ruleString.src_port + "%"
                           + ruleString.dst_port + "%"
                           + ruleString.time_flag + "%"
                           + ruleString.hour_begin + "%"
                           + ruleString.min_begin + "%"
                           + ruleString.hour_end + "%"
                           + ruleString.min_end + "%"
                           + ruleString.protocol + "%"
                           +ruleString.action;
                   textStream <<temp << endl;
               }
            textStream<<'\n'<<"- Meaning: ---------------------------------------------------------------------------------"<<'\n'<<endl;
            textStream<<"|     SIP      |     DIP      | SPort | DPort | Time | SHour | SMin | EHour | EMin | Protocol | Action |"<<endl;
           foreach (rule_str_tp ruleString, ruleStringList) {
                   QString temp = '|'+ruleString.src_addr.rightJustified(14,' ')+'|'
                           + ruleString.dst_addr.rightJustified(14,' ')+'|'
                           + ruleString.src_port.rightJustified(7,' ')+'|'
                           + ruleString.dst_port.rightJustified(7,' ')+'|'
                           + ruleString.time_flag.rightJustified(6,' ')+'|'
                           + ruleString.hour_begin.rightJustified(7,' ')+'|'
                           + ruleString.min_begin.rightJustified(6,' ')+'|'
                           + ruleString.hour_end.rightJustified(7,' ')+'|'
                           + ruleString.min_end.rightJustified(6,' ')+'|'
                           + ruleString.protocol.rightJustified(10,' ')+'|'
                           + ruleString.action.rightJustified(8,' ')+'|';
                   textStream << temp << endl;
               }

           QMessageBox::warning(this,tr("提示"),tr("保存文件成功"));
           file.close();
       }

}

void MainWindow::on_action_exitAPP_triggered()
{
    this->close();
}

void MainWindow::on_action_about_triggered()
{
    aboutDialog->setMessage("- 开发环境：\n"
                              "         操作系统：Ubuntu 15.10 \n"
                              "         内核版本：4.2.0-16-generic \n"
                              "         开发软件：Qt 5.9.0 \n"
                              "         编译器：gcc version 5.2.1 \n\n"
                              "- 作者：saxon \n");
    aboutDialog->exec();
}



//===== new from here =====

void MainWindow::on_pushButton_addTrust_clicked()
{
    if (trustStringList.length() >= 50){
        QMessageBox::information(this, "提示", "可信数量已达上限！");
        return;
    }
    addTrustDialog->exec();

    //===== new from here =====
    QString genSeedStr = trustSeedGen(trustStringList[trustStringList.length()-1]);//生成 seed 的可信端基底信息
    QString encryptSeedStr = rsaPriEncryptBase64(genSeedStr);//利用 RSA 私钥签名 seed 基底
    QString seed = sha256(encryptSeedStr);//利用 sha256 哈希加密后的 seed 基底
//    QMessageBox::information(this, "可信端 seed 已生成", "seed: \n\n"+seed);
    setTrustStringFile();
    sendTrustRuleToFirewall();
}

void MainWindow::on_pushButton_modTrust_clicked()
{
    numa=trustsTable->currentRow();
    if (numa < 0){
        QMessageBox::information(this, "提示", "请先选中要修改的可信条目！");
        return;
    }

    modrule=trustStringList[numa];
    modTrustDialog = new ruledialog_m(this);
    connect(modTrustDialog, SIGNAL(modRuleSignal(rule_str_tp)),
            this, SLOT(modTrustString(rule_str_tp)));
    modTrustDialog->exec();

    //===== new from here =====
    trustStringList[numa].action = "accept";
    QString genSeedStr = trustSeedGen(trustStringList[numa]);//生成 seed 的可信端基底信息
    QString encryptSeedStr = rsaPriEncryptBase64(genSeedStr);//利用 RSA 私钥签名 seed 基底
    QString seed = sha256(encryptSeedStr);//利用 sha256 哈希加密后的 seed 基底
//    QMessageBox::information(this, "可信端 seed 已生成", "seed: \n\n"+seed);
    setTrustStringFile();
    sendTrustRuleToFirewall();
}

void MainWindow::on_pushButton_delTrust_clicked()
{
    if (trustsTable->currentRow() < 0){
        QMessageBox::information(this, "提示", "请先选中要删除的可信条目！");
        return;
    }
    delTrustDialog->exec();
    setTrustStringFile();
    sendTrustRuleToFirewall();
}

//更新 trustsTable 序号的显示
void MainWindow::updateTrustNo()
{
    for (int i=0; i<trustsTable->rowCount(); i++){
        trustsTable->item(i, 0)->setText(QString::number(i+1));
    }
}

/*
 * 处理“添加可信”功能
 * 1. 修改了ACTION字段为accept
 * 2. 将 ruleStringList 与 trustStringList 解耦
 * 3. 将 rulesTable 与 trustsTable 解耦
 * 4. updateTrustNo 完成更新
 *
 */
void MainWindow::addTrustString(rule_str_tp trustString)
{
    //将单条可信添加至 trustStringList
    trustString.action="accept";
    trustStringList.append(trustString);
    int row = trustStringList.length();//计算在 trustsTable 表格中的第几行插入显示新的可信条目
    trustsTable->setRowCount(row);
    trustsTable->setItem(row - 1, 0, new QTableWidgetItem(""));
    trustsTable->setItem(row - 1, 1, new QTableWidgetItem(trustString.src_addr));
    trustsTable->setItem(row - 1, 2, new QTableWidgetItem(trustString.src_port));
    trustsTable->setItem(row - 1, 3, new QTableWidgetItem(trustString.dst_addr));
    trustsTable->setItem(row - 1, 4, new QTableWidgetItem(trustString.dst_port));
    trustsTable->setItem(row - 1, 5, new QTableWidgetItem(trustString.time_flag));
    trustsTable->setItem(row - 1, 6, new QTableWidgetItem(trustString.hour_begin+':'+trustString.min_begin));
    trustsTable->setItem(row - 1, 7, new QTableWidgetItem(trustString.hour_end+':'+trustString.min_end));
    trustsTable->setItem(row - 1, 8, new QTableWidgetItem(trustString.protocol));
    trustsTable->setItem(row - 1, 9, new QTableWidgetItem(trustString.action));
    for (int i=0; i<trustsTable->columnCount(); ++i){
        trustsTable->item(row - 1, i)->setTextAlignment(Qt::AlignCenter);
    }
    updateTrustNo();
}

/*
 * 处理“修改可信”功能
 * 1. 修改了ACTION字段为accept
 * 2. 将 ruleStringList 与 trustStringList 解耦
 * 3. 将 rulesTable 与 trustsTable 解耦
 * 4. updateTrustNo 完成更新
 */
void MainWindow::modTrustString(rule_str_tp trustString)
{
    trustStringList[numa]=trustString;
    trustsTable->setItem(numa, 0, new QTableWidgetItem(""));
    trustsTable->setItem(numa, 1, new QTableWidgetItem(trustString.src_addr));
    trustsTable->setItem(numa, 2, new QTableWidgetItem(trustString.src_port));
    trustsTable->setItem(numa, 3, new QTableWidgetItem(trustString.dst_addr));
    trustsTable->setItem(numa, 4, new QTableWidgetItem(trustString.dst_port));
    trustsTable->setItem(numa, 5, new QTableWidgetItem(trustString.time_flag));
    trustsTable->setItem(numa, 6, new QTableWidgetItem(trustString.hour_begin+':'+trustString.min_begin));
    trustsTable->setItem(numa, 7, new QTableWidgetItem(trustString.hour_end+':'+trustString.min_end));
    trustsTable->setItem(numa, 8, new QTableWidgetItem(trustString.protocol));
    trustsTable->setItem(numa, 9, new QTableWidgetItem("accept"));
    for (int i=0; i<trustsTable->columnCount(); ++i){
        trustsTable->item(numa, i)->setTextAlignment(Qt::AlignCenter);
    }
    updateTrustNo();
}

/*
 * 处理“删除可信”功能
 * 1. 将 ruleStringList 与 trustStringList 解耦
 * 2. 将 rulesTable 与 trustsTable 解耦
 * 3. updateTrustNo 完成更新
 */
void MainWindow::delTrustString(bool action)
{
    //从 trustStringList 和 trustsTable 中删除规则
    if (action){
        int rowIndex = trustsTable->currentRow();
        if (rowIndex >= 0){
            trustsTable->removeRow(rowIndex);
            trustStringList.removeAt(rowIndex);
        }
        trustsTable->setRowCount(trustStringList.length());
    }
    updateTrustNo();
}

//将有改动的可信信息 trustStringList 更新到 trust.txt 文档
bool MainWindow::setTrustStringFile()
{

    QDir dir("../data/");
    if (!dir.exists()){
        dir.mkdir("../data/");
    }
    QFile f("../data/trust.txt");
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)){
        QMessageBox::critical(this, "错误", "无法打开trust.txt！");
        return false;
    }
    QTextStream stream(&f);
    foreach (rule_str_tp trustString, trustStringList) {
        // seed add to trust.txt
        QString genSeedStr = trustSeedGen(trustString);//生成 seed 的可信端基底信息
        QString encryptSeedStr = rsaPriEncryptBase64(genSeedStr);//利用 RSA 私钥签名 seed 基底
        QString seed = sha256(encryptSeedStr);//利用 sha256 哈希加密后的 seed 基底

        QString temp = trustString.src_addr + "%"
                + trustString.dst_addr + "%"
                + trustString.src_port + "%"
                + trustString.dst_port + "%"
                + trustString.time_flag + "%"
                + trustString.hour_begin + "%"
                + trustString.min_begin + "%"
                + trustString.hour_end + "%"
                + trustString.min_end + "%"
                + trustString.protocol + "%"
                + trustString.action + "%"
                + seed;
        stream << temp << endl;
    }
    f.close();
    return true;
}

//打开前端时将已有的可信条目显示到 trustsTable 上
bool MainWindow::getTrustStringFile()
{
    //打开规则文件
    QFile f("../data/trust.txt");
    if (!f.exists()){
        return false;
    }
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)){
        QMessageBox::critical(this, "错误", "无法打开trust.txt！");
        return false;
    }
    QTextStream stream(&f);

    //逐条取规则并显示，存储在 trustStringList
    while (!stream.atEnd()){
        QString lineStr = stream.readLine();
        QStringList lineSpilt = lineStr.split("%");

        //===== mod 12 =====
        if (lineSpilt.length() != 12){
            continue;
        }
        rule_str_tp trustString;
        trustString.src_addr = lineSpilt[0];
        trustString.dst_addr = lineSpilt[1];
        trustString.src_port = lineSpilt[2];
        trustString.dst_port = lineSpilt[3];
        trustString.time_flag = lineSpilt[4];
        trustString.hour_begin = lineSpilt[5];
        trustString.min_begin = lineSpilt[6];
        trustString.hour_end = lineSpilt[7];
        trustString.min_end = lineSpilt[8];
        trustString.protocol = lineSpilt[9];
        trustString.action = lineSpilt[10];

        if (ruleAddrCheck(trustString.src_addr) &&ruleAddrCheck(trustString.dst_addr) &&
            rulePortCheck(trustString.src_port) &&rulePortCheck(trustString.dst_port))
        {addTrustString(trustString);}
    }
    return true;
}

