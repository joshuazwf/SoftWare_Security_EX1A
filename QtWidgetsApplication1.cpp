#include "QtWidgetsApplication1.h"
#include<QMessageBox>
#include<QStandardItemModel>
#pragma execution_character_set("utf-8")

//对界面中的相关控件进行操作
//这是对界面的一个初始化函数，构造初始的界面
QtWidgetsApplication1::QtWidgetsApplication1(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);

    //点击开始抓包之后，进行相关操作

    QStringList strHeader;
    strHeader << "NO"
        << "Time"
        << "Source"
        <<"DEST"
        <<"Protocol"
        <<"Length"
        <<"info";

    QStandardItemModel* model = new QStandardItemModel(this);
 
    model->setHorizontalHeaderLabels(strHeader);
    ui.tableView->setModel(model);

 
    connect(ui.pushButton,&QPushButton::clicked,this,[=]() {
            //接收用户输入
        QString src_ip = ui.lineEdit->text();
        QString dest_ip = ui.lineEdit_2->text();
        qDebug() << src_ip;
        qDebug() << dest_ip;
        int i = 0;
        while (true) {
            model->setItem(i, 0, new QStandardItem("1"));
            model->setItem(i, 1, new QStandardItem("13:10"));
            model->setItem(i, 2, new QStandardItem("10.0.1.2"));
            model->setItem(i, 3, new QStandardItem("198.10.2.3"));
            model->setItem(i, 4, new QStandardItem("ARP"));
            model->setItem(i, 5, new QStandardItem("11"));
            model->setItem(i++, 6, new QStandardItem("1009"));
            if (i == 6)
                break;
        }
        QMessageBox::information(this,"srds","sdsd");
        });

}
