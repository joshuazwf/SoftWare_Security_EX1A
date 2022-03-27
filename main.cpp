#include "QtWidgetsApplication1.h"
#include <QtWidgets/QApplication>
#include<QStandardItemModel>
#include "Network_Packet.h"
#include<QDebug>
#include<QJsonObject>
#include<QJsonDocument>


#pragma execution_character_set("utf-8")

void data_link_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
QJsonObject net4_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void net6_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void arp_pck(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void Transmission_tcp_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void Transmission_udp_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void HTTP_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

void data_link_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    //��ȡ��ǰ����ʱ��
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;
    (VOID)(param);
    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
    //����̫����֡���з���
    u_short type;
    ethernet_header* E_header = (ethernet_header*)pkt_data;
    type = ntohs(E_header->type);
    qDebug("%x:%x:%x:%x:%x:%x", E_header->src_mac.first, E_header->src_mac.second, E_header->src_mac.third, E_header->src_mac.four, E_header->src_mac.five, E_header->src_mac.six);
    qDebug("%x:%x:%x:%x:%x:%x", E_header->dst_mac.first, E_header->dst_mac.second, E_header->dst_mac.third, E_header->dst_mac.four, E_header->dst_mac.five, E_header->dst_mac.six);
    qDebug("0x%0x",type);
    if (type == 0x0800) {
        qDebug() << "ipv4";
        QJsonObject re=net4_layer_handler(param, header, pkt_data + 14);
        QJsonDocument docu;
        docu.setObject(re);
        QByteArray byte = docu.toJson(QJsonDocument::Compact);
        QString str(byte);
        qDebug() << "test json:"<<str;
    }
    else if (type == 0x86DD) {
        qDebug() << "ipv6";
        net6_layer_handler(param, header, pkt_data + 14);
    }
    else if (type == 0x0806) {
        qDebug() << "arp";
        arp_pck(param, header, pkt_data + 14);
    }
    else {
        //��ʱ������
    }
}

QJsonObject net4_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    IPV4_Header* ip4_header = (IPV4_Header*)pkt_data;
    // ip4���Ȳ���
    //���Ի�õ�ip���еĸ�������
    /** 1 ICMP * 2 IGMP* 6 TCP* 17 UDP*/
    QString src_ip = QString::number(ip4_header->src_ip.fisrt)+"."+ QString::number(ip4_header->src_ip.second)
        +"." + QString::number(ip4_header->src_ip.third) + "." + QString::number(ip4_header->src_ip.fourth);
    QString dst_ip = QString::number(ip4_header->dst_ip.fisrt) + "." + QString::number(ip4_header->dst_ip.second)
        +"."+ QString::number(ip4_header->dst_ip.third) +"." + QString::number(ip4_header->dst_ip.fourth);
    u_char version = (ip4_header->version_length) & (0xf0); //11110000
    version /= 16;
    u_int ip_len = ((ip4_header->version_length) & 0xf) * 4;
    u_char tos = ntohs(ip4_header->type_of_service);
    u_short t_len = ntohs(ip4_header->total_len);
    u_short identifier = ntohs(ip4_header->identifier);
    u_short flags = (ntohs(ip4_header->flags_fragment)) &0xe0000;//3λ��־
    u_short fragment = (ntohs(ip4_header->flags_fragment))& 0x1fff;//13λƫ��
    u_char ttl=ip4_header->TTL;
    u_char protocol = (ip4_header->protocol);
    u_short check_sum = ntohs(ip4_header->header_sum);
    QJsonObject obj;
    obj.insert("Version", (int)version);
    obj.insert("Header Length", QString::number(ip_len)+" bytes");
    QString toss= QString("%1").arg(tos, 2, 16, QLatin1Char('0'));
    obj.insert("Type of Service", "0x"+toss);
    obj.insert("Total Length",t_len);
    QString iden = QString("%1").arg(identifier, 2, 16, QLatin1Char('0'));
    obj.insert("Identification","0x"+iden);
    //flagsת��Ϊ��������ʾ
    QString b = QString("%1").arg(flags, 16, 2, QLatin1Char('0'));//תΪ2����  16λ���
    QString flag = b.left(3);
    obj.insert("flags[ReservedBit,Don't Fragment,More Fragment]", flag);
    QString f= QString("%1").arg(fragment, 16, 2, QLatin1Char('0'));
    QString frag = f.right(13);
    obj.insert("Fragment", frag);
    obj.insert("Time to Live", ttl);
    QString pro;
    if (protocol == 6)
        pro = "tcp(6)";
    if (protocol == 17)
        pro = "udp(17)";
    if (protocol == 1)
        pro = "icmp(1)";
    obj.insert("Protocol",pro);
    QString sum = QString("%1").arg(check_sum, 2, 16, QLatin1Char('0'));
    obj.insert("Check Sum", "0x"+sum);
    obj.insert("Src IP", src_ip);
    obj.insert("DST IP", dst_ip);


    qDebug("%d.%d.%d.%d -> %d.%d.%d.%d\n",
        ip4_header->src_ip.fisrt,
        ip4_header->src_ip.second,
        ip4_header->src_ip.third,
        ip4_header->src_ip.fourth,
        ip4_header->dst_ip.fisrt,
        ip4_header->dst_ip.second,
        ip4_header->dst_ip.third,
        ip4_header ->dst_ip.fourth
        );
      
    qDebug() << "pro=" << protocol;
    if (protocol == 6) {
        qDebug() << "tcp";
        Transmission_tcp_handler(param, header, pkt_data + ip_len);
    }
    else if (protocol == 17) {
        qDebug() << "udp";
        Transmission_udp_handler(param, header, pkt_data + ip_len);
    }
    else if (protocol == 1) {
        qDebug() << "icmp";
        //icmp_handler(param, header, pkt_data + ip_len);
    }
    else {
        //�ݲ�����
    }

    return obj;
}


void net6_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    IPV6_Header* ip6_header = (IPV6_Header*)pkt_data;
    qDebug("%x:%x:%x:%x:%x:%x:%x:%x", ip6_header->src_ip.first, ip6_header->src_ip.second, ip6_header->src_ip.third, 
        ip6_header->src_ip.fourth, ip6_header->src_ip.five
        ,ip6_header->src_ip.six, ip6_header->src_ip.second, ip6_header->src_ip.eight);

    qDebug("%x:%x:%x:%x:%x:%x:%x:%x", ip6_header->dst_ip.first, ip6_header->dst_ip.second, ip6_header->dst_ip.third,
        ip6_header->dst_ip.fourth, ip6_header->dst_ip.five
        , ip6_header->dst_ip.six, ip6_header->dst_ip.second, ip6_header->dst_ip.eight);
    qDebug()<<"limit="<<ip6_header->limit;
    if (ip6_header->next == 6) {
        qDebug() << "tcp";
        Transmission_tcp_handler(param, header, pkt_data + 40);
    }
    if (ip6_header->next == 17) {
        qDebug() << "udp";
        Transmission_udp_handler(param, header, pkt_data + 40);
    }
    if (ip6_header->next == 1) {
       // icmp_handler(param, header, pkt_data + 40);
    }
}


void arp_pck(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    ARP* arp_h = (ARP*)pkt_data;

    qDebug("type=%d", ntohs(arp_h->hard_type));
    qDebug("%d.%d.%d.%d -> %d.%d.%d.%d\n",
        arp_h->src_ip.fisrt,
        arp_h->src_ip.second,
        arp_h->src_ip.third,
        arp_h->src_ip.fourth,
        arp_h->dst_ip.fisrt,
        arp_h->dst_ip.second,
        arp_h->dst_ip.third,
        arp_h->dst_ip.fourth
    );
    qDebug("%x:%x:%x:%x:%x:%x", arp_h->src_mac.first, arp_h->src_mac.second, arp_h->src_mac.third, arp_h->src_mac.four,
        arp_h->src_mac.five, arp_h->src_mac.six);
    qDebug("%x:%x:%x:%x:%x:%x", arp_h->dst_mac.first, arp_h->dst_mac.second, arp_h->dst_mac.third, arp_h->dst_mac.four,
        arp_h->dst_mac.five, arp_h->dst_mac.six);
    //�õ�ARP�ĸ����ֶ�
}

void Transmission_tcp_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    TCP_header* tcp_header = (TCP_header*)pkt_data;
    //��ö˿ں�
    u_short dst_port = ntohs(tcp_header->dst_port);
    u_short src_port = ntohs(tcp_header->src_port);
    u_short head_len = (ntohs(tcp_header->len_keep_flag)) & 0xf0000;

    qDebug("dst_port=%d", dst_port);
    qDebug("src_port=%d", src_port);
    qDebug("seq=%d", ntohs(tcp_header->seq));
    qDebug("ack=%d", ntohs(tcp_header->ack));

    qDebug("winsize=%d", ntohs(tcp_header->win_size));

    //HTTP Ӧ�ò�Э��
    if (dst_port == 80 || src_port == 80) {
        //HTTP_layer_handler(param, header, pkt_data + head_len);
    }
    //TLS/SSLЭ�� �˿�Ϊ443
    if (dst_port == 443 || src_port == 443) {

    }
}

void Transmission_udp_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    UDP_Header* udp_header = (UDP_Header*)pkt_data;
    //֮����Լ���DNS�Ĳ���  53�˿�
    qDebug("dst_port=%d", ntohs(udp_header->dst_port));
    qDebug("len=%d", ntohs(udp_header->length));
}

void HTTP_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    //��pkt_data��ʼ����HTTP�������Ϣ�� ֱ���������
}

int main(int argc, char* argv[]){
    //�����û����뵽����ѡ�������Ľ���
    // 
    // 
    /*
    //����ѡ��֮�󣬽�����ת��ץ������
    QApplication a(argc, argv);
    //������ʾ
    QtWidgetsApplication1 w;
    QStringList strHeader;
    strHeader<< "Time"<< "Source"<< "DEST"<< "Protocol" << "Length"<< "info";
    QStandardItemModel* model = new QStandardItemModel(&w);
    model->setHorizontalHeaderLabels(strHeader);
    w.ui.tableView->setModel(model);
    w.show();
    */

    //char *filter = NULL;
    char filter[] = "ip";
    //��������һ����֮�󣬱�Ὺʼץ����
    Network_Packet sniffer = Network_Packet(filter);

    qDebug() << "test";

    pcap_loop(sniffer.handler,0,data_link_handler,NULL );

    delete(&sniffer);

    /*
    for (sniffer.d = sniffer.alldevs;sniffer.d;sniffer.d = sniffer.d->next) {
        qDebug() << sniffer.d->description;
    }
    */
    return 0;
    
    

    /*
    int i = 0;
    while (true) {
        model->setItem(i, 0, new QStandardItem("13:10"));
        model->setItem(i, 1, new QStandardItem("10.0.1.2"));
        model->setItem(i, 2, new QStandardItem("198.10.2.3"));
        model->setItem(i, 3, new QStandardItem("ARP"));
        model->setItem(i, 4, new QStandardItem("11"));
        model->setItem(i++, 5, new QStandardItem("1009"));
        if (i == 100)
            break;
        qApp->processEvents();
    }
	return  a.exec();*/
}










