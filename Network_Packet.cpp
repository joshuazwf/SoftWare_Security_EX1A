#include "Network_Packet.h"





Network_Packet::Network_Packet(char* filter) {
	Network_Packet::filter = filter;
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error inpcap_findalldevs: %s\n", errbuf);
	}
	//�����������������
	for (d = alldevs;d;d = d->next) {
		i++;
	}
	//���ʾû�еõ�����������
	if (i == 0) {

	}
	int choice = 2;//�����Ƕ��������а�
	if (choice<1 || choice>i) {
		pcap_freealldevs(alldevs);
	}
	//�����û������룬ͨ��ָ�������Ѱ����ǰ����
	for (d = alldevs, i = 0;i < choice;i++, d = d->next);
	/* d->name to hand to "pcap_open_live()" */
	/*ֵ65535Ӧ�����Բ������ݰ��п��õ���������*/
	/*�����豸���õ�����ģʽ�����ڼ���*/
	/*������Ϣ��ʾ*/
	handler = pcap_open_live(d->name, (int)65536, 1, 1000, errbuf);

	//��ʾû�д򿪳ɹ�
	if (handler == NULL) {
		pcap_freealldevs(alldevs);
	}
	int res = pcap_datalink(handler);
	//Ŀǰ�������·���Э���� ��̫����Э��
	if (res != DLT_EN10MB) {
		pcap_freealldevs(alldevs);
	}
	bpf_u_int32 netmask;
	if (d->addresses != NULL) {
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else {
		/* �������ӿ�û�е�ַ��ô���Ǽ�����ΪC���ַ */
		netmask = 0xffffff;
	}
	//Structure for "pcap_compile()", "pcap_setfilter()", etc..
	struct bpf_program fcode;
	int res_compile = pcap_compile(handler, &fcode, filter, 1, netmask);
	if (res_compile < 0) {
		pcap_freealldevs(alldevs);
	}
	if (pcap_setfilter(handler, &fcode) < 0) {
		pcap_freealldevs(alldevs);
	}
	//�����б�������Ϣ�Ѿ�ʹ����ϣ������ͷŸÿռ�
	pcap_freealldevs(alldevs);
	//����Ļص����� ������ȫ�ֻ����Ǿ�̬����
}



