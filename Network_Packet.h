#pragma once
#include "pcap.h"

//可以使用计数器对每一种类型的包进行统计
class Network_Packet
{
public:
	pcap_t* handler;
	pcap_if_t* alldevs, * d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *filter;
	Network_Packet(char* filter);
	/*
	static void data_link_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
	static void arp_pck(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
	static void net4_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
	static void net6_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
	static void icmp_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
	static void Transmission_tcp_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
	static void Transmission_udp_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
	static void HTTP_layer_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
	*/
};



class UDP_Header {
public:
	u_short src_port;
	u_short dst_port;
	u_short length;
	u_short check_sum;
};

class IP_Address {
public:
	u_char fisrt;
	u_char second;
	u_char third;
	u_char fourth;
};

class IPV4_Header {
public:
	u_char version_length;
	u_char type_of_service;
	u_short total_len;
	u_short identifier;
	u_short flags_fragment;
	u_char TTL;
	u_char protocol;
	u_short header_sum;
	IP_Address src_ip;
	IP_Address dst_ip;
	u_int opt_padding;
};

class IPV6_Add {
public:
	u_short first;
	u_short second;
	u_short third;
	u_short fourth;
	u_short five;
	u_short six;
	u_short seven;
	u_short eight;
};

class IPV6_Header {
public:
	u_int ver_flow_label;
	u_short data_len;
	u_char next;
	u_char limit;
	IPV6_Add src_ip;
	IPV6_Add dst_ip;
};

class TCP_header {
public:
	u_short src_port;
	u_short dst_port;
	u_int seq;
	u_int ack;
	u_short len_keep_flag;//存在首部长度的字段
	u_short win_size;
	u_short check_sum;
	u_short urgency;
};

class ether_add {
public:
	u_char first;
	u_char second;
	u_char third;
	u_char four;
	u_char five;
	u_char six;
};

class ethernet_header {
public:
	ether_add src_mac;
	ether_add dst_mac;
	u_short type;
};

class ARP {
public:
	u_short hard_type;
	u_short pro_type;
	u_char add_len;
	u_char pro_len;
	u_short op_type;
	ether_add src_mac;
	IP_Address src_ip;
	ether_add dst_mac;
	IP_Address dst_ip;
};

class ICMP {
public:
	u_char icmp_type;
	u_char icmp_code;
	u_short check_sum;
};
