#ifndef PROTOCOLDEFINITION_H
#define PROTOCOLDEFINITION_H
#include <stdlib.h>
#include <string.h>
#include "protocol.h"
#include "protocol-print.h"
struct ipv4header{
	unsigned char ihl:4,version:4;
	unsigned char ecn:2,dscp:6;
	unsigned short int length;
	unsigned short int id;
	unsigned short int frag_offset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short int checksum;
	unsigned int src_ip;
	unsigned int dst_ip;
};
struct ipv6header{
	unsigned long int flow_label:20,traffic_class:8,version:4;
	unsigned short int payload_length;
	unsigned char next_header;
	unsigned char hop_limit;
	unsigned char src_ip[16];
	unsigned char dst_ip[16];
};
struct icmp4header{
	unsigned char type;
	unsigned char code;
	unsigned short int checksum;
	unsigned short int id;
	unsigned short int seq;
};
struct udp4header{
	unsigned short int src_port;
	unsigned short int dst_port;
	unsigned short int length;
	unsigned short int checksum;
};
//#pragma pack(push,1)
struct pseudo_icmp6header{
	unsigned char ip_src[16];
	unsigned char ip_dst[16];
	unsigned int length;
	char zero[3];
	unsigned char next_header;
}__attribute__((packed));
//#pragma pack(pop)
struct pseudo_udp4header{
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned char zero;
	unsigned char protocole;
	unsigned short int length;
};
struct pseudo_udp6header{
	unsigned char src_ip[16];
	unsigned char dst_ip[16];
	unsigned char zero;
	unsigned char protocole;
	unsigned short int length;
};
struct tcp4header{
	unsigned short int src_port;
	unsigned short int dst_port;
	unsigned int seq;
	unsigned int ack;
	unsigned char ecn:1,reserved:3,header_size:4;
	unsigned char flags;
	unsigned short int window;
	unsigned short int checksum;
	unsigned short int urgptr;
};
struct pseudo_tcp4header{
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned char zero;
	unsigned char protocol;
	unsigned short int length;
};
struct pseudo_tcp6header{
	unsigned char src_ip[16];
	unsigned char dst_ip[16];
	unsigned char zero;
	unsigned char protocol;
	unsigned short int length;
};

unsigned short int checksum_calculation(const void *buffer,unsigned long int bufsize);
void *c_alloc(void *check, unsigned long int size);
void protocol_icmpv6(void *ip,unsigned long int *sz);
void protocol_icmp4(void *ip);
void protocol_tcp4(struct ipv4header *ip4, void *ip, unsigned long int *sz);
void protocol_tcp6(struct ipv6header *ip6, void *ip, unsigned long int *sz);
void protocol_udp4(struct ipv4header *ip4, void *ip, unsigned long int *sz);
void protocol_udp6(struct ipv6header *ip6, void *ip, unsigned long int *sz);
#endif

