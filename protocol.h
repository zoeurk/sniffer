#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "others.h"
#include "utils.h"

#define LINK_LAYER 14

#define IPV4 4
#define IPV6 6

#define ICMP 1
#define TCP 6
#define UDP 17
#define ICMPv6 58

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
enum printing{
	hdr		= 1,
	addr		= 2,
	linklayer	= 4,
	pkt		= 8,
	option		= 16,
	data		= 32,
	data_hex	= 64
};
struct tcpflags{
	int size;
	int ___;
	char flags[8];
	struct tcpflags *next;
};
struct host{
	char *host;
	struct host *next;
};
struct optflags{
	unsigned int version:4,protocol:28;
	int port;
	struct host *host;
	struct tcpflags *tcpflags;
	struct optflags *next;
};
enum ipv4header_flags{
	DF = 2,
	MF = 4
};
enum TCPFLAGS{
	FIN = 1,
	SYN = 2,
	RST = 4,
	PSH = 8,
	ACK = 16,
	URG = 32,
	ECE = 64
};
unsigned short int checksum_calculation(const void *buffer,unsigned long int bufsize);
void print_ipv4hdr(struct output *out);
void print_ipv6hdr(struct output *out);
void print_options(char *data,unsigned long int len);
void print_data(char *data,unsigned long int len);
void print_data_hex(char *data,unsigned long int len);
void print_linklayer(struct output *o);
void print_addr(struct output *o);
void print_icmp4(struct output *out);
void print_tcp4(struct output *out);
void print_udp4(struct output *out);
void *c_alloc(void *check, unsigned long int size);
void *analyse(void *buf);
void print_it(void *output);
int show_it(struct optflags *poptflags,struct output *myoutput);
#endif
