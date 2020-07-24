#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "protocol-definition.h"
#include "others.h"
#include "utils.h"

#define LINK_LAYER 14

#define IPV4 4
#define IPV6 6

#define ICMP 1
#define TCP 6
#define UDP 17
#define ICMPv6 58

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
	unsigned int version:4,protocol:24,protoflag:4;
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
void *analyse(void *buf);
void print_it(void *output);
int hostcmp(char *host1, char *host2);
int show_it(struct optflags *poptflags,struct output *myoutput);
#endif
