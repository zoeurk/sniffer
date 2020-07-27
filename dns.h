#ifndef DNS_H
#define DNS_H
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define ADDRESS 1
#define NS 2
#define CNAME 5
#define SOA 6
#define PTR 12
#define MX 15
#define TXT 16
#define ADDRESS6 28
#define OPT 41
#define ALL 255
#define CAA 257
struct dns{
	unsigned short int  id;
	unsigned char Rd:1,Tc:1,Aa:1,opcode:4,qr:1;
	unsigned char Rcode:4,Z:3,Ra:1;
	unsigned short int Qdcount;
	unsigned short int Ancount;
	unsigned short int Nscount;
	unsigned short int Arcount;
};
struct question{
	unsigned short int	qtype;
	unsigned short int	qclass;
};
struct answer{
	unsigned short int 	type;
	unsigned short int 	class;
	unsigned int		ttl;
	unsigned short int	len;
}__attribute__((packed));
struct dnsopt{
	unsigned short int	type;
	unsigned short int	class;
	unsigned short int	___;
	unsigned short int	DO;
	unsigned short int	ttl;
};
struct soa{
	unsigned int serial;
	unsigned int refresh;
	unsigned int retry;
	unsigned int expire;
	unsigned int minimum;
};
unsigned char *ReadName(unsigned char* reader,unsigned char* buffer,int* count, unsigned char *name);
void dns_type_41(void *pdata);
void dns_type(int type, unsigned char **pdata,unsigned char *data, int *len, unsigned char *host);
void services_udp_src(char *data);
void services_udp_dst(char *data);
#endif
