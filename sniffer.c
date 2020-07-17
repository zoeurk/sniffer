#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <time.h>

#include <argp.h>
#include <strings.h>

#define LINK_LAYER 14

#define IPV4 4
#define IPV6 6

#define ICMP 1
#define TCP 6
#define UDP 17
#define ICMPv6 58

#define ADDRESS 1
#define NS 2
#define CNAME 5
#define SOA 6
#define PTR 12
#define MX 15
#define TXT 16
#define ADDRESS6 28
#define OPT 41

#define DNS_PORT 53
#define NTP_PORT 123

#define MAXINT 4294967296.0
#define JAN_1970 2208988800U

#define UNSPECIFIED 0
#define PRIM_REF 1
#define INFO_QUERY 62
#define INFO_REPLY 63

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
struct icmp4output{
	unsigned char type;
	unsigned char code;
	unsigned short int id;
	unsigned short int seq;
	unsigned short int checksum;
	unsigned short int re_checksum;
};
struct udp4output{
	unsigned short int src_port;
	unsigned short int dst_port;
	unsigned short int checksum;
	unsigned short int re_checksum;
	unsigned short int length;
};
struct tcp4output{
	unsigned short int src_port;
	unsigned short int dst_port;
	unsigned short int checksum;
	unsigned short int re_checksum;
	unsigned short int length;
	unsigned short int ___;
	unsigned int seq;
	unsigned int ack;
	char ecn;
	char flags[7];
	unsigned short int window;
	unsigned short int urgptr;
	int header_size;
	int padding;
	unsigned long int optlen;
	char *options;
};
union ipv4output{
	struct icmp4output icmp4;
	struct udp4output udp4;
	struct tcp4output tcp4;
};
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
struct frac_32{
	short int seconds;
	unsigned short int fraction;
};
struct frac_64{
	int seconds;
	unsigned int fraction;
};
struct ntp{
	char m:3,v:3,l:2;
	char peer_clock_stratum;
	char peer_polling_interval;
	char peer_clock_precision;
	struct frac_32 root_delay;
	struct frac_32 clock_dispertion;
	int reference_clock_id;
	struct frac_64 reference_timestamp;
	struct frac_64 original_timestamp;
	struct frac_64 received_timestamp;
	struct frac_64 transmit_timestamp;
	unsigned int key_id;
	unsigned char msg_digest[16];
};
struct output{
	unsigned long int sizeread;
	char link_layer[14];
	unsigned char version;
	unsigned char ihl;
	unsigned short int id;
	unsigned short int ipchecksum;
	unsigned short int re_ipchecksum;
	unsigned short int offset;
	unsigned short int length;
	unsigned char ttl;
	unsigned char protocol;
	char ipflags[3], pad[5];
	char src_addr[48];
	char dst_addr[48];
	char src_hostname[NI_MAXHOST];
	char dst_hostname[NI_MAXHOST];
	char ______[14];
	int optlen;
	unsigned long int datalen;
	char *options;
	char *data;
	union {
		struct icmp4output icmp4;
		struct udp4output udp4;
		struct tcp4output tcp4;
	};
	void (*print_hdr)(struct output *);
	void (*print_addr)(struct output *);
	void (*print_linklayer)(struct output *);
	void (*print_pkt)(struct output *);
	void (*print_options)(char *,unsigned long int);
	void (*print_data)(char *, unsigned long int);
	void (*print_data_hex)(char *, unsigned long int);
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
struct arguments{
	char *interface;
	unsigned long int options;
	unsigned long int count_captured;
	unsigned long int count_selected;
	unsigned long int count_received;
	struct optflags *opt;
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
enum ARGS_OPTIONS{
	NORESOLV	= 1,
	NOLINKLAYER	= 2,
	NOADDRESS	= 4,
	NOTRANSPORT	= 8,
	NOHEADER	= 16,
	NOOPTIONS	= 32,
	NODATA		= 64,
	NODATAHEX	= 128,
	VERBEUX		= 256
};
const char 			*argp_program_version = "sniffer-2.0";
const char 			*argp_program_bug_address = "zoeurk@gmail.com";

static struct output		myoutput = {0, {'\0'}, 0, 0, 0, 0 ,0, 0, 0, 0, 0,
						"\0","\0","\0", "\0", "\0", "\0", "\0",
						0, 0, NULL, NULL, {{0,0,0,0,0,0}},
						NULL, NULL, NULL, NULL, NULL, NULL, NULL
				};
static int 			s;
static unsigned long int 	captured = 0, statsrecv = 0, statsdrops = 0, selected = 0;
static void 			*check = NULL;
static char			___flags___[7] = "FSRPAUE",
				*ip4flags[3]={ NULL, "DF", "MF" };
static char 			buffer[65535];
static char 			doc[] = "Simple sniffer TCP/IP";
static struct argp_option	options[] = {
						{"interface", 'i', "inteface", 0, "interface utilisée", 0 },
						{"flags", 'f', "opt1:arg;opt2:arg2[;...]", 0, "options de filtre", 0},
						{"noresolv", 'R', 0,  0, "ne faire de resolution de nom", 0},
						{"nolinklayer",'L', 0, 0, "pas afficher address mac", 0 },
						{"noaddress",'A', 0, 0, "ne pas afficher l'ip et les informations relatives(ex: hostname)", 0},
						{"notransport", 'T', 0 , 0, "ne pas afficher les infos relative à la couche transport (ex: checksum)",0},
						{"noheader", 'H', 0, 0, "ne pas afficher les entetes ip", 0},						
						{"nooptions", 'O', 0, 0, "ne pas afficher les options IP", 0},
						{"nodata", 'd', 0, 0, "pas afficher les datas", 0 },
						{"nohexa", 'D', 0, 0, "pas afficher les datas au format hexadecimal", 0},
						{"count_captured", 'c', "x", 0, "s'arreter après avoir capture un certain nombre de packet analysé", 0},
						{"count_received",'r', "x", 0, "s'arreter après avoir capture un certain nombre de packet recu", 0},
						{"count_selected",'C', "x", 0, "s'arreter après avoir capture un certain nombre de packet selectionné par les filtres", 0},
						{"verbose", 'v', 0, 0, "mode verbeux (port 53 et 123)", 0},
						{0}
				};
static struct arguments		args = { NULL, 0, 0, 0, 0, NULL };
void delete_arguments(struct arguments *args){
	struct optflags *opt_delete;
	struct tcpflags *tcpflags_delete;
	struct host *hs_delete;
	if(args->opt){
		opt_delete = args->opt->next;
		while(args->opt->host){
			hs_delete = args->opt->host->next;
			free(args->opt->host);
			args->opt->host = hs_delete;
		}
		while(args->opt->tcpflags){
			tcpflags_delete = args->opt->tcpflags->next;
			free(args->opt->tcpflags);
			args->opt->tcpflags = tcpflags_delete;
		}
		free(args->opt);
		args->opt = opt_delete;
	}
}
static error_t parse_opt(int key, char *arg, struct argp_state *state){
	struct arguments *_args_ = state->input;
	struct optflags *optflags = NULL, *poptflags;
	struct tcpflags *ptcpflags;
	struct host *phs;
	char *save, *ptr, *pstr, *_pstr_,
		*save2, *ptr2, *pstr2, *pchar,
		*allopt[] = {"VERSION:","HOST:", "PORT:", "PROTOCOL:", "TCPFLAGS:", NULL},
		*flags, *protocol, 
		*no_protocols[] = {"TCP","UDP","ICMP","ICMPv6", NULL};
	int i, ok;
	switch(key){
		case 'i':	_args_->interface = arg;
			 	break;
		case 'f':	ptr = arg;
				if(_args_->opt == NULL){
					poptflags = _args_->opt = calloc(1,sizeof(struct optflags));
					poptflags->next = NULL;
				}else{
					optflags = _args_->opt;
					while(optflags->next)
						optflags = optflags->next;
					poptflags = optflags;
					poptflags->next = calloc(1,sizeof(struct optflags));
					poptflags = poptflags->next;
				}
				while((pstr = strtok_r(ptr,";",&save))){
					ptr = NULL;
					for(i = 0, ok = 0; ok == 0 && allopt[i] != NULL; i++)
						if(strncasecmp(allopt[i],pstr,strlen(allopt[i])) == 0)
							switch(i){
								case 0: if((_pstr_ = strchr(pstr,':'))){
										poptflags->version = atoi(_pstr_+1);
										*_pstr_ = '\0';
										if(poptflags->version == 4 || poptflags->version == 6)
											ok = 1;
										else
											if(_pstr_[1] == '\0')
												ok = -1;
											else
												ok = -2;
									}else
										ok = -1;
									break;
								case 1:	if((_pstr_ = strchr(pstr,':'))){
										*_pstr_ = '\0';
										ptr2 = (_pstr_ + 1);
										if(strchr(ptr2,','))
											while((pstr2 = strtok_r(ptr2,",", &save2))){
											ptr2 = NULL;
											if(poptflags->host == NULL){
													phs = poptflags->host = calloc(1,sizeof(struct host));
												}else{
													phs = poptflags->host;
													while(phs->next)
														phs = phs->next;
													phs->next = calloc(1,sizeof(struct host));
													phs = phs->next;
												}
												phs->host = pstr2;
											}
										else{
											phs = poptflags->host = calloc(1,sizeof(struct host));
											phs->host = ptr2;
										}
									}else{
										ok = -1;
										break;
									}
									ok = 1;
									break;
								case 2: if(poptflags->protocol == 0 ||
										(poptflags->protocol != 1 && poptflags->protocol != 58))
									{
										if((_pstr_ = strchr(pstr,':'))){
											poptflags->port = atoi(_pstr_+1);
											*_pstr_ = '\0';
											if(poptflags->port <= 0 || poptflags->port > 65535){
												ok = -2;
											}else	
												ok = 1;
										}else
											ok = -1;
										break;
									}else
										ok = -3;
									break;
								case 3:	if((_pstr_ = strchr(pstr,':'))){
										protocol = (char *)(_pstr_+1);
										*_pstr_ = '\0';
										for(i = 0; no_protocols[i] != NULL && strcasecmp(protocol,no_protocols[i]) != 0; i++);;
										if(no_protocols[i] == NULL){
											ok = -2;
											break;
										}
										switch(i){
											case 0:	if(poptflags->protocol != 6 && poptflags->protocol != 0){
													ok  = -3;
													break;
												}
												poptflags->protocol = 6;
												break;
											case 1:	if(poptflags->protocol != 17 && poptflags->protocol != 0){
													ok  = -3;
													break;
												}
												poptflags->protocol = 17;
												break;
											case 2:	if(poptflags->protocol != 1 && poptflags->protocol != 0 
													&& poptflags->port == 0)
												{
													ok  = -3;
													break;
												}
												poptflags->protocol = 1;
												break;
											case 3:	if(poptflags->protocol != 58 && poptflags->protocol != 0
													&& poptflags->port == 0)
												{
													ok  = -3;
													break;
												}
												poptflags->protocol = 58;
												break;
										}
										if(ok != 0)break;
									}else{
										ok = -1;
										break;
									}
									ok = 1;
									break;
								case 4:	if(poptflags->protocol == 6 || poptflags->protocol == 0){
										if((_pstr_ = strchr(pstr,':'))){
											flags = (char *)(_pstr_+1);
											*_pstr_ = '\0';
											ptr2 = flags;
											for(pchar = ptr2, i = 0; *pchar != '\0' && i != 7;pchar++){
												if(*pchar == '|'){
													continue;
												}
												for(i = 0;
													i < 7 &&
													(*pchar != ___flags___[i] &&
														*pchar != ___flags___[i]+32);
													i++
												);;
											}
											if(i == 7){
												ok = -2;
												break;
											}
											while((pstr2 = strtok_r(ptr2,"|", &save2))){
												ptr2 = NULL;
												if(poptflags->tcpflags == NULL){
													ptcpflags = poptflags->tcpflags = calloc(1,sizeof(struct tcpflags));
												}else{
													ptcpflags = poptflags->tcpflags;
													while(ptcpflags->next)
														ptcpflags = ptcpflags->next;
													ptcpflags->next = calloc(1,sizeof(struct tcpflags));
													ptcpflags = ptcpflags->next;
												}
												strcpy(ptcpflags->flags,pstr2);
												ptcpflags->size = strlen(pstr2);
											}
											poptflags->protocol = 6;
										}else{
											ok = -1;
											break;
										}
										ok = 1;
										break;
									}else
										ok = -3;
									break;
					}
					switch(ok){
						case -3:printf("Mismatch in arguments.\n");
							delete_arguments(_args_);
							return -1;
						case -2:printf("Bad  argument in \"%s\"\n", pstr);
							delete_arguments(_args_);
							return -1;
						case -1:printf("\"%s\" take one argument\n", pstr);
							delete_arguments(_args_);
							return -1;
						case 0:	printf("Unknow option for \"%s\"\n",pstr);
							delete_arguments(_args_);
							return -1;
						case 1:break;
					}
				}
				break;
		case 'R':	_args_->options |= NORESOLV;
				break;
		case 'L':	_args_->options |= NOLINKLAYER;
				break;
		case 'A':	_args_->options |= NOADDRESS;
				break;
		case 'T':	_args_->options |= NOTRANSPORT;
				break;
		case 'H':	_args_->options |= NOHEADER;
				break;
		case 'O':	_args_->options |= NOOPTIONS;
				break;
		case 'd':	_args_->options |= NODATA;
				break;
		case 'D':	_args_->options |= NODATAHEX;
				break;
		case 'c':	_args_->count_captured = atol(arg);
				break;
		case 'r':	_args_->count_received = atol(arg);
				break;
		case 'C':	_args_->count_selected = atol(arg);
				break;
		case 'v':	_args_->options |= VERBEUX;
				break;
		case ARGP_KEY_END:
				break;
		case ARGP_KEY_ARG:
				break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp		argp = {options, parse_opt, NULL, doc, 0, 0 ,0 };

unsigned short int checksum_calculation(const void *buffer,unsigned long int bufsize){
	unsigned short int checksum;
	const unsigned short int *ptr;
	unsigned long int size = bufsize;
	unsigned int ___checksum___;
	unsigned char ___char___ = bufsize%2;
	for(	___checksum___ = 0,
		ptr = buffer,
		size -= ___char___;
		size > 0;
		___checksum___ += *((unsigned short int *)ptr),
		size-=2 , ptr++
	);;
   	if(___char___)
		___checksum___ += *((unsigned char *)ptr);
	while(___checksum___ >> 16)
		___checksum___ = (___checksum___ & 0xffff) + (___checksum___ >> 16);
	checksum = ~___checksum___;
   	return checksum;
}
void finish(int sig){
	struct tpacket_stats stats = {};
	socklen_t len = sizeof(stats);
	getsockopt(s, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
	statsrecv += stats.tp_packets;
	statsdrops  += stats.tp_drops;
	printf("\nPacket Selected:%lu\nPacket Captured:%lu\nPacket Received By Kernel:%lu\nPacket Dropped By Kernel:%lu\n",
		selected, captured, statsrecv, statsdrops);
	if(check != NULL)
		free(check);
	delete_arguments(&args);
	close(s);
	if(sig != -1)
		exit(EXIT_SUCCESS);
}
int ___getnameinfo___(void *sa,unsigned long int sa_sz,char **addr,unsigned long int addrlen,char *addr_ip){
	int ret;
	memset(sa, 0, sa_sz);
	((struct sockaddr_in *)sa)->sin_family = AF_INET;
	inet_pton(((struct sockaddr_in *)sa)->sin_family, addr_ip,
			&((struct sockaddr_in *)sa)->sin_addr);
	ret = getnameinfo((struct sockaddr *)sa, sa_sz,
		*addr,addrlen, NULL, 0, NI_NAMEREQD);
	if(ret == 0)
		return ret;
	((struct sockaddr_in6 *)sa)->sin6_family = AF_INET6;
	inet_pton(((struct sockaddr_in6 *)sa)->sin6_family, addr_ip,
			&((struct sockaddr_in6 *)sa)->sin6_addr);
	ret = getnameinfo((struct sockaddr *)sa, sa_sz,
		*addr,addrlen, NULL, 0, NI_NAMEREQD);
	if(ret == 0)
		return ret;
	else **addr = '\0';
	return -1;
	
}
void print_ipv4hdr(struct output *out){
	printf("Version:%u\nInternet header length:%u\nIP checksum:0x%x (0x%x)\nPacket Length:%u\nOffset:%u\nTime to live:%u\nProtocol:%u\nFlags:%s\n",
		out->version, out->ihl, out->ipchecksum, out->re_ipchecksum, out->length, out->offset, out->ttl, out->protocol, out->ipflags);
}
void print_ipv6hdr(struct output *out){
	
	printf("Version:%u\nInternet header length;%u\nPacket length:%u\n",
		out->version, out->ihl, out->length);
}

void print_options(char *data,unsigned long int len){
	unsigned long int i;
	char *pdata;
	if(len == 0)
		printf("No IP options.\n");
	else{
		printf("IP Options (%lu octet) (in hexadecimal):\n", len);
		for(i = 0, pdata = data; i < len; i++, pdata++)
			if(*pdata > 31 && *pdata != 127)
				printf("\tOctet %lu:\'%c\'\n", i+1, *pdata);
			else
				
				printf("\tOctet %lu:0x%02x\n", i+1, *pdata&0xFF);
		printf("End of options.\n");
	}
}
void print_data(char *data,unsigned long int len){
	unsigned long int i;
	char *pdata;
	if(len > 0){
		printf("Data (%lu octet):\n", len);
		for(i = 0, pdata = data; i < len; i++, pdata++){
			if((*pdata > 31 && *pdata != 127) || *pdata == '\n')
				printf("%c", *pdata);
			else
				printf(".");
		}
		printf("\nEnd of data.\n");
	}else
		printf("print_data():\n\tNo data.\n");
}
void print_data_hex(char *data,unsigned long int len){
	unsigned long int i;
	char *pdata;
	if(len > 0){
		printf("Data (%lu octet) (in hexadecimal):\n", len);
		for(i = 0, pdata = data; i < len; i++, pdata++)
			if(*pdata > 31 && *pdata != 127)
				printf("\tOctet %lu:\'%c\'\n", i+1, *pdata&0xFF);
			else
				printf("\tOctet %lu:0x%02x\n", i+1, *pdata&0xFF);
		printf("End of data.\n");
	}else
		printf("print_data_hex():\n\tNo data.\n");
}
void print_linklayer(struct output *o){
	int i;
	printf("MAC address info:\n");
	for(i = 0; i < 6;i++){
		printf("0x%02x",o->link_layer[i]&0xFF);
		if(i < 5)printf(":");
	}
	printf(" => ");
	for(i = i; i < 12;i++){
		printf("0x%02x",(char)o->link_layer[i]&0xFF);
		if(i < 11)printf(":");
	}
	printf("\n");

}
void print_addr(struct output *o){
	if(o->src_hostname && *o->src_hostname != 0)
		printf("%s (%s)", o->src_hostname, o->src_addr);
	else
		printf("%s", o->src_addr);
	printf(" => ");
	if(o->dst_hostname && strlen(o->dst_hostname) > 0)
		printf("%s (%s)\n", o->dst_hostname, o->dst_addr);
	else
		printf("%s\n", o->dst_addr);
}
void print_icmp4(struct output *out){
	printf("Checksum:0x%x (0x%x)\nType:%u\nCode:%u\nID=%u\nSequence=%u\n",
		out->icmp4.checksum, out->icmp4.re_checksum,
		out->icmp4.type, out->icmp4.code,
		out->icmp4.id, out->icmp4.seq);
}
void print_tcp4(struct output *out){
	unsigned long int i;
	printf("Port Src:%u\nPort Dst:%u\nChecksum:0x%x (0x%x)\nTCP Length:%u\nSequence:%u\nAcknowledgement:%u\nFlags:",
		out->tcp4.src_port, out->tcp4.dst_port,
		out->tcp4.checksum, out->tcp4.re_checksum,
		out->tcp4.length, out->tcp4.seq, out->tcp4.ack);
	for(i = 0; i < 7; i++){
		printf("%c", out->tcp4.flags[i]);
	}
	printf("\nWindow:%u\nurgptr:%u\nHeader size:%u\ntcp4 options (option lenght %lu):\n",
		out->tcp4.window,  out->tcp4.urgptr, out->tcp4.header_size, out->tcp4.optlen);
	for( i = 0; i < out->tcp4.optlen;i++ )
		printf("\tOctet %lu:0x%x\n", i+1, out->tcp4.options[i]&0xFF);
}
void print_udp4(struct output *out){
	printf("Port Src:%u\nPort Dst:%u\nChecksum:0x%x (0x%x)\nUDP Length:%u\n",
		out->udp4.src_port, out->udp4.dst_port,
		out->udp4.checksum, out->udp4.re_checksum,
		out->udp4.length);
}
void *c_alloc(void *check, unsigned long int size){
	if(check == NULL){
		if((check = malloc(size)) == NULL){
			perror("malloc()");
			exit(EXIT_FAILURE);
		}
	}else{
		if((check = realloc(check,size)) == NULL ){
			perror("realloc()");
			exit(EXIT_FAILURE);
		}
	}
	return check;
}
void *analyse(void *buf){
	static unsigned long int	sz = 0;
	struct ipv4header 		*ip4 = (struct ipv4header *)buf;
	struct ipv6header		*ip6 = (struct ipv6header *)buf;
	struct icmp4header 		*icmp4, *c_icmp6;
	struct tcp4header		*tcp4, *c_tcp4;
	struct udp4header 		*udp4, *c_udp4;
	struct pseudo_tcp4header	*pseudo_tcp4;
	struct pseudo_udp4header 	*pseudo_udp4;
	struct pseudo_icmp6header	*pseudo_icmp6;
	struct sockaddr_in 		sa;
	struct sockaddr_in6 		sa6;
	struct in_addr 			src,dst;
	struct in6_addr			src6,dst6;
	int 				fl, temp, size, i;
	char				*phostname, *ip,*ptr;
	switch(ip4->version){
		case IPV4:
			myoutput.ihl = ip4->ihl *4;
			temp = ip4->checksum;
			myoutput.ipchecksum = ntohs(ip4->checksum);
			myoutput.length = htons(ip4->length) - sizeof(struct ipv4header);
			ip4->checksum = 0;
			myoutput.re_ipchecksum = htons(checksum_calculation(ip4, myoutput.ihl));
			ip4->checksum = myoutput.ipchecksum;
			src.s_addr = ip4->src_ip;
			dst.s_addr = ip4->dst_ip;
			inet_ntop(AF_INET,&src,myoutput.src_addr,sizeof(myoutput.src_addr));
			inet_ntop(AF_INET,&dst,myoutput.dst_addr,sizeof(myoutput.dst_addr));
			if((args.options&NORESOLV) == 0){
				phostname = myoutput.src_hostname;
				___getnameinfo___(&sa, sizeof(sa), &phostname, sizeof(myoutput.src_hostname), myoutput.src_addr);
				phostname = myoutput.dst_hostname;
				___getnameinfo___(&sa, sizeof(sa), &phostname, sizeof(myoutput.dst_hostname), myoutput.dst_addr);
			}
			i = ntohs(ip4->frag_offset)>>13;
			*myoutput.ipflags = '\0';
			if( i ){
				for(temp = 1,fl = 2; fl < (1<<3);temp++,fl = fl<<1)
					if( i&fl ){
						strcpy(myoutput.ipflags,ip4flags[temp]);
						break;
					}
			}
			myoutput.id = ntohs(ip4->id);
			myoutput.offset = ntohs(ip4->frag_offset)&0x1ff;
			myoutput.ttl = ip4->ttl;
			myoutput.protocol = ip4->protocol;
			if(myoutput.ihl > sizeof(struct ipv4header)){
				myoutput.optlen = myoutput.ihl - sizeof(struct ipv4header);
				myoutput.options = ((char *)ip4 + sizeof(struct ipv4header));
				myoutput.print_options = print_options;
			}
			myoutput.print_hdr = print_ipv4hdr;
			myoutput.print_addr = print_addr;
			ip = ((char *)ip4 + myoutput.ihl);
			break;
		case IPV6:
			myoutput.protocol = ((struct ipv6header *)ip6)->next_header;
			myoutput.length = myoutput.sizeread - LINK_LAYER - sizeof(struct ipv6header);
			myoutput.ihl = sizeof(struct ipv6header);
			memcpy(src6.s6_addr, ip6->src_ip, sizeof(src6.s6_addr));
			memcpy(dst6.s6_addr, ip6->dst_ip, sizeof(dst6.s6_addr));
			inet_ntop(AF_INET6,&src6,myoutput.src_addr,sizeof(myoutput.src_addr));
			inet_ntop(AF_INET6,&dst6,myoutput.dst_addr,sizeof(myoutput.dst_addr));
			if((args.options&NORESOLV) == 0){
				phostname = myoutput.src_hostname;
				___getnameinfo___(&sa6, sizeof(sa6), &phostname, sizeof(myoutput.src_hostname), myoutput.src_addr);
				phostname = myoutput.dst_hostname;
				___getnameinfo___(&sa6, sizeof(sa6), &phostname, sizeof(myoutput.dst_hostname), myoutput.dst_addr);
			}
			ip = ((char *)ip6 + myoutput.ihl);
			myoutput.print_hdr = print_ipv6hdr;
			myoutput.print_addr = print_addr;
			break;
		default:printf("Unknow Version:%u\n", myoutput.version);
			return  NULL;
	}
	switch(myoutput.protocol){
		case ICMPv6:	icmp4 = (struct icmp4header *)ip;
				size = myoutput.sizeread + sizeof(struct pseudo_icmp6header) - myoutput.ihl - LINK_LAYER;
				if(sz < (unsigned long int)size || sz == 0){
					check = c_alloc(check, size);
					sz = size;
				}
				pseudo_icmp6 = check;
				c_icmp6 = (struct icmp4header *)((char *)check + sizeof(struct pseudo_icmp6header));
				memcpy(pseudo_icmp6->ip_src, ((struct ipv6header *)ip4)->src_ip, 16);
				memcpy(pseudo_icmp6->ip_dst, ((struct ipv6header *)ip4)->dst_ip, 16);
				pseudo_icmp6->zero[0] = pseudo_icmp6->zero[1] = pseudo_icmp6->zero[2] = 0;
				pseudo_icmp6->next_header = myoutput.protocol;
				ptr = (char *)&pseudo_icmp6->length;
				((unsigned short int *)ptr)[0] = 0;
				ptr[2] = myoutput.length/256;
				ptr[3] = myoutput.length%256;
				memcpy(c_icmp6, icmp4, myoutput.sizeread - myoutput.ihl - LINK_LAYER);
				c_icmp6->checksum = 0;
				myoutput.icmp4.type = icmp4->type;
				myoutput.icmp4.code = icmp4->code;
				myoutput.icmp4.id = ntohs(icmp4->id);
				myoutput.icmp4.seq = ntohs(icmp4->seq);
				myoutput.icmp4.checksum = icmp4->checksum;
				myoutput.icmp4.re_checksum = checksum_calculation(check,size);
				myoutput.datalen =  myoutput.sizeread - myoutput.ihl - LINK_LAYER;
				myoutput.data = (char *)ip;
				myoutput.print_pkt = print_icmp4;
				myoutput.print_data = print_data;
				myoutput.print_data_hex = print_data_hex;
				break;
		case ICMP:	icmp4 = (struct icmp4header *)ip;
				myoutput.icmp4.checksum = ntohs(icmp4->checksum);
				icmp4->checksum = 0; 
				myoutput.icmp4.re_checksum =
					htons(checksum_calculation((unsigned short int *)icmp4, myoutput.length));
				myoutput.icmp4.type = icmp4->type;
				myoutput.icmp4.code = icmp4->code;
				myoutput.icmp4.id = ntohs(icmp4->id);
				myoutput.icmp4.seq = ntohs(icmp4->seq);
				myoutput.datalen = myoutput.sizeread - (LINK_LAYER + myoutput.ihl);
				myoutput.data = (char *)ip;
				myoutput.print_pkt = print_icmp4;
				myoutput.print_data = print_data;
				myoutput.print_data_hex = print_data_hex;
				break;
		case TCP:	tcp4 = (struct tcp4header *)ip;
				size = myoutput.sizeread + sizeof(struct pseudo_tcp4header) - myoutput.ihl - LINK_LAYER;
				myoutput.tcp4.src_port = ntohs(tcp4->src_port);
				myoutput.tcp4.dst_port = ntohs(tcp4->dst_port);
				if(sz < (unsigned long int)size || sz == 0){
					check = c_alloc(check,size),
					sz = size;
				}
				pseudo_tcp4 = check;
				c_tcp4 = (struct tcp4header *)((char *)check + sizeof(struct pseudo_tcp4header));
				pseudo_tcp4->src_ip = ip4->src_ip;
				pseudo_tcp4->dst_ip = ip4->dst_ip;
				pseudo_tcp4->protocol = ip4->protocol;
				pseudo_tcp4->length = htons(size - sizeof(struct pseudo_tcp4header));
				pseudo_tcp4->zero = 0;
				memcpy(c_tcp4, tcp4, myoutput.sizeread - myoutput.ihl - LINK_LAYER);
				c_tcp4->checksum = 0;
   				myoutput.tcp4.re_checksum = htons(checksum_calculation(check,size));
				myoutput.tcp4.length = myoutput.sizeread - myoutput.ihl - LINK_LAYER;
				myoutput.tcp4.checksum= ntohs(tcp4->checksum);
				if(tcp4->flags){
					for(temp = 0, fl = 1; fl < (1<<8); temp++,fl = (fl<<1))
						if(tcp4->flags&fl)
							myoutput.tcp4.flags[temp] = ___flags___[temp];
						else
							myoutput.tcp4.flags[temp] = '.';
				}else
					memset(myoutput.tcp4.flags, '.', 7);
				myoutput.tcp4.seq = ntohl(tcp4->seq);
				myoutput.tcp4.ack = ntohl(tcp4->ack);
				myoutput.tcp4.window = ntohs(tcp4->window);
				myoutput.tcp4.ecn = tcp4->ecn;
				myoutput.tcp4.urgptr = ntohs(tcp4->urgptr);
				myoutput.tcp4.header_size = tcp4->header_size * 4;
				if(myoutput.tcp4.header_size > (int)sizeof(struct tcp4header)){
					i =  myoutput.tcp4.header_size - sizeof(struct tcp4header);
					myoutput.tcp4.options = ((char *)ip4 + myoutput.ihl);
					myoutput.tcp4.optlen = i;
				}
				myoutput.datalen = myoutput.sizeread -  myoutput.tcp4.header_size - myoutput.ihl - LINK_LAYER;
				myoutput.data = ((char *)ip + myoutput.tcp4.header_size);
				myoutput.print_pkt = print_tcp4;
				myoutput.print_data = print_data;
				myoutput.print_data_hex = print_data_hex;
				break;
		case UDP:	udp4 = (struct udp4header *)ip;
				size = myoutput.sizeread + sizeof(struct pseudo_udp4header) - myoutput.ihl - LINK_LAYER; 
				myoutput.udp4.src_port = ntohs(udp4->src_port);
				myoutput.udp4.dst_port = ntohs(udp4->dst_port);
				if( sz < (unsigned long int)size || sz == 0){
					check = c_alloc(check,size);
					sz = size;
				}
				pseudo_udp4 = check;
				c_udp4 = (struct udp4header *)(check + sizeof(struct pseudo_udp4header));
				pseudo_udp4->src_ip = ip4->src_ip;
				pseudo_udp4->dst_ip = ip4->dst_ip;
				pseudo_udp4->zero = 0;
				pseudo_udp4->protocole = ip4->protocol;
				pseudo_udp4->length = udp4->length;
				memcpy(c_udp4, udp4, ntohs(udp4->length));
				c_udp4->checksum = 0;
				myoutput.udp4.re_checksum = htons(checksum_calculation(check,size));
				myoutput.udp4.checksum = ntohs(udp4->checksum);
				myoutput.udp4.length = htons(udp4->length);
				myoutput.datalen =  myoutput.sizeread - sizeof(struct udp4header) - myoutput.ihl - LINK_LAYER;
				myoutput.data = ((char *)ip + sizeof(struct udp4header));
				myoutput.print_pkt = print_udp4;
				myoutput.print_data = print_data;
				myoutput.print_data_hex = print_data_hex;
				break;
		default:	printf("Unknow Protocol:%u\n",myoutput.protocol);
				return NULL;
	}
	return NULL;
}
void print_it(void *output){
	struct output *o = output;
	if(o->print_linklayer && (args.options&NOLINKLAYER) == 0)
		o->print_linklayer(o);
	if(o->print_hdr && (args.options&NOHEADER) == 0)
		o->print_hdr(o);
	if(o->print_addr && (args.options&NOADDRESS) == 0)
		o->print_addr(o);
	if(o->print_options && (args.options&NOOPTIONS) == 0)
		o->print_options(o->options, o->optlen);
	if(o->print_pkt && (args.options&NOTRANSPORT) == 0)
		myoutput.print_pkt(o);
	if(o->print_data && (args.options&NODATA) == 0)
		o->print_data(o->data, o->datalen);
	if(o->print_data_hex && (args.options&NODATAHEX) == 0)
		o->print_data_hex(o->data, o->datalen);
	myoutput.print_addr = NULL;
	myoutput.print_linklayer = NULL;
	myoutput.print_hdr = NULL;
	myoutput.print_pkt = NULL;
	myoutput.print_options = NULL;
	myoutput.print_data = NULL;
	myoutput.print_data_hex = NULL;
}
int show_it(struct optflags *poptflags,struct output *myoutput){
	struct tcpflags *pflags;
	struct host *phost;
	int	prt =1,
		prt_,
		i,j,k;
	poptflags = args.opt;
	if(poptflags){
		prt_ = 0;
		prt = 0;
		while(poptflags){
			if(poptflags->version != 0)
				prt_++;
			if(poptflags->protocol != 0)
				prt_++;
			if(poptflags->port != 0)
				prt_++;
			if(poptflags->host != NULL)
				prt_++;
			if(poptflags->tcpflags != NULL)
				prt_++;
			if(poptflags->version != 0 && myoutput->version == poptflags->version)
				prt++;
			if(poptflags->protocol != 0 && myoutput->protocol == poptflags->protocol)
				prt++;
			if((myoutput->protocol == 6 || myoutput->protocol == 17) && poptflags->port != 0)
				if(	myoutput->udp4.src_port == poptflags->port || myoutput->udp4.dst_port == poptflags->port
					|| myoutput->tcp4.dst_port == poptflags->port|| myoutput->tcp4.src_port == poptflags->port
				)
				prt++;
			if(poptflags->host){
				phost = poptflags->host;
				while(phost){
					if(strcmp(phost->host,myoutput->src_hostname) == 0 || strcmp(phost->host,myoutput->dst_hostname) == 0
						|| strcmp(phost->host,myoutput->src_addr) == 0 || strcmp(phost->host,myoutput->dst_addr) == 0
					)
					{
					prt++;
					break;
					}
					phost = phost->next;
				}
			}
			if(myoutput->protocol == 6 && poptflags->tcpflags){
				pflags = poptflags->tcpflags;
				while(pflags){
					for(i = 0, j = 0, k = 0;i < 7; i++){
						if(myoutput->tcp4.flags[i] == '.')continue;
						if(strchr(pflags->flags,myoutput->tcp4.flags[i])){
							j++;
							k++;
						}else	k++;
					}
					if(j == pflags->size && k == j){
						prt++;
						break;
					}
					pflags = pflags->next;
				}
			}
			if(prt_ == prt){
				break;
			}
			poptflags = poptflags->next;
		}
	}else{
		if(args.opt != NULL){
			return 0;
		}
	}
	if(prt == prt_ && prt_ > 0){
		return 1;
	}
	if(args.opt == NULL){
		return 1;
	}
	return 0;
}
unsigned char *ReadName(unsigned char* reader,unsigned char* buffer,int* count, unsigned char *name)
{
    //unsigned char *name;
    unsigned int p=0,jumped=0,offset = 0;
    int i , j;
 
    *count = 1;
    //name = (unsigned char*)malloc(256);
 
    name[0]='\0';
    //read the names in 3www6google3com format
    while(*reader!=0)
    {	if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
	    reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        { 	
		name[p++]=*reader;
        }

        reader = reader+1;

        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0; i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {     
	      name[i]=name[i+1];
              i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}
void dns_type_41(void *pdata){
	struct dnsopt *opt = (struct dnsopt *)pdata;
	printf("\tOPT:\n\t\ttype: %u\n\t\tLength: %u\n\t\tDO: %u\n\t\tTTL: %u\n",
		ntohs(opt->type), ntohs(opt->class), (ntohs(opt->DO)&0x8000) ? 1 : 0, ntohs(opt->ttl));
}
void dns_type(int type, unsigned char **pdata,unsigned char *data, int *len){
	struct in_addr s;
	struct in6_addr s6;
	unsigned char buf[NI_MAXHOST];
	char address[45];
	int stop;
	switch(type){
		case ADDRESS:
			*pdata = (*pdata + sizeof(struct answer));
			memcpy(&s.s_addr,*pdata,sizeof(s.s_addr));
			inet_ntop(AF_INET,&s,address,sizeof(address));
			printf("\tAddress: %s\n", address);
			*pdata = (*pdata + *len);
			break;
		case NS:
			*pdata = (*pdata + sizeof(struct answer));
 			ReadName(*pdata,data,&stop, buf);
			printf("\tMX: %s\n",buf);
			*pdata = (*pdata + stop);
			break;
		case CNAME:
			*pdata = (*pdata + sizeof(struct answer));
 			ReadName(*pdata,data,&stop, buf);
			printf("\tCNAME: %s\n",buf);
			*pdata += stop;
			break;
		case SOA:
			*pdata = (*pdata + sizeof(struct answer));
 			ReadName(*pdata,data,&stop, buf);
			printf("\tSOA: %s\n", buf);
			*pdata = (*pdata + stop);
			ReadName(*pdata,data,&stop, buf);
			printf("\tMX: %s\n",buf);
			*pdata = (*pdata + stop);
			printf("\tSerial: %u\n\tRefresh: %u\n\tRetry: %u\n\tExpire: %u\n\tMinimum: %u\n",
				ntohl(((struct soa *)*pdata)->serial), ntohl(((struct soa *)*pdata)->refresh),
				ntohl(((struct soa *)*pdata)->retry),ntohl(((struct soa *)*pdata)->expire),ntohl(((struct soa *)*pdata)->minimum));
			*pdata += (sizeof(struct soa));
			break;
		case PTR:
			*pdata = (*pdata + sizeof(struct answer));
 			ReadName(*pdata,data,&stop, buf);
			printf("\tHostname: %s\n", buf);
			*pdata = (*pdata + stop);
			break;
		case MX:
			*pdata = (*pdata + sizeof(struct answer));
 			*pdata = (*pdata + sizeof(short int));
			ReadName(*pdata,data,&stop, buf);
			*pdata = (*pdata + stop);
			printf("\tMX: %s\n",buf);
			break;
		case TXT:
			*pdata = (*pdata + sizeof(struct answer));
 			ReadName(*pdata,data,&stop, buf);
			while(*((char *)buf) == 0){
				*len -= stop;
				*pdata = (*pdata + stop);
				ReadName(*pdata,data,&stop, buf);
			}
			buf[*len-1] = 0;
			printf("\ttext: %s\n", buf);
			*pdata = (*pdata + (*len));
			break;
		case ADDRESS6:
			*pdata = (*pdata + sizeof(struct answer));
 			memcpy(&s6.s6_addr,*pdata,sizeof(s6.s6_addr));
			inet_ntop(AF_INET6,&s6,address,sizeof(address));
			printf("\tAddress: %s\n", address);
			*pdata = (*pdata + *len);
			break;
		case OPT:
			dns_type_41(*pdata);
			break;
		default:*pdata = (*pdata + sizeof(struct answer));
 			printf("\tTYPE (unknow): %u\n",type);
			ReadName(*pdata,data,&stop, buf);
			*pdata = (*pdata + stop);
			break;
	}
}
void services_udp_src(char *data){
	unsigned long int i, j;
	unsigned char buf[NI_MAXHOST];
	struct dns *d = (struct dns *)data;
	struct answer *a;
	int stop = 0,k = 0,l;
	unsigned short int count[3];
	char *text[3] = {"Answers records:","Authoritive records:","Additional records:"};
	printf("ID:%u\nqdcount:%u\nAncount:%u\nNscount:%u\nArcount:%u\n",
			ntohs(d->id),ntohs(d->Qdcount),ntohs(d->Ancount),ntohs(d->Nscount),ntohs(d->Arcount));
	count[0] = ntohs(d->Ancount);
	count[1] = ntohs(d->Nscount);
	count[2] = ntohs(d->Arcount);
	a = (struct answer *)(data + sizeof(struct dns) + strlen(data+sizeof(struct dns)) + 1 + sizeof(struct question));
	switch(d->Rcode){
		case 0:	for(l = 0; l < 3; l++){
				if(count[l])
					printf("%s\n",text[l]);
				for(i = 0; i < count[l]; i++){
					ReadName((unsigned char *)((char *)a),(unsigned char *)data,&stop, buf);
					printf("\tNAME: %s\n", buf);
					a = (struct answer *)(((char *)a + stop));
					k = ntohs(((struct answer *)a)->len);
					j = ntohs(((struct answer *)a)->type);
					dns_type(j, (unsigned char **)&a, (unsigned char *)data, &k);
				}
			}
			break;
		case 1: printf("Erreur dans le requete.\n");
			break;
		case 2: printf("Erreur du serveur.\n");
			break;
		case 3:	printf("Le nom n'existe pas.\n");
			break;
		case 4: printf("Nom implemente.\n");
			break;
		case 5: printf("Refus.\n");
			break;
		default:printf("Reserve.\n");
			break;
	}
}
void services_udp_dst(char *data){
	struct dns *d = (struct dns *)data;
	struct question * q = (struct question *)(data+sizeof(struct dns));
	unsigned char buf[NI_MAXHOST];
	char *text[4] = {"Question:","Answers records:","Authoritive records:","Additional records:"};
	long int i, j;
	int stop = 0,
		count[4] = { ntohs(d->Qdcount), ntohs(d->Ancount),ntohs(d->Nscount),ntohs(d->Arcount) };
	printf("ID:%u\nqdcount:%u\nAncount:%u\nNscount:%u\nArcount:%u\n",
		ntohs(d->id),ntohs(d->Qdcount),ntohs(d->Ancount),ntohs(d->Nscount),ntohs(d->Arcount)
	);
	for(i = 0; i < 4; i++){
		if(count[i]>0)
			printf("%s\n",text[i]);
		for(j = 0; j < count[i]; j++){
			ReadName((unsigned char *)q,(unsigned char *)data,&stop, buf);
			q = (struct question *)((char *)q + stop);
			if(i)
				q = (struct question *)((char *)q + sizeof(struct question));
			switch(ntohs(q->qtype)){
				case ADDRESS:
					printf("\tAddress: %s\n",buf);
					break;
				case NS:
					printf("\tNS: %s\n",buf);
					break;
				case CNAME:
					printf("\tCNAME: %s\n",buf);
					break;
				case SOA:
					printf("\tSOA: %s\n",buf);
					break;
				case PTR:
					printf("\tPTR: %s\n",buf);
					break;
				case MX:printf("\tMX: %s\n",buf);
					break;
				case TXT:
					printf("\tTXT: %s\n",buf);
					break;
				case ADDRESS6:
					printf("\tAddress: %s\n",buf);
					break;
				case OPT:
					dns_type_41(q);
					break;
				default:printf("\tTYPE (unknow):%u\n", ntohs(q->qtype));
					break;
			}
		}
	}
}
void ntp32bits(struct frac_32 *ntp, struct frac_32 *result){
	short int seconds = ntohs(ntp->seconds);
	short int fraction = ntohs(ntp->fraction);
	double ff = fraction/65536.0;
	fraction = (short int)(ff*1000000.0);
	result->seconds = seconds;
	result->fraction = fraction;
}
void ntp64bits(struct frac_64 *ntp, struct frac_64 *result, char *time, unsigned long int timelen){
	unsigned int seconds = ntohl(ntp->seconds);
	unsigned int fraction = ntohl(ntp->fraction);
	double ff = fraction;
	time_t s;
	struct tm *tm;
	if(ff < 0.0)
		ff += MAXINT;
	ff = ff/MAXINT;
	result->fraction = (unsigned int)(ff * 1000000000.0);
	result->seconds = seconds;
	if(result->seconds){
		s = result->seconds - JAN_1970;
		tm = localtime(&s);
		strftime(time, timelen, "%Y/%m/%d %H:%M:%S", tm);
	}else	*time = 0;
}
int ntp_diff(struct frac_64 *o_ntp,struct frac_64 *n_ntp, struct frac_64 *result,char *time, unsigned long int timelen){
	unsigned int f;
	int i, signebits;
	double ff;
	if(o_ntp->seconds == 0 && n_ntp->seconds == 0){
		ntp64bits(n_ntp, result, time, timelen);
		return -1;
	}
	i = n_ntp->seconds;
	if(i > 0){
		signebits = 0;
		f = n_ntp->fraction - o_ntp->fraction;
		if(o_ntp->fraction > n_ntp->fraction)
			i--;
	}else{
		if(i < 0){
			signebits = 1;
		f = o_ntp->fraction - n_ntp->fraction;
			if(n_ntp->fraction > o_ntp->fraction)
				i++;
			i = -i;
		}else{
			if(n_ntp->fraction > o_ntp->fraction){
				signebits = 0;
				f = n_ntp->fraction - o_ntp->fraction;
			}else{
				signebits = 1;
				f = o_ntp->fraction - n_ntp->fraction;
			}
		}
	}
	ff = f;
	if(ff < 0.0)
		ff += MAXINT;
	ff = ff/MAXINT;
	f = (unsigned int)(ff * 1000000000.0);
	result->seconds = i;
	result->fraction = f;
	*time = 0;
	if(signebits)
		return 1;
	return 0;
}
void timestamp(char *originator, char **buffer, struct frac_64 *f, int sign){
	if(*originator == 0)
	{
		sprintf(*buffer,"%s%d.%09d",
				(sign > 0)? "-": "+",
				f->seconds,
				f->fraction
			);
	}else{
		strcpy(*buffer,originator);
	}

}
void ___set_id_fn___(char **buf, int *clock_id, unsigned long int size){
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	struct in_addr s;
	struct in6_addr s6;
	char address[48];
	unsigned long int sz = sizeof(sa);
	void *___sa___ = &sa;
	memcpy(&s.s_addr,clock_id,sizeof(s.s_addr));
	if(!inet_ntop(AF_INET,&s,address,48)){
		memcpy(&s6.s6_addr,clock_id,sizeof(s6.s6_addr));
		inet_ntop(AF_INET6,&s6,*buf,48);
		___sa___ = &sa6;
		sz = sizeof(sa6);
	}
	if((args.options&NORESOLV) == 0){
		___getnameinfo___(___sa___, sz, buf, NI_MAXHOST+12-size, address);
		if(strlen(*buf) == 0)
			strcpy(*buf, address);
	}else strcpy(*buf,address);
}
void service_ntp(char *data, unsigned long int datalen){
	struct ntp *t =(struct ntp *) data;
	struct frac_32	root_delay,
			clock_dispertion;
	struct frac_64 reference_timestamp,
			original_timestamp,
			received_timestamp,
			transmit_timestamp,
			originator_received_timestamp,
			originator_transmit_timestamp;
	char ___reference_timestamp___[128],
		___original_timestamp___[128],
		___received_timestamp___[128],
		___transmit_timestamp___[128],
		___originator_received_timestamp___[128],
		___originator_transmit_timestamp___[128],
		*mode[8] = {"reserved",
				"symetric active",
				"symetric  active",
				"client",
				"server",
				"broadcast",
				"NTP control message",
				"reserved for  private use"
		},
		*stratum[5] = {"unspecified or invalid",
				"primary server",
				"secondary server",
				"unsychronized",
				"reserved"
		},
		*leap[4] = {"no warning",
				"+1s",
				"-1s",
				"unkonwn (clock unsyncrhonized)"
		},
		originator_buffer1[1024],originator_buffer2[1024], *buffer1 = originator_buffer1, *buffer2 = originator_buffer2, 
		refid[NI_MAXHOST+12], *id;
	unsigned long int timelen = 1024;
	int ___stratum___ = 0 + (t->peer_clock_stratum ==1 )*1
				+ (t->peer_clock_stratum >1 && t->peer_clock_stratum < 17) *2
				+ (t->peer_clock_stratum == 17) *3
				+ (t->peer_clock_stratum > 16)*4,
				s_originator_received_timestamp,
				s_originator_transmit_timestamp;
	memset(refid,0,NI_MAXHOST+12);
	switch(t->peer_clock_stratum){
		case UNSPECIFIED:
			strcpy(refid, "unspecified");
			break;
		case PRIM_REF:
			memcpy(refid,&t->reference_clock_id,4);
			break;
		case INFO_QUERY:
			strcpy(refid, "INFO_QUERY ");
			id = &refid[strlen(refid)-1];
			___set_id_fn___(&id,&t->reference_clock_id,strlen(refid));
			break;
		case INFO_REPLY:
			strcpy(refid, "INFO_REPLY ");
			id = &refid[strlen(refid)-1];
			___set_id_fn___(&id,&t->reference_clock_id,strlen(refid));
			break;
		default:id = refid;
			___set_id_fn___(&id,&t->reference_clock_id,strlen(refid));
			break;
	}
	ntp32bits(&t->root_delay,&root_delay);
	ntp32bits(&t->clock_dispertion, &clock_dispertion);
	ntp64bits(&t->reference_timestamp, &reference_timestamp, ___reference_timestamp___, timelen);
	ntp64bits(&t->original_timestamp, &original_timestamp, ___original_timestamp___, timelen);
	ntp64bits(&t->received_timestamp, &received_timestamp, ___received_timestamp___, timelen);
	ntp64bits(&t->transmit_timestamp, &transmit_timestamp, ___transmit_timestamp___, timelen);
	s_originator_received_timestamp =
		ntp_diff(&t->original_timestamp,
				&t->received_timestamp,
				&originator_received_timestamp,
				___originator_received_timestamp___,
				timelen
		);
	s_originator_transmit_timestamp =
		ntp_diff(&t->original_timestamp,
				&t->transmit_timestamp,
				&originator_transmit_timestamp,
				___originator_transmit_timestamp___,
				timelen
		);
	timestamp(___originator_received_timestamp___, &buffer1, &originator_received_timestamp, s_originator_received_timestamp);
	timestamp(___originator_transmit_timestamp___, &buffer2, &originator_transmit_timestamp, s_originator_transmit_timestamp);
printf("\
Version: %u; Mode: %s (%u); Stratum: %s (%u)\n\
\tLeap : %s\n\
\tReference clock id: %s\n\
\tClock precision: %d\n\
\tRoot delay: %d.%06d\n\
\tRoot dispersion: %d.%06d\n\
\tReference timestamp: %u.%09d (%s)\n\
\tReceived timestamp: %u.%09d (%s)\n\
\tTransmit timestamp: %u.%09d (%s)\n\
\tOriginator - Received timestamp: %s\n\
\tOriginator - Transmit timestamp: %s\n",
	t->v&0x07,
	mode[t->m&0x07],
	t->m&0x07,
	stratum[___stratum___],
	___stratum___,
	leap[t->l&2],
	refid,
	t->peer_clock_precision,
	root_delay.seconds, root_delay.fraction,
	clock_dispertion.seconds, clock_dispertion.fraction,
	reference_timestamp.seconds, reference_timestamp.fraction, ___reference_timestamp___,
	received_timestamp.seconds, received_timestamp.fraction, ___received_timestamp___,
	transmit_timestamp.seconds, transmit_timestamp.fraction, ___transmit_timestamp___,
	originator_buffer1,
	originator_buffer2
);
	if(sizeof(struct ntp) - datalen == 16){
		printf("Key ID: %u\n", t->key_id);
	}else{
		if(datalen == sizeof(struct ntp)){
			printf("Key ID: %u\nAuthentication:\n\t0x%08x\n\t0x%08x\n\t0x%08x\n\t%08x\n",
				t->key_id,
				ntohl(t->msg_digest[0]),
				ntohl(t->msg_digest[4]),
				ntohl(t->msg_digest[8]),
				ntohl(t->msg_digest[12])
			);
		}
	}
}
int main(int argc, char **argv){
	struct ipv4header 		*ip4;
	struct ifreq 			ifr;
	struct sockaddr_ll 		sll,from;
	struct tpacket_stats		stats = {};
	socklen_t 			len = sizeof(stats),fromlen = sizeof(from);
	int				loopback;
	if(argp_parse(&argp,argc, argv, 0, 0, &args) < 0)
		exit(EXIT_FAILURE);
	if((s = socket(AF_PACKET, SOCK_RAW,htons(ETH_P_ALL))) < 0){
		perror("socket()");
		exit(EXIT_FAILURE);
	}
	memset(&sll, 0, sizeof(sll));
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo");
	if(ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
		perror ("ioctl()");
		return (EXIT_FAILURE);
	}
	loopback = ifr.ifr_ifindex;
	memset(&ifr, 0, sizeof(ifr));
	if(args.interface != NULL){
		//snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", args.interface);
		strcpy(ifr.ifr_name,args.interface);
		if(ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
			perror ("ioctl()");
			return (EXIT_FAILURE);
		}
	}
	if(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		perror ("setsockopt()");
		exit (EXIT_FAILURE);
	}
	sll.sll_family = AF_PACKET;
	//0: Pour toutes les interfaces
	//ifr.ifr_index: interface specifique
	sll.sll_ifindex = ifr.ifr_ifindex;
	//ETH_P_ALL: Tous les protocoles
	sll.sll_protocol = htons(ETH_P_ALL);
	if(bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0){
		perror("bind()");
		exit(EXIT_FAILURE);
	}
	signal(SIGINT,finish);
	do{	myoutput.sizeread = recvfrom(s, buffer, 65535, 0, (struct sockaddr *)&from, &fromlen);
		if(from.sll_pkttype == PACKET_OUTGOING && from.sll_ifindex == loopback){
			captured++;
			getsockopt(s, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
			statsrecv += stats.tp_packets;
			statsdrops += stats.tp_drops;
			continue;
		}
		memcpy(myoutput.link_layer, buffer, LINK_LAYER);
		myoutput.print_linklayer = print_linklayer;
		ip4 = (struct ipv4header *)(buffer + LINK_LAYER);
		myoutput.version = ip4->version;
		analyse(ip4);
		if(show_it(args.opt, &myoutput) == 1){
			print_it(&myoutput);
			if((args.options&VERBEUX) == 0)
				goto end;
			if(myoutput.protocol == UDP && myoutput.udp4.src_port == DNS_PORT){
				services_udp_src(myoutput.data);
				goto end;
			}
			if(myoutput.protocol == UDP && myoutput.udp4.dst_port == DNS_PORT){
				services_udp_dst(myoutput.data);
				goto end;
			}
			if(myoutput.protocol == UDP && (myoutput.udp4.dst_port == NTP_PORT || myoutput.udp4.src_port == NTP_PORT)){
				service_ntp(myoutput.data, myoutput.datalen);
				goto end;
			}
			end:
			selected++;
		}
		captured++;
		getsockopt(s, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
		statsrecv += stats.tp_packets;
		statsdrops += stats.tp_drops;
		if((args.count_received > 0 && statsrecv >= args.count_received) ||
			(args.count_selected > 0 && selected >= args.count_selected) ||
			(args.count_captured > 0 && captured >= args.count_captured)
		)break;
	}while( 1 );
	finish(-1);
	return 0;
}
