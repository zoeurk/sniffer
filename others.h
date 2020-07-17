#ifndef OTHERS_H
#define OTHERS_H
#include <argp.h>

#include <netdb.h>

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
struct arguments{
	char *interface;
	unsigned long int options;
	unsigned long int count_captured;
	unsigned long int count_selected;
	unsigned long int count_received;
	struct optflags *opt;
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
extern const char 			*argp_program_version;
extern const char 			*argp_program_bug_address;

extern struct output		myoutput;
extern int 			s;
extern unsigned long int 	captured, statsrecv, statsdrops, selected;
extern void 			*check;
extern char			___flags___[7],
				*ip4flags[3];
extern char 			buffer[65535];
extern char 			doc[];
extern struct argp_option	options[];
extern struct arguments		args;
#endif
