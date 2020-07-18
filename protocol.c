#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "protocol.h"
#include "others.h"
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
			if(((args.options&PROTO)== PROTO) && myoutput->protocol == poptflags->protocol)
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

