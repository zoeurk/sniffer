#include <sys/socket.h>
#include <netinet/in.h>

#include "protocol-definition.h"
#include "protocol.h"
#include "others.h"
void *analyse(void *buf){
	static unsigned long int	sz = 0;
	struct ipv4header 		*ip4 = (struct ipv4header *)buf;
	struct ipv6header		*ip6 = (struct ipv6header *)buf;
	struct sockaddr_in 		sa;
	struct sockaddr_in6 		sa6;
	struct in_addr 			src,dst;
	struct in6_addr			src6,dst6;
	int 				fl, temp, i;
	char				*phostname, *ip;
	switch(ip4->version){
		case IPV4:
			myoutput.ihl = ip4->ihl *4;
			temp = ip4->checksum;
			myoutput.ipchecksum = ntohs(ip4->checksum);
			myoutput.length = htons(ip4->length);
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
			myoutput.length = myoutput.sizeread - LINK_LAYER;
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
		case ICMPv6:	protocol_icmpv6(ip, &sz);
				break;
		case ICMP:	protocol_icmp4(ip);
				break;
		case TCP:	if(ip4->version == 4)
					protocol_tcp4(ip4, ip, &sz);
				else	protocol_tcp6(ip6, ip, &sz);
				break;
		case UDP:	if(ip4->version == 4)
					protocol_udp4(ip4, ip, &sz);
				else	protocol_udp6(ip6, ip, &sz);
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
		prt_ = 0,
		i,j,k;
	poptflags = args.opt;
	if(poptflags){
		while(poptflags){
			prt_ = 0;
			prt = 0;
			if(poptflags->version != 0)
				prt_++;
			if(poptflags->protoflag != 0)
				prt_++;
			if(poptflags->port != 0)
				prt_++;
			if(poptflags->host != NULL)
				prt_++;
			if(poptflags->tcpflags != NULL)
				prt_++;
			if(poptflags->version != 0 && myoutput->version == poptflags->version)
				prt++;
			if((poptflags->protoflag&1) == 1 && myoutput->protocol == poptflags->protocol)
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

