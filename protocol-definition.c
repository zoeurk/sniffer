#include "protocol-definition.h"
#include "protocol-print.h"
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
void  protocol_icmpv6(void *ip6, void *ip,unsigned long int *sz){
	struct icmp4header *icmp4, *c_icmp6;
	struct pseudo_icmp6header *pseudo_icmp6;
	unsigned long int size;
	icmp4 = (struct icmp4header *)ip;
	size = myoutput.sizeread + sizeof(struct pseudo_icmp6header) - myoutput.ihl - LINK_LAYER;
	if(*sz < (unsigned long int)size || *sz == 0){
		check = c_alloc(check, size);
		*sz = size;
	}
	pseudo_icmp6 = check;
	c_icmp6 = (struct icmp4header *)((char *)check + sizeof(struct pseudo_icmp6header));
	memcpy(pseudo_icmp6->ip_src, ((struct ipv6header *)ip6)->src_ip, 16);
	memcpy(pseudo_icmp6->ip_dst, ((struct ipv6header *)ip6)->dst_ip, 16);
	pseudo_icmp6->zero[0] = pseudo_icmp6->zero[1] = pseudo_icmp6->zero[2] = 0;
	pseudo_icmp6->next_header = myoutput.protocol;
	pseudo_icmp6->length = htonl(myoutput.length);
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
}
void protocol_icmp4(void *ip){
	struct icmp4header *icmp4 = (struct icmp4header *)ip;
	icmp4 = (struct icmp4header *)ip;
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

}
void protocol_tcp4(struct ipv4header *ip4, void *ip, unsigned long int *sz){
	struct tcp4header *tcp4, *c_tcp4;
	struct pseudo_tcp4header *pseudo_tcp4;
	unsigned long int size;
	int fl,temp,i;
	tcp4 = (struct tcp4header *)ip;
	size = myoutput.sizeread + sizeof(struct pseudo_tcp4header) - myoutput.ihl - LINK_LAYER;
	myoutput.tcp4.src_port = ntohs(tcp4->src_port);
	myoutput.tcp4.dst_port = ntohs(tcp4->dst_port);
	if(*sz < (unsigned long int)size || *sz == 0){
		check = c_alloc(check,size),
		*sz = size;
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
}
void protocol_tcp6(struct ipv6header *ip6, void *ip, unsigned long int *sz){
	struct tcp4header *tcp4, *c_tcp4;
	struct pseudo_tcp6header *pseudo_tcp6;
	unsigned long int size;
	int fl,temp,i;
	tcp4 = (struct tcp4header *)ip;
	size = myoutput.sizeread + sizeof(struct pseudo_tcp6header) - myoutput.ihl - LINK_LAYER;
	myoutput.tcp4.src_port = ntohs(tcp4->src_port);
	myoutput.tcp4.dst_port = ntohs(tcp4->dst_port);
	if(*sz < (unsigned long int)size || *sz == 0){
		check = c_alloc(check,size),
		*sz = size;
	}
	pseudo_tcp6 = check;
	c_tcp4 = (struct tcp4header *)((char *)check + sizeof(struct pseudo_tcp6header));
	memcpy(pseudo_tcp6->src_ip, ip6->src_ip, 16);
	memcpy(pseudo_tcp6->dst_ip, ip6->dst_ip,16);
	pseudo_tcp6->protocol = ip6->next_header;
	pseudo_tcp6->length = htons(size - sizeof(struct pseudo_tcp6header));
	pseudo_tcp6->zero = 0;
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
		myoutput.tcp4.options = ((char *)ip6 + myoutput.ihl);
		myoutput.tcp4.optlen = i;
	}
	myoutput.datalen = myoutput.sizeread -  myoutput.tcp4.header_size - myoutput.ihl - LINK_LAYER;
	myoutput.data = ((char *)ip + myoutput.tcp4.header_size);
	myoutput.print_pkt = print_tcp4;
	myoutput.print_data = print_data;
	myoutput.print_data_hex = print_data_hex;
}
void protocol_udp4(struct ipv4header *ip4, void *ip, unsigned long int *sz){
	struct pseudo_udp4header *pseudo_udp4;
	struct udp4header *udp4, *c_udp4;
	unsigned long int size;
	udp4 = (struct udp4header *)ip;
	size = myoutput.sizeread + sizeof(struct pseudo_udp4header) - myoutput.ihl - LINK_LAYER; 
	myoutput.udp4.src_port = ntohs(udp4->src_port);
	myoutput.udp4.dst_port = ntohs(udp4->dst_port);
	if( *sz < (unsigned long int)size || *sz == 0){
		check = c_alloc(check,size);
		*sz = size;
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
}
void protocol_udp6(struct ipv6header *ip6, void *ip, unsigned long int *sz){
	struct pseudo_udp6header *pseudo_udp6;
	struct udp4header *udp4, *c_udp4;
	unsigned long int size;
	udp4 = (struct udp4header *)ip;
	size = myoutput.sizeread + sizeof(struct pseudo_udp6header) - myoutput.ihl - LINK_LAYER; 
	myoutput.udp4.src_port = ntohs(udp4->src_port);
	myoutput.udp4.dst_port = ntohs(udp4->dst_port);
	if( *sz < (unsigned long int)size || *sz == 0){
		check = c_alloc(check,size);
		*sz = size;
	}
	pseudo_udp6 = check;
	c_udp4 = (struct udp4header *)(check + sizeof(struct pseudo_udp6header));
	memcpy(pseudo_udp6->src_ip, ip6->src_ip, 16);
	memcpy(pseudo_udp6->dst_ip, ip6->dst_ip, 16);
	pseudo_udp6->zero = 0;
	pseudo_udp6->protocole = ip6->next_header;
	pseudo_udp6->length = udp4->length;
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
}
void protocol_hop_by_hop(void *ip6, void *ip, unsigned long int *sz){
	struct icmp4header *icmp4, *c_icmp6;
	struct pseudo_icmp6header *pseudo_icmp6;
	unsigned long int size,len;
	int i = 8;
	len = ((struct hop_by_hop *)ip6)->hdr_ext_len;
	icmp4 = (struct icmp4header *)((char *)ip + 8 + len);
	size = myoutput.sizeread + sizeof(struct pseudo_icmp6header) - myoutput.ihl - LINK_LAYER -i;
	if(*sz < (unsigned long int)size || *sz == 0){
		check = c_alloc(check, size);
		*sz = size;
	}
	pseudo_icmp6 = check;
	c_icmp6 = (struct icmp4header *)((char *)check + sizeof(struct pseudo_icmp6header));
	memcpy(pseudo_icmp6->ip_src, ((struct ipv6header *)ip6)->src_ip, 16);
	memcpy(pseudo_icmp6->ip_dst, ((struct ipv6header *)ip6)->dst_ip, 16);
	pseudo_icmp6->zero[0] = pseudo_icmp6->zero[1] = pseudo_icmp6->zero[2] = 0;
	pseudo_icmp6->next_header =((struct hop_by_hop *)ip)->next_header;
	pseudo_icmp6->length = htonl(myoutput.length-(8+len));
	memcpy(c_icmp6, ((char *)ip+(8+len)), myoutput.sizeread - myoutput.ihl - LINK_LAYER -i);
	c_icmp6->checksum = 0;
	myoutput.icmp4.type = icmp4->type;
	myoutput.icmp4.code = icmp4->code;
	myoutput.icmp4.id = ntohs(icmp4->id);
	myoutput.icmp4.seq = ntohs(icmp4->seq);
	myoutput.icmp4.checksum = icmp4->checksum;
	myoutput.icmp4.re_checksum = checksum_calculation(check,size);
	myoutput.datalen =  myoutput.sizeread - 8 - myoutput.ihl - LINK_LAYER;
	myoutput.data = ip;
	myoutput.print_hop_by_hop = print_hop_by_hop;
}
