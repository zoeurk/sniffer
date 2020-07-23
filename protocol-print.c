#include <stdio.h>
#include <string.h>
#include "protocol-print.h"
#include "others.h"
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
	unsigned long int i,k;
	char *pdata;
	if(len > 0){
		printf("Data (%lu octet) (in hexadecimal):\n", len);
		for(i = 0, k = 1, pdata = data; i < len; i++, pdata++,k++){
			/*if(*pdata > 31 && *pdata != 127)
				printf("\tOctet %lu:\'%c\'\n", i+1, *pdata&0xFF);
			else
				printf("\tOctet %lu:0x%02x\n", i+1, *pdata&0xFF);*/
			if((k-1)%16==0)
				printf("octets:%lu\t",i);
			if(*pdata > 31 && *pdata != 127)
				printf("c::%c",*pdata&0xFF);
			else
				printf("0x%02x", *pdata&0xFF);
			if(k == len || k%8 == 0){
				if(k%16 == 0 || k == len)
					printf("\n");
				else	printf("  ");
			}else	printf(" ");
		}
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

