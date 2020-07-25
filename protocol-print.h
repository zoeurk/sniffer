#ifndef PROTOCOLPRINT_H
#define PROTOCOLPRINT_H
#include <stdio.h>
#include <string.h>
#include "others.h"
#include "protocol.h"
#include "protocol-print.h"
#include "protocol-definition.h"
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
void print_hop_by_hop(char *data, unsigned long int len);
#endif
