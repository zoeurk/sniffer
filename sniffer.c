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

#include "protocol.h"
#include "ntp.h"
#include "dns.h"
#include "utils.h"
#include "others.h"

#define DNS_PORT 53
#define NTP_PORT 123

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
												poptflags->protoflag = 1;
												break;
											case 1:	if(poptflags->protocol != 17 && poptflags->protocol != 0){
													ok  = -3;
													break;
												}
												poptflags->protocol = 17;
												poptflags->protoflag = 1;
												break;
											case 2:	if(poptflags->protocol != 1 && poptflags->protocol != 0 
													&& poptflags->port == 0)
												{
													ok  = -3;
													break;
												}
												poptflags->protocol = 1;
												poptflags->protoflag = 1;
												break;
											case 3:	if(poptflags->protocol != 58 && poptflags->protocol != 0
													&& poptflags->port == 0)
												{
													ok  = -3;
													break;
												}
												poptflags->protoflag = 1;
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
