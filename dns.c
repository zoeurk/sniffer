#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns.h"
#include "others.h"
#include "utils.h"
const char *base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
void tobase64(char *input, char *output, unsigned int len)
{	unsigned char *pinput = (unsigned char *)input;
	output[0] = base64[pinput[0]>>2];
	output[1] = base64[((pinput[0]&3)<<4) | pinput[1]>>4];
	output[2] = (len<2)? '=' :base64[((pinput[1]&15)<<2) | (pinput[2]>>6)];
	output[3] = (len<3)? '=' :base64[(pinput[2]&63)];

}
int ReadName(unsigned char *reader, unsigned char *buf, int lablen, unsigned char *buffer, int len){
	int pos, _len_ = 0, jump = 0,ptr = 1;
	unsigned char *curpos, *jumped = NULL;
	unsigned char *pbuf = buffer;
	int l = len;
	curpos = reader;
	while((( l>0 || l == -1) && *curpos != 0) || jumped){
		if(jumped){
			if(*jumped >= 0xC0){
				pos = (*jumped << 8|jumped[1])&0x3FFF;
				jumped = &buf[pos];
			}
			_len_ = *jumped++;
			memcpy(pbuf,jumped,_len_);
			pbuf += _len_;
			*pbuf = '.';
			pbuf++;
			jumped += _len_;
			if(*jumped == 0){
				jumped = NULL;
				break;
			}
		}else{
			if(*curpos>=0xC0){
				pos = ((*curpos&0x3F) << 8)|curpos[1];
				if((buf + pos) > curpos){
					goto read;
				}
				jumped = &buf[pos];
				curpos += 2;
				jump += 2;
				if(l != -1)
					l -= 2;
				ptr = 0;
			}else{
				read:
				_len_ = *curpos++;
				jump++;
				memcpy(pbuf,curpos, _len_);
				pbuf += _len_;
				*pbuf = '.';
				pbuf++;
				curpos += _len_;
				jump += _len_;
				if(l != -1)
					l -= (_len_+1);
			}
		}
		if(lablen > 0 && jump >= lablen){
			*(pbuf - 1) = 0;
			return jump+ptr;
		}
	}
	*(pbuf - 1) = 0;
	return jump+ptr;
}
void dns_type_41(void *pdata){
	struct dnsopt *opt = (struct dnsopt *)pdata;
	printf("\tOPT:\n\t\ttype: %u\n\t\tLength: %u\n\t\tDO: %u\n\t\tTTL: %u\n",
		ntohs(opt->type), ntohs(opt->class), (ntohs(opt->DO)&0x8000) ? 1 : 0, ntohs(opt->ttl));
}
void dns_type(int type, unsigned char **pdata,long int *pdatalen, unsigned char *data, int *len){
	struct in_addr s;
	struct in6_addr s6;
	unsigned char buf[65535];
	char save[65535],
		*issuetag[3] = {"issuewild", "issue", "iodef"},
		input[4],output[5],*ptr;
	int stop, i, j, l, l_;
	long int time;
	memset(buf,0,65535);
	memset(input,0,4);
	memset(output,0,5);
	switch(type){
		case ADDRESS:
			*pdata = (*pdata + sizeof(struct answer));
			memcpy(&s.s_addr,*pdata,sizeof(s.s_addr));
			inet_ntop(AF_INET,&s,save,sizeof(save));
			printf("\tAddress: %s\n", save);
			*pdata = (*pdata + *len);
			*pdatalen -= (sizeof(struct answer) + *len);
			break;
		case NS:
			*pdata = (*pdata + sizeof(struct answer));
			stop = ReadName(*pdata,data, 0, buf, *len);
			printf("\tNS: %s\n", buf);
			*pdata = (*pdata + *len);
			*pdatalen -= (sizeof(struct answer) + stop);
			break;
		case CNAME:
			*pdata = (*pdata + sizeof(struct answer));
			stop = ReadName(*pdata,data, 0, buf, *len);
			printf("\tCNAME: %s\n", buf);
			*pdata += stop;
			*pdatalen -= (sizeof(struct answer) + stop);
			break;
		case SOA:
			*pdata = (*pdata + sizeof(struct answer));
			stop = ReadName(*pdata,data, 0, buf, *len);
			printf("\tSOA: %s\n", buf);
			*pdata = (*pdata + stop);
			*pdatalen -= (sizeof(struct answer) + stop);
			stop = ReadName(*pdata,data, 0, buf, *len);
			printf("\t\tMX: %s\n",buf);
			*pdata = (*pdata + stop);
			*pdatalen -= (stop);
			printf("\t\tSerial: %u\n\t\tRefresh: %u\n\t\tRetry: %u\n\t\tExpire: %u\n\t\tMinimum: %u\n",
				ntohl(((struct soa *)*pdata)->serial), ntohl(((struct soa *)*pdata)->refresh),
				ntohl(((struct soa *)*pdata)->retry),ntohl(((struct soa *)*pdata)->expire),ntohl(((struct soa *)*pdata)->minimum));
			*pdata += (sizeof(struct soa));
			*pdatalen -= (sizeof(struct soa));
			break;
		case PTR:
			*pdata = (*pdata + sizeof(struct answer));
			stop = ReadName(*pdata,data, 0, buf, *len);
			printf("\tHostname: %s\n", buf);
			*pdata = (*pdata + *len);
			*pdatalen -= (sizeof(struct answer) + *len);
			break;
		case MX:
			*pdata = (*pdata + sizeof(struct answer));
 			*pdata = (*pdata + sizeof(short int));
			stop = ReadName(*pdata,data, 0, buf, *len);
			*pdata = (*pdata + (*len-sizeof(short int)));
			*pdatalen -= (sizeof(struct answer) + sizeof(short int) + stop);
			printf("\tMX: %s\n", buf);
			break;
		case TXT:
			*pdata = (*pdata + sizeof(struct answer));
			stop = ReadName(*pdata,data, *len, buf, *len);
			printf("\tText: %s\n",buf);
			*pdata = (*pdata + *len);
			*pdatalen -= (*len + sizeof(struct answer));
			break;
		case ADDRESS6:
			*pdata = (*pdata + sizeof(struct answer));
 			memcpy(&s6.s6_addr,*pdata,sizeof(s6.s6_addr));
			inet_ntop(AF_INET6,&s6,save,sizeof(save));
			printf("\tAddress: %s\n", save);
			*pdata = (*pdata + *len);
			*pdatalen -= (*len + sizeof(struct answer));
			break;
		case OPT:
			dns_type_41(*pdata);
			*pdatalen -= sizeof(struct dnsopt);
			break;
		case CAA:*pdata = (*pdata + sizeof(struct answer));
			memset(save,0,45);
			for(i = 0; i < 3 && strstr(&((char *)*pdata)[1],issuetag[i]) == NULL; i++);;
			j = strlen(issuetag[i]);
			memcpy(save, &((char *)*pdata)[2], *len-2);
			printf("\tCAA = %u %s \"%s\"\n", **pdata, issuetag[i], &save[j]);
			*pdata = (*pdata + *len);
			*pdatalen -= (sizeof(struct answer) + *len);
			break;
		case RRSIG:
			printf("\trdata_%i ",RRSIG);
			*pdata = (*pdata + sizeof(struct answer));
			printf("\n\t\tCovered: %u\n\t\tAlgotithm: %i\n\t\tLabel: %i\n\t\tOriginal TTL: %u\n\t\tKey tag: %u\n",
				ntohs(*((unsigned short int *)*pdata)),((unsigned char *)*pdata)[2],
				((unsigned char *)*pdata)[3],ntohl(((unsigned int *)*pdata)[1]),
				ntohs(((unsigned short int *)*pdata)[8]));
			time = ntohl(((unsigned int *)*pdata)[2]);
			printf("\t\tExpiration: %s",ctime(&time));
			time = ntohl(((unsigned int *)*pdata)[3]);
			printf("\t\tInception: %s",ctime(&time));
			stop = ReadName(&((unsigned char *)*pdata)[18],data,0, buf,*len);
			printf("\t\tOwner: %s\n",buf);
			printf("\t\tSignature: ");
			l = *len-18-stop;
			ptr = (char *)&((unsigned char *)*pdata)[18 + stop];
			l_ = 3;
			while(l > 0){
				memcpy(input,ptr,l_);
				tobase64(input, output, l_);
				printf("%s", output);
				memset(input,0,4);
				memset(output,0,5);
				l -= 3;
				if(l < 3)
					l_ = l;
				ptr += 3;
			}
			printf("\n");
			*pdata += *len;
			*pdatalen -= (*len + sizeof(struct answer));
			break;
		default:*pdata = (*pdata + sizeof(struct answer));
 			printf("\tTYPE (unknow): %u\n",type);
			*pdata = (*pdata + *len);
			*pdatalen -= (*len + sizeof(struct answer));
			break;
	}
}
void services_udp_src(char *data, unsigned long int length, int proto, unsigned int seq, unsigned int ack){
	struct data_split *splited = NULL;
	unsigned long int i, j;
	long int len = (long int)length;
	unsigned char buf[65535];// *reader = (unsigned char *)data + sizeof(struct dns);
	struct dns *d;
	struct answer *a;
	int stop = 0,k = 0,l;
	unsigned short int count[3];
	char *text[3] = {"Answers records:","Authoritive records:","Additional records:"},
		*pdata;
	if(proto == 6){
		if(length -2 !=  ntohs(*((unsigned short int *)data))){
			if((splited = search_sdata(s_data,seq,ack)) == NULL){
				printf("Data splited\n");
				splited = add_sdata(s_data);
				if(s_data == NULL)
					s_data = splited;
				splited->seq = seq;
				splited->ack = ack;
				splited->data = calloc(length,sizeof(char));
				memcpy(splited->data,data,length);
				splited->len = length;
				splited->len_total = ntohs(*((unsigned short int *)data));
				return;
			}else{
				splited->data = realloc(splited->data,splited->len+length);
				memcpy(&((char *)splited->data)[splited->len],data,length);
				splited->len += length;
				if(splited->len < splited->len_total){
					printf("Data splited\n");
					return;
				}
				d = (struct dns *)(splited->data + 2);
				pdata = (splited->data + 2);
				len = splited->len - 2;
			}
		}else{
			d = (struct dns *)(data + 2);
			pdata = (data + 2);
			len -= 2;
		}
	}else{
		pdata = data;
		d = (struct dns *)data;
	}
	printf("ID:%u\nqdcount:%u\nAncount:%u\nNscount:%u\nArcount:%u\n",
			ntohs(d->id),ntohs(d->Qdcount),ntohs(d->Ancount),ntohs(d->Nscount),ntohs(d->Arcount));
	count[0] = ntohs(d->Ancount);
	count[1] = ntohs(d->Nscount);
	count[2] = ntohs(d->Arcount);
	a = (struct answer *)(pdata + sizeof(struct dns) + strlen(pdata+sizeof(struct dns)) + 1 + sizeof(struct question));
	memset(buf,0,65535);
	switch(d->Rcode){
		case 0:	for(l = 0; l < 3; l++){
				if(count[l])
					printf("%s\n",text[l]);
				for(i = 0; len > 0 && i < count[l]; i++){
					memset(buf,0,65535);
					stop = ReadName((unsigned char *)a,(unsigned char *)pdata, 0, buf, len);
					printf("\tNAME: %s\n", buf);
					len -= stop;
					a = (struct answer *)(((char *)a + stop));
					k = ntohs(((struct answer *)a)->len);
					j = ntohs(((struct answer *)a)->type);
					if(len <= 0 || len - k<=0)
						break;
					dns_type(j, (unsigned char **)&a, &len, (unsigned char *)pdata, &k);
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
	if(splited && splited->len >= splited->len_total){
		s_data = free_sdata(splited);
	}
}
void services_udp_dst(char *data){
	struct dns *d = (struct dns *)data;
	struct question * q = (struct question *)(data+sizeof(struct dns));
	unsigned char buf[65535];
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
			stop = ReadName((unsigned char *)q,(unsigned char *)data, 0, buf, -1);
			printf("\tQuestion: %s\n",buf);
			if(i || j){
					q = (struct question *)((char *)q + sizeof(struct question) + stop);
			}else{
				q = (struct question *)((char *)q + stop);
			}
			switch(ntohs(q->qtype)){
				case ADDRESS:
					printf("\tAddress: %s:%i\n",buf,stop);
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
				case ALL:
					printf("\tRequest for all registery\n");
					break;
				default:printf("\tTYPE (unknow):%u\n", ntohs(q->qtype));
					break;
			}
		}
	}
}

