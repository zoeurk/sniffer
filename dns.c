#include <stdio.h>
#include <string.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns.h"
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
	char address[45],
		*issuetag[3] = {"issue", "issuewild", "iodef"};
	int stop, i;
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
		case CAA:*pdata = (*pdata + sizeof(struct answer));
			memset(address,0,45);
			for(i = 0; i < 3 && strstr(&((char *)*pdata)[1],issuetag[i]) == NULL; i++);;
			i = strlen(issuetag[i]);
			memcpy(address, &((char *)*pdata)[7], *len-i-2);
			printf("\tCAA = %u issue \"%s\"\n",**pdata, address);
			*pdata = (*pdata + *len);
			break;
		default:*pdata = (*pdata + sizeof(struct answer));
 			printf("\tTYPE (unknow): %u\n",type);
			//ReadName(*pdata,data,&stop, buf);
			*pdata = (*pdata + *len);
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
	/*for(i = 0; i < 29;i++){
		d = (struct dns *)((char *)data +i);
		printf("==>%li;ID:%u\nqdcount:%u\nAncount:%u\nNscount:%u\nArcount:%u\n",
			i,ntohs(d->id),ntohs(d->Qdcount),ntohs(d->Ancount),ntohs(d->Nscount),ntohs(d->Arcount)
		);
	}
	printf("EXIT\n");
	exit(EXIT_FAILURE);*/
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
				case ALL:
					printf("\tRequest for all registery\n");
					break;
				default:printf("\tTYPE (unknow):%u\n", ntohs(q->qtype));
					break;
			}
		}
	}
}

