#include <stdio.h>
#include <string.h>

#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "ntp.h"
#include "others.h"
#include "utils.h"

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
