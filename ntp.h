#ifndef NTP_H
#define NTP_H
#include <stdio.h>
#include <string.h>

#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "others.h"
#include "utils.h"

#define MAXINT 4294967296.0
#define JAN_1970 2208988800U

#define UNSPECIFIED 0
#define PRIM_REF 1
#define INFO_QUERY 62
#define INFO_REPLY 63

struct frac_32{
	short int seconds;
	unsigned short int fraction;
};
struct frac_64{
	int seconds;
	unsigned int fraction;
};
struct ntp{
	char m:3,v:3,l:2;
	char peer_clock_stratum;
	char peer_polling_interval;
	char peer_clock_precision;
	struct frac_32 root_delay;
	struct frac_32 clock_dispertion;
	int reference_clock_id;
	struct frac_64 reference_timestamp;
	struct frac_64 original_timestamp;
	struct frac_64 received_timestamp;
	struct frac_64 transmit_timestamp;
	unsigned int key_id;
	unsigned char msg_digest[16];
};
void ntp32bits(struct frac_32 *ntp, struct frac_32 *result);
void ntp64bits(struct frac_64 *ntp, struct frac_64 *result, char *time, unsigned long int timelen);
int ntp_diff(struct frac_64 *o_ntp,struct frac_64 *n_ntp, struct frac_64 *result,char *time, unsigned long int timelen);
void timestamp(char *originator, char **buffer, struct frac_64 *f, int sign);
void ___set_id_fn___(char **buf, int *clock_id, unsigned long int size);
void service_ntp(char *data, unsigned long int datalen);
#endif
