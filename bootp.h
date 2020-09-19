#ifndef BOOTP_H
#define BOOTP_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "others.h"
#include "utils.h"

#define MAGIC_COOKIE { 99, 130, 83, 99 }
#define VF_SMASK 1

struct dhcp{
	unsigned char op;
	unsigned char htype;
	unsigned char hlen;
	unsigned char hops;
	unsigned int xid;
	unsigned short int secs;
	unsigned short int flags;
	unsigned int ciaddr;
	unsigned int yiaddr;
	unsigned int siaddr;
	unsigned int giaddr;
	unsigned int chaddr[4];
	unsigned int sname[16];
	unsigned int file[32];
	unsigned int vend[16];
};
/*chapitre 8*/
void service_dhcp(void *data, unsigned long int len);
#endif
