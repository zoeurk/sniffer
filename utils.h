#ifndef UTILS_H
#define UTILS_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <string.h>

#include "utils.h"
#include "others.h"

int ___getnameinfo___(void *sa,unsigned long int sa_sz,char **addr,unsigned long int addrlen,char *addr_ip);
struct data_split *search_sdata(struct data_split *data,unsigned int seq, unsigned int ack);
struct data_split *add_sdata(struct data_split *data);
struct data_split *free_sdata(struct data_split *ptr);
#endif
