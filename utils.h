#ifndef UTILS_H
#define UTILS_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <string.h>

#include "utils.h"

int ___getnameinfo___(void *sa,unsigned long int sa_sz,char **addr,unsigned long int addrlen,char *addr_ip);
#endif
