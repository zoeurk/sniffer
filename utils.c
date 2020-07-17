#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <string.h>

#include "utils.h"

int ___getnameinfo___(void *sa,unsigned long int sa_sz,char **addr,unsigned long int addrlen,char *addr_ip){
	int ret;
	memset(sa, 0, sa_sz);
	((struct sockaddr_in *)sa)->sin_family = AF_INET;
	inet_pton(((struct sockaddr_in *)sa)->sin_family, addr_ip,
			&((struct sockaddr_in *)sa)->sin_addr);
	ret = getnameinfo((struct sockaddr *)sa, sa_sz,
		*addr,addrlen, NULL, 0, NI_NAMEREQD);
	if(ret == 0)
		return ret;
	((struct sockaddr_in6 *)sa)->sin6_family = AF_INET6;
	inet_pton(((struct sockaddr_in6 *)sa)->sin6_family, addr_ip,
			&((struct sockaddr_in6 *)sa)->sin6_addr);
	ret = getnameinfo((struct sockaddr *)sa, sa_sz,
		*addr,addrlen, NULL, 0, NI_NAMEREQD);
	if(ret == 0)
		return ret;
	else **addr = '\0';
	return -1;
	
}
