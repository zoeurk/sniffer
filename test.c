#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void){
	struct addrinfo hints, *result, *rr;
	unsigned long int saddrlen;
	int s, s_, af;
	char buffer[45], buf[NI_MAXHOST];
	void *ptr;
	s = getaddrinfo("www.ovh.com",NULL, NULL, &result);
	if(s != 0){
		fprintf(stderr,"getaddrinfo(): %s\n",gai_strerror(s));
		exit(EXIT_FAILURE);
	}
	for(rr = result; rr != NULL; rr = rr->ai_next){
		af = rr->ai_family;
		switch(af){
			case AF_INET:
				ptr = &((struct sockaddr_in *)rr->ai_addr)->sin_addr;
				break;
			case AF_INET6:
				ptr = &((struct sockaddr_in6 *)rr->ai_addr)->sin6_addr;
				break;
		}
		memset(buf,0,NI_MAXHOST);
		if(inet_ntop(af, ptr, buffer, 45)){
			s_ = getnameinfo(rr->ai_addr,rr->ai_addrlen,buf,NI_MAXHOST, NULL, 0, 0);
			if(s_ == 0){
				printf("%s => %s\n",buffer, buf);
			}else{
				printf("getnameinfo(): %s; %i\n", gai_strerror(s_), s_);
			}
			//printf("%s\n",buffer);
			//break;
		}
	}
	freeaddrinfo(result);
	return 0;
}
