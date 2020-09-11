#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <string.h>

#include "utils.h"
#include "others.h"

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
struct data_split *search_sdata(struct data_split *data,unsigned int seq, unsigned int ack){
	struct data_split *d = data;
	while(d){
		//if(d->ack == ack || d->ack = seq)
		if(d->ack == ack)
			return d;
		d = d->next;
	}
	return NULL;
}
struct data_split *add_sdata(struct data_split *data){
	struct data_split *d = data;
	if(data == NULL){
		d = calloc(1,sizeof(struct data_split));
	}else{
		while(d->next)
			d = d->next;
		d->next = calloc(1,sizeof(struct data_split));
		d = d->next;
	}
	return d;
}
struct data_split *free_sdata(struct data_split *ptr){
	struct data_split *d, *start;
	if(ptr == s_data){
		d = ptr->next;
		free(ptr->data);
		free(ptr);
		return d;
	}else{
		start = ptr;
		while(d->next != ptr)
			d = d->next;
		d->next = d->next->next;
		free(d->data);
		free(d);
		return start;
	}
}
