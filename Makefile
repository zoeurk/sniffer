CC=gcc
OPTIONS=-Wall -Wpadded -Wextra -std=gnu89 -g -O2
all:
	$(CC) $(OPTIONS) sniffer.c protocol.c protocol-definition.c protocol-print.c ntp.c dns.c bootp.c others.c utils.c -o sniffer 
verbose:
	$(CC) -v $(OPTIONS) sniffer.c protocol.c protocol-definition.c protocol-print.c ntp.c dns.c bootp.c others.c utils.c -o sniffer
clean:
	rm -f sniffer
