CC=gcc
OPTIONS=-Wall -Wpadded -Wextra -std=gnu89 -g -O2
all:
	$(CC) $(OPTIONS) sniffer.c -o sniffer
verbose:
	$(CC) -v $(OPTIONS) sniffer.c -o sniffer
clean:
	rm -f sniffer
