CC=gcc
CFLAGS=-Wall -Wextra -Werror -std=c99 -D_GNU_SOURCE
LIBS=-lpcap

all: trace

trace: trace.c
	$(CC) $(CFLAGS) -o trace trace.c checksum.c $(LIBS)

clean:
	rm -f trace *.o