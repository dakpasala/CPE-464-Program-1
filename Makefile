CC=gcc
CFLAGS=-Wall -Wextra -Werror -std=c99
LIBS=-lpcap

all: trace

trace: trace.c
	$(CC) $(CFLAGS) -o trace trace.c $(LIBS)

clean:
	rm -f trace *.o