all: logappend logread

CFLAGS=-g -Wall -O0 -std=c99
LIBS=-lcrypto
CC = gcc
UNAME := $(shell uname)
ifeq ($UNAME), Linux)
CFLAGS += -DLINUX -I/usr/local/ssl/include -L/usr/local/ssl/lib
endif

logappend: logappend.o
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

logread: logread.o func.o
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

logappend.o: logappend.c
	$(CC) -c -o $@ $(CFLAGS) $^

logread.o: logread.c 
	$(CC) -c -o $@ $(CFLAGS) $^

func.o: func.c
	$(CC) -c -o $@ $(CFLAGS) $^

clean:
	rm -f *.0 logappend logread