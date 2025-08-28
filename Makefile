Makefile
CC=gcc
CFLAGS=-O2 -Wall
LDFLAGS=-lncurses -lpthread
SRC=src/main.c
BIN=bin/netmapper


all:
mkdir -p bin
$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LDFLAGS)


clean:
rm -rf bin
