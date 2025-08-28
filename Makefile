CC = gcc
CFLAGS = -O2 -Wall `pkg-config --cflags gtk+-3.0`
LIBS = `pkg-config --libs gtk+-3.0` -lpthread

SRC = src/main.c
BIN = bin/netmapper

all:
	mkdir -p bin
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LIBS)

clean:
	rm -rf bin
