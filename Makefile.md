
---

### **Makefile**

```makefile
CC=gcc
CFLAGS=`pkg-config --cflags gtk+-3.0` -O2 -Wall -pthread
LIBS=`pkg-config --libs gtk+-3.0`
SRC=src/main.c
OUT=netmapper

all:
	mkdir -p bin
	$(CC) $(CFLAGS) -o bin/$(OUT) $(SRC) $(LIBS)

clean:
	rm -rf bin
