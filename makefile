CC=g++
CFLAGS=-march=native -O2 -pipe
LDFLAGS=-lpcap -lpthread -lncurses

all:
	$(CC) $(CFLAGS) main.cpp sessionlist.cpp $(LDFLAGS) -o sessionlist && strip sessionlist

clean:
	rm *.o

