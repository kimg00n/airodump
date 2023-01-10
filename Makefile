CC=gcc
CFLAGS=-I.

all: airodump

airodump: airodump.o
	$(CC) -o airodump airodump.o -lpcap

airodump.o: airodump.c
	$(CC) $(CFLAGS) -c airodump.c

clean:
	rm -f airodump airodump.o
