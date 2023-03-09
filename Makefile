CFLAGS = -Wall -g

.PHONY: all
all: example

example: example.o libNet.a lib/net.h
	gcc ${CFLAGS} -o example example.o libNet.a

example.o: example.c
	gcc ${CFLAGS} -c -o example.o example.c


# TODO: Cross platform support

libNet.a: libNet.o lib/net.h
	ar cr libNet.a libNet.o

libNet.o: lib/net_linux.c
	gcc ${CFLAGS} -c -o libNet.o lib/net_linux.c

.PHONY: clean
clean:
	rm -f *.o
	rm -f *.a
	rm example