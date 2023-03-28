CFLAGS = -Wall -g

.PHONY: all
all: example-client example-server

example-client: example-client.o libNet.a lib/net.h
	gcc ${CFLAGS} -o example-client example-client.o libNet.a

example-client.o: example-client.c
	gcc ${CFLAGS} -c -o example-client.o example-client.c

example-server: example-server.o libNet.a lib/net.h
	gcc ${CFLAGS} -o example-server example-server.o libNet.a

example-server.o: example-server.c
	gcc ${CFLAGS} -c -o example-server.o example-server.c


# TODO: Cross platform support

libNet.a: libNet.o lib/net.h
	ar cr libNet.a libNet.o

libNet.o: lib/net_linux.c
	gcc ${CFLAGS} -c -o libNet.o lib/net_linux.c

.PHONY: clean
clean:
	rm -f *.o
	rm -f *.a
	rm example-client
	rm example-server