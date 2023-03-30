.PHONY: all

CFLAGS = -Wall -g

objLin = obj/linux/

objWin = obj/windows/

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
all: libSockLin.a example-clientLin example-serverLin
else
all: libSockWin.a example-clientWin example-serverWin
endif

libSockWin.a: net_windows.o
	ar -r -s -c libSockWin.a net_windows.o

libSockLin.a: net_linux.o
	ar -r -s -c libSockLin.a net_linux.o

net_windows.o: lib/net_windows.c lib/net.h
	gcc -o net_windows.o -c $(CFLAGS) lib/net_windows.c
	
net_linux.o: lib/net_linux.c lib/net.h
	gcc -o net_linux.o -c $(CFLAGS) lib/net_linux.c

example-clientWin: example-client.o libSockWin.a lib/net.h
	gcc $(CFLAGS) -o example-client example-client.o libSockWin.a -lws2_32

example-clientLin: example-client.o libSockLin.a lib/net.h
	gcc $(CFLAGS) -o example-client example-client.o libSockLin.a

example-client.o: example-client.c
	gcc $(CFLAGS) -c -o example-client.o example-client.c

example-serverWin: example-server.o libSockWin.a lib/net.h
	gcc $(CFLAGS) -o example-server example-server.o libSockWin.a -lws2_32

example-serverLin: example-server.o libSockLin.a lib/net.h
	gcc $(CFLAGS) -o example-server example-server.o libSockLin.a

example-server.o: example-server.c
	gcc $(CFLAGS) -c -o example-server.o example-server.c

clean:
	rm -f *.o
	rm -f *.a
	rm example-client
	rm example-server